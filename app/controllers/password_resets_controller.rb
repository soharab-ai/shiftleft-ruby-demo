# frozen_string_literal: true
class PasswordResetsController < ApplicationController
  skip_before_action :authenticated

def reset_password
  # Using JWT for signed tokens instead of database-stored tokens
  token = params[:token]
  
  # Implement rate limiting for password resets
  unless rate_limit_check(request.ip, 'password_reset')
    log_security_event("Password reset rate limit exceeded", request.ip)
    flash[:error] = "Too many attempts. Please try again later."
    return redirect_to :login
  end
  
  begin
    # JWT verification replaces simple token lookup
    decoded_token = verify_and_decode_token(token)
    user_id = decoded_token['user_id']
    user = User.find(user_id)
    
    # Additional verification step
    email_confirmation = params[:email]
    if user && token_not_expired?(decoded_token) && 
       params[:password] && params[:confirm_password] && 
       params[:password] == params[:confirm_password] && 
       user.email.downcase == email_confirmation.downcase
      
      user.password = params[:password]
      user.reset_password_token = nil
      user.save!
      
      # Comprehensive logging of successful password reset
      log_security_event("Password reset successful for user #{user_id}", request.ip, user_id)
      
      flash[:success] = "Your password has been reset please login"
      redirect_to :login
    else
      # Comprehensive logging of failed password reset
      log_security_event("Password reset failed - invalid parameters", request.ip, user_id)
      
      flash[:error] = "Error resetting your password. Please try again."
      redirect_to :login
    end
  rescue JWT::DecodeError, ActiveRecord::RecordNotFound => e
    # Comprehensive logging of token validation errors
    log_security_event("Password reset failed - invalid token", request.ip)
    
    flash[:error] = "Invalid or expired password reset link. Please request a new one."
    redirect_to :forgot_password_path
  end
end

private

# Generate a secure token with high entropy and HMAC verification
def generate_reset_token(user)
  # Create payload with user ID and expiration time
  payload = {
    user_id: user.id,
    exp: 24.hours.from_now.to_i,
    jti: SecureRandom.urlsafe_base64(32) # Add token entropy
  }
  
  # Sign token with application secret
  token = JWT.encode(payload, Rails.application.secrets.secret_key_base, 'HS256')
  
  # Add additional HMAC verification
  hmac = OpenSSL::HMAC.hexdigest('sha256', Rails.application.secrets.secret_key_base, "#{user.id}:#{payload[:jti]}")
  
  # Return combined token with HMAC
  "#{token}.#{hmac}"
end

# Verify and decode the token
def verify_and_decode_token(token)
  # Split token and HMAC
  jwt, hmac = token.split('.')
  
  # Decode the JWT
  decoded_token = JWT.decode(jwt, Rails.application.secrets.secret_key_base, true, { algorithm: 'HS256' })[0]
  
  # Verify HMAC
  expected_hmac = OpenSSL::HMAC.hexdigest('sha256', Rails.application.secrets.secret_key_base, "#{decoded_token['user_id']}:#{decoded_token['jti']}")
  
  raise JWT::DecodeError, "Invalid HMAC" unless hmac == expected_hmac
  
  decoded_token
end

# Check if token has not expired
def token_not_expired?(decoded_token)
  # JWT library automatically checks 'exp' claim
  # This is just an additional check
  exp_time = Time.at(decoded_token['exp'])
  exp_time > Time.now
end

# Rate limiting implementation
def rate_limit_check(ip, action, max: 5, period: 1.hour)
  # Use Rails.cache for tracking attempts
  cache_key = "rate_limit:#{action}:#{ip}"
  attempts = Rails.cache.read(cache_key) || 0
  
  if attempts >= max
    return false
  else
    Rails.cache.write(cache_key, attempts + 1, expires_in: period)
    return true
  end
end

# Secure logging implementation
def log_security_event(message, ip, user_id = nil)
  # Anonymize IP address for privacy
  anonymized_ip = ip.split('.').first(2).join('.') + '.x.x'
  
  log_data = {
    event: "password_reset_attempt",
    message: message,
    timestamp: Time.now.utc.iso8601,
    ip_partial: anonymized_ip
  }
  log_data[:user_id] = user_id if user_id
  
  # Use Rails logger for security events
  Rails.logger.info("SECURITY EVENT: #{log_data.to_json}")
end

  end

  def confirm_token
    if !params[:token].nil? && is_valid?(params[:token])
      flash[:success] = "Password reset token confirmed! Please create a new password."
      render "password_resets/reset_password"
    else
      flash[:error] = "Invalid password reset token. Please try again."
      redirect_to :login
    end
  end

  def send_forgot_password
    @user = User.find_by_email(params[:email]) unless params[:email].nil?

    if @user && password_reset_mailer(@user)
      flash[:success] = "Password reset email sent to #{params[:email]}"
      redirect_to :login
    else
      flash[:error] = "There was an issue sending password reset email to #{params[:email]}".html_safe unless params[:email].nil?
    end
  end

  private

  def password_reset_mailer(user)
    token = generate_token(user.id, user.email)
    UserMailer.forgot_password(user.email, token).deliver
  end

  def generate_token(id, email)
    hash = Digest::MD5.hexdigest(email)
    "#{id}-#{hash}"
  end

  def is_valid?(token)
    if token =~ /(?<user>\d+)-(?<email_hash>[A-Z0-9]{32})/i

      # Fetch the user by their id, and hash their email address
      @user = User.find_by(id: $~[:user])
      email = Digest::MD5.hexdigest(@user.email)

      # Compare and validate our hashes
      return true if email == $~[:email_hash]
    end
  end
end
