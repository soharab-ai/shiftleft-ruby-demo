# frozen_string_literal: true
class PasswordResetsController < ApplicationController
  skip_before_action :authenticated

def reset_password
  # Add security headers for the response
  response.headers['Cache-Control'] = 'no-store'
  response.headers['Pragma'] = 'no-cache'

  begin
    # Add anti-brute force rate limiting
    if Rails.cache.read("password_reset_attempts:#{request.remote_ip}").to_i > 5
      flash[:error] = "Too many attempts. Please try again later."
      Rails.logger.warn("[SECURITY] Rate limit exceeded for password reset from #{request.remote_ip}")
      redirect_to :login and return
    end
    Rails.cache.increment("password_reset_attempts:#{request.remote_ip}", 1, expires_in: 1.hour)

    # Enhanced JWT verification with audience and issuer claims
    payload = JWT.decode(params[:token], Rails.application.secrets.secret_key_base, true, 
                        { algorithm: 'HS256', verify_expiration: true, 
                          aud: "password_reset", iss: "your_application_name",
                          verify_aud: true, verify_iss: true }).first
    user = User.find_by(id: payload['user_id'])

    if user && valid_password?(params[:password], params[:confirm_password])
      user.password = params[:password]
      user.save!
      # Add audit logging for successful password reset
      Rails.logger.info("[SECURITY] Password reset successful for user #{user.id}")
      flash[:success] = "Your password has been reset please login"
      redirect_to :login
    else
      # Add audit logging for validation failure
      Rails.logger.warn("[SECURITY] Password reset failed due to validation errors for token #{params[:token][0..5]}...")
      flash[:error] = "Error resetting your password. Please try again."
      redirect_to :login
    end
  rescue JWT::DecodeError, JWT::ExpiredSignature, JWT::InvalidAudError, JWT::InvalidIssuerError
    # Add audit logging for invalid token
    Rails.logger.warn("[SECURITY] Failed password reset attempt with token #{params[:token][0..5]}...")
    flash[:error] = "Invalid or expired reset token. Please request a new password reset."
    redirect_to :login
  rescue ActiveRecord::RecordNotFound
    # Add audit logging for non-existent user
    Rails.logger.warn("[SECURITY] Password reset attempt for non-existent user with token #{params[:token][0..5]}...")
    flash[:error] = "User not found. Please request a new password reset."
    redirect_to :login
  end
end

# Added helper method for password complexity validation
def valid_password?(password, confirmation)
  return false unless password.present? && confirmation.present? && password == confirmation
  return false unless password.length >= 8
  return false unless password =~ /[A-Z]/ && password =~ /[0-9]/ && password =~ /[^A-Za-z0-9]/
  true
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
  email = params[:email]
  # Sanitize the email parameter for display in all contexts
  sanitized_email = email.present? ? sanitize(email) : nil
  
  # Validate email format before processing
  if email.present? && valid_email_format?(email)
    @user = User.find_by_email(email)
    
    if @user && password_reset_mailer(@user)
      # Use sanitized email in success message to prevent XSS
      flash[:success] = "Password reset email sent to #{sanitized_email}"
      redirect_to :login
      return
    end
  end
  
  # Use sanitized email in error message if email was provided
  if email.present?
    flash[:error] = "There was an issue sending password reset email to #{sanitized_email}"
  end
end

# Helper method to validate email format
def valid_email_format?(email)
  email =~ /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
end

# Helper method that combines multiple sanitization techniques for thorough protection
def sanitize(content)
  # First strip any HTML tags, then escape any remaining special characters
  ActionController::Base.helpers.strip_tags(
    ERB::Util.html_escape(content)
  )
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
