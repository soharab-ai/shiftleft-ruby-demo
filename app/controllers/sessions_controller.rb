# frozen_string_literal: true
class SessionsController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @url = params[:url]
    redirect_to home_dashboard_index_path if current_user
  end

def create
  path = params[:url].present? ? params[:url] : home_dashboard_index_path
  
  # Implement rate limiting before authentication
  if exceeded_login_attempts?(params[:email].to_s.strip.downcase)
    lock_account_temporarily(params[:email].to_s.strip.downcase)
    flash[:error] = "Too many failed login attempts. Account temporarily locked."
    return render "sessions/new", status: :too_many_requests
  end
  
  begin
    # Normalize the email address
    user = User.authenticate(params[:email].to_s.strip.downcase, params[:password])
  rescue RuntimeError => e
    # Properly log authentication failures with generic message to user
    Rails.logger.warn "Authentication failure: #{e.message}"
    record_failed_attempt(params[:email].to_s.strip.downcase)
  end

  if user
    # Rotate the auth token for enhanced security
    user.rotate_auth_token if user.respond_to?(:rotate_auth_token)
    
# Secure logout implementation
def destroy
  if session_id = cookies[:session_id]
    # Remove server-side session
    Rails.cache.delete("user_session:#{session_id}")
    
    # Remove client-side cookie
    cookies.delete(:session_id)
  end
  
  # If user is found, invalidate their token as well
  current_user.logout if current_user
  
  redirect_to login_path, notice: "You have been successfully logged out."
end

    context_fingerprint = generate_context_fingerprint(request)
    hmac_data = "#{user.id}|#{expiry_time.to_i}|#{context_fingerprint}"
    hmac_signature = OpenSSL::HMAC.hexdigest('SHA256', Rails.application.secrets.secret_key_base, hmac_data)
    
    # Store session data server-side
    Rails.cache.write(
      "user_session:#{session_id}", 
      {
        user_id: user.id,
        expires_at: expiry_time,
        hmac: hmac_signature,
        context_fingerprint: context_fingerprint
      },
      expires_in: params[:remember_me] ? 30.days : 2.hours
    )
    
    if params[:remember_me]
      # Only store the reference ID in the cookie, not the actual credentials
      cookies.permanent[:session_id] = {
        value: session_id,
        httponly: true,
        secure: true,
        same_site: :lax
      }
    else
      # Set session reference with shorter expiry
      cookies[:session_id] = {
        value: session_id,
        httponly: true,
        secure: true,
        same_site: :lax,
        expires: 2.hours.from_now
      }
    end
    
    # Reset failed login attempts counter
    reset_failed_attempts(params[:email].to_s.strip.downcase)
    
    redirect_to path
  else
    flash[:error] = "Invalid email or password. Please try again."
    render "sessions/new"
  end
end


  if user
    # Track successful login for rate limiting purposes
    Rack::Attack.reset_fail_count(request.ip, params[:email].to_s.strip.downcase)
    
    if params[:remember_me]
      # Generate a secure session identifier instead of using auth_token directly
      session_id = SecureRandom.hex(32)
      
      # Store the mapping between session_id and user auth_token in Redis
      # with appropriate expiration
      expiration_time = 2.weeks.from_now
      Redis.current.setex(
        "session:#{session_id}",
        2.weeks.to_i,
        user.id.to_s
      )
      
      # Store only the session ID in the cookie, not the actual auth token
      cookies[:session_id] = {
        value: session_id,
        expires: expiration_time,
        httponly: true,
        secure: Rails.env.production?,
        same_site: :lax
      }
    else
      # Use Rails session management for non-persistent sessions
      session[:user_id] = user.id
    end
    
    redirect_to path
  else
    # Implement rate limiting for failed attempts
    track_failed_login_attempt(request.ip, params[:email].to_s.strip.downcase)
    
    flash[:error] = error_message
    render "sessions/new"
  end
end

private

# Track failed login attempts for rate limiting
def track_failed_login_attempt(ip, email)
  Rack::Attack.increment_fail_count(ip, email)
  
  # Check if account should be temporarily locked
  if Rack::Attack.fail_count(ip, email) >= 5
    Rails.logger.warn("Multiple failed login attempts detected for #{email} from #{ip}")
  end
end

  end

  def destroy
    cookies.delete(:auth_token)
    reset_session
    redirect_to root_path
  end
end
