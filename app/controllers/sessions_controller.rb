# frozen_string_literal: true
class SessionsController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @url = params[:url]
    redirect_to home_dashboard_index_path if current_user
  end

def create
  # CSRF protection explicitly verified for authentication
  verify_authenticity_token
  
  # Sanitize and validate the redirect URL to prevent open redirects
  path = if params[:url].present? && params[:url] =~ /\A\/[a-zA-Z0-9\/\-_]*\z/
    params[:url]
  else
    home_dashboard_index_path
  end
  
  # Initialize error message variable outside exception block for proper scope
  error_message = "Invalid email or password"
  user = nil
  
  begin
    # Normalize the email address
    user = User.authenticate(params[:email].to_s.strip.downcase, params[:password])
  rescue RuntimeError => e
    # Store error message but don't expose specific details
    error_message = "Authentication failed"
    # Log the real error securely
    Rails.logger.error("Authentication error: #{e.message}")
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
