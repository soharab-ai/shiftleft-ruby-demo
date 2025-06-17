# frozen_string_literal: true
class SessionsController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @url = params[:url]
    redirect_to home_dashboard_index_path if current_user
  end

def create
  # Validate and sanitize URL parameter against allowed paths to prevent open redirects
  allowed_paths = [home_dashboard_index_path, root_path]
  safe_redirect_path = params[:url].present? && allowed_paths.include?(params[:url]) ? 
                      params[:url] : home_dashboard_index_path
  
  begin
    user = User.authenticate(params[:email]&.to_s&.strip&.downcase, params[:password])
  rescue => e
    # Log the error securely but don't expose details to users
    logger.error "Authentication error: #{e.message}"
    user = nil
  end

  if user
    # Generate a new server-side session instead of storing credentials in cookies
    reset_session # Prevent session fixation
    session_id = SecureRandom.uuid
    session[:session_id] = session_id
    
    # Create a context fingerprint for validating future requests
    fingerprint = user.create_fingerprint(request)
    
    # Store session data server-side in Redis with expiry
    redis = Redis.new
    session_data = {
      user_id: user.id,
      fingerprint: fingerprint,
      created_at: Time.now.to_i
    }
    
    # Set session expiry (30 minutes for inactivity, 2 weeks max if remember_me)
    expiry_time = params[:remember_me] ? 2.weeks.to_i : 30.minutes.to_i
    
    # Store in Redis - session_id as key, session data as value
    redis.setex("session:#{session_id}", expiry_time, session_data.to_json)
    
    # Set a reference cookie only - not containing actual credentials
    if params[:remember_me]
      cookies.permanent[:session_ref] = { 
        value: session_id,
        httponly: true,
        secure: Rails.env.production?,
        same_site: :lax,
        expires: 2.weeks.from_now
      }
    else
      # Short-lived session reference
      cookies[:session_ref] = {
        value: session_id,
        httponly: true,
        secure: Rails.env.production?,
        same_site: :lax
      }
    end
    
    # Add the session to the token registry for possible revocation
    TokenRegistry.register_token(user.id, session_id, expiry_time)
    
    redirect_to safe_redirect_path
  else
    # Generic error message to prevent user enumeration
    flash[:error] = "Invalid email or password"
    render "sessions/new"
  end
end

  end

  def destroy
    cookies.delete(:auth_token)
    reset_session
    redirect_to root_path
  end
end
