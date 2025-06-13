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
  
  # Rate limiting check
  if Rack::Attack.throttled?("logins/ip", request.remote_ip)
    flash[:error] = "Too many login attempts. Please try again later."
    return render "sessions/new"
  end
  
  begin
    # Normalize the email address
    user = User.authenticate(params[:email].to_s.strip.downcase, params[:password].to_s)
  rescue RuntimeError => e
    # Store error message for display
    @error_message = e.message
  end

  if user
    # Generate contextual information
    user_agent = request.user_agent
    remote_ip = request.remote_ip
    context_hash = Digest::SHA256.hexdigest(remote_ip + user_agent)
    
    if params[:remember_me]
      # Implement token rotation and contextual authentication
      new_token = user.regenerate_auth_token
      
      # Set secure cookie with context validation and proper attributes
      cookies[:auth_token] = {
        value: "#{new_token}|#{context_hash}",
        expires: 2.hours.from_now,
        secure: true,      # Only transmit over HTTPS
        httponly: true,    # Prevent JavaScript access
        same_site: :strict # Prevent CSRF attacks
      }
    else
      session[:user_id] = user.id
      # Even for session-based auth, regenerate the token for potential future use
      user.regenerate_auth_token
    end
    redirect_to path
  else
    # Track failed attempts for rate limiting
    Rack::Attack.track("logins/ip", request.remote_ip)
    
    flash[:error] = @error_message || "Authentication failed"
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
