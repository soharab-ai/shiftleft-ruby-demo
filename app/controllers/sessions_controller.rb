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
  begin
    # Normalize the email address, why not
    user = User.authenticate(params[:email].to_s.strip.downcase, params[:password])
  rescue RuntimeError => e
    # don't do ANYTHING
  end

  if user
    if params[:remember_me]
      # Generate a new timed token for this session instead of reusing auth_token
      token_data = { 
        user_id: user.id,
        client_ip: request.remote_ip,
        user_agent: request.user_agent,
        issued_at: Time.now.to_i,
        expires_at: 2.weeks.from_now.to_i
      }
      
      # Store session reference in server-side cache
      session_id = SecureRandom.hex(32)
      Rails.cache.write("remember_session:#{session_id}", token_data, expires_in: 2.weeks)
      
      # Set encrypted cookie with session reference only - not the actual credentials
      cookies.encrypted[:remember_token] = {
        value: session_id,
        httponly: true,     # Prevents JavaScript access to the cookie
        secure: true,       # Ensures cookie is only sent over HTTPS
        same_site: :strict, # Prevents cross-site cookie transmission
        expires: 2.weeks.from_now
      }
    else
      session[:user_id] = user.id
    end
    redirect_to path
  else
    flash[:error] = e.message
    render "sessions/new"
  end
end

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
