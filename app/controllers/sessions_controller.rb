# frozen_string_literal: true
class SessionsController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @url = params[:url]
    redirect_to home_dashboard_index_path if current_user
  end

def create
  # Verify CSRF token for authentication requests
  verify_authenticity_token
  
  path = params[:url].present? ? params[:url] : home_dashboard_index_path
  user = nil
  
  begin
    # Normalize the email address
    user = User.authenticate(params[:email].to_s.strip.downcase, params[:password])
  rescue => e
    # Log the exception securely without exposing details
    Rails.logger.error("Authentication error: #{e.class.name}")
  end

  if user
    # Check if 2FA is enabled for the user
    if user.totp_enabled
      # Store partial authentication state in session
      session[:pending_2fa_user_id] = user.id
      return redirect_to two_factor_auth_path
    end
    
    # Generate JWT token with client fingerprinting
    jwt_token = user.generate_jwt(request.remote_ip, request.user_agent)
    refresh_token = user.generate_refresh_token
    
    # Set server-side session instead of storing credentials in cookies
    session[:user_id] = user.id
    
    # Store the JWT in a short-lived, secure cookie
    cookies[:jwt_token] = {
      value: jwt_token,
      expires: 30.minutes.from_now,
      httponly: true,
      secure: Rails.env.production?,
      same_site: :strict
    }
    
    # Store refresh token in a separate secure cookie
    if params[:remember_me]
      cookies.encrypted[:refresh_token] = {
        value: refresh_token,
        expires: 2.weeks.from_now,
        httponly: true,
        secure: Rails.env.production?,
        same_site: :strict
      }
    end
    
    redirect_to path
  else
    # Generic error message that doesn't reveal specific authentication failures
    flash[:error] = "Invalid email or password"
    render "sessions/new"
  end
end

# New method to handle 2FA verification
def verify_2fa
  user_id = session[:pending_2fa_user_id]
  user = User.find_by(id: user_id)
  
  if user && user.verify_totp(params[:totp_code])
    # Clear temporary session data
    session.delete(:pending_2fa_user_id)
    
    # Complete authentication after successful 2FA
    jwt_token = user.generate_jwt(request.remote_ip, request.user_agent)
    refresh_token = user.generate_refresh_token
    
    session[:user_id] = user.id
    
    cookies[:jwt_token] = {
      value: jwt_token,
      expires: 30.minutes.from_now,
      httponly: true,
      secure: Rails.env.production?,
      same_site: :strict
    }
    
    if params[:remember_me]
      cookies.encrypted[:refresh_token] = {
        value: refresh_token,
        expires: 2.weeks.from_now,
        httponly: true,
        secure: Rails.env.production?,
        same_site: :strict
      }
    end
    
    redirect_to home_dashboard_index_path
  else
    flash[:error] = "Invalid verification code"
    render "sessions/two_factor"
  end
end

# Token refresh method
def refresh
  refresh_token = cookies.encrypted[:refresh_token]
  user = nil
  
  if refresh_token
    # Find user by hashed refresh token
    user = User.find_by(refresh_token_hash: Digest::SHA256.hexdigest(refresh_token))
  end
  
  if user && user.refresh_token_expiry > Time.now
    # Generate new tokens and invalidate old ones (token rotation)
    jwt_token = user.generate_jwt(request.remote_ip, request.user_agent)
    new_refresh_token = user.generate_refresh_token
    
    cookies[:jwt_token] = {
      value: jwt_token,
      expires: 30.minutes.from_now,
      httponly: true,
      secure: Rails.env.production?,
      same_site: :strict
    }
    
    cookies.encrypted[:refresh_token] = {
      value: new_refresh_token,
      expires: 2.weeks.from_now,
      httponly: true,
      secure: Rails.env.production?,
      same_site: :strict
    }
    
    render json: { success: true }
  else
    # Clear invalid tokens
    cookies.delete(:jwt_token)
    cookies.delete(:refresh_token)
    render json: { success: false }, status: :unauthorized
  end
end

  end

  def destroy
    cookies.delete(:auth_token)
    reset_session
    redirect_to root_path
  end
end
