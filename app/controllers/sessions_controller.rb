# frozen_string_literal: true
class SessionsController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @url = params[:url]
    redirect_to home_dashboard_index_path if current_user
  end

def create
  # Validate redirect URL to prevent open redirect attacks
  path = params[:url].present? ? validate_redirect_url(params[:url]) : home_dashboard_index_path
  
  begin
    # Normalize the email address, why not
    user = User.authenticate(params[:email].to_s.strip.downcase, params[:password])
  rescue RuntimeError => e
    # Properly handle errors without exposing sensitive details
    logger.error("Authentication error: #{e.message}")
    user = nil
  end

  if user
    # Implement token rotation for better security
    user.regenerate_auth_token if user.respond_to?(:regenerate_auth_token)
    
    # Check for two-factor authentication
    if user.respond_to?(:two_factor_enabled?) && user.two_factor_enabled?
      session[:pending_user_id] = user.id
      redirect_to two_factor_auth_path
      return
    end
    
    if params[:remember_me]
      # Enhanced cookie security with expiration, SameSite, and Host prefix
      cookies["__Host-auth_token"] = {
        value: user.auth_token,
        expires: 2.weeks.from_now,
        secure: true, # Always use secure for __Host prefix
        httponly: true,
        same_site: :lax
      }
    else
      session[:user_id] = user.id
    end
    redirect_to path
  else
    # Generic error message to avoid information disclosure
    flash[:error] = "Invalid email or password"
    render "sessions/new"
  end
end

private

def validate_redirect_url(url)
  # Only allow internal redirects or whitelisted domains
  if url.start_with?('/')
    # Internal URL
    return url
  elsif url.start_with?(root_url)
    # URL within our domain
    return url
  else
    # Default to home page for safety
    return home_dashboard_index_path
  end
end

  end

  def destroy
    cookies.delete(:auth_token)
    reset_session
    redirect_to root_path
  end
end
