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
    # Normalize the email address
    user = User.authenticate(params[:email].to_s.strip.downcase, params[:password])
    
    if user
      # Generate a new auth token on each login (token rotation)
      new_auth_token = SecureRandom.hex(32)
      
      # Store token with client context for binding validation
      token_data = {
        token: new_auth_token,
        ip: request.remote_ip,
        user_agent: request.user_agent,
        created_at: Time.now.to_i
      }
      
      # Update the user's auth token in the database
      user.update(auth_token: new_auth_token, auth_context: token_data.to_json)
      
      if params[:remember_me]
        # Set cookie with proper security flags and reasonable expiration
        cookies[:auth_token] = {
          value: new_auth_token,
          expires: 2.weeks.from_now,
          httponly: true,
          secure: true,
          same_site: :strict # Enhanced CSRF protection
        }
      else
        # For session-only authentication
        session[:user_id] = user.id
        # Store a secondary authentication factor for dual-auth strategy
        session[:auth_context] = token_data.to_json
      end
      
      # Add CSRF protection token
      form_authenticity_token
      
      redirect_to path
    else
      # Generic error message to prevent information disclosure
      flash[:error] = "Invalid email or password"
      # Private detailed logging
      Rails.logger.info("Failed authentication attempt for email: #{params[:email]}")
      render "sessions/new"
    end
  rescue RuntimeError => e
    # Generic error message to prevent information disclosure
    flash[:error] = "Authentication failed"
    # Private detailed logging
    Rails.logger.error("Authentication error: #{e.message}")
    render "sessions/new"
  end
end

# Helper method to validate and sanitize redirect URLs
def validate_redirect_url(url)
  # Only allow relative URLs
  return url if url.start_with?('/')
  
  begin
    # Check if URL belongs to permitted domains
    parsed_uri = URI.parse(url)
    allowed_domains = [request.host, 'your-app-domain.com'] # Add your allowed domains
    
    if allowed_domains.include?(parsed_uri.host)
      return url
    end
  rescue URI::InvalidURIError
    # URL parsing failed, likely malicious
    Rails.logger.warn("Invalid redirect URL attempt: #{url}")
  end
  
  # Default to safe path if URL is not valid or allowed
  home_dashboard_index_path
end

# Add a token validation method to be used before actions requiring authentication
def validate_auth_token
  if cookies[:auth_token].present?
    user = User.find_by(auth_token: cookies[:auth_token])
    
    if user
      # Parse stored context
      stored_context = JSON.parse(user.auth_context)
      
      # Validate token against client context
      if token_matches_context?(stored_context)
        @current_user = user
      else
        # If context doesn't match, require re-authentication
        cookies.delete(:auth_token)
        redirect_to login_path, alert: "Please log in again"
      end
    else
      cookies.delete(:auth_token)
      redirect_to login_path
    end
  elsif session[:user_id].present? && session[:auth_context].present?
    # Dual-authentication validation
    user = User.find_by(id: session[:user_id])
    stored_context = JSON.parse(session[:auth_context])
    
    if user && token_matches_context?(stored_context)
      @current_user = user
    else
      # If validation fails, clear session and require re-auth
      reset_session
      redirect_to login_path, alert: "Please log in again"
    end
  else
    redirect_to login_path
  end
end

# Check if token context matches current request context
def token_matches_context?(stored_context)
  # Token expiration (e.g., 2 weeks)
  max_age = 2.weeks.to_i
  
  # Validate token age
  return false if Time.now.to_i - stored_context['created_at'] > max_age
  
  # Validate IP address if available (with some tolerance for dynamic IPs)
  if stored_context['ip'].present?
    return false unless ip_match?(stored_context['ip'], request.remote_ip)
  end
  
  # Validate user agent
  if stored_context['user_agent'].present?
    return false unless stored_context['user_agent'] == request.user_agent
  end
  
  true
end

# Helper to check IP matching with some flexibility
def ip_match?(stored_ip, current_ip)
  # Exact match
  return true if stored_ip == current_ip
  
  # Or implement network-level matching for dynamic IPs
  # For example, check if first 3 segments match for IPv4
  stored_segments = stored_ip.split('.')[0..2]
  current_segments = current_ip.split('.')[0..2]
  
  stored_segments == current_segments
end

  end

  def destroy
    cookies.delete(:auth_token)
    reset_session
    redirect_to root_path
  end
end
