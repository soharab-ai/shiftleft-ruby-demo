# frozen_string_literal: true
class SessionsController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @url = params[:url]
    redirect_to home_dashboard_index_path if current_user
  end

def create
    # Validate and sanitize redirect path to prevent open redirect vulnerabilities
    path = params[:url].present? ? validate_redirect_path(params[:url]) : home_dashboard_index_path
private

  # FIXED: Enhanced validation method with whitelist approach to prevent open redirect attacks
  def validate_redirect_path(path)
    return home_dashboard_index_path unless path.present?
    
    # FIXED: Whitelist of allowed redirect paths for stronger security
    allowed_paths = [home_dashboard_index_path, '/profile', '/settings']
    
    uri = URI.parse(path)
    # FIXED: Only allow relative paths that match whitelist to prevent external redirects
    if uri.scheme.nil? && uri.host.nil? && allowed_paths.any? { |p| path.start_with?(p) }
      path
    else
      home_dashboard_index_path
    end
  rescue URI::InvalidURIError
    # Return safe default if URI parsing fails
    home_dashboard_index_path
  end

    end

    if user
      # FIXED: Clear failed login attempts on successful authentication
      Rails.cache.delete("login_attempts:#{request.remote_ip}")
      
      # Log successful authentication with sanitized output
      Rails.logger.info("Successful authentication for user: #{user.email.gsub(/[\n\r]/, '_')}")
      
      if params[:remember_me]
        # FIXED: Generate a new secure random session token (NOT the auth_token credential)
        # This separates session management from authentication credentials
        remember_token = SecureRandom.urlsafe_base64(32)
        remember_digest = Digest::SHA256.hexdigest(remember_token)

        # FIXED: Store only the hashed token in the database associated with the user
        user.update_columns(remember_digest: remember_digest, remember_created_at: Time.current)

        # FIXED: Store only the unhashed session token in cookie (not credentials)
        # Uses encrypted cookies with HttpOnly, Secure, and SameSite flags
        cookies.encrypted.permanent[:remember_token] = {
          value: remember_token,
          httponly: true,                         # Prevents JavaScript access (XSS protection)
          secure: Rails.env.production?,          # Ensures HTTPS-only transmission in production (MITM protection)
          same_site: :strict                      # Prevents CSRF attacks by restricting cross-site cookie sending
        }
      else
        session[:user_id] = user.id
      end
      redirect_to path
    else
      # FIXED: Increment failed attempts counter for invalid credentials
      Rails.cache.write("login_attempts:#{request.remote_ip}", failed_attempts + 1, expires_in: 15.minutes)
      flash[:error] = "Invalid email or password."
      render "sessions/new"
    end
  end

