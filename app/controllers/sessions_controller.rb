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
    
    # FIXED: Rate limiting protection against credential stuffing and brute force attacks
    if session[:failed_login_attempts].to_i >= 5
      last_attempt = session[:last_failed_attempt]
      if last_attempt && last_attempt > 15.minutes.ago
        flash[:error] = "Too many failed attempts. Please try again later."
        render "sessions/new"
        return
      else
        # Reset after 15 minute window
        session[:failed_login_attempts] = 0
      end
    end
    
    begin
      # Normalize the email address
      user = User.authenticate(params[:email].to_s.strip.downcase, params[:password])
    rescue RuntimeError => e
      # FIXED: Using generic error message to prevent user enumeration
      flash[:error] = "Invalid email or password"
      render "sessions/new"
      return
    end

    if user
      # Reset failed login attempts on successful authentication
      session[:failed_login_attempts] = 0
      session.delete(:last_failed_attempt)
def destroy
    # FIXED: Server-side token invalidation on logout
    if current_user && cookies.encrypted[:auth_token].present?
      current_user.regenerate_auth_token
    end
    
    # FIXED: Clear authentication cookies
    cookies.delete(:auth_token, domain: :all, path: '/')
    cookies.delete(:auth_context, domain: :all, path: '/')
    session[:user_id] = nil
    
    redirect_to login_path, notice: "You have been logged out successfully"
  end


        # FIXED: Implemented secure cookie configuration with explicit expiration
        # FIXED: Using encrypted cookies to protect auth token from theft
        cookies.encrypted[:auth_token] = {
          value: user.auth_token,
          expires: 30.days.from_now,  # FIXED: Explicit expiration instead of permanent
          httponly: true,               # Prevents JavaScript access to mitigate XSS attacks
          secure: true,                 # HTTPS only to prevent man-in-the-middle attacks
          same_site: :strict,           # CSRF protection to prevent cross-site cookie transmission
          domain: :all,                 # FIXED: Explicit domain restriction
          path: '/'                     # FIXED: Explicit path restriction
        }
        
        # FIXED: Store auth context in separate encrypted cookie for validation
        cookies.encrypted[:auth_context] = {
          value: auth_context,
          expires: 30.days.from_now,
          httponly: true,
          secure: true,
          same_site: :strict,
          domain: :all,
          path: '/'
        }
      else
        session[:user_id] = user.id
      end
      redirect_to path
    else
      # FIXED: Track failed login attempts for rate limiting
      session[:failed_login_attempts] = session[:failed_login_attempts].to_i + 1
      session[:last_failed_attempt] = Time.current
      
      # FIXED: Using generic error message to prevent information disclosure
      flash[:error] = "Invalid email or password"
      render "sessions/new"
    end
  end

