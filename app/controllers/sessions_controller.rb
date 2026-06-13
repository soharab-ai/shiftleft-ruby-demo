# frozen_string_literal: true
class SessionsController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @url = params[:url]
    redirect_to home_dashboard_index_path if current_user
  end

def create
    # Prevent open redirect vulnerability by validating the path parameter
    path = params[:url].present? && params[:url].start_with?('/') ? params[:url] : home_dashboard_index_path
    
    begin
      # Normalize the email address, why not
      user = User.authenticate(params[:email].to_s.strip.downcase, params[:password])
    rescue RuntimeError => e
      # Sanitize error message to prevent log injection attacks
      Rails.logger.warn("Authentication error: #{e.message.gsub(/[\n\r\t]/, '_')}")
      user = nil
    end

    if user
      # Prevent session fixation attacks by regenerating session ID
      reset_session
      
      # Use session-based authentication only - never store credentials/tokens in cookies
      session[:user_id] = user.id
      
      # Store login timestamp for absolute session timeout enforcement
      session[:login_time] = Time.current.to_i
      
      # Extend session expiration server-side for remember-me functionality
      if params[:remember_me]
        session.options[:expire_after] = 30.days
      end
      
      redirect_to path
    else
      # Use generic error message to prevent user enumeration attacks
      flash[:error] = "Invalid email or password"
      render "sessions/new", status: :unauthorized
    end
  end

