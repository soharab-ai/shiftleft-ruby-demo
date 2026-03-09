# frozen_string_literal: true
class UsersController < ApplicationController
  skip_before_action :has_info
  skip_before_action :authenticated, only: [:new, :create]

  def new
    @user = User.new
  end

  def create
    user = User.new(user_params)
    if user.save
      session[:user_id] = user.id
      redirect_to home_dashboard_index_path
    else
      @user = user
      flash[:error] = user.errors.full_messages.to_sentence
      redirect_to :signup
    end
  end

  def account_settings
    @user = current_user
  end

def update
    message = false

    # FIXED: Validate and sanitize user ID with explicit type casting
    begin
      validated_id = validate_user_id
      user = User.find_by(id: validated_id)
    rescue ArgumentError => e
      flash[:error] = "Invalid request parameters"
      redirect_to root_path
      return
    end
    
    # FIXED: Add authorization check to ensure users can only update their own records
    unless user && (user.id == current_user.id || (current_user.respond_to?(:admin?) && current_user.admin?))
      # FIXED: Add security audit logging for unauthorized access attempts
      Rails.logger.warn "Unauthorized update attempt - User: #{current_user&.id}, Target: #{params[:user][:id]}, IP: #{request.remote_ip}"
      flash[:error] = "Unauthorized access!"
      redirect_to root_path
      return
    end

    if user
      user.update(user_params_without_password)
      if params[:user][:password].present? && (params[:user][:password] == params[:user][:password_confirmation])
        user.password = params[:user][:password]
      end
      message = true if user.save!
      respond_to do |format|
        format.html { redirect_to user_account_settings_path(user_id: current_user.id) }
def user_params_without_password
    params.require(:user).permit(:email, :name, :phone, :address)
  end

def validate_user_id
    id = params.dig(:user, :id)
    raise ArgumentError, "Missing user ID" unless id.present?
    
    sanitized_id = id.to_i
    raise ArgumentError, "Invalid user ID format" if sanitized_id <= 0 || sanitized_id.to_s != id.to_s.strip
    
    sanitized_id
  end
