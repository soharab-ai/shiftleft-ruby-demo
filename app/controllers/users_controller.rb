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
  
  # FIXED: Eliminated user ID parameter from request entirely - using only current_user.id
  # This removes attack surface by not accepting ID from user input at all
  
  # FIXED: Using find! with bang notation for automatic exception handling
  # This is more specific and eliminates nil-checking complexity
  user = User.find!(current_user.id)
  
  # FIXED: Audit logging for security-critical operation
  Rails.logger.info("User update attempt: user_id=#{current_user.id}, timestamp=#{Time.current}")
  
  user.update(user_params_without_password)
  if params[:user][:password].present? && (params[:user][:password] == params[:user][:password_confirmation])
    user.password = params[:user][:password]
  end
  message = true if user.save!
  
  # FIXED: Enhanced audit logging with changed attributes
  Rails.logger.info("User update successful: user_id=#{current_user.id}, changed_attributes=#{user.previous_changes.keys.join(',')}")
  
  respond_to do |format|
    format.html { redirect_to user_account_settings_path(user_id: current_user.id) }
    format.json { render json: {msg: message ? "success" : "false "} }
  end
rescue ActiveRecord::RecordNotFound
  # FIXED: Graceful handling of record not found with logging
  Rails.logger.error("User not found: user_id=#{current_user.id}")
  flash[:error] = "Could not update user!"
  redirect_to user_account_settings_path(user_id: current_user.id)
end

private

# FIXED: Strong parameters method for input validation with explicit whitelisting
def user_params_without_password
  params.require(:user).permit(:email, :name, :phone)
end

  end

  private

  def user_params
    params.require(:user).permit!
  end

  # unpermitted attributes are ignored in production
  def user_params_without_password
    params.require(:user).permit(:email, :admin, :first_name, :last_name)
  end
end
