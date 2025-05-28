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
# Added CSRF protection to controller
protect_from_forgery with: :exception

def update
  message = false
  
  # Added parameter validation check
  return invalid_request unless params[:user] && params[:user][:id].present?
  
  # Added authorization control to ensure users can only modify their own profiles unless admin
  return unauthorized_access unless current_user.id.to_s == params[:user][:id].to_s || current_user.admin?
  
  # Using more idiomatic ActiveRecord pattern and preventing SQL injection with find_by
  user = current_user.admin? ? User.find_by(id: params[:user][:id]) : User.find_by(id: current_user.id)

  if user
    user.update(user_params_without_password)
    if params[:user][:password].present? && (params[:user][:password] == params[:user][:password_confirmation])
      user.password = params[:user][:password]
    end
    
    # Improved error handling by not using save! which raises exceptions
    if user.save
      message = true
      # Log successful update
      logger.info("User #{user.id} updated successfully by #{current_user.id}")
    else
      # Log validation errors
      logger.error("User update failed: #{user.errors.full_messages.join(', ')}")
      message = false
    end
    
    respond_to do |format|
      format.html { redirect_to user_account_settings_path(user_id: current_user.id) }
      format.json { render json: {msg: message ? "success" : "false"} }
    end
  else
    flash[:error] = "Could not update user!"
    redirect_to user_account_settings_path(user_id: current_user.id)
  end
end

# Helper methods for authorization and validation responses
private

def unauthorized_access
  flash[:error] = "You are not authorized to perform this action"
  redirect_to user_account_settings_path(user_id: current_user.id)
  return
end

def invalid_request
  flash[:error] = "Invalid request parameters"
  redirect_to user_account_settings_path(user_id: current_user.id)
  return
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
