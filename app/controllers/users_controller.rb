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
def update
  # Added parameter validation by converting ID to integer
  user_id = params[:user][:id].to_i
  user = User.find_by(id: user_id)
  
  # Added authorization check
  if !user || !current_user.can_modify?(user)
    respond_to do |format|
      format.html { 
        flash[:error] = "Unauthorized access or user not found"
        redirect_to user_account_settings_path(user_id: current_user.id)
      }
      format.json { render json: {msg: "unauthorized"}, status: :unauthorized }
    end
    return
  end
  
  # Use strong parameters for user attributes
  message = false
  
  begin
    # Improved error handling with better transaction management
    User.transaction do
      user.update(user_params_without_password)
      
      if params[:user][:password].present? && (params[:user][:password] == params[:user][:password_confirmation])
        user.password = params[:user][:password]
      end
      
      # Changed save! to save with proper error handling
      if user.save
        message = true
        # Added audit logging
        Rails.logger.info("User #{current_user.id} updated user #{user.id}")
      else
        # Log validation errors
        Rails.logger.warn("User update failed: #{user.errors.full_messages.join(', ')}")
        raise ActiveRecord::Rollback
      end
    end
    
    respond_to do |format|
      if message
        format.html { 
          flash[:success] = "User successfully updated"
          redirect_to user_account_settings_path(user_id: current_user.id) 
        }
        format.json { render json: {msg: "success"} }
      else
        format.html { 
          flash[:error] = "Could not update user!"
          redirect_to user_account_settings_path(user_id: current_user.id) 
        }
        format.json { render json: {msg: "false", errors: user.errors.full_messages}, status: :unprocessable_entity }
      end
    end
  rescue => e
    # Added exception logging
    Rails.logger.error("Exception in user update: #{e.message}")
    flash[:error] = "Could not update user due to an error"
    redirect_to user_account_settings_path(user_id: current_user.id)
  end
end

# Added strong parameters method if not already present
def user_params_without_password
  params.require(:user).permit(:name, :email, :other_allowed_fields)
end

# Ensure CSRF protection is enabled at the controller level
protect_from_forgery with: :exception

  private

  def user_params
    params.require(:user).permit!
  end

  # unpermitted attributes are ignored in production
  def user_params_without_password
    params.require(:user).permit(:email, :admin, :first_name, :last_name)
  end
end
