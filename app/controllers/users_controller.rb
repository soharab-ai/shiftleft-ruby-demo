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
  # Add authorization check to ensure user can only modify their own account or is an admin
  unless current_user.admin? || current_user.id.to_s == params[:user][:id].to_s
    flash[:error] = "Unauthorized access!"
    return redirect_to root_path
  end

  begin
    # Use find instead of find_by for primary keys, which will raise an exception if not found
    user = User.find(params[:user][:id])
    
    message = false
    
    # Use database transaction to ensure atomicity of updates
    User.transaction do
      # Update non-password attributes
      user.update!(user_params_without_password)
      
      # Improve password handling with better validation
      if params[:user][:password].present?
        unless params[:user][:password].length >= 8 && params[:user][:password] == params[:user][:password_confirmation]
          flash[:error] = "Password must be at least 8 characters and match confirmation"
          raise ActiveRecord::Rollback
        end
        user.password = params[:user][:password]
        user.save!
      end
      
      message = true
    end
    
    respond_to do |format|
      if message
        format.html { redirect_to user_account_settings_path(user_id: current_user.id), notice: "User updated successfully." }
        format.json { render json: {msg: "success"} }
      else
        format.html { redirect_to user_account_settings_path(user_id: current_user.id), error: "Could not update user!" }
        format.json { render json: {msg: "false"} }
      end
    end
    
  rescue ActiveRecord::RecordNotFound
    flash[:error] = "User not found!"
    redirect_to user_account_settings_path(user_id: current_user.id)
  rescue => e
    flash[:error] = "Could not update user: #{e.message}"
    redirect_to user_account_settings_path(user_id: current_user.id)
  end
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
