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

  # Added authorization check to verify current user has permission
  unless current_user.admin? || current_user.id == params[:user][:id].to_i
    flash[:error] = "Unauthorized access!"
    return redirect_to root_path
  end

  # Fixed SQL injection by using find_by with explicit type casting
  user = User.find_by(id: params[:user][:id].to_i)

  if user
    # Wrapped update operation in a transaction for data integrity
    User.transaction do
      # Using enhanced user_params method instead of user_params_without_password
      if user.update(user_params)
        message = true
      end
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

# Enhanced strong parameters method that conditionally includes password
def user_params
  base_params = params.require(:user).permit(:email, :first_name, :last_name)
  if params[:user][:password].present? && params[:user][:password] == params[:user][:password_confirmation]
    base_params.merge(password: params[:user][:password])
  else
    base_params
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
