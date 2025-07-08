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

  # Implementing Strong Parameters with type constraints for better security
  begin
    # Use tap to enforce integer type constraint
    user_id = user_id_params[:id]
    # Use ORM-level protection with where method for stronger typing
    user = User.where(id: user_id).first
  rescue ActionController::ParameterMissing, TypeError => e
    # Enhanced error handling with specific error types
    logger.warn "Parameter validation failed: #{e.message}"
    flash[:error] = "Invalid request parameters"
    redirect_to user_account_settings_path(user_id: current_user.id)
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
      format.json { render json: {msg: message ? "success" : "false"} }
    end
  else
    flash[:error] = "Could not update user!"
    redirect_to user_account_settings_path(user_id: current_user.id)
  end
end

private

# Strong Parameters with type constraints as suggested in mitigation notes
def user_id_params
  params.require(:user).permit(:id).tap do |whitelisted|
    whitelisted[:id] = whitelisted[:id].to_i if whitelisted[:id].present?
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
