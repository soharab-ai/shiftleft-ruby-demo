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

    # SECURE FIX: Validate that the ID is numeric before processing to prevent SQL injection
    unless params[:user][:id].to_s.match?(/\A\d+\z/)
      flash[:error] = "Invalid user ID format"
      redirect_to root_path and return
    end

    # SECURE FIX: Use parameterized query with type casting to prevent SQL injection
    user_id = params[:user][:id].to_i
    user = User.where(id: user_id).first

    if user
      # SECURE FIX: Use database-backed attribute for secure authorization check
      unless user.id == current_user.id || (current_user.admin == true)
        flash[:error] = "Unauthorized access!"
        redirect_to root_path and return
      end
private

def user_params_without_password
  # SECURE FIX: Explicit strong parameters definition to prevent mass assignment
  params.require(:user).permit(:name, :email, :username, :phone)
end

      # SECURE FIX: Use strong parameters to prevent mass assignment vulnerabilities
      user.update(user_params_without_password)
      
      # SECURE FIX: Use dedicated strong parameters method for password access
      if password_params[:password].present? && (password_params[:password] == password_params[:password_confirmation])
        user.password = password_params[:password]
      end
      
      message = true if user.save!
      respond_to do |format|
        format.html { redirect_to user_account_settings_path(user_id: current_user.id) }
        format.json { render json: {msg: message ? "success" : "false "} }
def password_params
  # SECURE FIX: Dedicated strong parameters method for password updates
  params.require(:user).permit(:password, :password_confirmation)
end

    end
  end

end
