# frozen_string_literal: true
class PasswordResetsController < ApplicationController
  skip_before_action :authenticated

def reset_password
  # Implement rate limiting to prevent brute force attacks
  if ResetAttempt.where(ip: request.remote_ip).where('created_at > ?', 1.hour.ago).count > 5
    flash[:error] = "Too many attempts. Please try again later."
    redirect_to :login and return
  end
  ResetAttempt.create(ip: request.remote_ip)
  
  # Use permitted parameters
  reset_params = reset_password_params
  
  # Use hashed token in database lookup to prevent token leakage
  token = reset_params[:token]
  hashed_token = Digest::SHA256.hexdigest(token)
  user = User.find_by(reset_token_hash: hashed_token)
  
  if user && user.reset_token_valid? && 
     reset_params[:password].present? && 
     reset_params[:confirm_password].present? && 
     reset_params[:password] == reset_params[:confirm_password]
    
    user.update_password(reset_params[:password])
    # Clear token after successful reset to prevent token reuse
    user.clear_reset_token
    flash[:success] = "Your password has been reset please login"
    redirect_to :login
  else
    flash[:error] = "Error resetting your password. Please try again."
    redirect_to :login
  end
end

private

# Define strong parameters
def reset_password_params
  params.permit(:token, :password, :confirm_password)
end

  end

  def confirm_token
    if !params[:token].nil? && is_valid?(params[:token])
      flash[:success] = "Password reset token confirmed! Please create a new password."
      render "password_resets/reset_password"
    else
      flash[:error] = "Invalid password reset token. Please try again."
      redirect_to :login
    end
  end

  def send_forgot_password
    @user = User.find_by_email(params[:email]) unless params[:email].nil?

    if @user && password_reset_mailer(@user)
      flash[:success] = "Password reset email sent to #{params[:email]}"
      redirect_to :login
    else
      flash[:error] = "There was an issue sending password reset email to #{params[:email]}".html_safe unless params[:email].nil?
    end
  end

  private

  def password_reset_mailer(user)
    token = generate_token(user.id, user.email)
    UserMailer.forgot_password(user.email, token).deliver
  end

  def generate_token(id, email)
    hash = Digest::MD5.hexdigest(email)
    "#{id}-#{hash}"
  end

  def is_valid?(token)
    if token =~ /(?<user>\d+)-(?<email_hash>[A-Z0-9]{32})/i

      # Fetch the user by their id, and hash their email address
      @user = User.find_by(id: $~[:user])
      email = Digest::MD5.hexdigest(@user.email)

      # Compare and validate our hashes
      return true if email == $~[:email_hash]
    end
  end
end
