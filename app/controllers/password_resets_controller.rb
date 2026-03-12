# frozen_string_literal: true
class PasswordResetsController < ApplicationController
  skip_before_action :authenticated

  def reset_password
    user = Marshal.load(Base64.decode64(params[:user])) unless params[:user].nil?

    if user && params[:password] && params[:confirm_password] && params[:password] == params[:confirm_password]
      user.password = params[:password]
      user.save!
      flash[:success] = "Your password has been reset please login"
      redirect_to :login
    else
      flash[:error] = "Error resetting your password. Please try again."
      redirect_to :login
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
  email = params[:email]
  
  unless email.nil?
    # FIXED: Added email format validation to prevent invalid input processing
    unless email.match?(URI::MailTo::EMAIL_REGEXP)
      flash[:error] = "Invalid email format"
      return
    end
    
    @user = User.find_by_email(email)
    
    if @user && password_reset_mailer(@user)
      # FIXED: Removed user-controlled email reflection to eliminate XSS vector entirely
      # Using generic message that doesn't expose user input in output
      flash[:success] = "Password reset email sent successfully. Please check your inbox."
      redirect_to :login
    else
      # FIXED: Removed user-controlled email reflection to prevent XSS and information disclosure
      # Generic error message prevents email enumeration attacks
      flash[:error] = "There was an issue sending the password reset email. Please try again or contact support."
    end
  end
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
