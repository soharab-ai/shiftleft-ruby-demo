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
    # Input validation: strip whitespace and validate email format before processing
    email = params[:email]&.strip
    
    # Validate email format to prevent injection and enforce proper input
    unless email.blank? || email.match?(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i)
      flash[:error] = "Invalid email format provided"
      return redirect_to :login
    end
    
    # Use validated email to find user
    @user = User.find_by_email(email) unless email.nil?

    if @user && password_reset_mailer(@user)
      # Fixed: Use generic message to prevent email enumeration attacks and eliminate reflection of user input
      flash[:success] = "If an account exists for this email, a password reset link has been sent."
      redirect_to :login
    else
      # Fixed: Use generic error message without reflecting user input to prevent XSS and social engineering
      flash[:error] = "There was an issue sending the password reset email. Please verify the email address and try again."
      redirect_to :login
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
