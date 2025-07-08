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
  @user = User.find_by_email(params[:email]) unless params[:email].nil?
  
  # Added email format validation before processing
  if params[:email].present? && !params[:email].match?(/\A[^@\s]+@[^@\s]+\z/)
    flash[:error] = "Invalid email format provided"
    return
  end
  
  if @user && password_reset_mailer(@user)
    # Applied explicit HTML encoding for user input in success message
    flash[:success] = "Password reset email sent to #{ERB::Util.html_escape(params[:email])}"
    redirect_to :login
  else
    # Fixed XSS vulnerability by explicitly encoding user input and using sanitization
    unless params[:email].nil?
      sanitized_email = Sanitize.fragment(params[:email])
      flash[:error] = "There was an issue sending password reset email to #{ERB::Util.html_escape(sanitized_email)}"
    end
  end
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
