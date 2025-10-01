# frozen_string_literal: true
class PasswordResetsController < ApplicationController
  skip_before_action :authenticated

def reset_password
  # Check rate limiting to prevent brute-force attacks
  if ResetAttempt.where(ip: request.remote_ip).where('created_at > ?', 1.hour.ago).count > 5
    flash[:error] = "Too many password reset attempts. Please try again later."
    return redirect_to :login
  end
  
  # Record this attempt
  ResetAttempt.create(ip: request.remote_ip, created_at: Time.now)
  
  # Find user by token with additional check for token expiration
  user = User.find_by(reset_token: params[:token]) if params[:token].present?
  
  # Verify token is valid and not expired (24 hour limit)
  if user && user.reset_token_created_at && user.reset_token_created_at > 24.hours.ago &&
     params[:password] && params[:confirm_password] && params[:password] == params[:confirm_password]
    
    # Update password
    user.password = params[:password]
    
    # Invalidate token after use (single-use token)
    user.reset_token = nil
    user.reset_token_created_at = nil
    
    user.save!
    flash[:success] = "Your password has been reset please login"
    redirect_to :login
  else
    flash[:error] = "Error resetting your password. Please try again."
    redirect_to :login
  end
end

# Supporting method for secure token generation (would be in the appropriate controller/model)
def generate_reset_token
  # Generate cryptographically secure token with sufficient entropy
  SecureRandom.hex(32)
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
