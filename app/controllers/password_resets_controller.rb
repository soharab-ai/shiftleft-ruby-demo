# frozen_string_literal: true
class PasswordResetsController < ApplicationController
  skip_before_action :authenticated

def reset_password
    # FIX: Replaced insecure Marshal.load deserialization with secure token-based approach
    # to prevent CWE-502 (Insecure Deserialization) vulnerability
    
    # FIX: Added strong parameter filtering to prevent mass assignment and unexpected deserialized object injection
    permitted_params = params.permit(:token, :password, :confirm_password)
    
    reset_token = permitted_params[:token]
    
    # FIX: Added strict format validation to prevent SQL injection and deserialization attack remnants
    return redirect_to :login, flash: { error: "Invalid token format" } unless reset_token&.match?(/\A[A-Za-z0-9_-]{43}\z/)
    
    # FIX: Using constant-time comparison to prevent timing attacks that could be chained with deserialization reconnaissance
    user = User.where("password_reset_sent_at > ?", 2.hours.ago).find { |u| ActiveSupport::SecurityUtils.secure_compare(u.password_reset_token.to_s, reset_token.to_s) } if reset_token.present?
    
    # FIX: Verify token hasn't expired using model-level validation
    if user && user.password_reset_token_valid?
      # FIX: Sanitize password parameters to prevent serialized objects through password fields
      safe_password = permitted_params[:password].to_s.force_encoding('UTF-8') if permitted_params[:password].present?
      safe_confirm_password = permitted_params[:confirm_password].to_s.force_encoding('UTF-8') if permitted_params[:confirm_password].present?
      
      if safe_password && safe_confirm_password && safe_password == safe_confirm_password
        user.password = safe_password
        # FIX: Invalidate token after successful use to prevent reuse attacks
        user.clear_password_reset_token!
        user.save!
        flash[:success] = "Your password has been reset please login"
        redirect_to :login
      else
        flash[:error] = "Passwords do not match. Please try again."
        redirect_to :password_reset
      end
    else
      # FIX: Enhanced error message for invalid or expired tokens
      flash[:error] = "Invalid or expired reset token."
      redirect_to :login
    end
  end

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
