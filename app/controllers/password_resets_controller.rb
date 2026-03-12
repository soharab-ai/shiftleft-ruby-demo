# frozen_string_literal: true
class PasswordResetsController < ApplicationController
  skip_before_action :authenticated

def reset_password
    # FIXED: Replaced insecure Marshal.load deserialization with secure token-based approach
    # Uses cryptographically secure token lookup instead of deserializing attacker-controlled data
    token = params[:token]
    
    # FIXED: Added rate limiting to prevent brute-force token guessing attacks
    if exceeded_password_reset_rate_limit?(request.remote_ip)
      flash[:error] = "Invalid or expired reset token."
      redirect_to :login
      return
    end
    
    # FIXED: Validate token and retrieve user securely from database instead of deserializing
    # Uses constant-time comparison to prevent timing attacks
    user = User.find_by_valid_password_reset_token(token)
    
    unless user
      # FIXED: Record failed attempt for rate limiting
      record_failed_password_reset_attempt(request.remote_ip)
      flash[:error] = "Invalid or expired reset token."
      redirect_to :login
      return
    end
    
    # FIXED: Added token binding validation to prevent token reuse from different contexts
    request_context_hash = Digest::SHA256.hexdigest("#{request.remote_ip}#{request.user_agent}")
    stored_context_hash = user.password_reset_context_hash
    
    unless stored_context_hash && ActiveSupport::SecurityUtils.secure_compare(stored_context_hash, request_context_hash)
      user.invalidate_password_reset_token! # Invalidate potentially compromised token
      flash[:error] = "Invalid or expired reset token."
      redirect_to :login
      return
    end
    
    # FIXED: Added comprehensive password strength validation before updating
    if params[:password] && params[:confirm_password]
      if params[:password] != params[:confirm_password]
        flash[:error] = "Passwords do not match."
        redirect_to :login
      elsif params[:password].length < 12
        flash[:error] = "Password must be at least 12 characters long."
        redirect_to :login
# FIXED: Added secure token generation method with collision detection and context binding
  def generate_password_reset_token(request_ip, user_agent)
    max_attempts = 3
    max_attempts.times do
      candidate_token = SecureRandom.urlsafe_base64(32)
      # FIXED: Check for token collision to ensure uniqueness
      unless User.exists?(password_reset_token: candidate_token)
        self.password_reset_token = candidate_token
        self.password_reset_token_expires_at = 1.hour.from_now
        # FIXED: Store request context hash for token binding
        self.password_reset_context_hash = Digest::SHA256.hexdigest("#{request_ip}#{user_agent}")
        save!
        return true
      end
    end
    # FIXED: Raise security error if token generation fails after all attempts
    raise SecurityError, "Failed to generate unique token after #{max_attempts} attempts"
  end

# FIXED: Added secure token validation method with constant-time comparison to prevent timing attacks
  def self.find_by_valid_password_reset_token(token)
    candidates = where('password_reset_token IS NOT NULL')
                  .where('password_reset_token_expires_at > ?', Time.current)
    
    # FIXED: Use constant-time comparison to prevent timing-based side-channel attacks
    candidates.find { |user| ActiveSupport::SecurityUtils.secure_compare(user.password_reset_token, token) }
  end

# FIXED: Added token invalidation method to prevent token reuse after successful password reset
  def invalidate_password_reset_token!
    update!(password_reset_token: nil, password_reset_token_expires_at: nil, password_reset_context_hash: nil)
  end

# FIXED: Rate limiting check to prevent brute-force token guessing attacks
  def exceeded_password_reset_rate_limit?(ip_address)
    cache_key = "password_reset_attempts:#{ip_address}"
    attempts = Rails.cache.read(cache_key) || { count: 0, first_attempt_at: Time.current }
    
    # Reset counter if 15 minutes have passed
    if attempts[:first_attempt_at] < 15.minutes.ago
      return false
    end
    
    attempts[:count] >= 5
  end
# FIXED: Record failed password reset attempts for rate limiting
  def record_failed_password_reset_attempt(ip_address)
    cache_key = "password_reset_attempts:#{ip_address}"
    attempts = Rails.cache.read(cache_key) || { count: 0, first_attempt_at: Time.current }
    
    attempts[:count] += 1
    attempts[:first_attempt_at] ||= Time.current
    
    Rails.cache.write(cache_key, attempts, expires_in: 15.minutes)
  end
# FIXED: Clear rate limit tracking after successful password reset
  def clear_password_reset_rate_limit(ip_address)
    cache_key = "password_reset_attempts:#{ip_address}"
    Rails.cache.delete(cache_key)
  end
# FIXED: Check if password is in common password list to enforce password strength
  def is_common_password?(password)
    # Common passwords list (subset for demonstration - in production use comprehensive dictionary)
    common_passwords = [
      'password', '123456', '12345678', 'qwerty', 'abc123', 
      'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
      'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
      'bailey', 'passw0rd', 'shadow', '123123', '654321'
    ]
    
    common_passwords.include?(password.downcase)
  end
