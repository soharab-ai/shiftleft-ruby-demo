# frozen_string_literal: true
require "encryption"

class User < ApplicationRecord
  validates :password, presence: true,
                       confirmation: true,
                       length: {within: 6..40},
                       on: :create,
                       if: :password

  validates_presence_of :email
  validates_uniqueness_of :email
  validates_format_of :email, with: /.+@.+\..+/i

  has_one :retirement, dependent: :destroy
  has_one :paid_time_off, dependent: :destroy
  has_one :work_info, dependent: :destroy
  has_many :performance, dependent: :destroy
  has_many :pay, dependent: :destroy
  has_many :messages, foreign_key: :receiver_id, dependent: :destroy

  before_save :hash_password
  after_create { generate_token(:auth_token) }
  before_create :build_benefits_data

  def build_benefits_data
    build_retirement(POPULATE_RETIREMENTS.sample)
    build_paid_time_off(POPULATE_PAID_TIME_OFF.sample).schedule.build(POPULATE_SCHEDULE.sample)
    build_work_info(POPULATE_WORK_INFO.sample)
    # Uncomment below line to use encrypted SSN(s)
    #work_info.build_key_management(:iv => SecureRandom.hex(32))
    performance.build(POPULATE_PERFORMANCE.sample)
  end

  def full_name
    "#{self.first_name} #{self.last_name}"
  end

  private

  def self.authenticate(email, password)
# Constants for account lockout
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME = 15.minutes

def self.authenticate(email, password)
  user = find_by_email(email)
  # Don't expose specific error messages to potential attackers
  return nil if !user
  
  # Check if account is locked out
  if user.failed_attempts.to_i >= MAX_FAILED_ATTEMPTS && user.locked_until && user.locked_until > Time.now
    Rails.logger.info("Authentication blocked due to lockout for: #{Digest::SHA256.hexdigest(email)}")
    return nil
  end
  
  # Use BCrypt for secure password verification
  if BCrypt::Password.new(user.password_digest).is_password?(password)
    # Reset failed attempts on successful login
    user.update(failed_attempts: 0, locked_until: nil)
    
    # No longer store auth token as we'll use JWT
    return user
  else
    # Increment failed login attempts
    new_attempts = user.failed_attempts.to_i + 1
    lock_time = new_attempts >= MAX_FAILED_ATTEMPTS ? Time.now + LOCKOUT_TIME : nil
    user.update(failed_attempts: new_attempts, locked_until: lock_time)
    return nil
  end
end

# Password setter that uses BCrypt
def password=(password)
  @password = password
  self.password_digest = BCrypt::Password.create(password)
end

# JWT token generation with short expiration
def generate_jwt(request_ip = nil, user_agent = nil)
  # Store only hashed tokens in database
  jti = SecureRandom.uuid
  self.token_jti = Digest::SHA256.hexdigest(jti)
  self.token_expiry = 30.minutes.from_now
  
  # Create fingerprint for token binding
  fingerprint = Digest::SHA256.hexdigest("#{request_ip}|#{user_agent}")
  self.token_fingerprint = fingerprint
  
  save!
  
  # Generate JWT with short expiration and fingerprint binding
  payload = {
    user_id: self.id,
    jti: jti,
    fingerprint: fingerprint,
    exp: token_expiry.to_i
  }
  
  # Use RS256 for asymmetric signing (private key would be stored securely)
  JWT.encode(payload, jwt_private_key, 'RS256')
end

# Generate refresh token with rotation
def generate_refresh_token
  token = SecureRandom.urlsafe_base64(32)
  self.refresh_token_hash = Digest::SHA256.hexdigest(token)
  self.refresh_token_expiry = 2.weeks.from_now
  save!
  token
end

def token_expired?
  token_expiry.nil? || token_expiry < Time.now
end

def verify_totp(code)
  return false unless totp_secret
  totp = ROTP::TOTP.new(totp_secret)
  totp.verify(code, drift_behind: 30, drift_ahead: 30)
end

def setup_2fa
  secret = ROTP::Base32.random_base32
  self.totp_secret = secret
  self.totp_enabled = false
  save!
  secret
end

def enable_2fa(code)
  if verify_totp(code)
    self.totp_enabled = true
    save!
    true
  else
    false
  end
end

private

def jwt_private_key
  # In production, this would be stored securely and accessed via environment variables
  # This is just a placeholder for the example
  OpenSSL::PKey::RSA.new(ENV['JWT_PRIVATE_KEY'])
end

def jwt_public_key
  OpenSSL::PKey::RSA.new(ENV['JWT_PUBLIC_KEY'])
end

  def hash_password
    if will_save_change_to_password?
      self.password = Digest::MD5.hexdigest(self.password)
    end
  end

  def generate_token(column)
    loop do
      self[column] = Encryption.encrypt_sensitive_value(self.id)
      break unless User.exists?(column => self[column])
    end

    self.save!
  end
end
