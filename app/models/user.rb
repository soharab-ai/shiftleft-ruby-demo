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
    # FIXED: Changed to return nil instead of raising exceptions to prevent user enumeration
    user = find_by_email(email)
    return nil unless user
    
    # FIXED: Using bcrypt for secure password comparison instead of MD5
    return nil unless user.authenticate_password(password)
    
    user
  end

    return auth
def authenticate_password(password)
    # FIXED: Using bcrypt to securely compare passwords instead of MD5
    BCrypt::Password.new(self.password) == password
  rescue BCrypt::Errors::InvalidHash
    false
  end

    end
  end

  def generate_token(column)
def validate_auth_context(user_agent, ip_address)
    # FIXED: Token binding validation to verify requesting client matches original authenticated session
    return false if self.auth_token_context.blank?
    
    # FIXED: Validate token hasn't expired
    return false if self.auth_token_expires_at.present? && self.auth_token_expires_at < Time.current
    
    # FIXED: Generate context hash from current request and compare
    current_context = self.class.generate_auth_context(user_agent, ip_address)
    ActiveSupport::SecurityUtils.secure_compare(self.auth_token_context, current_context)
  end

def self.generate_auth_context(user_agent, ip_address)
    # FIXED: Create token binding hash using HMAC-SHA256
    # Truncate IP to first 3 octets for IPv4 to allow some mobility
    truncated_ip = ip_address.to_s.split('.')[0..2].join('.') rescue ip_address.to_s
    context_string = "#{user_agent}:#{truncated_ip}"
    secret_key = Rails.application.secret_key_base
    OpenSSL::HMAC.hexdigest('SHA256', secret_key, context_string)
  end
