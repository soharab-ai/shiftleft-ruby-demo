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
    auth = nil
    user = find_by_email(email)
    raise "#{email} doesn't exist!" if !(user)
    if user.password == Digest::MD5.hexdigest(password)
      auth = user
    else
      raise "Incorrect Password!"
    end
    return auth
  end

# Method to rotate authentication tokens for security
def rotate_auth_token
  # Implement token versioning for future security upgrades
  self.auth_token = "v2:#{SecureRandom.urlsafe_base64(32)}"
  self.token_created_at = Time.current
  # Invalidate all existing sessions when token is rotated
# Check if the current token is still valid based on age and context
def token_valid?(request = nil)
  return false unless token_created_at.present? && token_created_at > 12.hours.ago
  
  # If request context provided, validate it
# Validate the request context matches what was stored during session creation
def validate_request_context(request)
  return true unless last_sign_in_ip.present?
  
  # Only check the first three octets of the IP to account for dynamic IPs
  current_ip_prefix = request.remote_ip.to_s.split('.')[0..2].join('.')
  stored_ip_prefix = last_sign_in_ip.to_s.split('.')[0..2].join('.')
  
# Securely terminate the user's authentication token
def logout
  self.auth_token = nil
  self.token_created_at = nil
  invalidate_all_sessions
  save!
end
# Invalidate all active sessions for this user
def invalidate_all_sessions
  # Find all session keys for this user
  session_keys = []
  Rails.cache.instance_variable_get(:@data).keys.each do |key|
    if key.to_s.start_with?("user_session:") && Rails.cache.read(key)&.dig(:user_id) == id
      Rails.cache.delete(key)
    end
  end
end
