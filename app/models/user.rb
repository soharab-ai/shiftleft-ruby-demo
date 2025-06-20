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
  user = find_by_email(email&.to_s&.strip&.downcase)
  # Return nil instead of raising an exception to prevent user enumeration
  return auth if user.nil?
  
  # Use secure comparison to prevent timing attacks
  if user.password_digest && BCrypt::Password.new(user.password_digest) == password
    # Regenerate auth token on each successful authentication for token rotation
    user.regenerate_auth_token
    auth = user
  end
  
  return auth
end

# Generate a new authentication token
def regenerate_auth_token
  update(auth_token: SecureRandom.urlsafe_base64(32))
end

# Create a user context fingerprint
def create_fingerprint(request)
  # Combine IP and user agent to create a context fingerprint
  fingerprint_data = "#{request.remote_ip}|#{request.user_agent}"
  Digest::SHA256.hexdigest(fingerprint_data)
end

    return auth
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
