# frozen_string_literal: true
class ApplicationController < ActionController::Base
  before_action :authenticated, :has_info, :create_analytic, :mailer_options
  helper_method :current_user, :is_admin?, :sanitize_font

  # Our security guy keep talking about sea-surfing, cool story bro.
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  #protect_from_forgery with: :exception

  private

  def mailer_options
    ActionMailer::Base.default_url_options[:protocol] = request.protocol
    ActionMailer::Base.default_url_options[:host]     = request.host_with_port
  end

def current_user
  return @current_user if defined?(@current_user)
  
  # Use the session reference ID to retrieve server-side session data
  if session_id = cookies[:session_id]
    if session_data = Rails.cache.read("user_session:#{session_id}")
      # Verify session hasn't expired
      return nil if Time.current > session_data[:expires_at]
# Generate a fingerprint based on request context for additional security
def generate_context_fingerprint(request)
  # Use a combination of IP and user agent, but don't include all details
  # to allow for some flexibility with dynamic IPs/proxy changes
  data_to_fingerprint = "#{request.remote_ip.to_s.split('.')[0..2].join('.')}"
  data_to_fingerprint += "|#{request.user_agent.to_s[0..50]}" if request.user_agent
  
# Rate limiting implementation to prevent brute force attacks
def exceeded_login_attempts?(email)
  attempts_key = "login_attempts:#{email}"
  attempts = Rails.cache.fetch(attempts_key, raw: true) { 0 }.to_i
  
  # Limit to 5 failed attempts within 15 minutes
  attempts >= 5
end
# Record failed login attempts for rate limiting
def record_failed_attempt(email)
  attempts_key = "login_attempts:#{email}"
  attempts = Rails.cache.fetch(attempts_key, raw: true) { 0 }.to_i
  
  # Increment and store with 15 minute expiration
  Rails.cache.write(attempts_key, attempts + 1, expires_in: 15.minutes, raw: true)
end

# Reset failed login attempts counter after successful login
def reset_failed_attempts(email)
  Rails.cache.delete("login_attempts:#{email}")
end

# Lock account temporarily after too many failed attempts
def lock_account_temporarily(email)
  Rails.cache.write("account_locked:#{email}", true, expires_in: 30.minutes)
  Rails.logger.warn "Account temporarily locked due to too many failed attempts: #{email}"
end

  end

  def administrative
    if !is_admin?
     redirect_to root_url
   end
  end

  def has_info
    redirect = false
    if current_user
      begin
      if !(current_user.retirement || current_user.paid_time_off || current_user.paid_time_off.schedule || current_user.work_info || current_user.performance)
        redirect = true
      end
      rescue
         redirect = true
      end
    end
    redirect_to home_dashboard_index_path if redirect
  end

  def create_analytic
    Analytics.create({ ip_address: request.remote_ip, referrer: request.referrer, user_agent: request.user_agent})
  end

  def sanitize_font(css)
    css
  end
end
