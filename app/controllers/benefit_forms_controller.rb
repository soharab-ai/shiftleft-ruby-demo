# frozen_string_literal: true
class BenefitFormsController < ApplicationController

  def index
    @benefits = Benefits.new
  end

  def download
def download
  begin
    # Extract request parameters
    path = params[:name]
    requested_type = params[:type]
    
    # Use the document security service to validate the request
    security_service = DocumentSecurityService.new(current_user)
    
    # Validate download token to prevent request tampering
    unless security_service.valid_download_token?(params[:token], requested_type, path)
      log_security_event("Invalid download token", :warning)
      raise DocumentSecurityError.new("Invalid download request")
    end
    
    # Rate limiting check
    if download_rate_exceeded?
      log_security_event("Download rate limit exceeded", :warning)
      raise RateLimitError.new("Too many download requests. Please try again later.")
    end
    
    # Document factory handles validation and instantiation of appropriate document type
    document = DocumentFactory.create_document(requested_type, path)
    
    # Log successful download attempt
    log_security_event("Document download", :info, {file_path: path, document_type: requested_type})
    
    send_file document.file_path, disposition: "attachment", content_type: document.content_type
  rescue DocumentSecurityError, RateLimitError => e
    log_security_event("Download error: #{e.message}", :error)
    flash[:error] = "Unable to download the requested document"
    redirect_to user_benefit_forms_path(user_id: current_user.id)
  rescue => e
    # Generic error handler for unexpected errors
    log_security_event("Unexpected download error: #{e.message}", :error)
    flash[:error] = "An error occurred while processing your request"
    redirect_to user_benefit_forms_path(user_id: current_user.id)
  end
end

private

# Security event logging with sanitization
def log_security_event(message, level = :info, details = null)
  sanitized_message = sanitize_log_entry(message)
  sanitized_details = details.transform_values { |v| sanitize_log_entry(v.to_s) }
  
  event_data = {
    user_id: current_user&.id || 'unauthenticated',
    ip_address: request.remote_ip,
    timestamp: Time.now.utc,
    action: params[:action],
    details: sanitized_details
  }
  
  case level
  when :info
    logger.info("SECURITY_EVENT: #{sanitized_message} | #{event_data.to_json}")
  when :warning
    logger.warn("SECURITY_EVENT: #{sanitized_message} | #{event_data.to_json}")
  when :error
    logger.error("SECURITY_EVENT: #{sanitized_message} | #{event_data.to_json}")
  end
  
  # Optionally send critical security events to a monitoring system
  SecurityMonitor.report(level, sanitized_message, event_data) if %i[warning error].include?(level)
end

# Sanitize log entries to prevent log forging
def sanitize_log_entry(entry)
  return "" if entry.nil?
  entry.to_s.gsub(/[\r\n]/, " ").strip
end

# Rate limiting implementation
def download_rate_exceeded?
  key = "download_rate_#{current_user.id}"
  count = Rails.cache.fetch(key, expires_in: 1.hour) { 0 }
  
  if count >= MAX_DOWNLOADS_PER_HOUR
    return true
  else
    Rails.cache.write(key, count + 1, expires_in: 1.hour)
    return false
  end
end

# Constants
MAX_DOWNLOADS_PER_HOUR = 20

# Document factory to handle document creation with proper validation
class DocumentFactory
  # Mapping of document types to their factory methods
  DOCUMENT_TYPES = {
    "PDF" => :create_pdf_document,
    "CSV" => :create_csv_document,
    "BenefitReport" => :create_benefit_report
  }
  
  def self.create_document(type, path)
    # Verify the requested document type is allowed
    unless DOCUMENT_TYPES.key?(type)
      raise DocumentSecurityError.new("Invalid document type requested")
    end
    
    # Validate path is safe
    unless safe_path?(path)
      raise DocumentSecurityError.new("Invalid document path requested")
    end
    
    # Call the appropriate factory method
    factory_method = DOCUMENT_TYPES[type]
    send(factory_method, path)
  end
  
  private
  
  def self.create_pdf_document(path)
    doc = PDF.new(path)
    validate_content_type(doc, 'application/pdf')
    doc
  end
  
  def self.create_csv_document(path)
    doc = CSV.new(path)
    validate_content_type(doc, 'text/csv')
    doc
  end
  
  def self.create_benefit_report(path)
    doc = BenefitReport.new(path)
    # BenefitReport type validation
    validate_content_type(doc, 'application/json')
    doc
  end
  
  def self.validate_content_type(document, expected_type)
    actual_type = document.content_type rescue nil
    unless actual_type == expected_type
      raise DocumentSecurityError.new("Content type mismatch")
    end
  end
  
  def self.safe_path?(path)
    return false if path.nil? || path.empty?
    
    # Ensure path is within allowed directory
    allowed_dir = Rails.root.join('app', 'documents').to_s
    real_path = File.expand_path(path)
    real_path.start_with?(allowed_dir) && File.exist?(real_path)
  end
end

# Document security service class
class DocumentSecurityService
  def initialize(user)
    @user = user
  end
  
  # Validate download token
  def valid_download_token?(token, type, path)
    return false if token.blank? || type.blank? || path.blank?
    
    # Verify token validity using ActiveSupport's secure comparison
    expected_token = generate_download_token(type, path)
    ActiveSupport::SecurityUtils.secure_compare(token, expected_token)
  end
  
  # Generate a secure download token
  def generate_download_token(type, path)
    # This would be exposed as an API for controllers to generate tokens
    # when creating links for downloads
    secret = Rails.application.secrets.secret_key_base
    data = "#{@user.id}|#{type}|#{path}|#{token_timestamp}"
    
    # Use Rails' built-in MessageVerifier for secure token generation
    verifier = ActiveSupport::MessageVerifier.new(secret, digest: 'SHA256')
    verifier.generate(data)
  end
  
  private
  
  def token_timestamp
    # Tokens valid for 1 hour
    (Time.now.to_i / 3600).to_s
  end
end

# Custom error classes
class DocumentSecurityError < StandardError; end
class RateLimitError < StandardError; end

  def upload
    file = params[:benefits][:upload]
    if file
      flash[:success] = "File Successfully Uploaded!"
      Benefits.save(file, params[:benefits][:backup])
    else
      flash[:error] = "Something went wrong"
    end
    redirect_to user_benefit_forms_path(user_id: current_user.id)
  end

end
