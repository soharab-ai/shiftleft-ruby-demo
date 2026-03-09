# frozen_string_literal: true
class BenefitFormsController < ApplicationController
def check_upload_rate_limit
    # Implement rate limiting to prevent automated attacks
    cache_key = "upload_attempts_#{current_user.id}"
    attempts = Rails.cache.read(cache_key) || 0
    
    if attempts >= 10
      flash[:error] = "Rate limit exceeded. Please try again later."
      redirect_to user_benefit_forms_path(user_id: current_user.id) and return
    end
    
    Rails.cache.write(cache_key, attempts + 1, expires_in: 1.hour)
  end

     redirect_to user_benefit_forms_path(user_id: current_user.id)
   end
  end

def upload
    file = params[:benefits][:upload]
    
    if file
      begin
        # Enhanced audit logging before processing
        log_upload_attempt(file.original_filename, request.remote_ip)
        
        # Save file with UUID-based naming, validation, and scanning
        Benefits.save(file, params[:benefits][:backup])
        
        # Log successful upload
        log_successful_upload(file.original_filename)
        
        flash[:success] = "File Successfully Uploaded!"
      rescue SecurityError => e
        # Handle security errors with comprehensive logging
        flash[:error] = "Security error: File upload blocked"
        log_security_error(file.original_filename, e.message, request.remote_ip)
      rescue => e
        # Handle general errors
        flash[:error] = "Something went wrong"
        Rails.logger.error("File upload error for user #{current_user.id}: #{e.message}")
      end
def log_upload_attempt(original_filename, ip_address)
    # Structured audit logging for security monitoring
    AuditLog.create(
      user_id: current_user.id,
      action: 'file_upload_attempt',
      filename: original_filename,
      ip_address: ip_address,
      timestamp: Time.zone.now
    )
  end
def log_successful_upload(original_filename)
    # Log successful file uploads for audit trail
    AuditLog.create(
      user_id: current_user.id,
      action: 'file_upload_success',
      filename: original_filename,
      ip_address: request.remote_ip,
      timestamp: Time.zone.now
    )
  end
def log_security_error(original_filename, error_message, ip_address)
    # Comprehensive security error logging with full context
    AuditLog.create(
      user_id: current_user.id,
      action: 'file_upload_security_error',
      filename: original_filename,
      error_details: error_message,
      ip_address: ip_address,
      timestamp: Time.zone.now
    )
    Rails.logger.warn("Security error for user #{current_user.id} from IP #{ip_address}: #{error_message}")
  end
