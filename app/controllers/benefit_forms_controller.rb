# frozen_string_literal: true
class BenefitFormsController < ApplicationController

  def index
    @benefits = Benefits.new
  end

  def download
   begin
     path = params[:name]
     file = params[:type].constantize.new(path)
     send_file file, disposition: "attachment"
   rescue
     redirect_to user_benefit_forms_path(user_id: current_user.id)
   end
  end

def upload
  file = params[:benefits][:upload]
  
  # Add validation for file object existence and proper type
  if file && file.respond_to?(:original_filename)
    # Add file size validation - prevents denial-of-service through large uploads
    MAX_FILE_SIZE = 10.megabytes
    
    if file.size > MAX_FILE_SIZE
      flash[:error] = "File size exceeds maximum limit"
      redirect_to user_benefit_forms_path(user_id: current_user.id) and return
    end
    
    # Add content type validation - validates uploaded content type matches expected formats
    allowed_content_types = ['application/pdf', 'image/jpeg', 'image/png', 'application/msword', 'text/plain']
    unless allowed_content_types.include?(file.content_type)
      flash[:error] = "File type not permitted"
      redirect_to user_benefit_forms_path(user_id: current_user.id) and return
    end
    
    begin
      flash[:success] = "File Successfully Uploaded!"
      Benefits.save(file, params[:benefits][:backup])
    rescue SecurityError => e
      # Handle security violations and log suspicious activity
      flash[:error] = "Invalid file upload attempt"
      Rails.logger.warn("Security: Path traversal attempt detected - #{e.message}")
    end
  else
    flash[:error] = "Something went wrong"
  end
  redirect_to user_benefit_forms_path(user_id: current_user.id)
end

