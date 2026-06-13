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
    MAX_FILE_SIZE = 10.megabytes # Maximum allowed file size
private

  def valid_filename?(filename)
    # Whitelist validation: only allow safe characters and valid file extension pattern
    filename.match?(/\A[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+\z/)
  end

      end
      
      begin
        flash[:success] = "File Successfully Uploaded!"
        Benefits.save(file, params[:benefits][:backup])
      rescue SecurityError => e
        # Handle security violations from model validation
        flash[:error] = "Upload failed: #{e.message}"
      end
    else
      flash[:error] = "Something went wrong"
    end
    redirect_to user_benefit_forms_path(user_id: current_user.id)
  end

