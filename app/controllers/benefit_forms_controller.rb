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
    if file
      # Added exception handling for security errors during file upload
      begin
        Benefits.save(file, params[:benefits][:backup])
        flash[:success] = "File Successfully Uploaded!"
      rescue ArgumentError, SecurityError => e
        # Catch validation and security errors to prevent directory traversal
        flash[:error] = "Invalid file upload: #{e.message}"
      end
    else
      flash[:error] = "Something went wrong"
    end
    redirect_to user_benefit_forms_path(user_id: current_user.id)
  end

    redirect_to user_benefit_forms_path(user_id: current_user.id)
  end

end
