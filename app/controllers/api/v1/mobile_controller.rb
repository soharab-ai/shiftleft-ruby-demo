# frozen_string_literal: true
class Api::V1::MobileController < ApplicationController
  skip_before_action :authenticated
  before_action :mobile_request?

  respond_to :json

def show
  # Direct mapping between route parameters and model classes to completely eliminate reflection
  MODEL_MAP = {
    "product" => Product,
    "user" => User,
    "order" => Order
  }
  
  # Get the normalized class parameter
  requested_class = params[:class]&.downcase
  
  if requested_class && MODEL_MAP.key?(requested_class)
    # Use the direct class reference from our mapping instead of reflection
    model = MODEL_MAP[requested_class]
    
    # Sanitize the ID parameter to prevent SQL injection
    id = params[:id].to_i
    
    # Find the record using the sanitized ID
    record = model.find(id)
    respond_with record.to_json
  else
    # Reject invalid class parameters with a bad request error
    render json: { error: "Invalid class parameter" }, status: :bad_request
  end
end

  end

  def index
    if params[:class]
      model = params[:class].classify.constantize
      respond_with model.all.to_json
    else
      respond_with nil.to_json
    end
  end

  private

  def mobile_request?
    if session[:mobile_param]
      session[:mobile_param] == "1"
    else
      request.user_agent =~ /ios|android/i
    end
  end
end
