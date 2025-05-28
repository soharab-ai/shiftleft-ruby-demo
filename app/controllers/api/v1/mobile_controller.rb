# frozen_string_literal: true
class Api::V1::MobileController < ApplicationController
  skip_before_action :authenticated
  before_action :mobile_request?

  respond_to :json

  def show
    if params[:class]
      model = params[:class].classify.constantize
      respond_with model.find(params[:id]).to_json
    end
def index
  # Direct mapping hash eliminates reflection entirely for improved security
  MODEL_MAPPING = {
    "product" => Product,
    "category" => Category,
    "article" => Article
  }
  
  # Scope rules provide fine-grained control over what data is accessible
  SCOPE_RULES = {
    "product" => -> { Product.active.visible },
    "category" => -> { Category.published },
    "article" => -> { Article.published.recent }
  }
  
  class_param = params[:class]&.downcase
  
  if class_param && MODEL_MAPPING.key?(class_param)
    # Implement contextual authorization check
    unless current_user.can_access?(class_param)
      render json: { error: "Access denied" }, status: :forbidden
      # Sanitized logging for security events
      logger.warn "Unauthorized access attempt to #{class_param} by user ID: #{current_user.id}"
      return
    end
    
    # Apply scope rules instead of returning all records
    records = SCOPE_RULES[class_param].call
    
    # Track API usage for rate limiting purposes
    ApiRequestTracker.log(user_id: current_user.id, resource: class_param, action: 'index')
    
    respond_with records.to_json
  else
    if class_param && !MODEL_MAPPING.key?(class_param)
      render json: { error: "Resource not found" }, status: :not_found
      # Sanitized logging for potential attack attempts
      logger.warn "Invalid resource request: #{class_param}"
    else
      # Default response when no class parameter is provided
      respond_with nil.to_json
    end
  end
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
