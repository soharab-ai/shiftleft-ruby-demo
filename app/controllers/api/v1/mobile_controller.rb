# frozen_string_literal: true
  # Whitelist of allowed model class names for reflection (defined at class level for performance)
  ALLOWED_MODELS = %w[User Product Order].freeze

  before_action :mobile_request?

  respond_to :json

  def show
    if params[:class]
      model = params[:class].classify.constantize
      respond_with model.find(params[:id]).to_json
    end
def index
    # Define allowed model class names at class level to prevent reflection attacks
    # This whitelist approach ensures only pre-approved models can be accessed
    class_name = params[:class].to_s.classify
    
    # Verify the class name exists in whitelist before constantizing (CWE-470 mitigation)
    if ALLOWED_MODELS.include?(class_name)
      begin
        model = class_name.constantize
        # Additional safety check: verify it's actually an ActiveRecord model to prevent access to dangerous Ruby classes
        if model.is_a?(Class) && model < ApplicationRecord
          respond_with model.all.to_json
        else
          # Reject non-ActiveRecord classes to prevent arbitrary code execution
          render json: { error: 'Invalid model class' }, status: :bad_request
        end
      rescue NameError
        # Handle cases where constantization fails unexpectedly
        render json: { error: 'Model not found' }, status: :bad_request
      end
    else
      # Return error response for invalid or unauthorized class parameter
      render json: { error: 'Unauthorized model access' }, status: :bad_request
    end
  end

      request.user_agent =~ /ios|android/i
    end
  end
end
