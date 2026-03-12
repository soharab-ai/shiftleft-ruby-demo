# frozen_string_literal: true
class Api::V1::MobileController < ApplicationController
  skip_before_action :authenticated
  before_action :mobile_request?

  respond_to :json

def show
    # Mitigation: Use namespace-based validation with safe constantization helper
    class_param = params[:class]&.strip
    model = safe_constantize(class_param)
private

  # Mitigation: Safe constantization helper with namespace restriction to prevent reflection attacks
  def safe_constantize(class_name)
    # Mitigation: Strict regex validation allowing only lowercase letters and underscores
    validated_name = class_name&.match(/\A[a-z_]+\z/)&.[](0)
    return nil unless validated_name
    
    # Mitigation: Restrict to models within a specific API-safe namespace
    safe_class_name = "ApiExposed::#{validated_name.classify}"
    
    # Mitigation: Use safe_constantize which returns nil for invalid classes
    klass = safe_class_name.safe_constantize
    
    # Mitigation: Verify the class inherits from ApplicationRecord and includes ApiExposable
    return klass if klass && klass < ApplicationRecord && klass.include?(ApiExposable)
    
    nil
  end

    # Mitigation: Validate that a safe model class was resolved
    if model
      record = model.find_by(id: params[:id])
      
      # Mitigation: Separate authorization check with timing-safe response
      if record
        unless authorized_to_view?(record)
          sleep(0.01) # Constant time delay to prevent timing attacks
          render json: { error: 'Resource not found' }, status: :not_found
          return
        end
        respond_with record.to_json
# Mitigation: Policy-based authorization implementation using policy objects
  def authorized_to_view?(record)
    # Mitigation: Dynamically resolve policy class based on record type
    policy_class = "#{record.class.name}Policy".safe_constantize
    return false unless policy_class
    
    policy_class.new(current_user, record).show?
  rescue NoMethodError
    false
  end

      request.user_agent =~ /ios|android/i
    end
  end
end
