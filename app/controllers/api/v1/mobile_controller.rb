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
  # Fix: Replaced unsafe reflection with a ModelAccessFactory pattern
  # that incorporates both authorization and object retrieval
  factory = ModelAccessFactory.new(current_user)
  
  if params[:class]
    result = factory.fetch_authorized_resources(params[:class])
    if result[:success]
      respond_with result[:data].to_json
    else
      respond_with({ error: "unauthorized", message: result[:message] }.to_json, status: 401)
    end
  else
    respond_with({ error: "bad_request", message: "Class parameter is required" }.to_json, status: 400)
  end
end

# ModelAccessFactory handles authorized access to models based on user roles
class ModelAccessFactory
  def initialize(user)
    @user = user
  end
  
  def fetch_authorized_resources(resource_name)
    # Define mappings between resource names and their corresponding model classes
    resource_mapping = {
      "users" => User,
      "products" => Product,
      "orders" => Order
      # Add more valid mappings as needed
    }
    
    unless resource_mapping.key?(resource_name)
      return { success: false, message: "Invalid resource specified" }
    end
    
    model_class = resource_mapping[resource_name]
    
    # Apply authorization checks based on user roles
    unless can_access?(resource_name)
      return { success: false, message: "You don't have permission to access this resource" }
    end
    
    # Apply filters based on user roles and permissions
    filtered_data = apply_access_filters(model_class.all, resource_name)
    
    { success: true, data: filtered_data }
  end
  
  private
  
  def can_access?(resource_name)
    # Role-based access control logic
    case resource_name
    when "users"
      @user&.admin? || @user&.manager?
    when "products"
      true # Everyone can access products
    when "orders"
      @user.present? # Only authenticated users
    else
      false
    end
  end
  
  def apply_access_filters(query, resource_name)
    case resource_name
    when "users"
      # Admins can see all users, managers see only their team
      if @user&.admin?
        query
      elsif @user&.manager?
        query.where(team_id: @user.team_id)
      else
        query.none # Empty result set
      end
    when "orders"
      # Users can only see their own orders unless they're admin
      if @user&.admin?
        query
      else
        query.where(user_id: @user.id)
      end
    else
      # No filtering for other resources
      query
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
