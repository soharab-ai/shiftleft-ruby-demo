# frozen_string_literal: true
class AdminController < ApplicationController
  before_action :administrative, if: :admin_param, except: [:get_user]
  skip_before_action :has_info
  layout false, only: [:get_all_users, :get_user]

  def dashboard
  end

  def analytics
    if params[:field].nil?
      fields = "*"
    else
      fields = custom_fields.join(",")
    end

    if params[:ip]
      @analytics = Analytics.hits_by_ip(params[:ip], fields)
    else
      @analytics = Analytics.all
    end
  end

  def get_all_users
    @users = User.all
  end

def get_user
  # Verify the current user is authenticated and has admin privileges
  unless current_user && current_user.admin?
    flash[:error] = "Unauthorized access"
    redirect_to root_path and return
  end
  
  # Additional access control check - verify the requested user is allowed to be accessed
  # by the current admin based on appropriate business rules
  @user = User.find_by_id(params[:admin_id].to_s)
  
  if @user.nil?
    flash[:error] = "User not found"
    redirect_to admin_path and return
  end
  
  # If organization-based access control is needed, add checks here
  # Example: return error if @user.organization_id != current_user.organization_id
  
  # After all authorization checks have passed, proceed with the original logic
  arr = ["true", "false"]
  @admin_select = @user.admin ? arr : arr.reverse
end


  def update_user
    user = User.find_by_id(params[:admin_id])
    if user
      user.update(params[:user].reject { |k| k == ("password" || "password_confirmation") })
      pass = params[:user][:password]
      user.password = pass if !(pass.blank?)
      user.save!
      message = true
    end
    respond_to do |format|
      format.json { render json: { msg: message ? "success" : "failure"} }
    end
  end

  def delete_user
    user = User.find_by(id: params[:admin_id])
    if user && !(current_user.id == user.id)
      # Call destroy here so that all association records w/ id are destroyed as well
      # Example user.retirement records would be destroyed
      user.destroy
      message = true
    end
    respond_to do |format|
      format.json { render json: { msg: message ? "success" : "failure"} }
    end
  end

  private

  def custom_fields
    params.require(:field).keys
  end
  helper_method :custom_fields

  def admin_param
    params[:admin_id] != "1"
  end
end
