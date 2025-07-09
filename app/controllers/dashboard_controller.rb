# frozen_string_literal: true
class DashboardController < ApplicationController
  skip_before_action :has_info
  layout false, only: [:change_graph]

  def home
    @user = current_user

    # See if the user has a font preference
    if params[:font]
      cookies[:font] = params[:font]
    end
  end

  def change_graph
# Define allowed graph types as constants for better maintenance
ALLOWED_GRAPH_TYPES = %w(bar_graph pie_chart).freeze

def change_graph
  # Implemented mapper pattern to replace reflection and case statement
  # for better maintainability and security
  graph_handlers = {
    "bar_graph" => -> { 
      bar_graph
      render "dashboard/bar_graph"
    },
    "pie_chart" => -> {
      pie_chart
      @user = current_user
      render "dashboard/pie_charts"
    }
  }
  
  # Use the mapper to handle valid graph types
  if handler = graph_handlers[params[:graph]]
    handler.call
  else
    # Handle invalid graph type securely
    flash[:error] = "Invalid graph type selected"
    redirect_to dashboard_path
  end
end

# Added validation at higher level as suggested in mitigation notes
before_action :validate_graph_type, only: [:change_graph]

def validate_graph_type
  unless ALLOWED_GRAPH_TYPES.include?(params[:graph])
    flash[:error] = "Invalid graph type selected"
    redirect_to dashboard_path and return
  end
end

