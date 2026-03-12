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
    # Define a hash mapping valid input values to their corresponding rendering logic to prevent reflection attacks
    GRAPH_RENDERERS = {
      'bar_graph' => -> { render "dashboard/bar_graph" },
      'pie_charts' => -> { @user = current_user; render "dashboard/pie_charts" }
    }.freeze
    
    graph_type = params[:graph]
    
    # Retrieve the renderer lambda from the hash - implicit allow list validation
    renderer = GRAPH_RENDERERS[graph_type]
    
    if renderer.nil?
      # Use to_s.inspect to sanitize input and prevent log forging attacks
      Rails.logger.warn("Invalid graph type attempted: #{graph_type.to_s.inspect}")
      render plain: "Invalid graph type", status: :bad_request
      return
    end
    
    # Execute the safe, pre-defined rendering logic instead of dangerous reflection
    instance_exec(&renderer)
  end

