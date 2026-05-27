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
    # SECURITY FIX: Define hash-based handler mapping for allowed graph types to prevent reflection-based injection
    GRAPH_HANDLERS = {
      'bar_graph' => -> { render "dashboard/bar_graph" },
      'pie_charts' => -> { @user = current_user; render "dashboard/pie_charts" }
    }.freeze
    
    # SECURITY FIX: Validate input against handler keys before processing
    unless GRAPH_HANDLERS.key?(params[:graph])
      # SECURITY FIX: Return error response for invalid graph types instead of executing reflection
      render plain: "Invalid graph type", status: :bad_request
      return
    end
    
    # SECURITY FIX: Execute the appropriate handler using hash-based dispatch instead of dynamic reflection
    instance_exec(&GRAPH_HANDLERS[params[:graph]])
  end

