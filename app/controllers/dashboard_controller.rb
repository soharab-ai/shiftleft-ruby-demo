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
# Define allowed graph types as a frozen constant at class level
ALLOWED_GRAPHS = {
  "bar_graph" => -> { render_bar_graph },
  "pie_chart" => -> { render_pie_chart },
  "line_graph" => -> { render_line_graph }
}.freeze

def change_graph
  # Complete elimination of reflection for better security
  if ALLOWED_GRAPHS.key?(params[:graph])
    # Call the mapped function directly instead of using reflection
    ALLOWED_GRAPHS[params[:graph]].call
  else
    # Handle invalid input securely
    flash[:error] = "Invalid graph type selected"
    redirect_to dashboard_path
  end
end

# Define separate methods for each graph type
private
def render_bar_graph
  render "dashboard/bar_graph"
end

def render_pie_chart
  @user = current_user
  render "dashboard/pie_charts"
end

def render_line_graph
  @user = current_user
  render "dashboard/pie_charts" # Assuming line graphs use the same template
end

