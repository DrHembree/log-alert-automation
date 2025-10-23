#!/bin/zsh
# ==============================================
# Startup Script for Log Alert Automation Project
# ==============================================

# Navigate to the project directory
cd ~/Desktop/log-alert-automation || exit

# Activate virtual environment
source .venv/bin/activate

# Launch Jupyter Notebook
echo "Starting Jupyter Notebook..."
jupyter notebook

