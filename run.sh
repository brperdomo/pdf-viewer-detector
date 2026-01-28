#!/bin/bash
# PDF Viewer Detector Launcher

cd "$(dirname "$0")"

echo "Starting PDF Viewer Detector..."
echo ""

# Activate virtual environment
source venv/bin/activate

# Run the application
python src/main.py

echo ""
echo "Application closed."
