#!/bin/bash
echo "---- Starting custom startup process ----"

# Ensure pip and dependencies are ready
python3 -m ensurepip --default-pip
python3 -m pip install --upgrade pip

# Install all dependencies directly into site-packages
python3 -m pip install -r requirements.txt

# Start Gunicorn
echo "---- Starting Gunicorn ----"
gunicorn --bind=0.0.0.0 --timeout 600 app:app