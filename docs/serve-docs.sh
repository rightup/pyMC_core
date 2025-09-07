#!/usr/bin/env bash
# Build and serve MkDocs documentation locally

set -e

echo "Building and serving pyMC_Core documentation..."
echo "============================================"

# Check if we're in the docs directory
if [ ! -f "mkdocs.yml" ]; then
    echo "Error: mkdocs.yml not found. Please run this script from the docs/ directory."
    exit 1
fi

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Installing documentation dependencies..."
    pip install -r requirements.txt
fi

# Build the documentation
echo "Building documentation..."
python -m mkdocs build --clean

# Serve the documentation
echo "Starting local server at http://localhost:8000"
echo "Press Ctrl+C to stop the server"
python -m mkdocs serve
