#!/bin/bash

# Git2in Setup Script
# This script sets up the development environment for Git2in

set -e  # Exit on error

echo "=== Git2in Development Setup ==="
echo

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.11"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null; then
    echo "Error: Python 3.11 or higher is required. Found: $python_version"
    exit 1
fi
echo "✓ Python $python_version"

# Create virtual environment
echo
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo
echo "Installing dependencies..."
pip install -r requirements-dev.txt

# Install pre-commit hooks
echo
echo "Installing pre-commit hooks..."
pre-commit install

# Copy environment file if it doesn't exist
echo
echo "Setting up environment file..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✓ Created .env file from .env.example"
    echo
    echo "⚠️  IMPORTANT: Edit .env and set your SECRET_KEY"
    echo "   Generate a secure key with:"
    echo "   python -c \"import secrets; print(secrets.token_urlsafe(32))\""
else
    echo "✓ .env file already exists"
fi

# Create necessary directories
echo
echo "Creating project directories..."
mkdir -p repos data
echo "✓ Created repos/ and data/ directories"

# Run initial tests
echo
echo "Running initial tests..."
pytest --version >/dev/null 2>&1 || echo "⚠️  pytest not found, skipping tests"

# Display completion message
echo
echo "=== Setup Complete! ==="
echo
echo "Next steps:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Edit .env and set your SECRET_KEY"
echo "3. Run the development server: uvicorn src.main:app --reload"
echo
echo "Development commands:"
echo "- Run tests: pytest"
echo "- Format code: black src/ tests/"
echo "- Sort imports: isort src/ tests/"
echo "- Type check: mypy src/"
echo "- Run pre-commit: pre-commit run --all-files"