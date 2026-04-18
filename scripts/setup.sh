#!/bin/bash
# Hayyan SOC Setup Script for Mac/Linux

set -e

echo "========================================"
echo "  Hayyan SOC — Setup"
echo "========================================"
echo ""

# Check Python
echo "[*] Checking Python..."
python3 --version || { echo "[ERROR] Python 3 not found"; exit 1; }

# Create venv
echo "[*] Creating virtual environment..."
python3 -m venv .venv

# Activate venv
echo "[*] Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create .env
if [ ! -f .env ]; then
    echo "[*] Creating .env file..."
    cp .env.example .env
    echo "[!] IMPORTANT: Edit .env and add your GOOGLE_API_KEY"
fi

# Create directories
echo "[*] Creating data directories..."
mkdir -p data/chroma_db

# Initialize knowledge base
echo "[*] Initializing ChromaDB knowledge base..."
python soc_agents/knowledge/build_kb.py

echo ""
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Edit .env and add your GOOGLE_API_KEY"
echo "2. Run: ./scripts/run.sh"
echo "3. Open: http://localhost:8500"
echo ""
