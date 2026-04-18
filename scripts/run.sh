#!/bin/bash
# Hayyan SOC — Start the system

set -e

echo "========================================"
echo "  Hayyan SOC — API Server"
echo "========================================"
echo ""

# Check venv
if [ ! -d ".venv" ]; then
    echo "[ERROR] Virtual environment not found. Run setup.sh first."
    exit 1
fi

# Activate venv
source .venv/bin/activate

# Check .env
if [ ! -f .env ]; then
    echo "[ERROR] .env file not found. Run setup.sh first."
    exit 1
fi

# Check for API key
if grep -q "your_gemini" .env; then
    echo "[WARNING] GOOGLE_API_KEY not set in .env"
    echo "  Edit .env and add your Gemini API key before running."
    exit 1
fi

echo "[*] Building knowledge base..."
python soc_agents/knowledge/build_kb.py

echo ""
echo "[*] Starting FastAPI server on http://0.0.0.0:8500"
echo "[*] Press Ctrl+C to stop"
echo ""

python -m uvicorn soc_agents.api.app:app \
    --host 0.0.0.0 \
    --port 8500 \
    --reload \
    --log-level info
