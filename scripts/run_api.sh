#!/bin/bash
# Start the Hayyan SOC API server
set -e

echo "[*] Activating virtual environment..."
source .venv/Scripts/activate

echo "[*] Building knowledge base..."
python soc_agents/knowledge/build_kb.py

echo "[*] Starting FastAPI server on 0.0.0.0:8500..."
python -m uvicorn soc_agents.api.app:app \
    --host 0.0.0.0 \
    --port 8500 \
    --reload \
    --log-level info
