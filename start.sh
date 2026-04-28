#!/bin/bash
# Digi Save WAF — Start Script (Linux/macOS)
set -e

echo "============================================="
echo "  Digi Save WAF — Startup"
echo "============================================="

cd "$(dirname "$0")"

# Create virtual environment if not exists
if [ ! -d ".venv" ]; then
    echo "[1/3] Creating virtual environment..."
    python3 -m venv .venv
fi

echo "[2/3] Installing dependencies..."
source .venv/bin/activate
pip install -q -r requirements.txt

echo "[3/3] Starting Digi Save WAF..."
cd backend
python main.py
