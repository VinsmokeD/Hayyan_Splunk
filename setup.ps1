# Hayyan SOC Setup Script
# Run once to initialize the system

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Hayyan SOC — Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "[*] Checking Python..." -ForegroundColor Yellow
python --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Python not found. Install Python 3.10+ from python.org" -ForegroundColor Red
    exit 1
}

# Create venv
Write-Host "[*] Creating virtual environment..." -ForegroundColor Yellow
python -m venv .venv
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to create venv" -ForegroundColor Red
    exit 1
}

# Activate venv
Write-Host "[*] Activating virtual environment..." -ForegroundColor Yellow
& ".\.venv\Scripts\Activate.ps1"

# Install dependencies
Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
pip install --upgrade pip
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Create .env if not exists
if (-not (Test-Path ".env")) {
    Write-Host "[*] Creating .env file..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env" -ErrorAction SilentlyContinue
    Write-Host "[!] IMPORTANT: Edit .env and add your GOOGLE_API_KEY" -ForegroundColor Red
}

# Create data directories
Write-Host "[*] Creating data directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path "data\chroma_db" -Force | Out-Null
New-Item -ItemType Directory -Path "data" -Force | Out-Null

# Initialize knowledge base
Write-Host "[*] Initializing ChromaDB knowledge base..." -ForegroundColor Yellow
python soc_agents/knowledge/build_kb.py

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Edit .env and add your GOOGLE_API_KEY" -ForegroundColor White
Write-Host "2. Run: .\run.ps1" -ForegroundColor White
Write-Host "3. Open: http://localhost:8500" -ForegroundColor White
Write-Host ""
