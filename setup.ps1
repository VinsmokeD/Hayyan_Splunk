# Hayyan SOC Agent Bootstrap
# Run once to set up venv and install dependencies
# Then start the server: .\run.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  [*] Hayyan SOC Agents - Bootstrap" -ForegroundColor Cyan
Write-Host ""

# Create virtualenv if not present
if (-not (Test-Path ".venv")) {
    Write-Host "  Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "  Activating virtual environment..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1

Write-Host "  Installing dependencies..." -ForegroundColor Yellow
pip install --upgrade pip -q
pip install -r requirements.txt -q

# Copy .env if missing
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host ""
    Write-Host "  [!] .env file created from .env.example" -ForegroundColor Yellow
    Write-Host "  [!] EDIT .env and set GOOGLE_API_KEY + Splunk credentials" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host ""
Write-Host "  [OK] Setup complete! Run .\run.ps1 to start the server." -ForegroundColor Green
Write-Host ""
