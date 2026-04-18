# Hayyan SOC — Start the system

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Hayyan SOC — API Server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Activate venv
if (-not (Test-Path ".\.venv\Scripts\Activate.ps1")) {
    Write-Host "[ERROR] Virtual environment not found. Run setup.ps1 first." -ForegroundColor Red
    exit 1
}

& ".\.venv\Scripts\Activate.ps1"

# Check .env
if (-not (Test-Path ".env")) {
    Write-Host "[ERROR] .env file not found. Run setup.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Verifying environment..." -ForegroundColor Yellow
$env_content = Get-Content ".env" | Select-String "GOOGLE_API_KEY"
if ($env_content -match "your_gemini") {
    Write-Host "[WARNING] GOOGLE_API_KEY not set in .env" -ForegroundColor Red
    Write-Host "  Edit .env and add your Gemini API key before running." -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Building knowledge base..." -ForegroundColor Yellow
python soc_agents/knowledge/build_kb.py

Write-Host ""
Write-Host "[*] Starting FastAPI server on http://0.0.0.0:8500" -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

python -m uvicorn soc_agents.api.app:app `
    --host 0.0.0.0 `
    --port 8500 `
    --reload `
    --log-level info
