# Hayyan SOC Agents — Start Server
# Usage: .\run.ps1
# Prereq: run .\setup.ps1 first

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  🛡️  Hayyan SOC AI Agent Platform" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# Activate venv
if (Test-Path ".venv\Scripts\Activate.ps1") {
    & .\.venv\Scripts\Activate.ps1
} else {
    Write-Host "  ⚠️  No .venv found. Run .\setup.ps1 first." -ForegroundColor Red
    exit 1
}

# Load port from .env (default 8500)
$port = 8500
if (Test-Path ".env") {
    $envContent = Get-Content ".env" -Raw
    if ($envContent -match "API_PORT=(\d+)") { $port = $matches[1] }
}

Write-Host "  🌐  UI:      http://localhost:$port" -ForegroundColor Green
Write-Host "  📡  API:     http://localhost:$port/api/health" -ForegroundColor Green
Write-Host "  📖  Docs:    http://localhost:$port/docs" -ForegroundColor Green
Write-Host ""
Write-Host "  Press Ctrl+C to stop" -ForegroundColor DarkGray
Write-Host ""

python main.py
