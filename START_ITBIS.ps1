$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

try {
    $py = $null
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:ProgramFiles\Python312\python.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $py = $candidate
            break
        }
    }
    if (-not $py) {
        try {
            & py -3.12 --version *> $null
            if ($LASTEXITCODE -eq 0) { $py = "py -3.12" }
        } catch {}
    }
    if (-not $py) { throw "Python 3.12 was not found. Install Python 3.12 and run START_ITBIS.bat again." }

    Write-Host "Using Python: $py" -ForegroundColor Cyan
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        & $py -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Could not create the Python virtual environment." }
    }
    $venvPy = Join-Path $Root ".venv\Scripts\python.exe"
    if (-not (Test-Path ".env")) { Copy-Item .env.example .env }

    Write-Host "Installing/checking packages..." -ForegroundColor Cyan
    & $venvPy -m pip install -r backend\requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Package installation failed." }

    Push-Location backend
    try {
        & $venvPy seed.py
        if ($LASTEXITCODE -ne 0) { throw "Demo-data initialization failed." }
        Write-Host "ITBIS is running at http://localhost:8000" -ForegroundColor Green
        Write-Host "Login: admin@ueba.com / admin123" -ForegroundColor Green
        & $venvPy -m uvicorn app.main:app --host 127.0.0.1 --port 8000
    } finally {
        Pop-Location
    }
} catch {
    Write-Host ""; Write-Host "ITBIS DID NOT START" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""; Read-Host "Press Enter to close"
}
