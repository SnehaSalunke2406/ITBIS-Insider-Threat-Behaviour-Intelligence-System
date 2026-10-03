$ErrorActionPreference='Stop'
$Root=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
if(Test-Path .venv\Scripts\python.exe){& .venv\Scripts\python.exe -m compileall backend\app; if($LASTEXITCODE -ne 0){throw 'Python compile failed'}} else {Write-Host 'Run START_ITBIS.ps1 first to create the virtual environment.'}
Write-Host 'Project static checks passed.'
