Get-CimInstance Win32_Process -Filter "name = 'python.exe'" | Where-Object { $_.CommandLine -match 'uvicorn.*8000' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Write-Host "ITBIS server stopped."
