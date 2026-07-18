$serverDir = Join-Path $PSScriptRoot "server"
$clientUrl = "http://localhost:3000"

Write-Host "Starte SecureChat Server..." -ForegroundColor Green
$job = Start-Job -ScriptBlock { Set-Location $using:serverDir; node index.js }
Start-Sleep -Seconds 1

Write-Host "Öffne in Chromium-App-Modus..." -ForegroundColor Cyan

$chromePaths = @(
  "C:\Program Files\Google\Chrome\Application\chrome.exe",
  "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
  "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
)

$chrome = $chromePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($chrome) {
  Start-Process -FilePath $chrome -ArgumentList "--app=$clientUrl", "--no-first-run", "--no-default-browser-check"
} else {
  Start-Process $clientUrl
}

Write-Host ""
Write-Host "SecureChat läuft auf $clientUrl" -ForegroundColor Yellow
Write-Host "STRG+C zum Beenden" -ForegroundColor Yellow

try { while ($true) { Start-Sleep -Seconds 10 } }
finally { Stop-Job $job -Force; Remove-Job $job -Force }
