$apiProject = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj"
$dbPath     = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\vulnerable.db"
$resultsDir = Join-Path $PSScriptRoot "..\TestResults"
$fecha      = "2026-09-23"

for ($run = 1; $run -le 10; $run++) {
    Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    Remove-Item $dbPath, "$dbPath-shm", "$dbPath-wal" -ErrorAction SilentlyContinue

    Start-Process "dotnet" -ArgumentList "run","--project",$apiProject,"--no-build","--configuration","Debug","--urls","http://localhost:5000" -WindowStyle Hidden

    $ok = $false
    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep -Seconds 2
        try {
            if ((Invoke-WebRequest "http://localhost:5000/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { $ok = $true; break }
        } catch {}
    }
    if (-not $ok) {
        Write-Host "Run $run : API no disponible, se omite"
        continue
    }

    $trxFile = "ScenarioA_Run${run}_${fecha}.trx"
    & dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build --configuration Debug `
        --logger "trx;LogFileName=$trxFile" --results-directory $resultsDir `
        -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5000" 2>&1 | Out-Null
    Write-Host "Run A $run listo (exit=$LASTEXITCODE)"
}

Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Write-Host "Escenario A: 10 runs completados"
