$patchedProj = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj"
$dbPath      = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\patched.db"
$resultsDir  = Join-Path $PSScriptRoot "..\TestResults"
$fecha       = "2026-09-23"

# Reinicia la API y limpia la BD antes de cada run (igual que Escenario A) para evitar
# contaminación de estado entre corridas en los asserts que sí modifican datos (BOLA,
# IDOR, Mass Assignment, BFLA) aunque la API ya esté parcheada.
for ($run = 1; $run -le 10; $run++) {
    Get-NetTCPConnection -LocalPort 5002 -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    Remove-Item $dbPath, "$dbPath-shm", "$dbPath-wal" -ErrorAction SilentlyContinue

    Start-Process "dotnet" -ArgumentList "run","--project",$patchedProj,"--no-build","--configuration","Debug","--urls","http://localhost:5002" -WindowStyle Hidden

    $ok = $false
    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep -Seconds 2
        try {
            if ((Invoke-WebRequest "http://localhost:5002/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { $ok = $true; break }
        } catch {}
    }
    if (-not $ok) {
        Write-Host "Run $run : VulnerableApi_Patched no disponible, se omite"
        continue
    }

    $trxFile = "ScenarioB_Run${run}_${fecha}.trx"
    & dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build --configuration Debug `
        --logger "trx;LogFileName=$trxFile" --results-directory $resultsDir `
        -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5002" 2>&1 | Out-Null
    Write-Host "Run B $run listo (exit=$LASTEXITCODE)"
}

Get-NetTCPConnection -LocalPort 5002 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Write-Host "Escenario B: 10 runs completados (DB reiniciada entre runs)"
