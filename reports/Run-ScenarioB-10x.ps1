# Get-NetTCPConnection requiere CIM; netstat funciona en cualquier host.
function Stop-ListenerOnPort([int]$Port) {
    netstat -ano -p TCP | Select-String ":$Port\s+\S+\s+LISTENING\s+(\d+)" | ForEach-Object { Stop-Process -Id ([int]$_.Matches[0].Groups[1].Value) -Force -ErrorAction SilentlyContinue }
}

$patchedProj = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj"
$dbPath      = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\patched.db"
$resultsDir  = Join-Path $PSScriptRoot "..\TestResults"
$fecha       = Get-Date -Format "yyyy-MM-dd"

# Reinicia la API y limpia la BD antes de cada run (igual que Escenario A) para evitar
# contaminación de estado entre corridas en los asserts que sí modifican datos (BOLA,
# IDOR, Mass Assignment, BFLA) aunque la API ya esté parcheada.
for ($run = 1; $run -le 10; $run++) {
    Stop-ListenerOnPort 5002
    Start-Sleep -Seconds 2
    Remove-Item $dbPath, "$dbPath-shm", "$dbPath-wal" -ErrorAction SilentlyContinue

    Start-Process "dotnet" -ArgumentList "run","--project",$patchedProj,"--no-build","--configuration","Debug","--urls","https://localhost:5002;http://localhost:5003" -WindowStyle Hidden

    $ok = $false
    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep -Seconds 2
        try {
            if ((Invoke-WebRequest "http://localhost:5003/health" -UseBasicParsing -MaximumRedirection 5 -SkipCertificateCheck -TimeoutSec 3).StatusCode -eq 200) { $ok = $true; break }
        } catch {}
    }
    if (-not $ok) {
        Write-Host "Run $run : VulnerableApi_Patched no disponible, se omite"
        continue
    }

    $trxFile = "ScenarioB_Run${run}_${fecha}.trx"
    & dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build --configuration Debug `
        --logger "trx;LogFileName=$trxFile" --results-directory $resultsDir `
        -- RunConfiguration.EnvironmentVariables.TEST_API_URL="https://localhost:5002" RunConfiguration.EnvironmentVariables.TEST_API_HTTP_URL="http://localhost:5003" 2>&1 | Out-Null
    Write-Host "Run B $run listo (exit=$LASTEXITCODE)"
}

Stop-ListenerOnPort 5002
Write-Host "Escenario B: 10 runs completados (DB reiniciada entre runs)"
