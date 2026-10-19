# Get-NetTCPConnection requiere CIM; netstat funciona en cualquier host.
function Stop-ListenerOnPort([int]$Port) {
    netstat -ano -p TCP | Select-String ":$Port\s+\S+\s+LISTENING\s+(\d+)" | ForEach-Object { Stop-Process -Id ([int]$_.Matches[0].Groups[1].Value) -Force -ErrorAction SilentlyContinue }
}

$apiProject = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj"
$dbPath     = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\vulnerable.db"
$resultsDir = Join-Path $PSScriptRoot "..\TestResults"
$fecha      = Get-Date -Format "yyyy-MM-dd"

for ($run = 1; $run -le 10; $run++) {
    Stop-ListenerOnPort 5000
    Start-Sleep -Seconds 2
    Remove-Item $dbPath, "$dbPath-shm", "$dbPath-wal" -ErrorAction SilentlyContinue
    # Rota app.log (llegó a 128 MB): los asserts A28d/A28e leen su cola y el archivo grande ralentiza/bloquea escrituras
    Remove-Item (Join-Path (Split-Path $apiProject) "bin\Debug\net8.0\logs\app.log") -ErrorAction SilentlyContinue

    Start-Process "dotnet" -ArgumentList "run","--project",$apiProject,"--no-build","--configuration","Debug","--urls","http://localhost:5000;https://localhost:5001" -WindowStyle Hidden

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
        -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5000" RunConfiguration.EnvironmentVariables.TEST_API_HTTPS_URL="https://localhost:5001" 2>&1 | Out-Null
    Write-Host "Run A $run listo (exit=$LASTEXITCODE)"
}

Stop-ListenerOnPort 5000
Write-Host "Escenario A: 10 runs completados"
