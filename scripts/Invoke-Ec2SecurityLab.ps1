$ErrorActionPreference = 'Stop'

foreach ($name in @('LAB_SOURCE_DIR', 'LAB_TEMP_DIR', 'LAB_RESULTS_DIR', 'LAB_BUILD_ID')) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "Missing required environment variable: $name"
    }
}
if ($env:LAB_BUILD_ID -notmatch '^\d+$') {
    throw 'LAB_BUILD_ID must be numeric.'
}

$source = $env:LAB_SOURCE_DIR
$results = $env:LAB_RESULTS_DIR
$work = Join-Path $env:LAB_TEMP_DIR "security-lab-$env:LAB_BUILD_ID"
$env:PATH = "$env:ProgramFiles\Git\cmd;$env:ProgramFiles\dotnet;$env:PATH"
if (Test-Path -LiteralPath $work) {
    throw "Run directory already exists: $work"
}
New-Item -ItemType Directory -Path $work, $results -Force | Out-Null
$app = Join-Path $work 'app'
$asserts = Join-Path $source 'SecurityAsserts\SecurityAsserts.csproj'

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code $LASTEXITCODE."
    }
}

function Wait-Health {
    param([string]$Url, [System.Diagnostics.Process]$Process)
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($Process.HasExited) {
            throw "API process exited with code $($Process.ExitCode); inspect the published logs."
        }
        try {
            $response = Invoke-WebRequest -Uri "$Url/health" -SkipCertificateCheck -TimeoutSec 3
            if ($response.StatusCode -eq 200) { return }
        } catch {
            Write-Host "Waiting for $Url ($($attempt + 1)/30): $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 2
    }
    throw "API did not become ready at $Url."
}

function Get-TestRate {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Missing test results: $Path" }
    [xml]$trx = Get-Content -LiteralPath $Path -Raw
    $counters = $trx.TestRun.ResultSummary.Counters
    if (-not $counters -or [int]$counters.total -lt 103) {
        throw "Test result file contains fewer than the 103 documented test cases: $Path"
    }
    if ([int]$counters.notExecuted -gt 0) {
        throw "Test result file contains unexecuted tests: $Path"
    }
    if ($trx.TestRun.ResultSummary.outcome -notin @('Completed', 'Failed')) {
        throw "Test run did not complete normally: $Path"
    }
    return @{
        Rate = 100.0 * [double]$counters.passed / [double]$counters.total
        Total = [int]$counters.total
    }
}

$processes = @()
$variables = @(
    'ASPNETCORE_ENVIRONMENT', 'ASPNETCORE_URLS', 'ConnectionStrings__DefaultConnection',
    'TEST_API_URL', 'TEST_API_HTTP_URL', 'TEST_API_HTTPS_URL'
)
$previous = @{}
foreach ($name in $variables) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

try {
    foreach ($port in @(5000, 5001, 5002, 5003)) {
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
            throw "Port $port is already in use; the lab will not stop an existing process."
        }
    }
    Invoke-Checked 'git' @('clone', '--depth', '1', '--branch', 'main', 'https://github.com/IBIOHAZARDI/App---EAC-en-etapa-de-construcci-n-de-WS-RESTful-en-ASPNET.git', $app)
    Invoke-Checked 'git' @('-C', $app, 'rev-parse', 'HEAD')
    Invoke-Checked 'dotnet' @('dev-certs', 'https')
    foreach ($project in @('VulnerableApi\VulnerableApi.csproj', 'VulnerableApi_Patched\VulnerableApi_Patched.csproj')) {
        Invoke-Checked 'dotnet' @('build', (Join-Path $app $project), '--configuration', 'Debug', '--nologo')
    }
    Invoke-Checked 'dotnet' @('build', $asserts, '--configuration', 'Debug', '--nologo')

    $dotnet = (Get-Command dotnet -ErrorAction Stop).Source
    $scenarios = @(
        @{ Name = 'A'; Folder = 'VulnerableApi'; Assembly = 'VulnerableApi.dll'; Base = 'http://localhost:5000'; Http = 'http://localhost:5000'; Https = 'https://localhost:5001' },
        @{ Name = 'B'; Folder = 'VulnerableApi_Patched'; Assembly = 'VulnerableApi_Patched.dll'; Base = 'https://localhost:5002'; Http = 'http://localhost:5003'; Https = 'https://localhost:5002' }
    )
    $rates = @{}
    foreach ($scenario in $scenarios) {
        $apiDir = Join-Path $app $scenario.Folder
        $dll = Join-Path $apiDir "bin\Debug\net8.0\$($scenario.Assembly)"
        $db = Join-Path $work "scenario-$($scenario.Name).db"
        $env:ASPNETCORE_ENVIRONMENT = 'Development'
        $env:ASPNETCORE_URLS = "$($scenario.Http);$($scenario.Https)"
        $env:ConnectionStrings__DefaultConnection = "Data Source=$db"
        $env:TEST_API_URL = $scenario.Base
        $env:TEST_API_HTTP_URL = $scenario.Http
        $env:TEST_API_HTTPS_URL = $scenario.Https
        $stdout = Join-Path $results "scenario-$($scenario.Name)-stdout.log"
        $stderr = Join-Path $results "scenario-$($scenario.Name)-stderr.log"
        $process = Start-Process -FilePath $dotnet -ArgumentList @("`"$dll`"") -WorkingDirectory $apiDir -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
        $processes += $process
        Wait-Health -Url $scenario.Base -Process $process
        $trx = "scenario-$($scenario.Name).trx"
        & $dotnet test $asserts --configuration Debug --no-build --logger "trx;LogFileName=$trx" --results-directory $results
        $testExit = $LASTEXITCODE
        if ($testExit -ne 0) {
            Write-Warning "Scenario $($scenario.Name) returned test exit code $testExit; evaluating the TRX gate."
        }
        $rates[$scenario.Name] = Get-TestRate (Join-Path $results $trx)
        Write-Host "Scenario $($scenario.Name) passed $($rates[$scenario.Name].Rate)% of $($rates[$scenario.Name].Total) tests."
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -ErrorAction Stop
            $process.WaitForExit()
        }
    }
    if ($rates.A.Total -ne $rates.B.Total) {
        throw 'Scenario A and B ran different numbers of tests.'
    }
    if ($rates.A.Rate -ge 95 -or $rates.B.Rate -le 95) {
        throw "Security gates failed: scenario A must be <95%, scenario B must be >95%."
    }
} finally {
    foreach ($process in $processes) {
        $process.Refresh()
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -ErrorAction Stop
            $process.WaitForExit()
        }
    }
    foreach ($name in $variables) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}
