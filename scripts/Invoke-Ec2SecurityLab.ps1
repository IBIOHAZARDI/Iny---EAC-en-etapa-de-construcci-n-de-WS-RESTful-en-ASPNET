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
    if ([int]$counters.skipped -gt 0) {
        throw "Test result file contains skipped tests: $Path"
    }
    if ($trx.TestRun.ResultSummary.outcome -notin @('Completed', 'Failed')) {
        throw "Test run did not complete normally: $Path"
    }
    $start = [datetime]::Parse($trx.TestRun.Times.start)
    $finish = [datetime]::Parse($trx.TestRun.Times.finish)
    return [PSCustomObject]@{
        Passed = [int]$counters.passed
        Failed = [int]$counters.failed
        Total = [int]$counters.total
        Rate = 100.0 * [double]$counters.passed / [double]$counters.total
        DurationMs = [math]::Round(($finish - $start).TotalMilliseconds)
    }
}

function Get-SampleStandardDeviation {
    param([double[]]$Values)
    if ($Values.Count -lt 2) { return 0.0 }
    $average = ($Values | Measure-Object -Average).Average
    $sumOfSquares = 0.0
    foreach ($value in $Values) {
        $sumOfSquares += [math]::Pow($value - $average, 2)
    }
    return [math]::Sqrt($sumOfSquares / ($Values.Count - 1))
}

function Stop-LabProcess {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    $Process.Refresh()
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -ErrorAction Stop
        $Process.WaitForExit()
    }
}

function Get-ScenarioStats {
    param(
        [string]$Name,
        [object[]]$Runs
    )
    if ($Runs.Count -ne 10) {
        throw "Scenario $Name completed $($Runs.Count) of the required 10 runs."
    }
    $totals = @($Runs | ForEach-Object { $_.Total } | Sort-Object -Unique)
    if ($totals.Count -ne 1) {
        throw "Scenario $Name produced different test counts across runs."
    }
    $rates = [double[]]@($Runs | ForEach-Object { $_.Rate })
    $passed = [double[]]@($Runs | ForEach-Object { $_.Passed })
    $failed = [double[]]@($Runs | ForEach-Object { $_.Failed })
    $durations = [double[]]@($Runs | ForEach-Object { $_.DurationMs })
    return [PSCustomObject]@{
        scenario = $Name
        buildId = [int]$env:LAB_BUILD_ID
        runCount = $Runs.Count
        testCasesPerRun = [int]$totals[0]
        avgPassed = [math]::Round(($passed | Measure-Object -Average).Average, 2)
        avgFailed = [math]::Round(($failed | Measure-Object -Average).Average, 2)
        avgRatePercent = ($rates | Measure-Object -Average).Average
        stdDevRatePercentagePoints = [math]::Round((Get-SampleStandardDeviation $rates), 2)
        avgDurationMs = [math]::Round(($durations | Measure-Object -Average).Average, 2)
        stdDevDurationMs = [math]::Round((Get-SampleStandardDeviation $durations), 2)
        runs = @(
            $Runs | ForEach-Object {
                [PSCustomObject]@{
                    run = $_.Run
                    trxFile = $_.TrxFile
                    passed = $_.Passed
                    failed = $_.Failed
                    total = $_.Total
                    ratePercent = [math]::Round($_.Rate, 2)
                    durationMs = $_.DurationMs
                }
            }
        )
    }
}

$processes = @()
$runCount = 10
$date = Get-Date -Format 'yyyy-MM-dd'
$variables = @(
    'ASPNETCORE_ENVIRONMENT', 'ConnectionStrings__DefaultConnection',
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
        @{ Name = 'A'; Environment = 'Development'; Folder = 'VulnerableApi'; Assembly = 'VulnerableApi.dll'; Base = 'http://localhost:5000'; Http = 'http://localhost:5000'; Https = 'https://localhost:5001' },
        @{ Name = 'B'; Environment = 'Production'; Folder = 'VulnerableApi_Patched'; Assembly = 'VulnerableApi_Patched.dll'; Base = 'https://localhost:5002'; Http = 'http://localhost:5003'; Https = 'https://localhost:5002' }
    )
    $statsByScenario = @{}
    foreach ($scenario in $scenarios) {
        $apiDir = Join-Path $app $scenario.Folder
        $dll = Join-Path $apiDir "bin\Debug\net8.0\$($scenario.Assembly)"
        $env:ASPNETCORE_ENVIRONMENT = $scenario.Environment
        $env:TEST_API_URL = $scenario.Base
        $env:TEST_API_HTTP_URL = $scenario.Http
        $env:TEST_API_HTTPS_URL = $scenario.Https
        $urls = "$($scenario.Http);$($scenario.Https)"
        $runResults = @()
        for ($run = 1; $run -le $runCount; $run++) {
            $runLabel = 'Run{0:D2}' -f $run
            $db = Join-Path $work "scenario-$($scenario.Name)-$runLabel.db"
            $apiLog = Join-Path $apiDir 'bin\Debug\net8.0\logs\app.log'
            if (Test-Path -LiteralPath $apiLog) {
                Remove-Item -LiteralPath $apiLog -Force -ErrorAction Stop
            }
            $env:ConnectionStrings__DefaultConnection = "Data Source=$db"
            $stdout = Join-Path $results "scenario-$($scenario.Name)-$runLabel-stdout.log"
            $stderr = Join-Path $results "scenario-$($scenario.Name)-$runLabel-stderr.log"
            $process = $null
            try {
                $process = Start-Process -FilePath $dotnet -ArgumentList @("`"$dll`"", '--urls', "`"$urls`"") -WorkingDirectory $apiDir -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
                $processes += $process
                Wait-Health -Url $scenario.Base -Process $process
                $trx = "Scenario$($scenario.Name)_Run${run}_${date}.trx"
                & $dotnet test $asserts --configuration Debug --no-build --logger "trx;LogFileName=$trx" --results-directory $results
                $testExit = $LASTEXITCODE
                if ($testExit -gt 1) {
                    throw "dotnet test failed for scenario $($scenario.Name), run $run with exit code $testExit."
                }
                if ($testExit -eq 1) {
                    Write-Warning "Scenario $($scenario.Name) run $run reported failed assertions; evaluating its TRX as part of the 10-run gate."
                }
                $testSummary = Get-TestRate (Join-Path $results $trx)
                $runResult = [PSCustomObject]@{
                    Run = $run
                    TrxFile = $trx
                    Passed = $testSummary.Passed
                    Failed = $testSummary.Failed
                    Total = $testSummary.Total
                    Rate = $testSummary.Rate
                    DurationMs = $testSummary.DurationMs
                }
                $runResults += $runResult
                Write-Host "Scenario $($scenario.Name) run $run passed $($testSummary.Passed)/$($testSummary.Total) ($([math]::Round($testSummary.Rate, 2))%) in $($testSummary.DurationMs) ms."
            } finally {
                Stop-LabProcess $process
            }
        }
        $stats = Get-ScenarioStats -Name $scenario.Name -Runs $runResults
        $statsPath = Join-Path $results "scenario$($scenario.Name)-stats.json"
        [System.IO.File]::WriteAllText($statsPath, ($stats | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
        $statsByScenario[$scenario.Name] = $stats
        Write-Host "Scenario $($scenario.Name) average: $($stats.avgPassed)/$($stats.testCasesPerRun) ($([math]::Round($stats.avgRatePercent, 2))%); SD $($stats.stdDevRatePercentagePoints) pp."

        if ($env:LAB_ZAP_ENABLED -eq 'true') {
            if (Test-Path -LiteralPath $apiLog) {
                Remove-Item -LiteralPath $apiLog -Force -ErrorAction Stop
            }
            $env:ConnectionStrings__DefaultConnection = "Data Source=$(Join-Path $work "zap-scenario-$($scenario.Name).db")"
            $zapStdout = Join-Path $results "zap-api-$($scenario.Name)-stdout.log"
            $zapStderr = Join-Path $results "zap-api-$($scenario.Name)-stderr.log"
            $process = $null
            try {
                $process = Start-Process -FilePath $dotnet -ArgumentList @("`"$dll`"", '--urls', "`"$urls`"") -WorkingDirectory $apiDir -RedirectStandardOutput $zapStdout -RedirectStandardError $zapStderr -PassThru
                $processes += $process
                Wait-Health -Url $scenario.Base -Process $process
                & (Join-Path $PSScriptRoot 'Invoke-Ec2ZapScan.ps1') -Scenario $scenario.Name -BaseUrl $scenario.Base -Work $work -Results $results
                $process.Refresh()
                if ($process.HasExited) {
                    throw "Scenario $($scenario.Name) API exited during its ZAP scan; inspect the published logs."
                }
                Wait-Health -Url $scenario.Base -Process $process
            } finally {
                Stop-LabProcess $process
            }
        }
    }
    if ($statsByScenario.A.testCasesPerRun -ne $statsByScenario.B.testCasesPerRun) {
        throw 'Scenario A and B ran different numbers of tests.'
    }
    if ($statsByScenario.A.avgRatePercent -ge 95 -or $statsByScenario.B.avgRatePercent -le 95) {
        throw "Security gates failed: average scenario A must be <95%, and average scenario B must be >95%."
    }
    Write-Host '10-run quality gates passed: average A < 95% and average B > 95%.'
} finally {
    foreach ($process in $processes) {
        Stop-LabProcess $process
    }
    foreach ($name in $variables) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}

# The expected failing assertions leave a nonzero native exit code after the gates pass.
$global:LASTEXITCODE = 0
