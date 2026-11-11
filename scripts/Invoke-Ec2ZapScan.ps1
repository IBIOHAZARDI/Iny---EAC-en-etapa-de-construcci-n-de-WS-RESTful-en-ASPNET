param(
    [Parameter(Mandatory)]
    [ValidateSet('A', 'B')]
    [string]$Scenario,
    [Parameter(Mandatory)]
    [string]$BaseUrl,
    [Parameter(Mandatory)]
    [string]$Work,
    [Parameter(Mandatory)]
    [string]$Results,
    [string]$ZapJar = 'C:\ProgramData\ITM-Lab\tools\ZAP_2.17.0\zap-2.17.0.jar'
)

$ErrorActionPreference = 'Stop'
$expectedUrl = if ($Scenario -eq 'A') { 'http://localhost:5000' } else { 'https://localhost:5002' }
if ($BaseUrl -cne $expectedUrl) {
    throw "Unexpected target for scenario ${Scenario}: $BaseUrl"
}
if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
    throw 'JAVA_HOME is required for ZAP.'
}
$java = Join-Path $env:JAVA_HOME 'bin\java.exe'
$plan = Join-Path $PSScriptRoot 'zap-ec2-plan.yml'
foreach ($path in @($java, $ZapJar, $plan)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required ZAP file not found: $path"
    }
}

$login = @{ email = 'usera@test.local'; password = 'UserA123!' } | ConvertTo-Json -Compress
$response = Invoke-RestMethod -Uri "$BaseUrl/api/v2/auth/login" -Method Post `
    -ContentType 'application/json' -Body $login -SkipCertificateCheck -TimeoutSec 15
if ($response.token -notmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' -or $response.role -ne 'user') {
    throw "Scenario $Scenario did not return the expected synthetic user token."
}

$names = @('ZAP_LAB_URL', 'ZAP_LAB_RESULTS', 'ZAP_LAB_SCENARIO')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:ZAP_LAB_URL = $BaseUrl
    $env:ZAP_LAB_SCENARIO = $Scenario
    $zapHome = Join-Path $Work "zap-$Scenario"
    New-Item -ItemType Directory -Path $zapHome -ErrorAction Stop | Out-Null
    $env:ZAP_LAB_RESULTS = $zapHome
    $runtimePlan = Join-Path $zapHome 'plan.yml'
    $planText = (Get-Content -LiteralPath $plan -Raw).Replace('${ZAP_LAB_TOKEN}', $response.token)
    [System.IO.File]::WriteAllText($runtimePlan, $planText, [System.Text.UTF8Encoding]::new($false))
    $planText = $null
    $stdout = Join-Path $zapHome 'stdout.log'
    $stderr = Join-Path $zapHome 'stderr.log'
    $arguments = @('-Xmx768m', '-jar', "`"$ZapJar`"", '-cmd', '-dir', "`"$zapHome`"", '-autorun', "`"$runtimePlan`"")
    $process = $null
    try {
        $process = Start-Process -FilePath $java -ArgumentList $arguments -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr -PassThru
        if (-not $process.WaitForExit(1800000)) {
            throw "ZAP scenario $Scenario exceeded the 30-minute process timeout."
        }
        if ($process.ExitCode -ne 0) {
            throw "ZAP scenario $Scenario failed with exit code $($process.ExitCode); inspect its logs."
        }
        $zapLog = Join-Path $zapHome 'zap.log'
        if (-not (Test-Path -LiteralPath $zapLog -PathType Leaf)) {
            throw "ZAP scenario $Scenario did not create its diagnostic log."
        }
        $counts = @{ SqlInjectionScanRule = 0; CrossSiteScriptingScanRule = 0 }
        foreach ($line in Get-Content -LiteralPath $zapLog) {
            if ($line -match 'completed host/plugin .+ \| (SqlInjectionScanRule|CrossSiteScriptingScanRule) in .+ with (\d+) message\(s\) sent') {
                $counts[$Matches[1]] += [int]$Matches[2]
            }
        }
        foreach ($rule in $counts.Keys) {
            if ($counts[$rule] -lt 1) {
                throw "ZAP scenario $Scenario sent no verified active requests for $rule."
            }
            Write-Host "ZAP scenario ${Scenario}: $rule sent $($counts[$rule]) active requests."
        }
    } finally {
        if ($process) {
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -ErrorAction Stop
                $process.WaitForExit()
            }
        }
        foreach ($log in @(@{ Source = $stdout; Name = "zap-$Scenario-stdout.log" }, @{ Source = $stderr; Name = "zap-$Scenario-stderr.log" })) {
            if (Test-Path -LiteralPath $log.Source -PathType Leaf) {
                $text = [System.IO.File]::ReadAllText($log.Source).Replace($response.token, '[REDACTED LAB TOKEN]')
                [System.IO.File]::WriteAllText((Join-Path $Results $log.Name), $text, [System.Text.UTF8Encoding]::new($false))
            }
        }
        $privateReport = Join-Path $zapHome "zap-$Scenario.html"
        if (Test-Path -LiteralPath $privateReport -PathType Leaf) {
            $reportText = [System.IO.File]::ReadAllText($privateReport).Replace($response.token, '[REDACTED LAB TOKEN]')
            [System.IO.File]::WriteAllText((Join-Path $Results "zap-$Scenario.html"), $reportText, [System.Text.UTF8Encoding]::new($false))
        }
        Remove-Item -LiteralPath $runtimePlan -ErrorAction Stop
    }
    $report = Join-Path $Results "zap-$Scenario.html"
    if (-not (Test-Path -LiteralPath $report -PathType Leaf)) {
        throw "ZAP did not create its report: $report"
    }
    Write-Host "ZAP scenario $Scenario completed; report: $report"
} finally {
    foreach ($name in $names) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}
