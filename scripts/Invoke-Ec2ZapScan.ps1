param(
    [Parameter(Mandatory)]
    [ValidateSet('A', 'B')]
    [string]$Scenario,
    [Parameter(Mandatory)]
    [string]$BaseUrl,
    [Parameter(Mandatory)]
    [string]$Work,
    [Parameter(Mandatory)]
    [string]$Results
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
$jar = 'C:\ProgramData\ITM-Lab\tools\ZAP_2.17.0\zap-2.17.0.jar'
$plan = Join-Path $PSScriptRoot 'zap-ec2-plan.yml'
foreach ($path in @($java, $jar, $plan)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required ZAP file not found: $path"
    }
}

$login = @{ email = 'usera@test.local'; password = 'UserA123!' } | ConvertTo-Json -Compress
$response = Invoke-RestMethod -Uri "$BaseUrl/api/v2/auth/login" -Method Post `
    -ContentType 'application/json' -Body $login -SkipCertificateCheck -TimeoutSec 15
if ([string]::IsNullOrWhiteSpace($response.token) -or $response.role -ne 'user') {
    throw "Scenario $Scenario did not return the expected synthetic user token."
}

$names = @('ZAP_LAB_URL', 'ZAP_LAB_TOKEN', 'ZAP_LAB_RESULTS', 'ZAP_LAB_SCENARIO')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:ZAP_LAB_URL = $BaseUrl
    $env:ZAP_LAB_TOKEN = $response.token
    $env:ZAP_LAB_RESULTS = $Results
    $env:ZAP_LAB_SCENARIO = $Scenario
    $zapHome = Join-Path $Work "zap-$Scenario"
    New-Item -ItemType Directory -Path $zapHome -ErrorAction Stop | Out-Null
    $stdout = Join-Path $Results "zap-$Scenario-stdout.log"
    $stderr = Join-Path $Results "zap-$Scenario-stderr.log"
    $arguments = @('-jar', "`"$jar`"", '-cmd', '-dir', "`"$zapHome`"", '-autorun', "`"$plan`"")
    $process = Start-Process -FilePath $java -ArgumentList $arguments -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -PassThru
    try {
        if (-not $process.WaitForExit(1800000)) {
            throw "ZAP scenario $Scenario exceeded the 30-minute process timeout."
        }
        if ($process.ExitCode -ne 0) {
            throw "ZAP scenario $Scenario failed with exit code $($process.ExitCode); inspect its logs."
        }
    } finally {
        $process.Refresh()
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -ErrorAction Stop
            $process.WaitForExit()
        }
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
