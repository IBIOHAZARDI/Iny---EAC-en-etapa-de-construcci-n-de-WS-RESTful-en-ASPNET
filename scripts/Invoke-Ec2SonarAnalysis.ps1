param(
    [Parameter(Mandatory)]
    [ValidateSet('App', 'Injector')]
    [string]$Target
)

$ErrorActionPreference = 'Stop'
foreach ($name in @('BUILD_SOURCESDIRECTORY', 'BUILD_BUILDID', 'BUILD_SOURCEBRANCH', 'AGENT_TEMPDIRECTORY', 'SONAR_ANALYSIS_TOKEN', 'SONAR_PROJECT_KEY', 'JAVA_HOME')) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "Missing required environment variable: $name"
    }
}
if ($env:BUILD_SOURCEBRANCH -ne 'refs/heads/main') {
    throw 'This Community Build pipeline only analyzes the main branch.'
}
if ($env:BUILD_BUILDID -notmatch '^\d+$' -or $env:SONAR_ANALYSIS_TOKEN -match '^\$\(') {
    throw 'Invalid build ID or missing secret variable sonarAnalysisToken.'
}

$source = $env:BUILD_SOURCESDIRECTORY
$app = Join-Path $source "sonar-app-$env:BUILD_BUILDID"
$token = $env:SONAR_ANALYSIS_TOKEN
Remove-Item Env:\SONAR_ANALYSIS_TOKEN
$env:PATH = "$env:ProgramFiles\Git\cmd;$env:ProgramFiles\dotnet;$env:JAVA_HOME\bin;$env:PATH"
$manifest = Join-Path $source '.config\dotnet-tools.json'
$reportPath = Join-Path $env:AGENT_TEMPDIRECTORY "sonar-$env:BUILD_BUILDID-$Target-report-task.txt"
if (Test-Path -LiteralPath $reportPath) {
    throw "SonarQube task report already exists: $reportPath"
}

function Invoke-Checked {
    param([string]$Description, [string[]]$Arguments)
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

if ($Target -eq 'App') {
    if (Test-Path -LiteralPath $app) {
        throw "Application directory already exists: $app"
    }
    & git clone --branch main 'https://github.com/IBIOHAZARDI/App---EAC-en-etapa-de-construcci-n-de-WS-RESTful-en-ASPNET.git' $app
    if ($LASTEXITCODE -ne 0) { throw "Application clone failed with exit code $LASTEXITCODE." }
    & git -C $app rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw "Cannot identify application revision: $LASTEXITCODE." }
    $base = $app
    $projects = @('VulnerableApi\VulnerableApi.csproj', 'VulnerableApi_Patched\VulnerableApi_Patched.csproj')
} else {
    $base = $source
    $projects = @('SecurityAsserts\SecurityAsserts.csproj')
}

Push-Location $source
try {
    Invoke-Checked 'Scanner tool restore' @('tool', 'restore', '--tool-manifest', $manifest)
    $scanner = @('tool', 'run', 'dotnet-sonarscanner', '--')
    Invoke-Checked 'SonarScanner begin' ($scanner + @(
        'begin', "/k:$env:SONAR_PROJECT_KEY",
        '/d:sonar.host.url=http://127.0.0.1:9000',
        "/d:sonar.token=$token",
        "/d:sonar.projectBaseDir=$base",
        "/d:sonar.scanner.metadataFilePath=$reportPath",
        '/d:sonar.scanner.scanAll=false',
        '/d:sonar.exclusions=**/bin/**,**/obj/**,**/TestResults/**'
    ))
    foreach ($project in $projects) {
        Invoke-Checked "Build $project" @('build', (Join-Path $base $project), '--configuration', 'Debug', '--no-incremental', '--nologo')
    }
    Invoke-Checked 'SonarScanner end' ($scanner + @('end', "/d:sonar.token=$token"))

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "SonarScanner did not create its task report: $reportPath"
    }
    $taskLine = @(Get-Content -LiteralPath $reportPath | Where-Object { $_ -match '^ceTaskId=' })
    if ($taskLine.Count -ne 1 -or $taskLine[0] -notmatch '^ceTaskId=([A-Za-z0-9_-]+)$') {
        throw 'Invalid SonarQube compute task ID.'
    }
    $taskId = $Matches[1]
    $headers = @{ Authorization = "Bearer $token" }
    $analysisId = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $task = Invoke-RestMethod -Uri "http://127.0.0.1:9000/api/ce/task?id=$taskId" -Headers $headers -TimeoutSec 10
        if ($task.task.status -eq 'SUCCESS') {
            $analysisId = $task.task.analysisId
            break
        }
        if ($task.task.status -in @('FAILED', 'CANCELED')) {
            throw "SonarQube compute task ended with status $($task.task.status)."
        }
        Start-Sleep -Seconds 5
    }
    if ([string]::IsNullOrWhiteSpace($analysisId) -or $analysisId -notmatch '^[A-Za-z0-9_-]+$') {
        throw 'SonarQube did not complete analysis within 300 seconds or returned an invalid analysis ID.'
    }
    $gate = Invoke-RestMethod -Uri "http://127.0.0.1:9000/api/qualitygates/project_status?analysisId=$analysisId" -Headers $headers -TimeoutSec 10
    if ($gate.projectStatus.status -notin @('OK', 'WARN', 'ERROR')) {
        throw "Unexpected SonarQube quality gate status: $($gate.projectStatus.status)"
    }
    Write-Host "SonarQube quality gate for ${Target}: $($gate.projectStatus.status)"
    if ($gate.projectStatus.status -ne 'OK') {
        Write-Warning "SonarQube quality gate for ${Target}: $($gate.projectStatus.status)."
    }
} finally {
    $headers = $null
    $token = $null
    Pop-Location
}
