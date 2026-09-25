<#
    Cuenta resultados Passed/Failed/Skipped por ID de assert (trait "Assert") a partir de los TRX
    en TestResults/, agrupando por escenario (A/B). El ID se deriva del nombre del método
    de test (p. ej. "A15_SSRF_..." -> "A15"), que es 1:1 con [Trait("Assert","A15")].
    Uso: pwsh reports/Get-AssertCountsFromTrx.ps1 -Fecha 2026-09-23
    Para una serie ejecutada detrás de HTTPS: añadir -TlsChecksApplicable
#>
param(
    [string]$Fecha = "2026-05-15",
    [switch]$TlsChecksApplicable
)

$resultsDir = Join-Path $PSScriptRoot "..\TestResults"
$trxFiles = Get-ChildItem $resultsDir -Filter "Scenario*_$Fecha.trx"

# assertId -> @{ A = @{Passed=0;Failed=0;Skipped=0}; B = @{Passed=0;Failed=0;Skipped=0} }
$counts = @{}

foreach ($file in $trxFiles) {
    $scenario = if ($file.Name -like "ScenarioA_*") { "A" } else { "B" }

    [xml]$xml = Get-Content $file.FullName
    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace("t", "http://microsoft.com/schemas/VisualStudio/TeamTest/2010")

    # testId -> nombre corto del método (sin namespace ni parámetros de InlineData)
    $methodByTestId = @{}
    foreach ($ut in $xml.SelectNodes("//t:TestDefinitions/t:UnitTest", $ns)) {
        $testId = $ut.id
        $methodName = $ut.TestMethod.name
        $methodByTestId[$testId] = $methodName
    }

    foreach ($res in $xml.SelectNodes("//t:Results/t:UnitTestResult", $ns)) {
        $methodName = $methodByTestId[$res.testId]
        if (-not $methodName) { continue }

        $assertId = ($methodName -split "_")[0]
        if (-not $counts.ContainsKey($assertId)) {
            $counts[$assertId] = @{ A = @{ Passed = 0; Failed = 0; Skipped = 0 }; B = @{ Passed = 0; Failed = 0; Skipped = 0 } }
        }

        # A10/C02 retornan temprano en el laboratorio HTTP local: no hay TLS que validar.
        if (-not $TlsChecksApplicable -and $assertId -in @("A10", "C02")) {
            $counts[$assertId][$scenario].Skipped++
            continue
        }

        if ($res.outcome -eq "Passed") {
            $counts[$assertId][$scenario].Passed++
        } elseif ($res.outcome -in @("Skipped", "NotExecuted")) {
            $counts[$assertId][$scenario].Skipped++
        } else {
            $counts[$assertId][$scenario].Failed++
        }
    }
}

$rows = foreach ($id in ($counts.Keys | Sort-Object)) {
    $a = $counts[$id].A
    $b = $counts[$id].B
    [PSCustomObject]@{
        Assert     = $id
        A_Passed   = $a.Passed
        A_Failed   = $a.Failed
        A_Skipped  = $a.Skipped
        A_Total    = $a.Passed + $a.Failed + $a.Skipped
        B_Passed   = $b.Passed
        B_Failed   = $b.Failed
        B_Skipped  = $b.Skipped
        B_Total    = $b.Passed + $b.Failed + $b.Skipped
    }
}

$rows | Format-Table -AutoSize
$rows | Export-Csv (Join-Path $PSScriptRoot "AssertCounts_TRX_$Fecha.csv") -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Total IDs distintos encontrados en TRX: $($rows.Count)"
Write-Host "Total ejecuciones Escenario A: $(($rows.A_Total | Measure-Object -Sum).Sum)"
Write-Host "Total ejecuciones Escenario B: $(($rows.B_Total | Measure-Object -Sum).Sum)"
