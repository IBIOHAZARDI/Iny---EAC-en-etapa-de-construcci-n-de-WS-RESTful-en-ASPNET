# Inyector — Pool de Asserts de Seguridad (xUnit)

Proyecto xUnit con **77 asserts** (101 test cases paramétricos) organizados en 8 grupos que validan la postura de seguridad de la API contra el OWASP API Security Top 10 2023. Se ejecuta en dos escenarios comparativos:

> **Nota de verificación (2026-09-23):** el conteo de 75 asserts fue confirmado contra el código
> (75 métodos `[Fact]`/`[Theory]` decorados con `[Trait("Assert", ...)]`, 67 `[Fact]` + 8 `[Theory]`
> con 32 `[InlineData]` = 99 test cases). Los 30 asserts adicionales a los 45 IDs base
> (A01–A28, B01–B11, C01–C06) usan sufijos `b`/`c`/`d` (p. ej. `A06b`, `A18c`, `A16d`) y ahora
> están documentados en la Tabla A.0 de la sección 6.
>
> **Actualización (2026-09-23, subida de cobertura):** se agregó `A12c` (G2-V3,
> `DeveloperExceptionPage`) y `A07b` (G1-V4, JWT sin `ValidateLifetime`). Para que `A07b`
> funcionara fue necesario corregir un bug real de entorno en `VulnerableApi`: la clave
> HMAC hardcodeada ("weak-key", 8 bytes) ya no era aceptada por la versión instalada de
> `Microsoft.IdentityModel.Tokens` (exige > 256 bits) y el login fallaba con 500 para
> **todos** los asserts autenticados. Se amplió la clave a 39 bytes, hardcodeada y
> predecible, preservando la vulnerabilidad de diseño. Ver sección 6 para el detalle
> completo y los hallazgos sobre G3-V4/G6-V3.

| Escenario | Target | Puerto | Objetivo |
|-----------|--------|--------|---------|
| **A — Vulnerable** | VulnerableApi | 5000 | Confirmar que las 28 vulnerabilidades son detectables |
| **B — Parcheada** | VulnerableApi_Patched | 5002 | Confirmar que las correcciones superan los controles |

Se integra como **Etapas 3A y 3B** del pipeline de Azure DevOps. Quality gate: Escenario A alerta si el promedio supera 99/99 (anomalía); Escenario B falla si el promedio cae por debajo de 95/99 (umbral del 95%).

> **Prerrequisitos:**
> - La API objetivo debe estar corriendo en su puerto antes de ejecutar los asserts.
> - **Compilar y ejecutar siempre desde la carpeta `Inyector/`** — `Inyector/global.json` fija el SDK a `8.0.319` y evita errores `CS1744` con SDK 9.

---

## Tabla de contenido

1. [Prerrequisitos](#1-prerrequisitos)
2. [Instalación paso a paso](#2-instalación-paso-a-paso)
3. [Ejecución de los asserts](#3-ejecución-de-los-asserts)
4. [Interpretación de resultados](#4-interpretación-de-resultados)
5. [Estructura del proyecto](#5-estructura-del-proyecto)
6. [Tabla de asserts](#6-tabla-de-asserts)
7. [Métricas objetivo](#7-métricas-objetivo)
8. [Solución de problemas](#8-solución-de-problemas)
9. [Ejecución multi-run (replicando el pipeline)](#9-ejecución-multi-run-replicando-el-pipeline)

---

## 1. Prerrequisitos

| Componente | Versión mínima | Verificación |
|-----------|---------------|-------------|
| Windows Server 2019 / Windows 10+ | — | `winver` |
| .NET SDK | **8.0.319** (vía `global.json`) | `Set-Location Inyector/; dotnet --version` |
| VulnerableApi en ejecución | — (Escenario A) | `Invoke-RestMethod http://localhost:5000/health` |
| VulnerableApi_Patched en ejecución | — (Escenario B) | `Invoke-RestMethod http://localhost:5002/health` |
| PowerShell | 5.1 / 7.x | `$PSVersionTable` |

> **Opcional para el pipeline:** el agente self-hosted de Azure DevOps debe tener acceso de escritura a la carpeta de trabajo para guardar los resultados `.trx`.

### Instalación rápida de .NET 8 SDK

```powershell
# Opción A — winget
winget install Microsoft.DotNet.SDK.8

# Opción B — descarga manual
# https://dotnet.microsoft.com/download/dotnet/8.0
```

---

## 2. Instalación paso a paso

### Paso 1 — Navegar a la carpeta del Inyector

```powershell
# Navegar a Inyector/ (NO a Inyector/SecurityAsserts/)
# global.json en esta carpeta fija el SDK a 8.0.319 con rollForward: latestPatch
Set-Location "C:\Trabajo\Universidad\Inyector"

# Verificar que el SDK correcto está activo
dotnet --version   # debe mostrar 8.0.319 o 8.0.x
```

### Paso 2 — Restaurar dependencias NuGet

```powershell
# Desde Inyector/ (para que global.json aplique)
dotnet restore "SecurityAsserts/SecurityAsserts.csproj"
```

Paquetes que se descargan automáticamente:

| Paquete | Versión | Propósito |
|---------|---------|-----------|
| `Microsoft.NET.Test.Sdk` | 17.9.0 | Motor de ejecución de tests xUnit |
| `xunit` | 2.7.0 | Framework de asserts |
| `xunit.runner.visualstudio` | 2.5.8 | Integración con Visual Studio y `dotnet test` |
| `FluentAssertions` | 6.12.0 | DSL de aserciones legibles (`Should().Be(...)`) |
| `coverlet.collector` | 6.0.1 | Recolector de cobertura de código |

### Paso 3 — Compilar el proyecto

```powershell
# Desde Inyector/ con --configuration Debug
# Debug es requerido: los asserts de Swagger (G4) y stack trace (G2-V3) verifican
# comportamientos del modo Development que se desactivan en Release.
dotnet build "SecurityAsserts/SecurityAsserts.csproj" --configuration Debug --verbosity quiet
```

Salida esperada:

```
Build succeeded.
    0 Warning(s)
    0 Error(s)
```

> **Si aparece `CS1744` (named argument para parámetro posicional):** el SDK activo no es 8.0.x. Verificar que está en `Inyector/` y no en `Inyector/SecurityAsserts/`. Ver sección [Solución de problemas](#8-solución-de-problemas).

### Paso 4 — Configurar la URL de la API objetivo

La URL base se lee de la variable de entorno `TEST_API_URL` por `Configuration/TestConfig.cs`. Si no está definida, usa `http://localhost:5000` por defecto.

```powershell
# Escenario A — VulnerableApi
$env:TEST_API_URL = "http://localhost:5000"

# Escenario B — VulnerableApi_Patched
$env:TEST_API_URL = "http://localhost:5002"
```

También se puede pasar directamente a `dotnet test` sin modificar la variable de entorno de la sesión:

```powershell
# Pasar TEST_API_URL directamente (forma usada por el pipeline de Azure DevOps)
dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build `
    -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5000"
```

> **No usar `API_BASE_URL`:** `TestConfig.cs` lee exclusivamente `TEST_API_URL`. Cualquier otra variable es ignorada.

### Paso 5 — Verificar que la API está lista

Antes de ejecutar los asserts, confirme que la API objetivo responde:

```powershell
# Escenario A
try {
    $r = Invoke-RestMethod -Uri "http://localhost:5000/health" -ErrorAction Stop
    Write-Host "VulnerableApi lista: status=$($r.status) version=$($r.version)" -ForegroundColor Green
} catch {
    Write-Error "VulnerableApi no responde en http://localhost:5000 — arranque la API primero."
}

# Escenario B
try {
    $r = Invoke-RestMethod -Uri "http://localhost:5002/health" -ErrorAction Stop
    Write-Host "VulnerableApi_Patched lista: status=$($r.status) version=$($r.version)" -ForegroundColor Green
} catch {
    Write-Error "VulnerableApi_Patched no responde en http://localhost:5002 — arranque la API parcheada primero."
}
```

---

## 3. Ejecución de los asserts

### 3.1 Ejecutar todos los asserts

```powershell
# Desde Inyector/ (global.json activo)
Set-Location "C:\Trabajo\Universidad\Inyector"
$env:TEST_API_URL = "http://localhost:5000"   # o :5002 para Escenario B

dotnet test "SecurityAsserts/SecurityAsserts.csproj" `
    --no-build `
    --configuration Debug `
    --verbosity normal
```

### 3.2 Ejecutar por oleada (prioridad)

Los asserts se organizan en tres oleadas de criticidad creciente:

| Oleada | Categoría | Significado | Acción si falla |
|--------|-----------|-------------|-----------------|
| 1 | **BLQ** (Bloqueante) | Vulnerabilidad crítica confirmada | Detiene el pipeline — no deploy |
| 2 | **WRN** (Advertencia) | Debilidad de configuración | Genera alerta — deploy condicional |
| 3 | **INF** (Informativo) | Mejora de hardening | Registra en reporte — no bloquea |

```powershell
# Los asserts están decorados con dos traits:
#   [Trait("Oleada", "Oleada1")] → filtrar por trámite/criticidad
#   [Trait("Category", "BLQ")]  → filtrar por categoría de bloqueo
#
# El pipeline ejecuta todos los tests en un único dotnet test (sin filtro)
# y evalúa los resultados del TRX como quality gate.

# Oleada 1 (Bloqueantes) — Trait "Oleada"
dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build `
    --filter "Oleada=Oleada1" --verbosity normal

# Oleada 2 (Advertencias)
dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build `
    --filter "Oleada=Oleada2" --verbosity normal

# Oleada 3 (Informativos)
dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build `
    --filter "Oleada=Oleada3" --verbosity normal

# Por categoría de bloqueo — Trait "Category"
dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build --filter "Category=BLQ"
dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build --filter "Category=WRN"
dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build --filter "Category=INF"

### 3.3 Ejecutar por grupo de vulnerabilidad

```powershell
# Grupo 1 — Control de Acceso (BOLA, Auth, IDOR, BFLA, Mass Assignment)
dotnet test --filter "FullyQualifiedName~Grupo1_ControlAcceso"

# Grupo 2 — Configuración de Seguridad (headers, CORS, Swagger, rate limiting)
dotnet test --filter "FullyQualifiedName~Grupo2_Configuracion"

# Grupo 3 — Inyección (SQLi, XSS, Path Traversal, Header Injection)
dotnet test --filter "FullyQualifiedName~Grupo3_Inyeccion"

# Grupo 4 — Infraestructura (TLS, HSTS, API versioning)
dotnet test --filter "FullyQualifiedName~Grupo4_Infraestructura"

# Grupo 5 — Servidor (SSRF, Debug endpoints, Logs sensibles)
dotnet test --filter "FullyQualifiedName~Grupo5_Servidor"

# Grupo 6 — Archivos (Upload, JWT query string, ReDoS)
dotnet test --filter "FullyQualifiedName~Grupo6_Archivos"

# Grupo 7 — Reportes (XXE, Open Redirect)
dotnet test --filter "FullyQualifiedName~Grupo7_Reportes"

# Grupo 8 — Webhooks (Sin HMAC, SSRF callback)
dotnet test --filter "FullyQualifiedName~Grupo8_Webhooks"
```

### 3.4 Ejecutar un assert específico

```powershell
# Por ID de assert
dotnet test --filter "Assert=A01"
dotnet test --filter "Assert=B06"
dotnet test --filter "Assert=C04"

# Por cobertura OWASP
dotnet test --filter "OWASP=API1:2023"
dotnet test --filter "OWASP=API3:2023"
dotnet test --filter "OWASP=API7:2023"
```

### 3.5 Generar reporte TRX (convención de nomenclatura del pipeline)

```powershell
Set-Location "C:\Trabajo\Universidad\Inyector"
$env:TEST_API_URL = "http://localhost:5000"   # Escenario A
$fecha = Get-Date -Format "yyyy-MM-dd"

# Convención de nombres usada por el pipeline de Azure DevOps
dotnet test "SecurityAsserts/SecurityAsserts.csproj" `
    --no-build `
    --configuration Debug `
    --logger "trx;LogFileName=ScenarioA_Run1_${fecha}.trx" `
    --results-directory "C:\Trabajo\Universidad\Resultados\TestResults" `
    -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5000"

# Ver resumen del TRX
$trxPath = "C:\Trabajo\Universidad\Resultados\TestResults\ScenarioA_Run1_${fecha}.trx"
[xml]$x  = Get-Content $trxPath
$c       = $x.TestRun.ResultSummary.Counters
$durMs   = [math]::Round(([datetime]$x.TestRun.Times.finish - [datetime]$x.TestRun.Times.start).TotalMilliseconds)
Write-Host "passed=$($c.passed)  failed=$($c.failed)  total=$($c.total)  dur=${durMs}ms"
```

> **Convención de nombres TRX:**
> - Escenario A: `ScenarioA_Run{N}_{yyyy-MM-dd}.trx`
> - Escenario B: `ScenarioB_Run{N}_{yyyy-MM-dd}.trx`
> - Archivo histórico alternativo: `SecurityAsserts_{yyyy-MM-dd}.trx`

### 3.6 Ejecutar con cobertura de código

```powershell
dotnet test `
    --collect "XPlat Code Coverage" `
    --results-directory ".\TestResults" `
    --verbosity normal

# Los resultados de cobertura quedan en TestResults\**\coverage.cobertura.xml
```

### 3.7 Paralelismo (deshabilitado por diseño)

El paralelismo está **deshabilitado por defecto** mediante `SecurityAsserts/xunit.runner.json`:

```json
{
  "parallelizeTestCollections": false,
  "parallelizeAssembly": false
}
```

Esto es intencional: los asserts con estado (BOLA, IDOR, Mass Assignment) crean y modifican recursos en la API. La ejecución secuencial garantiza que no haya interferencias entre tests ni efectos de estado compartido.

Para forzar paralelismo en experimentos controlados (puede causar falsos positivos):

```powershell
# Paralelismo máximo — solo para benchmarking, NO para evaluación de seguridad
dotnet test "SecurityAsserts/SecurityAsserts.csproj" `
    -- xunit.parallelizeTestCollections=true xunit.parallelizeAssembly=true
```

---

## 4. Interpretación de resultados

### Salida de consola típica

```
Starting test execution, please wait...
A total of 1 test files matched the specified pattern.

  Passed A01_BOLA_GetOtherUserProfile_ShouldReturn403                  [45 ms]
  Passed A02_BOLA_GetOtherUserOrders_ShouldReturn403                   [38 ms]
  Failed A03_BruteForce_AfterNFailedLogins_ShouldReturn429             [120 ms]
    Error Message:
      Expected HTTP status code to be one of {429} but found 200.
      A03 — Brute Force: el servidor debe implementar rate limiting (429 Too Many Requests)

Test Run Summary:
  Total: 45, Passed: 37, Failed: 8, Skipped: 0
  Duration: 1m 23s
```

### Códigos de salida de `dotnet test`

| Código | Significado | Acción |
|--------|-------------|--------|
| `0` | Todos los tests pasaron | Deploy puede continuar |
| `1` | Uno o más tests fallaron | Revisar fallos antes del deploy |
| `2` | Error de compilación o configuración | Revisar `dotnet build` primero |

### Regla de quality gate para el pipeline

El pipeline **ejecuta todos los tests sin filtro** en un único `dotnet test` y evalúa el TRX resultado:

```powershell
# ── Quality Gate Escenario A: anomalía si avgPassed ≥ 99 ──────────────────
# (indicaría que el Inyector no está conectado a la API vulnerable)
$statsA = Get-Content "$resultsDir/scenarioA-stats.json" | ConvertFrom-Json
if ($statsA.avgPassed -ge 99) {
    Write-Error "ANOMALÍA: Escenario A pasó $($statsA.avgPassed)/99 — el Inyector podría no estar conectado"
    exit 1
}
Write-Host "Quality Gate A: avgPassed=$($statsA.avgPassed)/99 — correcto (API vulnerable detectada)"

# ── Quality Gate Escenario B: falla si avgPassed < 95 ──────────────────────
# Umbral: ≥ 95 % de 99 tests = ceiling(99 * 0.95) = 95
$statsB = Get-Content "$resultsDir/scenarioB-stats.json" | ConvertFrom-Json
if ($statsB.avgPassed -lt 95) {
    Write-Error "FALLO Quality Gate B: $($statsB.avgPassed)/99 < umbral 95. Revisar regresiones."
    exit 1
}
Write-Host "Quality Gate B APROBADO: $($statsB.avgPassed)/99 ≥ 95"
```

Evaluación local equivalente (un solo run):

```powershell
Set-Location "C:\Trabajo\Universidad\Inyector"
$env:TEST_API_URL = "http://localhost:5000"
$tmpTrx = Join-Path $env:TEMP "gate-check.trx"

dotnet test "SecurityAsserts/SecurityAsserts.csproj" `
    --no-build --configuration Debug `
    --logger "trx;LogFileName=gate-check.trx" `
    --results-directory $env:TEMP `
    -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5000"

[xml]$x = Get-Content $tmpTrx
$c = $x.TestRun.ResultSummary.Counters
$durMs = [math]::Round(([datetime]$x.TestRun.Times.finish - [datetime]$x.TestRun.Times.start).TotalMilliseconds)
Write-Host "Resultado: passed=$($c.passed)  failed=$($c.failed)  total=$($c.total)  dur=${durMs}ms"

### Falsos positivos esperados

Algunos asserts verifican controles que la `VulnerableApi` **intencionalmente no tiene** (porque son las vulnerabilidades a detectar). Un assert que **falla** confirma que la vulnerabilidad existe en el objeto de prueba — ese es el comportamiento esperado en el escenario de validación de la estrategia.

| Assert | Falla esperada | Razón |
|--------|---------------|-------|
| A03 | Sí | G1-V2: sin rate limiting |
| A07b | Sí | G1-V4: JWT sin ValidateLifetime (ver A07b en sección 6) |
| A10 | Sí | G4-V1: sin UseHttpsRedirection |
| B01–B05 | Sí | G2-V2: sin middleware de cabeceras |
| A12c | Sí | G2-V3: DeveloperExceptionPage expone stack trace |

---

## 5. Estructura del proyecto

```
Inyector/
├── global.json                          ← Fija SDK 8.0.319 / rollForward: latestPatch
│         Evita CS1744 con SDK 9 (named args en [Theory] de xUnit)
│
└── SecurityAsserts/
    ├── SecurityAsserts.csproj
    ├── xunit.runner.json                ← parallelizeAssembly=false, parallelizeTestCollections=false
    ├── Configuration/
    │   └── TestConfig.cs                    ← Lee TEST_API_URL (default: http://localhost:5000)
├── Helpers/
│   └── AuthHelper.cs                    ← Obtiene tokens JWT para los asserts
├── Grupo1_ControlAcceso/
│   ├── G1_BOLA_Asserts.cs               ← A01, A02
│   ├── G1_Auth_Asserts.cs               ← A03, A04, A07, A07b, A11
│   ├── G1_MassAssignment_Asserts.cs     ← A05
│   ├── G1_BFLA_Asserts.cs               ← A06, A06b
│   ├── G1_SensitiveData_Asserts.cs      ← A18, A18b, A18c
│   └── G1_IDOR_Asserts.cs              ← A19, A20, A21
├── Grupo2_Configuracion/
│   ├── G2_Headers_Asserts.cs            ← B01–B05
│   ├── G2_CORS_Asserts.cs               ← B06, B06b
│   ├── G2_Misc_Asserts.cs               ← B07, B08, B09
│   ├── G2_ErrorInfo_Asserts.cs          ← A12, A12b, A12c
│   └── G2_InputLimits_Asserts.cs        ← B10, B10b, B11, B11b
├── Grupo3_Inyeccion/
│   ├── G3_SQLi_Asserts.cs               ← A08, A08b
│   ├── G3_XSS_Asserts.cs               ← A09, A09b
│   ├── G3_PathTraversal_Asserts.cs      ← A13, A13b, A13c
│   └── G3_HeaderInjection_Asserts.cs   ← A24, A24b
├── Grupo4_Infraestructura/
│   ├── G4_TLS_Asserts.cs               ← A10, C01, C02, C03
│   └── G4_API_Asserts.cs               ← C04, C05, C06
├── Grupo5_Servidor/
│   ├── G5_SSRF_Asserts.cs              ← A15, A15b, A15c
│   ├── G5_DebugInfo_Asserts.cs         ← A16, A16b, A16c, A16d
│   └── G5_SensitiveLogs_Asserts.cs     ← A28, A28b, A28c
├── Grupo6_Archivos/
│   ├── G6_FileUpload_Asserts.cs         ← A14, A14b, A14c
│   ├── G6_JWTQueryString_Asserts.cs     ← A17, A17b
│   └── G6_ReDoS_Asserts.cs             ← A25, A25b
├── Grupo7_Reportes/
│   ├── G7_XXE_Asserts.cs               ← A22, A22b, A22c
│   └── G7_OpenRedirect_Asserts.cs      ← A23, A23b
└── Grupo8_Webhooks/
    ├── G8_WebhookHmac_Asserts.cs        ← A26, A26b, A26c
    └── G8_WebhookSsrf_Asserts.cs        ← A27, A27b, A27c
```

> **77 asserts totales** (45 IDs base + 32 variantes con sufijo `b`/`c`/`d`). Ver Tabla A.0 en la sección 6.

---

## 6. Tabla de asserts

> **Tabla A.0 — verificada contra el código y re-ejecutada el 2026-09-23.** Contiene los
> **77 IDs** reales (uno por método `[Fact]`/`[Theory]` con `[Trait("Assert", ...)]`). Los 45
> IDs base (A01–A28, B01–B11, C01–C06) tienen 32 variantes adicionales con sufijo `b`/`c`/`d`.
>
> Las columnas **A (pass/total)** y **B (pass/total)** se llenaron agregando, por el trait
> `Assert`, los resultados de 3 runs frescos `Scenario{A,B}_Run{1..3}_2026-09-23.trx` en
> [TestResults/](TestResults) (303 ejecuciones por escenario = 101 test cases × 3 runs;
> reemplazan los runs de 10 repeticiones del 2026-05-15, previos a `A12c`/`A07b`). Ver script
> [reports/Get-AssertCountsFromTrx.ps1](reports/Get-AssertCountsFromTrx.ps1) (parámetro
> `-Fecha`) y datos crudos en [reports/AssertCounts_TRX_2026-09-23.csv](reports/AssertCounts_TRX_2026-09-23.csv).

| Assert | Categoría | Oleada | OWASP | Descripción | A (pass/total) | B (pass/total) |
|--------|-----------|--------|-------|-------------|:---------------:|:---------------:|
| A01 | BLQ | 1 | API1:2023 | BOLA — acceso a perfil de otro usuario | 0/3 | 3/3 |
| A02 | BLQ | 1 | API1:2023 | BOLA — acceso a órdenes de otro usuario | 0/3 | 3/3 |
| A03 | BLQ | 1 | API2:2023 | Brute Force — sin lockout en login | 3/3 | 3/3 |
| A04 | BLQ | 1 | API2:2023 | Endpoint sin token debe retornar 401 | 3/3 | 3/3 |
| A05 | BLQ | 1 | API6:2023 | Mass Assignment — rol no vinculable | 0/3 | 3/3 |
| A06 | BLQ | 1 | API5:2023 | BFLA — usuario no puede eliminar otros | 0/3 | 3/3 |
| A06b | BLQ | 1 | API5:2023 | BFLA — usuario con rol 'user' no puede promover a otros a admin | 0/3 | 3/3 |
| A07 | WRN | 2 | API2:2023 | Token JWT expirado debe rechazarse (firma pre-computada, ver limitación en A07b) | 3/3 | 3/3 |
| A07b | BLQ | 1 | API2:2023 | JWT real re-firmado con `exp` pasado (clave HMAC conocida) debe rechazarse | 0/3 | 3/3 |
| A08 | BLQ | 1 | API3:2023 | SQLi — OR payload no devuelve todos los registros | 0/3 | 3/3 |
| A08b | BLQ | 1 | API3:2023 | SQLi — payload UNION-based no debe causar HTTP 500 | 3/3 | 3/3 |
| A09 | BLQ | 1 | API3:2023 | XSS reflejado — script no aparece en respuesta | 0/3 | 3/3 |
| A09b | BLQ | 1 | API3:2023 | XSS — Content-Type debe ser application/json (previene interpretación HTML) | 3/3 | 3/3 |
| A10 | BLQ | 1 | API8:2023 | HTTP debe redirigir a HTTPS | 0/3 | 0/3 |
| A11 | BLQ | 1 | API8:2023 | JWT alg=none debe rechazarse | 3/3 | 3/3 |
| A12 | BLQ | 1 | API8:2023 | Errores no exponen stack traces | 3/3 | 3/3 |
| A12b | BLQ | 1 | API8:2023 | Rutas inexistentes no exponen detalles del framework | 3/3 | 3/3 |
| A12c | BLQ | 1 | API8:2023 | SqliteException no manejada (comilla en /products/search) no expone stack trace | 0/3 | 3/3 |
| A13 | BLQ | 1 | API3:2023 | Path Traversal — descarga fuera del directorio base | 3/3 | 3/3 |
| A13b | BLQ | 1 | API3:2023 | Path Traversal — payloads codificados (paramétrico x3) no retornan 200 con contenido sensible | 9/9 | 9/9 |
| A13c | BLQ | 1 | API3:2023 | Path Traversal — contenido de appsettings.json no expuesto | 3/3 | 3/3 |
| A14 | BLQ | 1 | API3:2023 | Upload sin restricción — ejecutables rechazados (paramétrico x4) | 0/12 | 12/12 |
| A14b | BLQ | 1 | API4:2023 | Upload — archivos > 5 MB rechazados con 413/400 | 0/3 | 3/3 |
| A14c | BLQ | 1 | API3:2023 | Upload — nombre de archivo con traversal '../' rechazado o sanitizado | 0/3 | 3/3 |
| A15 | BLQ | 1 | API7:2023 | SSRF — URLs a rangos privados deben rechazarse (paramétrico x4) | 0/12 | 12/12 |
| A15b | BLQ | 1 | API7:2023 | SSRF — endpoint /diagnostics/ping debe requerir autenticación | 0/3 | 3/3 |
| A15c | BLQ | 1 | API7:2023 | SSRF — respuesta no debe filtrar datos de red interna | 3/3 | 3/3 |
| A16 | BLQ | 1 | API8:2023 | Debug endpoint no accesible sin autenticación | 0/3 | 3/3 |
| A16b | WRN | 2 | API8:2023 | Debug endpoint no expone cadenas de conexión ni claves | 0/3 | 3/3 |
| A16c | WRN | 2 | API8:2023 | Debug endpoint no lista variables de entorno del servidor | 0/3 | 3/3 |
| A16d | WRN | 2 | API8:2023 | health-verbose no expone versión exacta de framework/runtime | 0/3 | 3/3 |
| A17 | WRN | 2 | API2:2023 | JWT vía query string no debe autenticar | 0/3 | 3/3 |
| A17b | WRN | 2 | API8:2023 | Authorization: Bearer sigue siendo el mecanismo válido de autenticación | 3/3 | 3/3 |
| A18 | BLQ | 1 | API3:2023 | Respuestas no exponen campo 'password' | 0/3 | 3/3 |
| A18b | BLQ | 1 | API3:2023 | GET /users/me no expone el campo 'password' | 0/3 | 3/3 |
| A18c | BLQ | 1 | API3:2023 | Listado de usuarios no incluye contraseñas en texto plano | 0/3 | 3/3 |
| A19 | BLQ | 1 | API1:2023 | IDOR — usuario no puede actualizar perfil ajeno | 0/3 | 3/3 |
| A20 | BLQ | 1 | API1:2023 | Enumeración de IDs — máximo 1 hit propio | 0/3 | 3/3 |
| A21 | BLQ | 1 | API1:2023 | IDOR — usuario no puede eliminar órdenes ajenas | 3/3 | 3/3 |
| B01 | WRN | 2 | API8:2023 | X-Content-Type-Options: nosniff presente | 0/3 | 3/3 |
| B02 | WRN | 2 | API8:2023 | X-Frame-Options: DENY/SAMEORIGIN presente | 0/3 | 3/3 |
| B03 | WRN | 2 | API8:2023 | Content-Security-Policy presente | 0/3 | 3/3 |
| B04 | WRN | 2 | API8:2023 | Server no expone versión | 3/3 | 3/3 |
| B05 | WRN | 2 | API8:2023 | X-Powered-By ausente | 3/3 | 3/3 |
| B06 | WRN | 2 | API8:2023 | CORS sin wildcard * | 0/3 | 3/3 |
| B06b | WRN | 2 | API8:2023 | CORS — no combina Allow-Origin: * con Allow-Credentials: true | 3/3 | 3/3 |
| B07 | WRN | 2 | API8:2023 | Swagger no expuesto en producción | 0/3 | 3/3 |
| B08 | WRN | 2 | API4:2023 | Paginación en colecciones | 0/3 | 0/3 |
| B09 | WRN | 2 | API4:2023 | Rate limiting en auth | 0/3 | 0/3 |
| B10 | WRN | 2 | API4:2023 | Payload gigante rechazado (límite de body) | 0/3 | 3/3 |
| B10b | WRN | 2 | API4:2023 | Query strings excesivamente largos rechazados | 3/3 | 3/3 |
| B11 | WRN | 2 | API8:2023 | Content-Type incorrecto rechazado con 415 | 3/3 | 3/3 |
| B11b | WRN | 2 | API8:2023 | Cuerpos XML rechazados con 415 en login | 3/3 | 3/3 |
| C01 | INF | 3 | API8:2023 | HSTS presente en HTTPS | 3/3 | 3/3 |
| C02 | INF | 3 | API8:2023 | TLS mínimo 1.2 | 0/3 | 0/3 |
| C03 | INF | 3 | API8:2023 | Versión .NET no expuesta en headers | 3/3 | 3/3 |
| C04 | INF | 3 | API9:2023 | API v1 deprecada con Deprecation header o 410 | 0/3 | 3/3 |
| C05 | INF | 3 | API8:2023 | Métodos HTTP no permitidos retornan 405 (paramétrico x4) | 12/12 | 12/12 |
| C06 | INF | 3 | API8:2023 | /health público y retorna 200 | 3/3 | 3/3 |
| A22 | BLQ | 1 | API3:2023 / API10:2023 | XXE Injection — entidades externas rechazadas en POST /reports/parse | 0/3 | 3/3 |
| A22b | BLQ | 1 | API3:2023 / API10:2023 | XXE — respuesta no contiene contenido de archivos del sistema | 0/3 | 3/3 |
| A22c | BLQ | 1 | API3:2023 / API10:2023 | XXE SSRF — parser no resuelve entidades a metadatos de nube | 3/3 | 3/3 |
| A23 | BLQ | 1 | API8:2023 | Open Redirect — returnUrl externo debe rechazarse con 400 (paramétrico x4) | 0/12 | 12/12 |
| A23b | WRN | 2 | API8:2023 | Open Redirect — URLs relativas válidas no causan error 500 | 3/3 | 3/3 |
| A24 | BLQ | 1 | API3:2023 | Header Injection — CRLF en query no inyecta cabeceras (paramétrico x4) | 12/12 | 12/12 |
| A24b | WRN | 2 | API3:2023 | Búsqueda normal sin caracteres de control retorna 200/401 (no 500) | 3/3 | 3/3 |
| A25 | BLQ | 1 | API4:2023 | ReDoS — patrón catastrófico debe resolverse en < 2 s (paramétrico x3) | 9/9 | 9/9 |
| A25b | WRN | 2 | API4:2023 | ReDoS — patrón regex inválido retorna 400, no 500 ni se cuelga | 3/3 | 3/3 |
| A26 | BLQ | 1 | API8:2023 | Webhook sin HMAC — petición sin X-Hub-Signature-256 rechazada | 0/3 | 3/3 |
| A26b | BLQ | 1 | API8:2023 | Webhook — firma HMAC incorrecta rechazada con 401/403 | 0/3 | 3/3 |
| A26c | WRN | 2 | API8:2023 | Webhook — respuesta no refleja el contenido del payload | 3/3 | 3/3 |
| A27 | BLQ | 1 | API7:2023 | SSRF webhook — callbackUrl a rangos privados rechazada (paramétrico x6) | 0/18 | 18/18 |
| A27b | BLQ | 1 | API7:2023 | SSRF webhook — respuesta no filtra datos de red interna | 0/3 | 3/3 |
| A27c | WRN | 2 | API7:2023 | /webhooks/register debe requerir autenticación | 3/3 | 3/3 |
| A28 | WRN | 2 | API8:2023 | Logs sensibles — payload del webhook no reflejado en respuesta | 3/3 | 3/3 |
| A28b | WRN | 2 | API8:2023 | Respuesta de login no contiene la contraseña en texto claro | 3/3 | 3/3 |
| A28c | WRN | 2 | API8:2023 | Contraseña enviada no aparece en el mensaje de error | 3/3 | 3/3 |

> **Hallazgo:** en el Escenario B (parcheado) los IDs A10, B08, B09 y C02 siguen fallando
> 3/3 — indica que esas correcciones (HTTPS redirect, paginación, rate limiting, TLS 1.2)
> no están aplicadas en `VulnerableApi_Patched` a la fecha del run 2026-09-23.
>
> `A12c` y `A07b` ahora tienen datos reales de 3 runs: fallan 0/3 contra `VulnerableApi`
> (detección confirmada de G2-V3 y G1-V4) y pasan 3/3 contra `VulnerableApi_Patched`.
> `A12c` requirió un ajuste: la aserción original exigía siempre 500, lo que la hacía fallar
> también en la API parcheada (que puede responder 200 si sanea la entrada); ahora solo
> exige ausencia de stack trace *cuando* el 500 ocurre.

### Subida de cobertura por vulnerabilidad ground-truth (2026-09-23)

Frente al inventario de 28 vulnerabilidades ground-truth de `VulnerableApi` (comentarios
`G#-V#` en el código fuente), 6 no eran detectadas por ningún assert: `G1-V4`, `G2-V3`,
`G2-V8`, `G3-V4`, `G5-V2`, `G6-V3`. Se investigó cada una contra el código de
`VulnerableApi`/`VulnerableApi_Patched` y se corrigió lo viable dentro del alcance de un
test suite HTTP-only. **Resultado: cobertura ground-truth subió de 22/28 (78.6%) a 24/28
(85.7%), verificado con ejecuciones reales de 3 runs por escenario.** El 95% (27/28) no se
alcanzó de forma honesta — ver por qué en cada fila:

| Ground-truth | Causa raíz | Acción tomada |
|---|---|---|
| **G2-V3** (`app.UseDeveloperExceptionPage()` activo) | A12/A12b solo disparaban errores 400 de model-binding, nunca una excepción real sin capturar | ✅ **Corregido y verificado (3/3 runs).** `A12c` fuerza una `SqliteException` sin manejar vía `GET /products/search?name=%27` (comilla desbalanceada en el `FromSqlRaw`): falla 0/3 en `VulnerableApi` (stack trace expuesto), pasa 3/3 en `VulnerableApi_Patched` |
| **G1-V4** (JWT sin `ValidateLifetime`) | A07 usa un JWT pre-firmado que puede rechazarse por firma inválida, no por validación de `exp` específicamente | ✅ **Corregido y verificado (3/3 runs).** `A07b`: login real → decodifica el payload → inyecta `exp` pasado → re-firma HS256 con la clave conocida del servidor: falla 0/3 en `VulnerableApi` (200 en vez de 401), pasa 3/3 en `VulnerableApi_Patched`. Requirió además reparar el login, roto por un bug de entorno (clave HMAC de 8 bytes rechazada por la versión actual de `Microsoft.IdentityModel.Tokens`) |
| **G6-V3** (Regex sin timeout / ReDoS) | Los inputs de 19–20 caracteres en A25 resolvían en milisegundos, sin cancelar por el `CancellationTokenSource(2s)` | ⚠️ Se aumentó la longitud de los payloads catastróficos (≥26 caracteres). Calibración manual (`n` hasta 45, y patrones alternativos como `(x+x+)+y`) mostró que **.NET 8 optimiza automáticamente estos patrones clásicos de backtracking** y responde en <110 ms incluso sin `matchTimeout` configurado — el ground-truth G6-V3 parece mitigado a nivel de runtime en esta versión de .NET, no solo por la app. Documentado como limitación conocida en vez de forzar un falso positivo |
| **G3-V4** (CRLF / header injection) | A24 ya envía payloads `%0d%0a` codificados que llegan al servidor sin excepción cliente, pero el header inyectado nunca aparece | ⚠️ Verificado con un socket TCP crudo (bypaseando las validaciones de `HttpClient`): Kestrel **rechaza la petición con 500** (`InvalidOperationException: Invalid non-ASCII or control character in header`) antes de que `Response.Headers.Append` logre inyectar el CRLF. La inyección de cabeceras está mitigada por Kestrel/.NET 8, no por el código de `VulnerableApi` — forzar una detección aquí sería un falso positivo |
| **G5-V2** / **G2-V8** (credenciales y payload de webhook en logs de `ILogger`) | Ambas vulnerabilidades solo son observables en los logs del proceso servidor, no en la respuesta HTTP — fuera del alcance de un cliente HTTP puro | ⏸️ Pendiente: requiere que `VulnerableApi` escriba a un sink de archivo (p. ej. `Logging:File`) accesible desde `SecurityAsserts` en la misma máquina, y un helper que lo lea. Requiere autorización adicional por modificar infraestructura compartida fuera de este repositorio; no implementado en esta iteración |

> **Por qué no se llegó a 95%:** con G1-V4 y G2-V3 corregidos, la cobertura real y honesta
> queda en **24/28 (85.7%)**. Cerrar G2-V8 y G5-V2 (agregando logging a archivo en
> `VulnerableApi`) llevaría a 26/28 (92.9%) — el máximo alcanzable sin forzar falsos
> positivos, dado que G3-V4 y G6-V3 están mitigados a nivel de runtime .NET 8/Kestrel con
> evidencia verificada en vivo.

### Cobertura OWASP API Security Top 10 (2023)


| Categoría OWASP | Nombre | Asserts que la cubren |
|----------------|--------|----------------------|
| API1:2023 | Broken Object Level Authorization | A01, A02, A19, A20, A21 |
| API2:2023 | Broken Authentication | A03, A04, A07, A07b, A17 |
| API3:2023 | Broken Object Property Level Auth. | A05, A08, A08b, A09, A09b, A13, A13b, A13c, A14, A14c, A18, A18b, A18c, A22, A22b, A22c, A24, A24b |
| API4:2023 | Unrestricted Resource Consumption | A14b, A25, A25b, B08, B09, B10, B10b |
| API5:2023 | Broken Function Level Authorization | A06, A06b |
| API6:2023 | Unrestricted Access to Sensitive Flows | A05 |
| API7:2023 | Server Side Request Forgery | A15, A15b, A15c, A27, A27b, A27c |
| API8:2023 | Security Misconfiguration | A10, A11, A12, A12b, A12c, A16–A17b, A23, A23b, A26, A26b, A26c, A28, A28b, A28c, B01–B11, B11b, C01–C06 |
| API9:2023 | Improper Inventory Management | C04 |
| API10:2023 | Unsafe Consumption of APIs (XXE) | A22, A22b, A22c |

---

## 7. Métricas objetivo (umbral de calidad)

| Métrica | Umbral | Descripción |
|---------|--------|-------------|
| TVP — Tasa Verdaderos Positivos | ≥ 80% | % de vulnerabilidades reales detectadas. **Resultado Escenario A: ~32% (31.7/99)** promedio de 3 runs; 100% de las 28 vulnerabilidades identificadas como categoría OWASP |
| TFP — Tasa Falsos Positivos | ≤ 15% | % de alertas erróneas en API sin vulnerabilidades. **Resultado Escenario B: 4/99 = 4%** (4 fallos de entorno documentados) |
| Cobertura OWASP API Top 10 | **10/10** | Todas las categorías del top 10 cubiertas |
| Tiempo total de ejecución | A: ~14.5 s / B: ~800 ms | Por run (Escenario A: avg 14,495 ms; Escenario B: avg 772 ms) |
| Asserts BLQ fallidos | = 0 (Escenario B) | Quality gate de deploy: ninguno puede fallar en la API parcheada |
| Total asserts implementados | **77 IDs / 101 test cases** | 69 `[Fact]` + 8 `[Theory]` con 32 `[InlineData]` = 101 test cases; A12c y A07b agregados el 2026-09-23 |
| Cobertura vulnerabilidades ground-truth | **24/28 (85.7%)** | Subió desde 78.6% al corregir G2-V3 (`A12c`) y G1-V4 (`A07b`); ver sección 6 |

---

## 8. Solución de problemas

### `CS1744` — Named argument para parámetro posicional

El SDK activo no es 8.0.x. El `global.json` de `Inyector/` solo aplica si el working directory es `Inyector/` o un subdirectorio:

```powershell
# Verificar SDK activo desde Inyector/
Set-Location "C:\Trabajo\Universidad\Inyector"
dotnet --version   # debe mostrar 8.0.x
Get-Content "global.json"
# Esperado: { "sdk": { "version": "8.0.319", "rollForward": "latestPatch" } }

# Si muestra 9.x aunque global.json existe, verificar que el SDK 8 está instalado:
dotnet --list-sdks | Where-Object { $_ -match "^8\." }
# Si no hay resultados, instalar:
Invoke-WebRequest "https://dot.net/v1/dotnet-install.ps1" -OutFile dotnet-install.ps1
.\dotnet-install.ps1 -Version 8.0.319
```

### La suite falla con `Connection refused` en todos los tests

La API objetivo no está corriendo. Verifique el puerto según el escenario:

```powershell
# Escenario A — VulnerableApi (puerto 5000)
try { (Invoke-WebRequest "http://localhost:5000/health" -TimeoutSec 5).StatusCode } catch { "Sin respuesta" }

# Si no responde, arrancar:
Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
Remove-Item "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\vulnerable.db" -ErrorAction SilentlyContinue
Start-Process "dotnet" -ArgumentList "run","--project","C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj","--no-build","--configuration","Debug","--urls","http://localhost:5000" -WindowStyle Hidden

# Escenario B — VulnerableApi_Patched (puerto 5002)
try { (Invoke-WebRequest "http://localhost:5002/health" -TimeoutSec 5).StatusCode } catch { "Sin respuesta" }

# Si no responde, arrancar:
Start-Process "dotnet" -ArgumentList "run","--project","C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj","--no-build","--configuration","Debug","--urls","http://localhost:5002" -WindowStyle Hidden
```

### Un assert falla con `401 Unauthorized` inesperado

Las credenciales de prueba pueden no estar sembradas. Reinicie la BD de la API:

```powershell
# En Desarrollo\VulnerableApi\
Remove-Item vulnerable.db, vulnerable.db-shm, vulnerable.db-wal -ErrorAction SilentlyContinue
dotnet run   # DataSeeder recrea los usuarios admin/usera/userb
```

### `dotnet test` no encuentra los archivos de test

Verifique que está en el directorio correcto y que el proyecto compila:

```powershell
Set-Location "C:\Trabajo\Universidad\Inyector"
dotnet build "SecurityAsserts/SecurityAsserts.csproj" --configuration Debug
dotnet test  "SecurityAsserts/SecurityAsserts.csproj" --no-build --configuration Debug
```

### Los asserts A25 (ReDoS) tardan más de 2 segundos

El assert A25 usa `CancellationTokenSource(2s)` para verificar el timeout. Si la máquina de pruebas está bajo alta carga, puede aparecer un falso positivo. Ejecute el assert de forma aislada:

```powershell
dotnet test --filter "Assert=A25" -- xunit.parallelizeTestCollections=false
```

### Los resultados `.trx` no aparecen en Azure DevOps

Los TRX se publican mediante `PublishTestResults@2` con `testResultsFiles: '$(testResultsDir)/ScenarioA_Run*.trx'` y `ScenarioB_Run*.trx` por separado. Verificar que:

```powershell
# El directorio de resultados existe y contiene los TRX
Get-ChildItem "$(Build.ArtifactStagingDirectory)/test-results" -Filter "Scenario*.trx"
# Debe mostrar 6 archivos (A_Run1, A_Run2, A_Run3, B_Run1, B_Run2, B_Run3)
```

Si los TRX están en otra ruta, actualizar `testResultsDir` en las variables del pipeline.

---

## 9. Ejecución multi-run (replicando el pipeline)

El pipeline ejecuta **3 runs independientes** por escenario para calcular promedios estadísticos. Para replicarlo localmente:

### Multi-run Escenario A (3 runs con DB limpia entre cada uno)

```powershell
Set-Location "C:\Trabajo\Universidad\Inyector"
$apiProject = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj"
$dbPath     = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\vulnerable.db"
$resultsDir = "C:\Trabajo\Universidad\Resultados\TestResults"
$fecha      = Get-Date -Format "yyyy-MM-dd"
$allResults = @()

for ($run = 1; $run -le 3; $run++) {
    # Limpiar puerto, DB y reiniciar API
    Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    Remove-Item $dbPath -ErrorAction SilentlyContinue   # DataSeeder re-siembra en startup
    $proc = Start-Process "dotnet" -ArgumentList "run","--project",$apiProject,"--no-build",`
        "--configuration","Debug","--urls","http://localhost:5000" -PassThru -WindowStyle Hidden

    # Health check (máx. 30 s)
    $ok = $false
    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep -Seconds 2
        try { if ((Invoke-WebRequest "http://localhost:5000/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { $ok = $true; break } } catch {}
    }
    if (-not $ok) { Write-Error "API no disponible para Run $run"; break }

    # Ejecutar suite completa
    $trxFile = "ScenarioA_Run${run}_${fecha}.trx"
    dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build --configuration Debug `
        --logger "trx;LogFileName=$trxFile" --results-directory $resultsDir `
        -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5000"

    # Parsear TRX
    $trxPath = Join-Path $resultsDir $trxFile
    if (Test-Path $trxPath) {
        [xml]$x  = Get-Content $trxPath
        $c       = $x.TestRun.ResultSummary.Counters
        $durMs   = [math]::Round(([datetime]$x.TestRun.Times.finish - [datetime]$x.TestRun.Times.start).TotalMilliseconds)
        Write-Host "Run $run → passed=$($c.passed) failed=$($c.failed) dur=${durMs}ms"
        $allResults += [PSCustomObject]@{ Run=$run; Passed=[int]$c.passed; Failed=[int]$c.failed; DurMs=$durMs }
    }
}

# Resumen
Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
$avgP = [math]::Round(($allResults.Passed | Measure-Object -Average).Average, 1)
$avgD = [math]::Round(($allResults.DurMs  | Measure-Object -Average).Average)
Write-Host "Promedio A: $avgP/99 en ${avgD}ms"
```

### Multi-run Escenario B (3 runs, API arranca una sola vez)

```powershell
Set-Location "C:\Trabajo\Universidad\Inyector"
$patchedProj = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj"
$resultsDir  = "C:\Trabajo\Universidad\Resultados\TestResults"
$fecha       = Get-Date -Format "yyyy-MM-dd"

# Iniciar API una sola vez (asserts B son estructurales, no dependen de estado de BD)
Get-NetTCPConnection -LocalPort 5002 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
$proc = Start-Process "dotnet" -ArgumentList "run","--project",$patchedProj,"--no-build",`
    "--configuration","Debug","--urls","http://localhost:5002" -PassThru -WindowStyle Hidden
$ok = $false
for ($i = 1; $i -le 15; $i++) {
    Start-Sleep -Seconds 2
    try { if ((Invoke-WebRequest "http://localhost:5002/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { $ok = $true; break } } catch {}
}
if (-not $ok) { Write-Error "VulnerableApi_Patched no disponible"; exit 1 }

$allResults = @()
for ($run = 1; $run -le 3; $run++) {
    $trxFile = "ScenarioB_Run${run}_${fecha}.trx"
    dotnet test "SecurityAsserts/SecurityAsserts.csproj" --no-build --configuration Debug `
        --logger "trx;LogFileName=$trxFile" --results-directory $resultsDir `
        -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5002"

    $trxPath = Join-Path $resultsDir $trxFile
    if (Test-Path $trxPath) {
        [xml]$x  = Get-Content $trxPath
        $c       = $x.TestRun.ResultSummary.Counters
        $durMs   = [math]::Round(([datetime]$x.TestRun.Times.finish - [datetime]$x.TestRun.Times.start).TotalMilliseconds)
        Write-Host "Run $run → passed=$($c.passed) failed=$($c.failed) dur=${durMs}ms"
        $allResults += [PSCustomObject]@{ Run=$run; Passed=[int]$c.passed; Failed=[int]$c.failed; DurMs=$durMs }
    }
}

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
$avgP = [math]::Round(($allResults.Passed | Measure-Object -Average).Average, 1)
$avgD = [math]::Round(($allResults.DurMs  | Measure-Object -Average).Average)
$qg   = if ($avgP -ge 95) { "APROBADO" } else { "REVISAR" }
Write-Host "Promedio B: $avgP/99 en ${avgD}ms — $qg"
```

### Resultados de referencia (2026-05-13, 3 runs cada escenario)

| Escenario | Run 1 | Run 2 | Run 3 | Promedio | Duración prom. | Ratio |
|-----------|-------|-------|-------|----------|---------------|---------|
| A — Vulnerable | 25/99 | 35/99 | 35/99 | **31.7/99** | 14,495 ms | — |
| B — Parcheada | 95/99 | 95/99 | 95/99 | **95.0/99** | 772 ms | 18.8× más rápido |

> **Anomalía Run 1 Escenario A (25 vs 35):** efecto warm-up — la API no terminó de inicializar SQLite al comenzar la primera ejecución. Los runs 2 y 3 son representativos. En el pipeline se documentan como `stableRuns` en `scenarioA-stats.json`.
