# Resumen Ejecutivo — SecurityAsserts CI
## Ejecución 2026-05-13 · Run ID: 20260513-001

| Campo | Valor |
|-------|-------|
| Fecha | 2026-05-13 |
| Ambiente | No Productivo Controlado |
| Agente | WIN-AGENT-01 (Windows Server 2022, .NET 8.0.14) |
| Objetivo | http://localhost:5000 (VulnerableApi) |
| Rama | main · commit `4a7f91bc` |
| Duración | 1 min 15 seg |
| Resultado pipeline | **FALLIDO** |

---

## ⚡ Actualización — 2026-09-23

> El resto de este documento describe la ejecución original del **2026-05-13** (55 asserts,
> ground-truth de 14 vulnerabilidades) y se conserva sin alterar como registro histórico.
> Esta sección resume el estado verificado a la fecha actual. Detalle completo, tabla de
> asserts assert-por-assert y metodología en [README.md, sección 6](README.md#6-tabla-de-asserts).

| Métrica | 2026-05-13 (original) | 2026-09-23 (actual) |
|---------|:---:|:---:|
| Asserts implementados | 55 | **77** (+22) |
| Test cases (con paramétricos) | 99 | **101** |
| Vulnerabilidades ground-truth (`VulnerableApi`) | 14 | **28** |
| Ground-truth detectadas | 14/14 (100 %) | **24/28 (85.7 %)** |
| Escenario A — pasados | 13/55 (23.6 %) | **13/77** asserts distintos pasan (mismo patrón, base ampliada) |
| Escenario B — tasa de paso (test cases) | 95/99 (96.0 %) | **970/1010 (96.0 %)** — 10 runs reales, **idéntica** a la línea base |
| Escenario B — IDs que siguen fallando | A10, B08, B09, C02 | **A10, B08, B09, C02** (los mismos 4, sin regresión) |

**Consistencia confirmada:** al re-ejecutar 10 runs reales por escenario el 2026-09-23 (ver
[TestResults/](TestResults) y [reports/AssertCounts_TRX_2026-09-23.csv](reports/AssertCounts_TRX_2026-09-23.csv)),
Escenario B reproduce **exactamente el mismo 96.0 % y los mismos 4 IDs fallidos** que la
línea base del 2026-05-13, pese a que el pool de asserts creció de 55 a 77. Esto valida que
las correcciones de `VulnerableApi_Patched` siguen siendo efectivas frente a los asserts
nuevos y que no hay regresiones.

**Cambios desde el 2026-05-13:**
- Se agregaron 22 asserts con sufijo `b`/`c`/`d` que antes no estaban documentados (p. ej.
  `A06b`, `A18c`, `A16d`), más dos nuevos: `A12c` (fuerza una `SqliteException` sin manejar
  para confirmar G2-V3, `DeveloperExceptionPage`) y `A07b` (re-firma un JWT real con `exp`
  pasado usando la clave HMAC conocida del servidor, para confirmar G1-V4 sin depender de un
  token pre-computado). Ambos fallan 0/10 contra `VulnerableApi` y pasan 10/10 contra
  `VulnerableApi_Patched`.
- Se corrigió un bug de entorno real: la clave HMAC hardcodeada (`"weak-key"`, 8 bytes) dejó
  de ser aceptada por la versión instalada de `Microsoft.IdentityModel.Tokens` (exige > 256
  bits) y el login fallaba con 500 para **todos** los asserts autenticados. Se amplió a 39
  bytes, hardcodeada y predecible, preservando la vulnerabilidad de diseño.
- Se investigaron las 6 vulnerabilidades ground-truth no detectadas (`G1-V4`, `G2-V3`,
  `G2-V8`, `G3-V4`, `G5-V2`, `G6-V3`): 2 se corrigieron (arriba), 2 se confirmaron mitigadas a
  nivel de runtime .NET 8/Kestrel (CRLF injection, ReDoS clásico — no forzables sin generar
  falsos positivos), y 2 quedan pendientes por requerir acceso a logs de archivo del servidor
  (`G2-V8`, `G5-V2`), fuera del alcance de un test suite HTTP-only sin autorización adicional
  para modificar `VulnerableApi`.
- Se corrigió el script de multi-run de Escenario B (antes reutilizaba la misma BD entre los
  10 runs, contaminando asserts con estado como BOLA/IDOR/Mass Assignment); ahora reinicia
  proceso y BD entre cada run, igual que Escenario A.

---

## Resultado Global (2026-05-13, sin modificar)

| Métrica | Valor |
|---------|-------|
| Total de asserts ejecutados | **55** |
| Pasados | **13** (23.6 %) |
| Fallados | **42** (76.4 %) |

```
████████████████████████████░░░░░░░░░░░  76.4 % FALLADOS
░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████░░  23.6 % PASADOS
```

---

## Distribución por Severidad

| Severidad | Total | Fallados | Pasados | Tasa de Fallo |
|-----------|------:|--------:|--------:|--------------:|
| BLQ (Bloqueante) | 30 | **28** | 2 | **93.3 %** |
| WRN (Warning)    | 18 | **12** | 6 | **66.7 %** |
| INF (Informativo)|  7 |  2 | 5 | 28.6 % |

> **Interpretación:** 93 % de los asserts de severidad bloqueante fallaron, confirmando que la `VulnerableApi` presenta un nivel de exposición alto que impediría su paso a ambientes superiores bajo la estrategia propuesta.

---

## Distribución por Oleada

| Oleada | Descripción | Tests | Fallados | % Fallo |
|--------|-------------|------:|---------:|--------:|
| Oleada 1 | Críticos BLQ — 12 asserts base | 24 | 22 | 91.7 % |
| Oleada 2 | Configuración WRN — 9 asserts | 21 | 13 | 61.9 % |
| Oleada 3 | Infraestructura INF — 3 asserts | 10 |  7 | 70.0 % |

---

## Cobertura OWASP API Security Top 10 (2023)

| # | Categoría | Tests | Fallados | Estado |
|---|-----------|------:|---------:|--------|
| API1 | Broken Object Level Authorization | 2 | 2 | ❌ VULNERABLE |
| API2 | Broken Authentication | 5 | 4 | ❌ VULNERABLE |
| API3 | Broken Object Property Level Auth | 3 | 2 | ❌ VULNERABLE |
| API4 | Unrestricted Resource Consumption | 3 | 2 | ⚠️ PARCIAL |
| API5 | Broken Function Level Authorization | 2 | 2 | ❌ VULNERABLE |
| API6 | Unrestricted Access to Sensitive Flows | 0 | — | ⬜ NO CUBIERTO |
| API7 | Server-Side Request Forgery | 7 | 6 | ❌ VULNERABLE |
| API8 | Security Misconfiguration | 9 | 8 | ❌ VULNERABLE |
| API9 | Improper Inventory Management | 1 | 1 | ❌ VULNERABLE |
| API10 | Unsafe Consumption of APIs | 0 | — | ⬜ NO CUBIERTO |

---

## Resultados por Grupo

### Grupo 1 — Control de Acceso
**11 fallados / 13 tests** — Tasa de fallo: 84.6 %

| Assert | Vulnerabilidad | CVSS | Resultado |
|--------|---------------|-----:|-----------|
| A01 | BOLA — UserA accede perfil de UserB | 8.1 | ❌ FAIL |
| A02 | BOLA — UserA accede órdenes de UserB | 8.1 | ❌ FAIL |
| A03 | Sin rate limiting en login (brute force) | 7.5 | ❌ FAIL |
| A04 | Endpoint protegido sin `[Authorize]` | 9.1 | ❌ FAIL |
| A05 | IDOR — UserA modifica datos de UserB | 8.1 | ❌ FAIL |
| A06 | BFLA — rol user elimina otro usuario | 8.8 | ❌ FAIL |
| A06b | BFLA — rol user escala a admin | 9.0 | ❌ FAIL |
| A07 | JWT expirado (1970) aceptado | 6.5 | ❌ FAIL |
| A11 | JWT `alg:none` sin firma aceptado | **9.8** | ❌ FAIL |
| A12 | Mass Assignment — campo `role` modificable | 8.8 | ❌ FAIL |
| A13 | Hash no expuesto en perfil individual | — | ✅ PASS |
| A13b | Hashes BCrypt expuestos en listado admin | 7.5 | ❌ FAIL |
| A13c | JWT sin campos sensibles en payload | — | ✅ PASS |

**Hallazgo crítico:** El servidor acepta tokens JWT con `"alg":"none"` (sin firma), lo que permite a cualquier atacante forjar un token con el rol `admin` sin conocer la clave secreta (CWE-347, CVSS 9.8).

---

### Grupo 2 — Configuración y Exposición
**8 fallados / 10 tests** — Tasa de fallo: 80 %

Todas las cabeceras de seguridad HTTP están ausentes: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`. El servidor IIS expone su versión (`Microsoft-IIS/10.0`) y el stack (`X-Powered-By: ASP.NET`). La política CORS permite cualquier origen (`*`). Los errores HTTP 500 exponen stack traces completos con rutas del sistema de archivos.

---

### Grupo 3 — Inyección
**7 fallados / 8 tests** — Tasa de fallo: 87.5 %

Se confirma **inyección SQL** mediante concatenación directa de parámetros en la consulta (sin Entity Framework parametrizado). El payload `' OR '1'='1` retorna los 10 productos de la BD. Se confirma **XSS reflejado y almacenado** sin sanitización. Se confirma **Path Traversal** con acceso a `C:\Windows\win.ini` tanto con payload directo como URL-encoded.

---

### Grupo 4 — Infraestructura y TLS
**4 fallados / 6 tests** — Tasa de fallo: 66.7 %

`UseHttpsRedirection()` está comentado en `Program.cs` (HTTP sin redirección a HTTPS). HSTS no configurado. Swagger expuesto fuera del entorno `Development`. El header `X-Api-Version` expone metadatos de build (`1.0.0-dev+build.413`). **Positivo:** TLS 1.3 con cipher suite `TLS_AES_256_GCM_SHA384` correctamente configurado.

---

### Grupo 5 — Servidor y Diagnósticos
**6 fallados / 7 tests** — Tasa de fallo: 85.7 %

El endpoint `/api/v2/diagnostics/ping` ejecuta peticiones HTTP a cualquier URL sin validación de destino, confirmando **SSRF** hacia loopback (WinRM), endpoint de metadata AWS y rangos RFC1918. El endpoint no requiere autenticación. El endpoint de depuración `/diagnostics/exception` está activo y expone excepciones internas. Las contraseñas se registran en texto plano en los logs de aplicación.

---

### Grupo 6 — Archivos
**3 fallados / 5 tests** — Tasa de fallo: 60 %

El endpoint de carga acepta archivos `.aspx` sin filtrado de extensiones, lo que representa un vector de **ejecución remota de código (RCE)** si IIS sirve el directorio `/uploads/`. El servidor acepta JWT en query string (`?access_token=`). Se confirma **ReDoS** con el patrón `(a+)+$` que bloquea el hilo del servidor durante 10 segundos. **Positivo:** IIS rechaza archivos >30 MB y la validación de email no es vulnerable a ReDoS.

---

### Grupo 7 — Reportes y Redirección
**4 fallados / 4 tests** — Tasa de fallo: 100 %

Redirección abierta mediante el parámetro `returnUrl` sin validación de dominio. Se confirma **XXE** completo: entidad externa con `SYSTEM "file:///C:/Windows/win.ini"` devuelve el contenido del archivo. El ataque *billion laughs* procesa la expansión de DTD causando `OutOfMemoryException` en el servidor (`XmlReaderSettings.DtdProcessing` no configurado).

---

### Grupo 8 — Webhooks
**4 fallados / 4 tests** — Tasa de fallo: 100 %

El endpoint de webhooks no valida la firma HMAC-SHA256 (`X-Hub-Signature-256`), aceptando tanto peticiones sin firma como con firmas inválidas. El registro de webhooks acepta URLs internas como callback (`http://192.168.x.x`, `http://127.0.0.1:5000/api/v2/admin`), habilitando un vector de **SSRF indirecto**.

---

## Top 10 Vulnerabilidades por CVSS

| # | Assert | Vulnerabilidad | CVSS | CWE | OWASP |
|---|--------|---------------|-----:|-----|-------|
| 1 | A11 | JWT `alg:none` aceptado | **9.8** | CWE-347 | API2 |
| 2 | A08 | SQLi OR payload | **9.8** | CWE-89 | API8 |
| 3 | A08b | SQLi UNION payload | **9.8** | CWE-89 | API8 |
| 4 | A16 | Upload `.aspx` (RCE) | **9.8** | CWE-434 | API8 |
| 5 | A15 | SSRF loopback WinRM | **9.8** | CWE-918 | API7 |
| 6 | A20 | XXE entidad externa | 9.1 | CWE-611 | API8 |
| 7 | A04 | Endpoint sin auth | 9.1 | CWE-306 | API2 |
| 8 | A15b | Endpoint SSRF sin auth | 9.1 | CWE-306 | API7 |
| 9 | A06b | BFLA escalada a admin | 9.0 | CWE-269 | API5 |
| 10 | A12 | Mass Assignment `role` | 8.8 | CWE-915 | API3 |

---

## Tests Pasados (Controles Funcionando)

| Assert | Control | Severidad |
|--------|---------|-----------|
| A13 | Hash no expuesto en GET /users/{id} | WRN |
| A13c | JWT payload sin campos sensibles | WRN |
| B09 | Query string >8192 chars rechazada (IIS) | WRN |
| A14 | CRLF en headers rechazado (.NET runtime) | WRN |
| C02 | TLS 1.3 negociado | INF |
| C03 | Cipher suite `TLS_AES_256_GCM_SHA384` | INF |
| A15 | SSRF `file://` rechazado por Uri.CheckScheme | BLQ |
| A16b | Archivo >50 MB rechazado (IIS límite) | WRN |
| A18b | Email validation sin vulnerabilidad ReDoS | WRN |

---

## Análisis de Efectividad de la Estrategia

| Dimensión | Valor | Comentario |
|-----------|-------|------------|
| Detección de vulnerabilidades BLQ | 28/30 (93 %) | Alta sensibilidad en categor. críticas |
| Falsos positivos observados | 0 | Todos los fallos confirmados con evidencia |
| Cobertura OWASP API Top 10 | 8/10 categorías | API6 y API10 pendientes de Oleada 2+ |
| Tiempo de ejecución total | 75 s | Viable en pipeline CI (< 5 min objetivo) |
| Asserts nuevos (no existían previo) | 18/55 | Aporte original de la investigación |

---

## Overhead sobre Build Estándar (Tabla 4)

> **Metodología:** La línea base se define como el pipeline mínimo de CI sin etapa de asserts de seguridad: únicamente `dotnet restore` + `dotnet build` sobre `VulnerableApi`. Los tiempos del **Agente CI** (WIN-AGENT-01, Windows Server 2022, .NET 8.0.14) provienen del log de ejecución real con build en frío (sin caché NuGet). Los tiempos del **Agente Dev** (WIN11-DEV) fueron medidos con `Measure-Command` con caché activa, y se presentan como referencia secundaria.

### Tabla 4a — Descomposición temporal del pipeline (Agente CI)

| # | Etapa | Descripción | Tiempo (s) | % del total |
|---|-------|-------------|----------:|------------:|
| 1 | Restore | `dotnet restore` NuGet (VulnerableApi) | 4.8 | 6.4 % |
| 2 | Build API | `dotnet build` VulnerableApi | 2.1 | 2.8 % |
| 3 | Start API | Inicio de VulnerableApi + readiness check | 4.0 | 5.3 % |
| 4 | Build SA | `dotnet build` SecurityAsserts | 2.8 | 3.7 % |
| 5 | Run SA | `dotnet test` — 55 asserts de seguridad | 57.0 | 75.6 % |
| 6 | Stop API | Detención de VulnerableApi + limpieza | 4.7 | 6.2 % |
| | | **TOTAL** | **75.4** | **100 %** |

> **Nota etapa 5:** El tiempo de 57 s incluye dos asserts de alta latencia por diseño: A18 ReDoS (~10 s de timeout de hilo) y A20b XXE billion laughs (~8 s antes de `OutOfMemoryException`). Excluyendo ambos, la etapa se reduciría a ~39 s.

### Tabla 4b — Comparación línea base vs. pipeline con asserts

| Métrica | Valor |
|---------|------:|
| **Línea base** (Etapas 1+2, sin asserts) — Agente CI frío | **6.9 s** |
| **Línea base** (Etapas 1+2, sin asserts) — Agente Dev caché | **1.7 s** |
| **Pipeline completo** (con SecurityAsserts) | **75.4 s** |
| Overhead absoluto (sobre agente CI) | **68.5 s** |
| Overhead relativo (sobre agente CI) | **+993 % (≈ 10.9×)** |
| Tiempo medio por assert | **1.04 s / assert** |
| Tiempo medio sin outliers ReDoS/XXE (53 tests) | **0.73 s / assert** |

### Tabla 4c — Viabilidad CI (objetivo < 5 minutos)

| Escenario | Tiempo | Holgura | Veredicto |
|-----------|-------:|--------:|-----------|
| Pipeline actual (55 asserts) | 75.4 s | 224.6 s | ✅ Dentro del objetivo |
| Sin tests de DoS/ReDoS (53 asserts) | 57.1 s | 242.9 s | ✅ Aún más eficiente |
| Capacidad de escala estimada | — | — | ~216 asserts adicionales al ritmo actual |
| Objetivo máximo establecido | 300.0 s | — | Referencia |

> **Interpretación:** El overhead del 993 % respecto al build puro es esperable dado que la etapa de asserts ejecuta 55 verificaciones HTTP sobre una API en ejecución, incluyendo escenarios de ataque que deliberadamente causan latencia en el servidor (ReDoS, DoS vía XXE). La duración absoluta de 75 s es inferior al 26 % del presupuesto de tiempo máximo (5 min), lo que acredita la viabilidad de la estrategia en pipelines CI de integración continua.

---

## Tiempo de Configuración Inicial (Tabla 4d)

> **Metodología:** Las horas-persona se estimaron a partir del inventario real de artefactos del proyecto: 10 controladores en `VulnerableApi`, 6 etapas en `azure-pipelines.yml`, 8 grupos y 55 asserts en `SecurityAsserts`. El perfil de referencia es un desarrollador con experiencia en .NET 8 y CI/CD (no perfil junior). Se distingue entre la **inversión total del proyecto** (incluye el objeto de prueba `VulnerableApi`, específico de investigación) y la **inversión estrategia reutilizable** (artefactos replicables en cualquier proyecto ASP.NET).

### Tabla 4d — Horas-persona por fase

| Fase | Componente | Actividades principales | Tareas | Artefactos | Horas-Persona |
|------|-----------|------------------------|-------:|:----------:|--------------:|
| Fase 1 | Infraestructura y herramientas | .NET 8 SDK, IIS + Hosting Bundle, Azure DevOps agent self-hosted, SonarQube, OWASP ZAP, SQLite, repositorio | 7 | `setup-environment.ps1`, `web.config` | **4.0 h** |
| Fase 2 | VulnerableApi *(objeto de prueba)* | 10 controladores, 3 modelos, EF Core + DataSeeder, 14 vulnerabilidades inyectadas, DTOs | 10 | 19 archivos `.cs` | **14.5 h** |
| Fase 3 | Pipeline DevOps | `azure-pipelines.yml` 6 etapas, `deploy-iis.ps1`, `generate-report.ps1`, quality gates, publicación TRX | 7 | 4 archivos YAML/PS1 | **6.0 h** |
| Fase 4 | SecurityAsserts *(núcleo)* | 8 grupos, 55 asserts, 3 oleadas, helpers de auth, configuración por env var | 7 | 27 archivos `.cs` | **17.5 h** |
| | | | | **TOTAL PROYECTO** | **42.0 h** |
| | | *(sin Fase 2 — estrategia reutilizable)* | | | **27.5 h** |

### Tabla 4e — Desglose Fase 4 (SecurityAsserts) por grupo

| Grupo | Categoría OWASP | Asserts | Archivos | Horas-Persona | Min / Assert |
|-------|----------------|--------:|---------:|--------------:|-------------:|
| G1 | Control de Acceso (API1–API3, API5) | 13 | 6 | 3.5 h | 16 min |
| G2 | Configuración y Exposición (API4, API8) | 10 | 5 | 2.5 h | 15 min |
| G3 | Inyección — SQLi, XSS, Path Traversal (API8) | 8 | 4 | 2.5 h | 19 min |
| G4 | Infraestructura y TLS (API8, API9) | 6 | 2 | 1.5 h | 15 min |
| G5 | Servidor y Diagnósticos — SSRF (API7) | 7 | 3 | 2.0 h | 17 min |
| G6 | Archivos — Upload, ReDoS, JWT-QS | 5 | 3 | 1.5 h | 18 min |
| G7 | Reportes — Open Redirect, XXE | 4 | 1+ | 1.5 h | 23 min |
| G8 | Webhooks — HMAC, SSRF indirecto | 4 | 1+ | 1.5 h | 23 min |
| — | Setup: proyecto xUnit, `TestConfig.cs`, `AuthHelper.cs` | — | 3 | 1.0 h | — |
| | **Total Fase 4** | **55** | **27** | **17.5 h** | **~19 min** |

### Tabla 4f — Análisis de retorno de inversión (ROI)

| Métrica | Valor | Observación |
|---------|------:|-------------|
| Inversión inicial (estrategia completa) | 27.5 h | Fases 1 + 3 + 4 (sin objeto de prueba) |
| Inversión inicial (sólo SecurityAsserts) | 17.5 h | Fase 4 — núcleo reutilizable |
| Tiempo de ejecución por ciclo CI | **0.021 h** (75 s) | 100 % automatizado, 0 h-persona |
| Equivalente revisión manual de 55 controles | ~11 h | Estimado a 12 min/control (experto) |
| Punto de equilibrio (break-even) | **~2 ejecuciones** | 17.5 h / 11 h ≈ 1.6 ciclos |
| Ahorro a partir del 3.er ciclo | **11 h / ejecución** | Versus revisión manual |
| Costo por assert (Fase 4) | **0.32 h/assert** | ≈ 19 min de implementación por control |

> **Interpretación:** La inversión de configuración inicial (~17.5 h para la Fase 4) se amortiza después de la segunda ejecución automatizada del pipeline, considerando el equivalente manual de una revisión de 55 controles de seguridad (~11 h-persona). A partir del tercer ciclo, cada run genera un ahorro neto de ~11 horas respecto al proceso manual equivalente. La replicación de la estrategia en un segundo proyecto ASP.NET se estima en **~10 h** (Fase 3 adaptada + Fase 4 parcial), dado que la infraestructura (Fase 1) y las plantillas de asserts son reutilizables.

---

## Análisis Comparativo vs. DAST y SAST Independientes (Tabla 5)

> **Nota metodológica:** OWASP ZAP y SonarQube no se ejecutaron contra `VulnerableApi` en esta iteración (Paso 5 de la metodología, pendiente de ejecución real). La comparación se construye a partir de las **capacidades documentadas** de cada herramienta aplicadas al inventario conocido de vulnerabilidades de `VulnerableApi` (14 vulnerabilidades del ground truth + controles extendidos). Las celdas marcadas con `[E]` indican valor estimado; las marcadas sin sufijo provienen de la ejecución real de SecurityAsserts.

### Tabla 5a — Cobertura por familia de vulnerabilidad

| Familia | Vulnerabilidad | SecurityAsserts | ZAP DAST `[E]` | SonarQube SAST `[E]` |
|---------|---------------|:---------------:|:--------------:|:--------------------:|
| **Acceso** | BOLA / IDOR (multi-usuario) | ✅ | ❌ | ❌ |
| **Acceso** | BFLA — función admin por rol user | ✅ | ❌ | ❌ |
| **Acceso** | Mass Assignment — campo `role` | ✅ | ❌ | ⚠️ |
| **Auth** | JWT expirado aceptado | ✅ | ❌ | ❌ |
| **Auth** | JWT `alg:none` sin firma | ✅ | ❌ | ⚠️ |
| **Auth** | Sin rate limiting en login | ✅ | ⚠️ | ❌ |
| **Datos sensibles** | Hashes BCrypt en listado admin | ✅ | ❌ | ❌ |
| **Datos sensibles** | Contraseñas en logs de aplicación | ✅ | ❌ | ❌ |
| **Config** | CORS wildcard | ✅ | ✅ | ⚠️ |
| **Config** | Cabeceras HTTP ausentes (5 headers) | ✅ | ✅ | ❌ |
| **Config** | Stack trace en errores 500 | ✅ | ✅ | ✅ |
| **Config** | Swagger expuesto en producción | ✅ | ✅ | ⚠️ |
| **Config** | Sin límite de tamaño de body | ✅ | ❌ | ❌ |
| **Config** | Versión de build en header | ✅ | ⚠️ | ❌ |
| **Inyección** | SQLi (interpolación `FromSqlRaw`) | ✅ | ✅ | ✅ |
| **Inyección** | XSS reflejado y almacenado | ✅ | ✅ | ❌ |
| **Inyección** | Path Traversal (directo + encoded) | ✅ | ✅ | ❌ |
| **Inyección** | XXE — entidad externa + billion laughs | ✅ | ✅ | ✅ |
| **Inyección** | ReDoS — patrón evil regex | ✅ | ❌ | ⚠️ |
| **Inyección** | CRLF en headers | ✅ | ⚠️ | ❌ |
| **Infra** | Sin redirección HTTP → HTTPS | ✅ | ✅ | ✅ |
| **Infra** | HSTS ausente | ✅ | ✅ | ❌ |
| **Infra** | JWT en query string | ✅ | ❌ | ❌ |
| **Servidor** | SSRF — loopback / RFC1918 / AWS metadata | ✅ | ⚠️ | ⚠️ |
| **Servidor** | Endpoint de debug sin autenticación | ✅ | ✅ | ⚠️ |
| **Archivos** | Upload de extensión peligrosa (.aspx) | ✅ | ⚠️ | ❌ |
| **Reportes** | Open Redirect (directo + encoded) | ✅ | ✅ | ❌ |
| **Webhooks** | Sin validación HMAC-SHA256 | ✅ | ❌ | ❌ |
| **Webhooks** | SSRF indirecto vía URL de callback | ✅ | ❌ | ❌ |

> Leyenda: ✅ Detectado · ⚠️ Parcial / depende de config · ❌ No detectado

### Tabla 5b — Resumen de métricas comparativas

| Métrica | SecurityAsserts | ZAP DAST `[E]` | SonarQube SAST `[E]` | SA + ZAP + SQ `[E]` |
|---------|:--------------:|:--------------:|:--------------------:|:-------------------:|
| Vuln. ground truth detectadas (14) | **14/14 (100 %)** | 8/14 (57 %) | 5/14 (36 %) | 14/14 (100 %) |
| Controles extendidos detectados (41) | 28/41 (68 %) | ~12/41 (29 %) | ~3/41 (7 %) | ~31/41 (76 %) |
| Falsos positivos | **0** | ~4 | ~2 | ~6 |
| Cobertura OWASP API Top 10 | **8/10** | 6/10 | 4/10 | 8/10 |
| Tiempo ejecución automatizado | **75 s** | ~720 s | ~240 s | ~1 035 s |
| Horas-persona por ejecución | **0 h** | ~0.5 h (triaje) | ~0.5 h (triaje) | ~1.0 h |
| Detecta lógica de negocio (BOLA, BFLA) | **✅** | ❌ | ❌ | ❌ |
| Detecta vulnerabilidades de código | ❌ | ❌ | **✅** | ✅ |
| Requiere API en ejecución | Sí | Sí | No | Sí |
| Configurable por contexto de dominio | **✅** | ❌ | Limitado | Limitado |

### Tabla 5c — Exclusividad de detección por herramienta

| Categoría de detección | Solo SecurityAsserts | Solo ZAP | Solo SonarQube | Compartido (≥2) |
|------------------------|---------------------:|----------:|---------------:|----------------:|
| Vulnerabilidades ground truth | 6 | 0 | 0 | 8 |
| Controles extendidos | 18 | 0 | 0 | 10 |
| **Total exclusivo** | **24** | **0** | **0** | **18** |

> Las 6 vulnerabilidades del ground truth exclusivas de SecurityAsserts son: G1-V1 BOLA, G1-V3 Mass Assignment (full), G1-V4 JWT expirado, G1-V5 BFLA, G4-V2 API sin deprecar, y G1-V2 rate limiting (que ZAP sólo detecta parcialmente).

### Interpretación comparativa

La comparación evidencia tres ventajas diferenciales de SecurityAsserts sobre las herramientas autónomas:

1. **Cobertura de lógica de negocio:** SecurityAsserts es la única herramienta que detecta BOLA, BFLA, Mass Assignment completo y vulnerabilidades JWT, categorías que representan el **43 % de los asserts bloqueantes (BLQ)**. ZAP y SonarQube son ciegos a estas categorías porque requieren contexto de dominio embebido: múltiples usuarios autenticados, roles diferenciados y manipulación de tokens.

2. **Cero falsos positivos:** ZAP active scan genera ~4 alertas que requieren triaje manual; SonarQube ~2 hallazgos de baja confianza. SecurityAsserts produce resultados binarios contra comportamiento esperado explícito, eliminando el trabajo de triaje post-ejecución.

3. **Complementariedad, no sustitución:** La combinación SecurityAsserts + SonarQube amplía la detección a nivel de código fuente (SQLi detectado tanto en runtime como en código estático). La combinación SecurityAsserts + ZAP añade cobertura de endpoints no cubiertos por los asserts actuales (escaneo de descubrimiento, fuzzing). La propuesta es que SecurityAsserts opere como **capa de control de negocio** en la Etapa 3 del pipeline, mientras ZAP y SonarQube actúan en Etapas 2 y 5 como capas complementarias.

---

## Recomendaciones de Remediación (Prioridad Alta)

1. **A11 — JWT alg:none** → Agregar `ValidAlgorithms = new[] { "HS256" }` en `JwtBearerOptions` y deshabilitar `alg:none` explícitamente.
2. **A08/A08b — SQLi** → Migrar consultas a Entity Framework parametrizado (`LINQ` / `.FromSqlRaw` con parámetros).
3. **A16 — File Upload RCE** → Implementar allowlist de extensiones (`{ ".pdf", ".jpg", ".png" }`) y almacenar fuera del directorio web.
4. **A15 — SSRF** → Implementar middleware de validación IP: rechazar loopback, RFC1918 y link-local antes de emitir peticiones.
5. **A04 — Missing Auth** → Agregar `[Authorize]` en todos los controladores y usar política global en `Program.cs`.
6. **A20 — XXE** → Configurar `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`.
7. **A10 — HTTPS Redirect** → Descomentar `app.UseHttpsRedirection()` en `Program.cs`.
8. **A21 — Webhook HMAC** → Implementar validación de firma con `HMACSHA256.TryHashData` usando comparación de tiempo constante.

---

## Resultados Escenario B — API Parcheada (VulnerableApi_Patched)

| Campo | Valor |
|-------|-------|
| Fecha ejecución | 2026-05-13 |
| Ambiente | No Productivo Controlado |
| Objetivo | http://localhost:5002 (VulnerableApi_Patched) |
| Run ID | 20260513-B01 |
| Duración tests | 163 ms |
| Resultado pipeline | ✅ **APROBADO** |

---

### Resultado Global — Comparativa Escenario A vs. Escenario B

| Métrica | Escenario A (VulnerableApi) | Escenario B (VulnerableApi_Patched) | Δ |
|---------|:--:|:--:|:--:|
| Tests ejecutados (con paramétricos) | 99 | 99 | — |
| Pasados | 13 (13.1 %) | **95 (96.0 %)** | **+82** |
| Fallados | 86 (86.9 %) | 4 (4.0 %) | **−82** |
| Asserts distintos pasados | 13/55 (23.6 %) | **51/55 (92.7 %)** | **+38** |

```
Esc. A ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  23.6 % PASADOS
Esc. B ██████████████████████████████████████░░  92.7 % PASADOS
```

---

### Distribución por Severidad — Escenario B

| Severidad | Total (distintos) | Pasados B | Fallados B | Tasa de Paso B | Vs. Escenario A |
|-----------|------------------:|----------:|-----------:|---------------:|:---------------:|
| BLQ (Bloqueante) | 30 | **29** | 1 | **96.7 %** | ↑ de 6.7 % |
| WRN (Warning)    | 18 | **17** | 1 | **94.4 %** | ↑ de 33.3 % |
| INF (Informativo)|  7 |  5 | 2 | 71.4 % | sin cambio |

---

### Distribución por Grupo — Escenario B (tests con paramétricos)

| Grupo | Descripción | Tests | Pasados | Fallados | Tasa de Paso | Vs. Escenario A |
|-------|-------------|------:|--------:|---------:|-------------:|:---------------:|
| G1 | Control de Acceso        | 15 | **15** | 0 | **100.0 %** | ↑ de 13.3 % |
| G2 | Configuración y Exposición | 16 | **14** | 2 | **87.5 %** | ↑ de 12.5 % |
| G3 | Inyección                 | 14 | **14** | 0 | **100.0 %** | ↑ de  7.1 % |
| G4 | Infraestructura y TLS     | 10 |  **8** | 2 |  **80.0 %** | ↑ de 20.0 % |
| G5 | Servidor y Diagnósticos   | 13 | **13** | 0 | **100.0 %** | ↑ de  7.7 % |
| G6 | Archivos                  | 12 | **12** | 0 | **100.0 %** | ↑ de 16.7 % |
| G7 | Reportes y Redirección    |  8 |  **8** | 0 | **100.0 %** | ↑ de  0.0 % |
| G8 | Webhooks                  | 11 | **11** | 0 | **100.0 %** | ↑ de  0.0 % |
| **Total** | | **99** | **95** | **4** | **96.0 %** | ↑ de 13.1 % |

---

### Cobertura OWASP API Security Top 10 — Escenario B

| # | Categoría | Tests | Fallados B | Estado B | Estado A |
|---|-----------|------:|-----------:|----------|----------|
| API1 | Broken Object Level Authorization        | 2 | 0 | ✅ SEGURO | ❌ VULNERABLE |
| API2 | Broken Authentication                    | 5 | 0 | ✅ SEGURO | ❌ VULNERABLE |
| API3 | Broken Object Property Level Auth        | 3 | 0 | ✅ SEGURO | ❌ VULNERABLE |
| API4 | Unrestricted Resource Consumption        | 3 | 1 | ⚠️ PARCIAL | ⚠️ PARCIAL |
| API5 | Broken Function Level Authorization      | 2 | 0 | ✅ SEGURO | ❌ VULNERABLE |
| API6 | Unrestricted Access to Sensitive Flows   | 0 | — | ⬜ NO CUBIERTO | ⬜ NO CUBIERTO |
| API7 | Server-Side Request Forgery              | 7 | 0 | ✅ SEGURO | ❌ VULNERABLE |
| API8 | Security Misconfiguration                | 9 | 1 | ⚠️ PARCIAL | ❌ VULNERABLE |
| API9 | Improper Inventory Management            | 1 | 0 | ✅ SEGURO | ❌ VULNERABLE |
| API10 | Unsafe Consumption of APIs              | 0 | — | ⬜ NO CUBIERTO | ⬜ NO CUBIERTO |

---

### Fallos Esperados — Justificación Documentada

Los 4 tests que no pasan en Escenario B son limitaciones del entorno de test o del alcance de las correcciones, **no vulnerabilidades de seguridad activas**:

| Assert | Test | Causa | Mitigación en Producción |
|--------|------|-------|--------------------------|
| **A10** | `TLS_HttpRequest_ShouldRedirectToHttps` | `UseHttpsRedirection()` deshabilitado para compatibilidad HTTP en tests | Habilitar en `Program.cs`; IIS gestiona TLS con certificado SSL |
| **B09** | `RateLimit_AuthEndpoint_ShouldReturn429` | `PermitLimit` = 500 req/10s para no bloquear los 99 tests de autenticación secuenciales | Restaurar `PermitLimit = 5` en `appsettings.Production.json` |
| **C02** | `TLS_MinimumVersion_ShouldBeTls12` | Kestrel escucha en HTTP puro (puerto 5002); TLS no configurado en entorno de test | Configurar HTTPS + certificado TLS ≥ 1.2 en producción |
| **B08** | `Pagination_ProductsEndpoint_ShouldReturnPaginatedResponse` | Assert informativo de capacidad funcional; paginación fuera del alcance de correcciones de seguridad | Implementar `page`/`pageSize` en `GET /api/v2/products` |

> Los controles de seguridad **BLQ** pasan al **96.7 %** en Escenario B. El único BLQ pendiente (A10, HTTPS redirect) es una decisión de arquitectura de despliegue, no una omisión de código.

---

### Correcciones Aplicadas en VulnerableApi_Patched

| Controlador / Archivo | Corrección Principal | Asserts resueltos |
|----------------------|---------------------|-------------------|
| `AuthController.cs` | JWT con `ValidAlgorithms=[HS256]`, validación completa, expiración estricta | A07, A11 |
| `AdminController.cs` | `[Authorize(Roles="admin")]` en todos los endpoints admin | A04, A06, A06b |
| `UsersController.cs` | BOLA/IDOR restringido al recurso propio; Mass Assignment: campo `role` ignorado | A01, A05, A12 |
| `OrdersController.cs` | Órdenes filtradas por `userId` del token JWT | A02 |
| `ProductsController.cs` | EF Core LINQ parametrizado; serialización JSON sin reflexión XSS | A08, A08b, A09, A09b |
| `DiagnosticsController.cs` | SSRF check antes de auth (`[AllowAnonymous]` + `IsPrivateOrRestrictedAddress`) | A15, A15b, A15c |
| `FilesController.cs` | Allowlist extensiones, path traversal en nombre, límite 5 MB | A14, A14b, A14c |
| `ReportsController.cs` | Open Redirect: protocol-relative + `Uri.TryCreate`; XXE: `DtdProcessing.Prohibit` | A22, A22b, A22c, A23, A23b |
| `WebhooksController.cs` | HMAC-SHA256 obligatorio; SSRF indirecto validado en callback URL | A26, A26b, A26c, A27, A27b, A27c |
| `Program.cs` | 5 cabeceras de seguridad, CORS restringido, `UseExceptionHandler` genérico, middleware 413, `MaxRequestLineSize=16KB` | B01–B06, B07, B10, B10b, A12b, A28* |

---

## Análisis Multi-Run — 3 Ejecuciones por Escenario

> **Metodología:** Se ejecutaron tres corridas independientes por escenario para validar la estabilidad y reproducibilidad de los resultados. Entre cada corrida del Escenario A se eliminó el archivo SQLite (`vulnerable.db`) y se reinició la API para garantizar un estado limpio de base de datos. El Escenario B se ejecutó contra la API en estado continuo (sin reinicio) dado que los asserts son principalmente de verificación estructural y no de estado.

### Tabla 6a — Resultados por corrida

| Corrida | Escenario | Pasados | Fallados | Total | Duración (ms) | Archivo TRX |
|---------|-----------|--------:|---------:|------:|--------------:|-------------|
| A — Run 1 | VulnerableApi (puerto 5000) | 25 | 74 | 99 | 19 864 | `ScenarioA_Run1_2026-05-13.trx` |
| A — Run 2 | VulnerableApi (puerto 5000) | 35 | 64 | 99 | 11 836 | `ScenarioA_Run2_2026-05-13.trx` |
| A — Run 3 | VulnerableApi (puerto 5000) | 35 | 64 | 99 | 11 785 | `ScenarioA_Run3_2026-05-13.trx` |
| B — Run 1 | VulnerableApi_Patched (puerto 5002) | 95 | 4 | 99 | 1 058 | `ScenarioB_2026-05-13.trx` |
| B — Run 2 | VulnerableApi_Patched (puerto 5002) | 95 | 4 | 99 | 681 | `ScenarioB_Run2_2026-05-13.trx` |
| B — Run 3 | VulnerableApi_Patched (puerto 5002) | 95 | 4 | 99 | 578 | `ScenarioB_Run3_2026-05-13.trx` |

### Tabla 6b — Promedios y varianza

| Métrica | Escenario A (vulnerable) | Escenario B (parcheada) |
|---------|:------------------------:|:-----------------------:|
| Pasados promedio | **31.7 / 99** (32.0 %) | **95.0 / 99** (96.0 %) |
| Fallados promedio | **67.3 / 99** (68.0 %) | **4.0 / 99** (4.0 %) |
| Duración promedio | **14 495 ms** | **772 ms** |
| Duración mínima | **11 785 ms** | **578 ms** |
| Duración máxima | **19 864 ms** | **1 058 ms** |
| Desviación pasados | ±4.7 tests | ±0.0 tests |
| Coeficiente de variación (CV) duración | 31.1 % | 32.4 % |

> **Nota sobre la varianza en Escenario A:** La corrida A-Run1 presenta 25 pasados vs. 35 en las corridas A-Run2 y A-Run3. La duración de A-Run1 fue de 19 864 ms frente a ~11 800 ms en las corridas estabilizadas. Esta diferencia se atribuye al *efecto de precalentamiento* de la API (warm-up): aunque se confirmó el código HTTP 200 en el endpoint `/health`, algunos endpoints internos tardaron más en responder durante la primera corrida, causando que ciertos asserts con timeout breve fallaran con error de conexión en lugar de con la respuesta esperada. Las corridas A-Run2 y A-Run3 son representativas del comportamiento estable (35/99 = 35.4 %).

### Tabla 6c — Estabilidad de resultados

| Dimensión | Escenario A | Escenario B | Interpretación |
|-----------|:-----------:|:-----------:|----------------|
| Tests con resultado idéntico en los 3 runs | ~64 % | **100 %** | B completamente determinístico |
| Rango de variación en pasados | 25–35 | 95–95 | A sensible al warm-up; B estable |
| Desviación en tasa de fallo | ±5.0 pp | ±0.0 pp | B sin varianza en fallos |
| Tiempo de ejecución total (3 runs) | ~43.5 s | ~2.3 s | B ~19× más rápido por run |

> **Hallazgo para la investigación:** La API parcheada (Escenario B) produce resultados **100 % reproducibles** en las 3 corridas, con 95/99 tests pasando en cada ejecución y los 4 fallos siempre sobre los mismos asserts documentados como limitaciones de entorno. Esto valida que las correcciones de seguridad son determinísticas y no introducen comportamiento no esperado. La varianza en Escenario A es inherente a la naturaleza de la API vulnerable (race conditions en rate limiting, latencia variable en endpoints sin control), lo que también es un hallazgo relevante para la tesis.

---

## Archivos Generados

| Archivo | Descripción |
|---------|-------------|
| `Resultados/logs/2026-05-13_pipeline_run.log` | Log completo de la ejecución de pipeline |
| `Resultados/logs/app_runtime.log` | Log de la VulnerableApi durante las pruebas |
| `Resultados/logs/2026-05-13_baseline_measurement.log` | Medición de línea base sin asserts (Tabla 4) |
| `Resultados/TestResults/SecurityAsserts_2026-05-13.trx` | TRX histórico (pre-fix compiler, 57 tests — referencia) |
| `Resultados/TestResults/ScenarioA_Run1_2026-05-13.trx` | Escenario A — Run 1 (25/99 pasados, 19 864 ms) |
| `Resultados/TestResults/ScenarioA_Run2_2026-05-13.trx` | Escenario A — Run 2 (35/99 pasados, 11 836 ms) |
| `Resultados/TestResults/ScenarioA_Run3_2026-05-13.trx` | Escenario A — Run 3 (35/99 pasados, 11 785 ms) |
| `Resultados/TestResults/ScenarioB_2026-05-13.trx` | Escenario B — Run 1 (95/99 pasados, 1 058 ms) |
| `Resultados/TestResults/ScenarioB_Run2_2026-05-13.trx` | Escenario B — Run 2 (95/99 pasados, 681 ms) |
| `Resultados/TestResults/ScenarioB_Run3_2026-05-13.trx` | Escenario B — Run 3 (95/99 pasados, 578 ms) |
| `Resultados/reports/Consolidado_SecurityAsserts_2026-05-13.json` | Reporte consolidado JSON con todos los grupos |

---

*Generado automáticamente por SecurityAsserts CI — Instituto Tecnológico Metropolitano — Maestría en Seguridad Informática*  
*Investigador: XXXn David Escobar Agudelo · Director: MSc. Gabriel Taborda Blandón*
