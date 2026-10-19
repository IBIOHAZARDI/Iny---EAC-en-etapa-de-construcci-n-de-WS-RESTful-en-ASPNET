# Causas y correcciones de los tests inestables (Escenario A)

Serie de referencia: 2026-10-18, 10 corridas por escenario. Resultado tras las correcciones: A = 47/103 en las 10 corridas y B = 101/103 en las 10 corridas, sin IDs intermitentes.

| ID(s) | Causa probable (evidencia) | Acción correctiva |
|-------|---------------------------|-------------------|
| A02, A13, A13b, A13c, A17b, A22c, B04, B05 | Precondición de login con 500: `IOException` ("archivo en uso") en `File.AppendAllText` sobre `logs\app.log` (23 casos en el log), con escrituras concurrentes y un archivo de 126 MB. | Nuevo `AppLog.Append` (lock, escritor único, `FileShare.ReadWrite`, reintentos); `app.log` se rota al inicio de cada corrida. |
| A28d, A28e (detectan G5-V2 y G2-V8) | (1) Mismo `IOException` (el 500 impedía escribir la entrada); (2) el lector leía solo el último 1 MB y A14 escribe una línea de ~2 MB que desplazaba las entradas; (3) las pruebas corrían en paralelo. | Lectura de `app.log` por líneas con marcadores en la misma línea y 20 reintentos × 100 ms; log rotado por corrida; ejecución serial. Resultado: 10/10 corridas con fuga detectada, base de 26/28. |
| A19, A01 | Estado compartido: otro test destructivo (A05/A06) borraba o alteraba al usuario B antes y la API devolvía 404 (falso negativo). | `StateAwareOrderers.cs`: pruebas de lectura primero y las mutantes al final (A19, A21 → A05 → A06b → A06). |
| A21 | Misma dependencia de estado; además la API no expone `DELETE /orders` y responde 405, por lo que pasa siempre. | Orden determinista; el pase 10/10 se documenta como no detectable por diseño. |
| Todos | `xunit.runner.json` (`parallelizeTestCollections=false`) no se copiaba a `bin`, de modo que las pruebas sí corrían en paralelo. | `CopyToOutputDirectory` en el csproj y `[assembly: CollectionBehavior(DisableTestParallelization = true)]`. |
| C02 | Timeout puntual (~4 s) del handshake TLS cuando el servidor estaba bajo carga. | Se redujo con la ejecución serial; en la serie final pasa 10/10. La causa de fondo no se investigó. |

Nota: la copia `App---EAC-.../VulnerableApi` conserva la clave JWT de 8 bytes (`IDX10653`) y no incluye `AppLog`; las series usan `Desarrollo\VulnerableApi`.
