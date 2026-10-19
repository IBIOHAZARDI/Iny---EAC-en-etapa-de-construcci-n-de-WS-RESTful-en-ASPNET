# Causas probables y correcciones de las pruebas inestables (Escenario A)

Serie de referencia: 10 corridas del 2026-09-25 (`TestResults/ScenarioA_Run*_2026-09-25.trx`). Son las 11 pruebas con veredicto mixto en esa serie.

## Tabla de causas y correcciones

| Prueba (ID) | Pasa en 25/09 | Causa probable | Acción correctiva |
|---|---|---|---|
| A28d (G5-V2) | 7/10 | Lectura del log en el test: la `IOException` se traga y devuelve vacío; la ventana de espera es de 1–2 s. Falla junto con A28e en las mismas corridas. | No silenciar el error: reintentar y reportar ruta, tamaño y excepción en el mensaje. Ventana de espera ≥5 s. Validar con 10 corridas. |
| A28e (G2-V8) | 6/10 | Igual que A28d (mismo sink de log y mismo lector). | Igual que A28d. |
| A02 (BOLA) | 2/10 | Precondición: el login de `usera` devuelve 500 porque `AppLog` no puede escribir `app.log` (archivo bloqueado). | Ya corregido en `VulnerableApi/AppLog.cs` (reintentos y captura de `IOException`). Validar con 10 corridas. Separar la precondición de login del assert para que un 500 no cuente como fallo de seguridad. |
| A13 | 7/10 | Igual: login → 500 por bloqueo de `app.log`. | Igual que A02. |
| A13b (paramétrico ×3) | 17/30 | Igual: login → 500, en cada caso paramétrico. | Igual que A02. Hacer una sola precondición de login por clase. |
| A13c | 7/10 | Igual: login → 500. | Igual que A02. |
| A17b | 2/10 | Igual: login → 500. | Igual que A02. |
| A21 | 7/10 | Igual: login → 500. | Igual que A02. |
| A22c | 8/10 | Igual: login → 500. | Igual que A02. |
| B04 | 4/10 | Igual: login → 500. | Igual que A02. |
| B05 | 9/10 | Igual: login → 500. | Igual que A02. |

## Evidencia

- `logs/apiA.log` (25/09): 56 ocurrencias de `IOException: The process cannot access the file '...\logs\app.log' because it is being used by another process`, y el login responde 500.
- `AppLog.cs` ya captura `IOException` y reintenta hasta 5 veces. Las corridas limpias de prueba posteriores a ese cambio no muestran 500 en login.
- A28d y A28e fallan en las mismas corridas de la serie del 2026-10-18 (corridas 3, 4 y 7), lo que apunta a un problema compartido de lectura del log y no a cada prueba por separado.

## Pendiente

- Las pruebas A01, A02, A19 y C02 también aparecen con veredicto mixto en la serie del 2026-10-18. Esa serie no se ha diagnosticado todavía.
- Los cambios en `SecurityAsserts/Grupo5_Servidor/G5_SensitiveLogs_Asserts.cs` (lectura sin silenciar errores y ventana más larga) están pendientes de aplicar.
- Las cifras de `README.md` y de `reports/AssertCounts_TRX_2026-10-18.csv` deben regenerarse con la serie vigente.
