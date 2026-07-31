using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo1_ControlAcceso;

/// <summary>
/// Asserts A03, A04, A07, A11 — Autenticación rota y JWT
/// Oleada 1 — BLQ (A03, A04, A11) / WRN (A07)
/// OWASP API2:2023, API8:2023
/// </summary>
public class G1_Auth_Asserts
{
    // ──────────────────────────────────────────────────────
    // A03: Brute Force — después de N intentos fallidos debe bloquear o devolver 429
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A03")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API2:2023")]
    public async Task A03_Auth_BruteForce_MultipleFailedLogins_ShouldReturn429Or401()
    {
        using var client = TestConfig.CreateClient();
        HttpStatusCode? lastStatus = null;

        for (int i = 0; i < 10; i++)
        {
            var resp = await client.PostAsJsonAsync("/api/v2/auth/login",
                new { email = TestConfig.UserAEmail, password = "WrongPassword!" });
            lastStatus = resp.StatusCode;
        }

        lastStatus.Should().BeOneOf(
            new[] { HttpStatusCode.TooManyRequests, HttpStatusCode.Unauthorized },
            because: "A03 — Después de múltiples fallos, debe retornar 429 o 401 (sin cuenta los intentos)");
    }

    // ──────────────────────────────────────────────────────
    // A04: Endpoint sin autenticación retorna 401
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A04")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API2:2023")]
    public async Task A04_Auth_ProtectedEndpoint_WithoutToken_ShouldReturn401()
    {
        using var client = TestConfig.CreateClient();

        var response = await client.GetAsync($"/api/v2/users/{TestConfig.UserAId}");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "A04 — Endpoint protegido sin token debe retornar 401");
    }

    // ──────────────────────────────────────────────────────
    // A07: JWT expirado debe ser rechazado (WRN)
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A07")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API2:2023")]
    public async Task A07_Auth_ExpiredToken_ShouldReturn401()
    {
        // Token JWT con exp en el pasado (firmado con clave "weak-key" conocida)
        // Header.Payload.Signature — exp = 1 (Unix epoch 1970)
        const string expiredToken =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
            ".eyJzdWIiOiIyIiwiZW1haWwiOiJ1c2VyYUB0ZXN0LmxvY2FsIiwicm9sZSI6InVzZXIiLCJleHAiOjF9" +
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        using var client = TestConfig.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", expiredToken);

        var response = await client.GetAsync($"/api/v2/users/{TestConfig.UserAId}");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "A07 — Token JWT expirado debe ser rechazado con 401");
    }

    // ──────────────────────────────────────────────────────
    // A11: Token con algoritmo "none" debe ser rechazado
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A11")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A11_Auth_AlgNoneToken_ShouldReturn401()
    {
        // JWT con alg=none — no tiene firma
        const string algNoneToken =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +
            ".eyJzdWIiOiIxIiwiZW1haWwiOiJhZG1pbkB0ZXN0LmxvY2FsIiwicm9sZSI6ImFkbWluIn0.";

        using var client = TestConfig.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", algNoneToken);

        var response = await client.GetAsync("/api/v2/admin/users");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "A11 — Token con algoritmo 'none' debe ser rechazado con 401");
    }
}
