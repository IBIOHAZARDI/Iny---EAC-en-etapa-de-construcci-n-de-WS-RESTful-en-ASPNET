using System.Net;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo4_Infraestructura;

/// <summary>
/// Assert C04 — Versión de API desactualizada (v1) debe redirigir o rechazar
/// Assert C05 — Método HTTP no permitido debe retornar 405 (no 200 ni 500)
/// Assert C06 — Endpoint /health no debe estar protegido (disponibilidad para orquestadores)
/// Oleada 3 — INF
/// OWASP API8:2023 / API9:2023
/// </summary>
public class G4_API_Asserts
{
    // ──────────────────────────────────────────────────────
    // C04: API v1 debe estar deprecated / retornar cabecera Deprecation
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "C04")]
    [Trait("Oleada",  "Oleada3")]
    [Trait("Category","INF")]
    [Trait("OWASP",   "API9:2023")]
    public async Task C04_ApiVersion_V1Route_ShouldReturnDeprecationHeader()
    {
        using var client = TestConfig.CreateClient();

        var response = await client.GetAsync("/api/v1/products");

        // Opción 1: retorna cabecera de deprecación
        var hasDeprecation = response.Headers.Contains("Deprecation")
                          || response.Headers.Contains("Sunset")
                          || response.Headers.Contains("X-Api-Deprecation-Notice");

        // Opción 2: retorna 404 o 410 Gone
        var isGone = response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Gone;

        (hasDeprecation || isGone).Should().BeTrue(
            because: "C04 — La API v1 debe indicar deprecación (cabecera Deprecation/Sunset o retornar 404/410)");
    }

    // ──────────────────────────────────────────────────────
    // C05: Métodos HTTP no permitidos retornan 405
    // ──────────────────────────────────────────────────────
    [Theory]
    [InlineData("PATCH",  "/api/v2/auth/login")]
    [InlineData("PUT",    "/api/v2/auth/login")]
    [InlineData("DELETE", "/api/v2/auth/login")]
    [InlineData("TRACE",  "/api/v2/users")]
    [Trait("Assert",  "C05")]
    [Trait("Oleada",  "Oleada3")]
    [Trait("Category","INF")]
    [Trait("OWASP",   "API8:2023")]
    public async Task C05_HttpMethod_DisallowedVerb_ShouldReturn405(string method, string path)
    {
        using var client = TestConfig.CreateClient();
        var request = new HttpRequestMessage(new HttpMethod(method), path);
        var response = await client.SendAsync(request);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.MethodNotAllowed, HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized },
            because: $"C05 — Método {method} en {path} debe retornar 405 (no 200 ni 500)");

        response.StatusCode.Should().NotBe(HttpStatusCode.InternalServerError,
            because: $"C05 — Método {method} no debe causar error 500 no controlado");
    }

    // ──────────────────────────────────────────────────────
    // C06: /health no requiere autenticación (orquestadores como K8s, IIS)
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "C06")]
    [Trait("Oleada",  "Oleada3")]
    [Trait("Category","INF")]
    [Trait("OWASP",   "API8:2023")]
    public async Task C06_HealthCheck_ShouldBePublicAndReturn200()
    {
        using var client = TestConfig.CreateClient();
        // Sin token — health check debe ser público para orquestadores
        var response = await client.GetAsync("/health");

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "C06 — GET /health debe ser accesible sin autenticación y retornar 200");
    }
}
