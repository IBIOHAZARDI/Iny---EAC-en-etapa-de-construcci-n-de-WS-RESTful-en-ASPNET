using System.Net;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo3_Inyeccion;

/// <summary>
/// Assert A13 — Path Traversal en descarga de archivos
/// El endpoint GET /files/download NO debe permitir leer archivos fuera de su directorio base.
/// Oleada 1 — BLQ
/// OWASP API3:2023
/// </summary>
public class G3_PathTraversal_Asserts
{
    // Payloads de traversal estándar
    private static readonly string[] TraversalPayloads =
    [
        "../../appsettings.json",
        "..%2F..%2Fappsettings.json",
        "%2e%2e%2f%2e%2e%2fappsettings.json",
        "....//....//appsettings.json",
        "..\\..\\appsettings.json"
    ];

    [Fact]
    [Trait("Assert",  "A13")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A13_PathTraversal_DownloadOutsideBaseDir_ShouldReturn400Or403()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        // El payload clásico ../.. debe ser rechazado
        var response = await client.GetAsync("/api/v2/files/download?path=../../appsettings.json");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.BadRequest, HttpStatusCode.Forbidden, HttpStatusCode.NotFound },
            because: "A13 — Path Traversal: rutas con '../' deben rechazarse con 400/403 (no 200)");
    }

    [Theory]
    [InlineData("../../appsettings.json")]
    [InlineData("..%2F..%2Fappsettings.json")]
    [InlineData("%2e%2e/%2e%2e/appsettings.json")]
    [Trait("Assert",  "A13b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A13b_PathTraversal_EncodedPayloads_ShouldNotReturn200(string payload)
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.GetAsync($"/api/v2/files/download?path={payload}");

        response.StatusCode.Should().NotBe(HttpStatusCode.OK,
            because: $"A13b — Payload codificado '{payload}' NO debe retornar 200 con contenido de archivo sensible");
    }

    [Fact]
    [Trait("Assert",  "A13c")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A13c_PathTraversal_ConfigFile_ShouldNotExposeContent()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.GetAsync("/api/v2/files/download?path=../../appsettings.json");

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            // Si retorna 200, el body NO debe contener secretos del appsettings
            body.Should().NotContainAny(
                new[] { "weak-key", "weak-key-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "ConnectionStrings", "DefaultConnection", "JwtKey" },
                because: "A13c — Path Traversal: el contenido de appsettings.json NO debe estar expuesto");
        }
        // Si retorna 400/403/404, el assert pasa automáticamente
    }
}
