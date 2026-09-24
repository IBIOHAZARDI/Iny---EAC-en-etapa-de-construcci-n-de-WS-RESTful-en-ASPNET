using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo5_Servidor;

/// <summary>
/// Assert A16 — Debug endpoint expone información interna
/// GET /diagnostics/info debe requerir autenticación y NO exponer variables de entorno,
/// cadenas de conexión ni rutas absolutas del servidor.
/// Oleada 1 — BLQ (acceso sin auth) / Oleada 2 — WRN (contenido)
/// OWASP API8:2023
/// </summary>
public class G5_DebugInfo_Asserts
{
    [Fact]
    [Trait("Assert",  "A16")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A16_DebugInfo_WithoutAuth_ShouldReturn401Or404()
    {
        using var client = TestConfig.CreateClient();
        // Sin token — el endpoint de info no debe ser público
        var response = await client.GetAsync("/api/v2/diagnostics/info");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Unauthorized, HttpStatusCode.NotFound, HttpStatusCode.Forbidden },
            because: "A16 — El endpoint /diagnostics/info NO debe ser accesible sin autenticación");
    }

    [Fact]
    [Trait("Assert",  "A16b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A16b_DebugInfo_ShouldNotExposeConnectionString()
    {
        using var client = TestConfig.CreateClient();
        var response = await client.GetAsync("/api/v2/diagnostics/info");

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            body.Should().NotContainAny(
                new[] { "DefaultConnection", "Data Source=", "Server=", "Password=", "weak-key", "weak-key-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" },
                because: "A16b — El endpoint de diagnóstico NO debe exponer cadenas de conexión ni claves");
        }
    }

    [Fact]
    [Trait("Assert",  "A16c")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A16c_DebugInfo_ShouldNotExposeEnvironmentVariables()
    {
        using var client = TestConfig.CreateClient();
        var response = await client.GetAsync("/api/v2/diagnostics/info");

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            // Variables de entorno como PATH, USERNAME, USERDOMAIN no deben filtrarse
            body.Should().NotContainAny(
                new[] { "\"environment\"", "USERDOMAIN", "COMPUTERNAME", "PROCESSOR_ARCHITECTURE" },
                because: "A16c — El endpoint de diagnóstico NO debe listar variables de entorno del servidor");
        }
    }

    [Fact]
    [Trait("Assert",  "A16d")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A16d_HealthVerbose_ShouldNotExposeRuntimeVersion()
    {
        using var client = TestConfig.CreateClient();
        var response = await client.GetAsync("/api/v2/diagnostics/health-verbose");

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            body.Should().NotContain("ASP.NET Core",
                because: "A16d — El health-verbose NO debe exponer el framework con versión exacta");
            body.Should().NotMatchRegex(@"\d+\.\d+\.\d+\.\d+",
                because: "A16d — El health-verbose NO debe exponer versiones exactas del runtime");
        }
    }
}
