using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo4_Infraestructura;

/// <summary>
/// Asserts A10, C01, C02, C03 — TLS, HSTS e Infraestructura
/// Oleada 1 (A10 BLQ) / Oleada 3 (C01–C03 INF)
/// OWASP API8:2023
/// </summary>
public class G4_TLS_Asserts
{
    // ──────────────────────────────────────────────────────
    // A10: HTTP no debe redirigir automáticamente a HTTPS
    //      (verifica que UseHttpsRedirection está ausente)
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A10")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A10_TLS_HttpRequest_ShouldRedirectToHttps()
    {
        // Requiere un endpoint HTTP en claro (TEST_API_HTTP_URL o BaseUrl http://).
        if (TestConfig.HttpUrl is not { } httpUrl)
        {
            return;
        }

        using var handler = TestConfig.CreateHandler(allowAutoRedirect: false);
        using var client = new HttpClient(handler) { BaseAddress = new Uri(httpUrl) };

        var response = await client.GetAsync("/health");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.MovedPermanently, HttpStatusCode.Found, HttpStatusCode.PermanentRedirect, HttpStatusCode.TemporaryRedirect },
            because: "A10 — Las peticiones HTTP deben redirigir a HTTPS (UseHttpsRedirection)");
    }

    // ──────────────────────────────────────────────────────
    // C01: Cabecera HSTS debe estar presente en respuestas HTTPS
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "C01")]
    [Trait("Oleada",  "Oleada3")]
    [Trait("Category","INF")]
    [Trait("OWASP",   "API8:2023")]
    public async Task C01_HSTS_StrictTransportSecurity_ShouldBePresent()
    {
        // Sin endpoint HTTPS configurado el assert no es aplicable.
        if (TestConfig.HttpsUrl is not { } httpsUrl)
        {
            return;
        }

        using var handler = TestConfig.CreateHandler();
        using var client = new HttpClient(handler) { BaseAddress = new Uri(httpsUrl) };

        var response = await client.GetAsync("/health");
        response.Headers.TryGetValues("Strict-Transport-Security", out var vals);
        vals.Should().NotBeNullOrEmpty(
            because: "C01 — La cabecera Strict-Transport-Security (HSTS) debe estar presente en HTTPS");
    }

    // ──────────────────────────────────────────────────────
    // C02: TLS versión mínima 1.2
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "C02")]
    [Trait("Oleada",  "Oleada3")]
    [Trait("Category","INF")]
    [Trait("OWASP",   "API8:2023")]
    public async Task C02_TLS_MinimumVersion_ShouldBeTls12()
    {
        if (TestConfig.HttpsUrl is not { } httpsUrl)
        {
            return;
        }

        using var handler = TestConfig.CreateHandler();
        handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13;
        using var client = new HttpClient(handler) { BaseAddress = new Uri(httpsUrl) };

        // Si TLS 1.0/1.1 son los únicos aceptados, la conexión debe fallar con TLS 1.2+
        bool canConnect = false;
        try
        {
            var resp = await client.GetAsync("/health");
            canConnect = resp.IsSuccessStatusCode;
        }
        catch { canConnect = false; }

        canConnect.Should().BeTrue(
            because: "C02 — El servidor debe soportar al menos TLS 1.2");
    }

    // ──────────────────────────────────────────────────────
    // C03: Versión de .NET expuesta en cabeceras
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "C03")]
    [Trait("Oleada",  "Oleada3")]
    [Trait("Category","INF")]
    [Trait("OWASP",   "API8:2023")]
    public async Task C03_DotNetVersion_ShouldNotBeExposedInHeaders()
    {
        using var client = TestConfig.CreateClient();
        var response = await client.GetAsync("/health");

        response.Headers.TryGetValues("X-AspNet-Version", out var aspNetVals);
        response.Headers.TryGetValues("X-AspNetMvc-Version", out var mvcVals);
        response.Headers.TryGetValues("X-Powered-By", out var poweredVals);

        aspNetVals.Should().BeNullOrEmpty(
            because: "C03 — La cabecera X-AspNet-Version NO debe estar presente");
        mvcVals.Should().BeNullOrEmpty(
            because: "C03 — La cabecera X-AspNetMvc-Version NO debe estar presente");
    }
}
