using System.Net;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo5_Servidor;

/// <summary>
/// Assert A15 — SSRF (Server-Side Request Forgery)
/// El endpoint GET /diagnostics/ping NO debe realizar peticiones a rangos de IP privadas,
/// loopback, link-local ni esquemas no HTTP.
/// Oleada 1 — BLQ
/// OWASP API7:2023
/// </summary>
public class G5_SSRF_Asserts
{
    private static readonly (string payload, string description)[] SsrfPayloads =
    [
        ("http://127.0.0.1:5985/",           "loopback WinRM"),
        ("http://169.254.169.254/latest/meta-data/", "AWS instance metadata"),
        ("http://10.0.0.1/",                 "RFC 1918 clase A"),
        ("http://192.168.1.1/",              "RFC 1918 clase C"),
        ("http://172.16.0.1/",               "RFC 1918 clase B"),
        ("http://[::1]/",                    "loopback IPv6"),
        ("file:///C:/Windows/win.ini",       "file:// scheme"),
        ("dict://127.0.0.1:6379/",           "Redis internal"),
    ];

    [Theory]
    [InlineData("http://127.0.0.1:5985/",            "loopback WinRM")]
    [InlineData("http://169.254.169.254/latest/",    "AWS metadata")]
    [InlineData("http://192.168.1.1/",               "RFC 1918")]
    [InlineData("file:///C:/Windows/win.ini",        "file scheme")]
    [Trait("Assert",  "A15")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API7:2023")]
    public async Task A15_SSRF_PrivateRangeUrl_ShouldReturn400Or403(string url, string description)
    {
        using var client = TestConfig.CreateClient();

        var encoded = Uri.EscapeDataString(url);
        var response = await client.GetAsync($"/api/v2/diagnostics/ping?url={encoded}");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.BadRequest, HttpStatusCode.Forbidden },
            because: $"A15 — SSRF: URL a {description} ('{url}') debe rechazarse con 400/403");
    }

    [Fact]
    [Trait("Assert",  "A15b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API7:2023")]
    public async Task A15b_SSRF_PingEndpointRequiresAuthentication()
    {
        using var client = TestConfig.CreateClient();
        // Sin token — el endpoint de diagnóstico SSRF debe requerir autenticación
        var response = await client.GetAsync("/api/v2/diagnostics/ping?url=http://example.com");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden },
            because: "A15b — El endpoint /diagnostics/ping debe requerir autenticación (no ser público)");
    }

    [Fact]
    [Trait("Assert",  "A15c")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API7:2023")]
    public async Task A15c_SSRF_ResponseShouldNotContainInternalNetworkData()
    {
        using var client = TestConfig.CreateClient();

        // Intentar SSRF a loopback
        var encoded = Uri.EscapeDataString("http://127.0.0.1/");
        var response = await client.GetAsync($"/api/v2/diagnostics/ping?url={encoded}");

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            // Si responde 200, no debe contener datos de red interna
            body.Should().NotContainAny(
                new[] { "meta-data", "ami-id", "instance-id", "local-ipv4", "192.168.", "10.0.", "172.16." },
                because: "A15c — La respuesta no debe filtrar datos de red interna via SSRF");
        }
    }
}
