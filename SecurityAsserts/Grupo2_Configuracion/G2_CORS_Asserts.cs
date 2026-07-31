using System.Net.Http;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo2_Configuracion;

/// <summary>
/// Assert B06 — Política CORS
/// El servidor NO debe responder con Access-Control-Allow-Origin: * en rutas autenticadas.
/// Oleada 2 — WRN
/// OWASP API8:2023
/// </summary>
public class G2_CORS_Asserts
{
    [Fact]
    [Trait("Assert",  "B06")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B06_CORS_AllowOriginWildcard_ShouldNotBePresent()
    {
        using var client = TestConfig.CreateClient();
        // Preflight CORS desde origen externo
        var request = new HttpRequestMessage(HttpMethod.Options, "/api/v2/users");
        request.Headers.Add("Origin", "https://attacker.example.com");
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "Authorization");

        var response = await client.SendAsync(request);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var vals);
        var origin = vals?.FirstOrDefault() ?? "";

        origin.Should().NotBe("*",
            because: "B06 — CORS: Access-Control-Allow-Origin: * NO debe estar configurado (permite cualquier origen)");
    }

    [Fact]
    [Trait("Assert",  "B06b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B06b_CORS_AllowCredentials_WithWildcardOrigin_ShouldNotBePresent()
    {
        using var client = TestConfig.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Options, "/api/v2/users");
        request.Headers.Add("Origin", "https://attacker.example.com");
        request.Headers.Add("Access-Control-Request-Method", "GET");

        var response = await client.SendAsync(request);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var aoVals);
        response.Headers.TryGetValues("Access-Control-Allow-Credentials", out var acVals);

        var ao = aoVals?.FirstOrDefault() ?? "";
        var ac = acVals?.FirstOrDefault() ?? "";

        (ao == "*" && ac.Equals("true", StringComparison.OrdinalIgnoreCase))
            .Should().BeFalse(
                because: "B06b — CORS: No debe combinar Allow-Origin: * con Allow-Credentials: true");
    }
}
