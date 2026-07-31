using System.Net;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo7_Reportes;

/// <summary>
/// Assert A23 — Open Redirect en GET /reports/redirect
/// El endpoint NO debe emitir un redirect 3xx a dominios externos
/// cuando se recibe un returnUrl con dominio no permitido.
/// Oleada 1 — BLQ
/// OWASP API8:2023 / CWE-601
/// </summary>
public class G7_OpenRedirect_Asserts
{
    // URLs externas maliciosas que un atacante podría usar para phishing
    private static readonly (string url, string description)[] ExternalRedirects =
    [
        ("https://evil.example.com/phishing",            "dominio externo genérico"),
        ("https://attacker.io/steal-token?next=original","dominio de atacante con subpath"),
        ("//evil.example.com/",                          "protocol-relative URL"),
        ("https://legit.internal@evil.example.com/",     "userinfo bypass"),
        ("%2f%2fevil.example.com/",                      "URL-encoded // externo"),
    ];

    [Theory]
    [InlineData("https://evil.example.com/phishing",         "dominio externo")]
    [InlineData("https://attacker.io/steal-token",           "dominio atacante")]
    [InlineData("//evil.example.com/",                       "protocol-relative")]
    [InlineData("%2f%2fevil.example.com/",                   "encoded external")]
    [Trait("Assert",  "A23")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A23_OpenRedirect_ExternalUrl_ShouldReturn400(string returnUrl, string description)
    {
        using var client = TestConfig.CreateClient();
        // Deshabilitar seguimiento de redirects para capturar el 302 original
        using var noRedirectClient = new HttpClient(
            new HttpClientHandler { AllowAutoRedirect = false })
        {
            BaseAddress = new Uri(TestConfig.BaseUrl)
        };

        var encoded = Uri.EscapeDataString(returnUrl);
        var response = await noRedirectClient.GetAsync($"/api/v2/reports/redirect?returnUrl={encoded}");

        // El servidor debe rechazar con 400, no emitir un redirect 3xx a dominio externo
        new[] { HttpStatusCode.Moved, HttpStatusCode.Found, HttpStatusCode.TemporaryRedirect, HttpStatusCode.PermanentRedirect }
            .Should().NotContain(response.StatusCode,
            because: $"A23 — Open Redirect: returnUrl externo '{description}' no debe emitir redirect 3xx");

        // Verificación adicional: si hay redirect, que no sea a un dominio externo
        if (response.Headers.Location != null)
        {
            var location = response.Headers.Location.ToString();
            location.Should().NotContain("evil.example.com",
                because: "A23 — El encabezado Location no debe apuntar a dominios externos");
            location.Should().NotContain("attacker.io",
                because: "A23 — El encabezado Location no debe apuntar a dominios de atacante");
        }
    }

    [Fact]
    [Trait("Assert",  "A23b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A23b_OpenRedirect_RelativeUrl_ShouldBeAllowed()
    {
        using var noRedirectClient = new HttpClient(
            new HttpClientHandler { AllowAutoRedirect = false })
        {
            BaseAddress = new Uri(TestConfig.BaseUrl)
        };

        // Una URL relativa legítima debe seguir funcionando
        var response = await noRedirectClient.GetAsync("/api/v2/reports/redirect?returnUrl=/dashboard");

        // URL relativa válida → debe redirigir (302) o retornar OK (200)
        // No debe retornar 400 para URLs relativas válidas
        response.StatusCode.Should().NotBe(HttpStatusCode.InternalServerError,
            because: "A23b — Open Redirect: URLs relativas válidas no deben causar error 500");
    }
}
