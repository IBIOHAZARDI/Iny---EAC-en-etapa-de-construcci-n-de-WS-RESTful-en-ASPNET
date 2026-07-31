using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo8_Webhooks;

/// <summary>
/// Assert A27 — SSRF vía callbackUrl en registro de webhook
/// El endpoint POST /webhooks/register NO debe realizar peticiones HTTP
/// a rangos de IP privadas, loopback, link-local ni esquemas no HTTP/S.
/// Oleada 1 — BLQ
/// OWASP API7:2023 / CWE-918
/// </summary>
public class G8_WebhookSsrf_Asserts
{
    [Theory]
    [InlineData("http://127.0.0.1:5985/wsman",            "loopback WinRM")]
    [InlineData("http://169.254.169.254/latest/meta-data/","AWS metadata")]
    [InlineData("http://192.168.1.1/admin",                "RFC 1918")]
    [InlineData("http://10.0.0.1/",                        "RFC 1918 clase A")]
    [InlineData("http://172.16.0.1/",                      "RFC 1918 clase B")]
    [InlineData("file:///C:/Windows/win.ini",              "file scheme")]
    [Trait("Assert",  "A27")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API7:2023")]
    public async Task A27_WebhookSsrf_PrivateCallbackUrl_ShouldReturn400(string callbackUrl, string description)
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.AdminEmail, TestConfig.AdminPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.PostAsJsonAsync("/api/v2/webhooks/register",
            new { callbackUrl, eventType = "order.created" });

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.BadRequest, HttpStatusCode.Forbidden },
            because: $"A27 — SSRF webhook: callbackUrl a '{description}' ({callbackUrl}) debe rechazarse con 400/403");
    }

    [Fact]
    [Trait("Assert",  "A27b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API7:2023")]
    public async Task A27b_WebhookSsrf_LoopbackUrl_ResponseShouldNotLeakInternalData()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.AdminEmail, TestConfig.AdminPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.PostAsJsonAsync("/api/v2/webhooks/register",
            new { callbackUrl = "http://127.0.0.1/", eventType = "test" });

        var body = await response.Content.ReadAsStringAsync();

        // Si retorna 200, la respuesta no debe filtrar datos de la red interna
        if (response.StatusCode == HttpStatusCode.OK)
        {
            body.Should().NotContainAny(
                new[] { "localhost", "127.0.0.1", "::1", "internal", "hostname" },
                because: "A27b — SSRF webhook: la respuesta no debe contener datos de red interna");
        }
    }

    [Fact]
    [Trait("Assert",  "A27c")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API7:2023")]
    public async Task A27c_WebhookRegister_RequiresAuthentication()
    {
        using var client = TestConfig.CreateClient();
        // Sin token — registro de webhooks debe requerir autenticación

        var response = await client.PostAsJsonAsync("/api/v2/webhooks/register",
            new { callbackUrl = "https://external-valid.example.com/hook", eventType = "order.created" });

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden },
            because: "A27c — El endpoint /webhooks/register debe requerir autenticación");
    }
}
