using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo8_Webhooks;

/// <summary>
/// Assert A26 — Webhook sin verificación de firma HMAC
/// El endpoint POST /webhooks/receive debe exigir la cabecera X-Hub-Signature-256
/// con un HMAC-SHA256 válido del payload. Sin firma válida debe retornar 401.
/// Oleada 1 — BLQ
/// OWASP API8:2023 / CWE-345
/// </summary>
public class G8_WebhookHmac_Asserts
{
    [Fact]
    [Trait("Assert",  "A26")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A26_Webhook_WithoutHmacSignature_ShouldReturn401()
    {
        using var client = TestConfig.CreateClient();

        var payload = new StringContent(
            """{"eventType":"payment.completed","amount":99999}""",
            System.Text.Encoding.UTF8,
            "application/json");

        // POST sin cabecera X-Hub-Signature-256 — debe rechazarse
        var response = await client.PostAsync("/api/v2/webhooks/receive", payload);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden },
            because: "A26 — Webhook sin HMAC: peticiones sin X-Hub-Signature-256 válida deben retornar 401/403");
    }

    [Fact]
    [Trait("Assert",  "A26b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A26b_Webhook_WithInvalidHmacSignature_ShouldReturn401()
    {
        using var client = TestConfig.CreateClient();

        var payload = new StringContent(
            """{"eventType":"order.created","amount":10}""",
            System.Text.Encoding.UTF8,
            "application/json");

        // Firma deliberadamente inválida (no calculada con la clave compartida real)
        client.DefaultRequestHeaders.Add("X-Hub-Signature-256", "sha256=deadbeefdeadbeefdeadbeef");

        var response = await client.PostAsync("/api/v2/webhooks/receive", payload);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden },
            because: "A26b — Webhook con HMAC falso: una firma incorrecta debe retornar 401/403");
    }

    [Fact]
    [Trait("Assert",  "A26c")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A26c_Webhook_ResponseShouldNotEchoPayloadBack()
    {
        using var client = TestConfig.CreateClient();

        var sensitiveData = "secret-payload-12345-unique-marker";
        var payload = new StringContent(
            $$"""{"eventType":"test","sensitiveField":"{{sensitiveData}}"}""",
            System.Text.Encoding.UTF8,
            "application/json");

        var response = await client.PostAsync("/api/v2/webhooks/receive", payload);
        var body = await response.Content.ReadAsStringAsync();

        // La respuesta no debe devolver el contenido del payload (evitar data reflection)
        body.Should().NotContain(sensitiveData,
            because: "A26c — El servidor no debe reflejar el contenido del webhook en la respuesta");
    }
}
