using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

using System.IO;

namespace SecurityAsserts.Grupo5_Servidor;

/// <summary>
/// Assert A28 — Datos sensibles registrados en logs (Sensitive Data in Logs)
/// El endpoint POST /webhooks/receive no debe exponer el contenido completo
/// del body del webhook en la respuesta HTTP. Los logs no son verificables
/// directamente desde un assert HTTP, por eso se valida que la respuesta
/// no refleje el payload (información observable por el atacante).
///
/// Complementariamente, POST /auth/login (G5-V2) no debe devolver
/// las credenciales en la respuesta ni en cabeceras.
///
/// Oleada 2 — WRN
/// OWASP API8:2023 / CWE-532
/// </summary>
public class G5_SensitiveLogs_Asserts
{
    private static string GetTargetLogPath()
    {
        var isPatched = TestConfig.BaseUrl.Contains("5002");
        var root = isPatched
            ? "C:\\Trabajo\\Universidad\\Desarrollo\\VulnerableApi_Patched\\bin\\Debug\\net8.0"
            : "C:\\Trabajo\\Universidad\\Desarrollo\\VulnerableApi\\bin\\Debug\\net8.0";

        return Path.Combine(root, "logs", "app.log");
    }

    private static string ReadLogTail()
    {
        var path = GetTargetLogPath();
        if (!File.Exists(path))
            return string.Empty;

        return File.ReadAllText(path);
    }

    [Fact]
    [Trait("Assert",  "A28")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A28_SensitiveLog_WebhookResponseShouldNotReflectPayload()
    {
        using var client = TestConfig.CreateClient();

        // Payload con marcador único y datos sensibles simulados
        var uniqueMarker    = "SENSITIVE-MARKER-7f3a9c2e";
        var sensitiveSecret = "supersecret-api-key-12345";

        var payload = new StringContent(
            $$"""{"eventType":"order.created","marker":"{{uniqueMarker}}","apiKey":"{{sensitiveSecret}}"}""",
            System.Text.Encoding.UTF8,
            "application/json");

        var response = await client.PostAsync("/api/v2/webhooks/receive", payload);
        var body = await response.Content.ReadAsStringAsync();

        // La respuesta no debe reflejar el contenido del payload (no data reflection)
        body.Should().NotContain(uniqueMarker,
            because: "A28 — Los datos del webhook no deben reflejarse en la respuesta HTTP");
        body.Should().NotContain(sensitiveSecret,
            because: "A28 — Datos sensibles del payload no deben aparecer en la respuesta");
    }

    [Fact]
    [Trait("Assert",  "A28b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A28b_SensitiveLog_LoginResponseShouldNotReturnPassword()
    {
        using var client = TestConfig.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v2/auth/login",
            new { email = TestConfig.UserAEmail, password = TestConfig.UserAPassword });

        var body = await response.Content.ReadAsStringAsync();

        // La respuesta de login no debe devolver la contraseña en texto plano
        body.Should().NotContain(TestConfig.UserAPassword,
            because: "A28b — La respuesta de login no debe contener la contraseña en texto claro");

        // Tampoco en cabeceras
        foreach (var header in response.Headers)
        {
            var headerValues = string.Join(",", header.Value);
            headerValues.Should().NotContain(TestConfig.UserAPassword,
                because: $"A28b — La contraseña no debe aparecer en la cabecera '{header.Key}'");
        }
    }

    [Fact]
    [Trait("Assert",  "A28c")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A28c_SensitiveLog_ErrorResponseShouldNotContainCredentials()
    {
        using var client = TestConfig.CreateClient();

        // Login fallido — el mensaje de error no debe revelar qué campo es incorrecto
        // ni reflejar la contraseña enviada
        var fakePassword = "wrong-password-unique-9z7x";
        var response = await client.PostAsJsonAsync("/api/v2/auth/login",
            new { email = TestConfig.UserAEmail, password = fakePassword });

        var body = await response.Content.ReadAsStringAsync();

        body.Should().NotContain(fakePassword,
            because: "A28c — La contraseña enviada no debe aparecer en el mensaje de error");
    }

    [Fact]
    [Trait("Assert",  "A28d")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A28d_LoginCredentialsShouldLeakIntoApplicationLogsOnVulnerableApi()
    {
        using var client = TestConfig.CreateClient();
        var uniquePassword = $"P@ssA28d-{Guid.NewGuid():N}";

        var response = await client.PostAsJsonAsync("/api/v2/auth/login",
            new { email = TestConfig.UserAEmail, password = uniquePassword });

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.OK, HttpStatusCode.Unauthorized },
            because: "A28d — El login puede fallar si la contraseña no se reconoce; lo importante es verificar si se registra en logs");

        var logText = ReadLogTail();
        var hasLeak = logText.Contains(TestConfig.UserAEmail) && logText.Contains(uniquePassword);

        if (TestConfig.BaseUrl.Contains("5002"))
        {
            hasLeak.Should().BeFalse(
                because: "A28d — La API parcheada no debe registrar credenciales ni password en el archivo de logs");
        }
        else
        {
            hasLeak.Should().BeTrue(
                because: "A28d — La API vulnerable registra email y password en texto plano en el log");
        }
    }

    [Fact]
    [Trait("Assert",  "A28e")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A28e_WebhookPayloadShouldLeakIntoApplicationLogsOnVulnerableApi()
    {
        using var client = TestConfig.CreateClient();
        var marker = $"WEBHOOK-TRACE-{Guid.NewGuid():N}";
        var secret = $"api-key-{Guid.NewGuid():N}";

        var payload = new StringContent(
            $$"""{"eventType":"order.created","marker":"{{marker}}","apiKey":"{{secret}}"}""",
            System.Text.Encoding.UTF8,
            "application/json");

        var response = await client.PostAsync("/api/v2/webhooks/receive", payload);
        var body = await response.Content.ReadAsStringAsync();

        body.Should().NotBeNullOrEmpty();

        var logText = ReadLogTail();
        var hasLeak = logText.Contains(marker) && logText.Contains(secret);

        if (TestConfig.BaseUrl.Contains("5002"))
        {
            hasLeak.Should().BeFalse(
                because: "A28e — La API parcheada no debe registrar el payload completo del webhook en el archivo de logs");
        }
        else
        {
            hasLeak.Should().BeTrue(
                because: "A28e — La API vulnerable registra el payload completo del webhook en el log");
        }
    }
}
