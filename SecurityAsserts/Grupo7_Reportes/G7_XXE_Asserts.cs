using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo7_Reportes;

/// <summary>
/// Assert A22 — XXE Injection en POST /reports/parse
/// El endpoint NO debe procesar entidades XML externas (SYSTEM / PUBLIC).
/// Oleada 1 — BLQ
/// OWASP API3:2023 / CWE-611
/// </summary>
public class G7_XXE_Asserts
{
    // Payload XXE canónico: intenta leer el archivo de hosts del sistema operativo
    private const string XxePayload = """
        <?xml version="1.0"?>
        <!DOCTYPE report [
          <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
        ]>
        <report>
          <title>&xxe;</title>
          <content>test</content>
        </report>
        """;

    // Payload de SSRF vía XXE: el parser realiza petición HTTP al resolver la entidad
    private const string XxeSsrfPayload = """
        <?xml version="1.0"?>
        <!DOCTYPE report [
          <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
        ]>
        <report>
          <title>&xxe;</title>
          <content>ssrf</content>
        </report>
        """;

    [Fact]
    [Trait("Assert",  "A22")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    [Trait("OWASP",   "API10:2023")]
    public async Task A22_XXE_LocalFileEntity_ShouldBeRejected()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var content = new StringContent(XxePayload, System.Text.Encoding.UTF8, "application/xml");
        var response = await client.PostAsync("/api/v2/reports/parse", content);

        // Debe rechazar el XML con DTD/entidades externas — no retornar 200 con el contenido del archivo
        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.BadRequest, HttpStatusCode.Forbidden, HttpStatusCode.UnsupportedMediaType, HttpStatusCode.InternalServerError },
            because: "A22 — XXE: entidades XML externas deben ser rechazadas (DtdProcessing.Prohibit)");
    }

    [Fact]
    [Trait("Assert",  "A22b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    [Trait("OWASP",   "API10:2023")]
    public async Task A22b_XXE_LocalFileEntity_ResponseShouldNotContainFileContent()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var content = new StringContent(XxePayload, System.Text.Encoding.UTF8, "application/xml");
        var response = await client.PostAsync("/api/v2/reports/parse", content);
        var body = await response.Content.ReadAsStringAsync();

        // Si retorna 200, el cuerpo NO debe contener líneas del archivo hosts del SO
        if (response.StatusCode == HttpStatusCode.OK)
        {
            body.Should().NotContainAny(
                new[] { "localhost", "127.0.0.1", "::1", "hosts" },
                because: "A22b — XXE: la respuesta no debe contener el contenido de archivos del sistema");
        }
    }

    [Fact]
    [Trait("Assert",  "A22c")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    [Trait("OWASP",   "API10:2023")]
    public async Task A22c_XXE_SsrfViaXml_ShouldNotLeakCloudMetadata()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var content = new StringContent(XxeSsrfPayload, System.Text.Encoding.UTF8, "application/xml");
        var response = await client.PostAsync("/api/v2/reports/parse", content);
        var body = await response.Content.ReadAsStringAsync();

        // La respuesta no debe incluir datos de metadatos de nube
        body.Should().NotContainAny(
            new[] { "ami-id", "instance-id", "iam", "security-credentials" },
            because: "A22c — XXE SSRF: el parser no debe resolver entidades externas a URLs de metadatos de nube");
    }
}
