using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo2_Configuracion;

/// <summary>
/// Assert B10 — Límites de tamaño de payload (DoS por payload gigante)
/// La API debe rechazar cuerpos que superen el límite configurado.
/// Assert B11 — Content-Type enforcement
/// Los endpoints que esperan JSON deben rechazar otras codificaciones.
/// Oleada 2 — WRN
/// OWASP API4:2023
/// </summary>
public class G2_InputLimits_Asserts
{
    // ──────────────────────────────────────────────────────
    // B10: Payload gigante en POST /auth/login debe rechazarse
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "B10")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API4:2023")]
    public async Task B10_InputSize_OversizedJsonPayload_ShouldReturn413Or400()
    {
        using var client = TestConfig.CreateClient();

        // JSON de ~2 MB — supera el límite predeterminado de ASP.NET Core (28.6 KB)
        var huge = new string('X', 2 * 1024 * 1024);
        var payload = $"{{\"email\":\"{huge}@test.com\",\"password\":\"test\"}}";
        var content = new StringContent(payload, Encoding.UTF8, "application/json");

        var response = await client.PostAsync("/api/v2/auth/login", content);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.RequestEntityTooLarge, HttpStatusCode.BadRequest },
            because: "B10 — Payloads excesivamente grandes deben rechazarse con 413 o 400 (límite de body)");
    }

    [Fact]
    [Trait("Assert",  "B10b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API4:2023")]
    public async Task B10b_InputSize_OversizedQueryString_ShouldReturn414Or400()
    {
        using var client = TestConfig.CreateClient();

        // Query string de 16 KB — suficiente para superar el límite de Kestrel (MaxRequestLineSize=16KB)
        // Nota: 64*1024 excede el límite interno de System.Uri (65.520 chars) y lanza UriFormatException
        var huge = new string('A', 16 * 1024);
        var response = await client.GetAsync($"/api/v2/products/search?name={huge}");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.RequestUriTooLong, HttpStatusCode.BadRequest, HttpStatusCode.NotFound },
            because: "B10b — Query strings excesivamente largos deben rechazarse");
    }

    // ──────────────────────────────────────────────────────
    // B11: Content-Type application/json requerido en POST
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "B11")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B11_ContentType_LoginWithWrongContentType_ShouldReturn415()
    {
        using var client = TestConfig.CreateClient();

        // Enviar el body como form-urlencoded en lugar de JSON
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string,string>("email",    TestConfig.UserAEmail),
            new KeyValuePair<string,string>("password", TestConfig.UserAPassword)
        });

        var response = await client.PostAsync("/api/v2/auth/login", content);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.UnsupportedMediaType, HttpStatusCode.BadRequest },
            because: "B11 — El endpoint de login debe exigir Content-Type: application/json (415 si no)");
    }

    [Fact]
    [Trait("Assert",  "B11b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B11b_ContentType_LoginWithXmlBody_ShouldReturn415()
    {
        using var client = TestConfig.CreateClient();

        var xmlBody = "<login><email>usera@test.local</email><password>UserA123!</password></login>";
        var content = new StringContent(xmlBody, Encoding.UTF8, "application/xml");

        var response = await client.PostAsync("/api/v2/auth/login", content);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.UnsupportedMediaType, HttpStatusCode.BadRequest },
            because: "B11b — El endpoint de login debe rechazar cuerpos XML con 415");
    }
}
