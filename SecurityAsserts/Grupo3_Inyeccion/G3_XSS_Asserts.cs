using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo3_Inyeccion;

/// <summary>
/// Assert A09 — Cross-Site Scripting (XSS) reflejado
/// La respuesta NO debe reflejar el payload script sin sanitizar.
/// Oleada 1 — BLQ
/// OWASP API3:2023
/// </summary>
public class G3_XSS_Asserts
{
    private const string XssPayload = "<script>alert('XSS')</script>";
    private const string EncodedPayload = "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E";

    [Fact]
    [Trait("Assert",  "A09")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A09_XSS_CategoryPayload_ShouldNotReflectScriptInBody()
    {
        using var client = TestConfig.CreateClient();

        var response = await client.GetAsync($"/api/v2/products/by-category?category={EncodedPayload}");

        response.StatusCode.Should().NotBe(HttpStatusCode.InternalServerError);

        var body = await response.Content.ReadAsStringAsync();

        // La respuesta NO debe contener el script sin codificar
        body.Should().NotContain("<script>",
            because: "A09 — XSS reflejado: el payload <script> NO debe aparecer sin codificar en la respuesta");
        body.Should().NotContain("alert(",
            because: "A09 — XSS reflejado: funciones JS NO deben reflejarse en la respuesta");
    }

    [Fact]
    [Trait("Assert",  "A09b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A09b_XSS_ContentTypeHeader_ShouldBeApplicationJson()
    {
        using var client = TestConfig.CreateClient();
        var response = await client.GetAsync($"/api/v2/products/by-category?category=test");

        var contentType = response.Content.Headers.ContentType?.MediaType ?? "";
        contentType.Should().Be("application/json",
            because: "A09b — La respuesta debe tener Content-Type: application/json para prevenir interpretación HTML");
    }
}
