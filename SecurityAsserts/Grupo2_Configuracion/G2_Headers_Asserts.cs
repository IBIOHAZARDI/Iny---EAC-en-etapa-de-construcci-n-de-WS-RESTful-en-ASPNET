using System.Net;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo2_Configuracion;

/// <summary>
/// Asserts B01–B05 — Cabeceras de seguridad HTTP
/// Oleada 2 — WRN
/// OWASP API8:2023
/// </summary>
public class G2_Headers_Asserts
{
    private async Task<HttpResponseMessage> GetAnyAuthenticatedResponse()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);
        return await client.GetAsync($"/api/v2/users/{TestConfig.UserAId}");
    }

    [Fact]
    [Trait("Assert",  "B01")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B01_Headers_XContentTypeOptions_ShouldBeNoSniff()
    {
        var response = await GetAnyAuthenticatedResponse();
        response.Headers.TryGetValues("X-Content-Type-Options", out var vals);
        vals.Should().ContainSingle(v => v == "nosniff",
            because: "B01 — La cabecera X-Content-Type-Options: nosniff debe estar presente");
    }

    [Fact]
    [Trait("Assert",  "B02")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B02_Headers_XFrameOptions_ShouldBeDenyOrSameOrigin()
    {
        var response = await GetAnyAuthenticatedResponse();
        response.Headers.TryGetValues("X-Frame-Options", out var vals);
        vals.Should().NotBeNullOrEmpty(because: "B02 — La cabecera X-Frame-Options debe estar presente");
        vals!.Any(v => v.Contains("DENY", StringComparison.OrdinalIgnoreCase)
                    || v.Contains("SAMEORIGIN", StringComparison.OrdinalIgnoreCase))
             .Should().BeTrue(because: "B02 — X-Frame-Options debe ser DENY o SAMEORIGIN");
    }

    [Fact]
    [Trait("Assert",  "B03")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B03_Headers_ContentSecurityPolicy_ShouldBePresent()
    {
        var response = await GetAnyAuthenticatedResponse();
        response.Headers.TryGetValues("Content-Security-Policy", out var vals);
        vals.Should().NotBeNullOrEmpty(
            because: "B03 — La cabecera Content-Security-Policy debe estar presente");
    }

    [Fact]
    [Trait("Assert",  "B04")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B04_Headers_ServerHeader_ShouldNotExposeVersion()
    {
        var response = await GetAnyAuthenticatedResponse();
        response.Headers.TryGetValues("Server", out var vals);
        var serverHeader = vals?.FirstOrDefault() ?? "";
        serverHeader.Should().NotMatchRegex(@"\d+\.\d+",
            because: "B04 — La cabecera Server NO debe exponer la versión del servidor");
    }

    [Fact]
    [Trait("Assert",  "B05")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B05_Headers_XPoweredBy_ShouldNotBePresent()
    {
        var response = await GetAnyAuthenticatedResponse();
        response.Headers.TryGetValues("X-Powered-By", out var vals);
        vals.Should().BeNullOrEmpty(
            because: "B05 — La cabecera X-Powered-By NO debe estar presente");
    }
}
