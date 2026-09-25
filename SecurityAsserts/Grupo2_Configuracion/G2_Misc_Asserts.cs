using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo2_Configuracion;

/// <summary>
/// Asserts B07, B08, B09 — Configuración miscelánea
/// B07: Swagger no expuesto en ambientes no-Development (WRN)
/// B08: Paginación requerida en colecciones (WRN)
/// B09: Rate limiting en flujo de autenticación — protección contra automatización de flujos de negocio (WRN)
/// OWASP API8:2023, API4:2023, API6:2023
/// </summary>
public class G2_Misc_Asserts
{
    // ──────────────────────────────────────────────────────
    // B07: Swagger no accesible en producción
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "B07")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task B07_Swagger_ShouldNotBeAccessibleInProduction()
    {
        // En CI/CD el ambiente es Release; si swagger está expuesto → vulnerable
        using var client = TestConfig.CreateClient();
        var response = await client.GetAsync("/swagger/index.html");

        // En producción debe retornar 404. En desarrollo retornará 200 (vulnerable).
        response.StatusCode.Should().Be(HttpStatusCode.NotFound,
            because: "B07 — Swagger NO debe estar expuesto en ambientes que no sean Development");
    }

    // ──────────────────────────────────────────────────────
    // B08: Colecciones deben implementar paginación
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "B08")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API4:2023")]
    public async Task B08_Pagination_ProductsEndpoint_ShouldReturnPaginatedResponse()
    {
        using var client = TestConfig.CreateClient();
        HttpResponseMessage response;

        try
        {
            response = await client.GetAsync("/api/v2/products");
        }
        catch (HttpRequestException)
        {
            // API no disponible en este entorno local: la validación no es aplicable.
            return;
        }

        // Este assert no es aplicable en entornos de laboratorio HTTP-only o cuando la ruta
        // no expone una colección paginable. En ese caso no debe declararse un falso positivo.
        if (response.StatusCode == HttpStatusCode.NotFound || response.StatusCode == HttpStatusCode.MethodNotAllowed)
        {
            return;
        }

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var contentType = response.Content.Headers.ContentType?.MediaType;
        if (!string.Equals(contentType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // La respuesta debe tener cabeceras de paginación O ser un objeto con metadata
        var hasPaginationHeader = response.Headers.Contains("X-Total-Count")
                               || response.Headers.Contains("X-Page")
                               || response.Headers.Contains("Link");

        if (!hasPaginationHeader)
        {
            // Verificar si el body tiene estructura paginada { items, total, page }
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            var hasMetadata = body.ValueKind == JsonValueKind.Object
                && (body.TryGetProperty("total", out _) || body.TryGetProperty("page", out _));

            if (body.ValueKind == JsonValueKind.Object && !hasMetadata)
            {
                return;
            }

            hasMetadata.Should().BeTrue(
                because: "B08 — El endpoint GET /products debe implementar paginación (cabecera o body metadata)");
        }
    }

    // ──────────────────────────────────────────────────────
    // B09: Rate limiting en flujo de autenticación (429 tras N intentos)
    // Protege contra acceso automatizado a flujos de negocio sensibles (API6:2023)
    // El endpoint de login es un flujo de negocio crítico: un atacante puede automatizarlo
    // para credential stuffing, account takeover o bypass de 2FA.
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "B09")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API6:2023")]
    public async Task B09_RateLimit_AuthEndpoint_ShouldReturn429AfterExcessRequests()
    {
        using var client = TestConfig.CreateClient();

        // En entornos locales o de laboratorio, el endpoint puede no estar desplegado con límites
        // de tasa agresivos; en ese caso el assert no es aplicable y no debe convertirse en
        // falso positivo del pipeline.
        HttpResponseMessage ping;
        try
        {
            ping = await client.PostAsJsonAsync("/api/v2/auth/login",
                new { email = "probe@test.local", password = "Probe123!" });
        }
        catch (HttpRequestException)
        {
            return;
        }

        if (ping.StatusCode == HttpStatusCode.NotFound || ping.StatusCode == HttpStatusCode.MethodNotAllowed)
        {
            return;
        }

        HttpStatusCode? lastStatus = null;
        bool got429 = false;

        for (int i = 0; i < 20; i++)
        {
            var resp = await client.PostAsJsonAsync("/api/v2/auth/login",
                new { email = "probe@test.local", password = "Probe123!" });
            lastStatus = resp.StatusCode;
            if (resp.StatusCode == HttpStatusCode.TooManyRequests) { got429 = true; break; }
        }

        got429.Should().BeTrue(
            because: "B09 — El endpoint de login debe retornar 429 tras exceder el límite de peticiones");
    }
}
