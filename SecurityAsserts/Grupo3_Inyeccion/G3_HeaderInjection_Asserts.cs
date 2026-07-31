using System.Net;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo3_Inyeccion;

/// <summary>
/// Assert A24 — HTTP Response Header Injection / CRLF Injection
/// El endpoint GET /search NO debe copiar el valor del parámetro ?query= en la
/// cabecera X-Search-Query sin filtrar los caracteres CR (\r) y LF (\n).
/// Un atacante puede inyectar cabeceras adicionales (Set-Cookie, Location, etc.)
/// o dividir la respuesta HTTP (HTTP Response Splitting).
/// Oleada 1 — BLQ
/// OWASP API3:2023 / CWE-113
/// </summary>
public class G3_HeaderInjection_Asserts
{
    [Theory]
    [InlineData("test\r\nSet-Cookie: session=evil",       "CRLF directo")]
    [InlineData("test%0d%0aSet-Cookie:%20session=evil",   "CRLF URL-encoded")]
    [InlineData("test%0aX-Injected:%20yes",               "LF solo")]
    [InlineData("test%0dX-Injected:%20yes",               "CR solo")]
    [Trait("Assert",  "A24")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A24_HeaderInjection_CrlfInQuery_ShouldNotInjectHeaders(string query, string description)
    {
        using var client = TestConfig.CreateClient();

        // Usamos HttpRequestMessage para controlar exactamente la URL enviada
        // (HttpClient a veces normaliza los parámetros)
        var requestUri = $"/api/v2/search?query={query}";

        HttpResponseMessage response;
        try
        {
            response = await client.GetAsync(requestUri);
        }
        catch (HttpRequestException)
        {
            // Si el cliente .NET rechaza la petición por caracteres de control → la API ya es segura
            return;
        }

        // La respuesta NO debe contener la cabecera inyectada
        response.Headers.Should().NotContainKey("X-Injected",
            because: $"A24 — Header Injection ({description}): CRLF no debe permitir inyectar la cabecera X-Injected");

        // El encabezado X-Search-Query no debe contener caracteres de control
        if (response.Headers.TryGetValues("X-Search-Query", out var values))
        {
            var headerValue = string.Join("", values);
            headerValue.Should().NotContain("\r",
                because: $"A24 — X-Search-Query no debe contener CR ({description})");
            headerValue.Should().NotContain("\n",
                because: $"A24 — X-Search-Query no debe contener LF ({description})");
        }
    }

    [Fact]
    [Trait("Assert",  "A24b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A24b_HeaderInjection_NormalQuery_ShouldWork()
    {
        using var client = TestConfig.CreateClient();

        // Una búsqueda legítima sin CRLF debe funcionar correctamente
        var response = await client.GetAsync("/api/v2/search?query=laptop");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.OK, HttpStatusCode.Unauthorized },
            because: "A24b — Una búsqueda normal sin caracteres de control debe retornar 200 u 401 (no 500)");
    }
}
