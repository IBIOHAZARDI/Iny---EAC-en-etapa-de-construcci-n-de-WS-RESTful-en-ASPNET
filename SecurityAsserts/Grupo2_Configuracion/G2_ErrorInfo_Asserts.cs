using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo2_Configuracion;

/// <summary>
/// Assert A12 — Información sensible en respuestas de error
/// Los errores NO deben incluir stack traces, nombres de archivo, ni versiones de framework.
/// Oleada 1 — BLQ
/// OWASP API8:2023
/// </summary>
public class G2_ErrorInfo_Asserts
{
    [Fact]
    [Trait("Assert",  "A12")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A12_ErrorInfo_InvalidRequest_ShouldNotExposeStackTrace()
    {
        using var client = TestConfig.CreateClient();

        // Provocar un error: PUT con body inválido a endpoint que espera un tipo específico
        var content = new StringContent("{\"invalid\": true, \"nested\": {\"deep\": null}}",
            System.Text.Encoding.UTF8, "application/json");
        var response = await client.PutAsync("/api/v2/users/99999", content);

        var body = await response.Content.ReadAsStringAsync();

        body.Should().NotContainAny(
            new[] { "StackTrace", "at System.", "at Microsoft.", "Exception:", ".cs:line " },
            because: "A12 — Las respuestas de error NO deben exponer stack traces ni información interna");
    }

    [Fact]
    [Trait("Assert",  "A12b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A12b_ErrorInfo_NotFoundRoute_ShouldNotExposeInternalDetails()
    {
        using var client = TestConfig.CreateClient();
        var response = await client.GetAsync("/api/v2/nonexistent-endpoint-12345");

        var body = await response.Content.ReadAsStringAsync();
        body.Should().NotContainAny(
            new[] { "Exception", "StackTrace", "Microsoft.AspNetCore", "System.Private" },
            because: "A12b — Rutas inexistentes no deben exponer detalles del framework");
    }

    // A12c provoca una SqliteException real y sin capturar (comilla desbalanceada en
    // FromSqlRaw de ProductsController) para ejercer efectivamente DeveloperExceptionPage,
    // a diferencia de A12/A12b que solo activan errores de model-binding (400).
    [Fact]
    [Trait("Assert",  "A12c")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A12c_ErrorInfo_UnhandledSqlException_ShouldNotExposeStackTrace()
    {
        using var client = TestConfig.CreateClient();

        // Comilla simple desbalanceada rompe la sintaxis SQL en FromSqlRaw y
        // lanza una SqliteException sin manejar -> DeveloperExceptionPage si está activo.
        var response = await client.GetAsync("/api/v2/products/search?name=%27");

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError,
            because: "A12c — El error SQL desbalanceado debe llegar como excepción no manejada (500)");

        var body = await response.Content.ReadAsStringAsync();
        body.Should().NotContainAny(
            new[] { "StackTrace", "at System.", "at Microsoft.", "SqliteException", ".cs:line " },
            because: "A12c — El 500 no debe exponer stack trace ni el tipo de excepción SQL interna");
    }
}

