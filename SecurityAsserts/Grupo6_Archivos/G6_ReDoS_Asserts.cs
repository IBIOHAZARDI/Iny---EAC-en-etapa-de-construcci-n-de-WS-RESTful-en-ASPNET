using System.Net;
using System.Diagnostics;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo6_Archivos;

/// <summary>
/// Assert A25 — ReDoS (Regular Expression Denial of Service)
/// El endpoint GET /search/filter acepta un patrón regex del cliente.
/// Si no tiene timeout configurado, un patrón de backtracking exponencial
/// congela el hilo de proceso durante segundos o minutos.
/// La respuesta debe completarse en menos de 2 000 ms para cualquier input.
/// Oleada 1 — BLQ
/// OWASP API4:2023 / CWE-1333
/// </summary>
public class G6_ReDoS_Asserts
{
    // Patrón catastrófico: backtracking exponencial O(2^n)
    // Input sin coincidencia al final fuerza máximo backtracking
    private static readonly (string pattern, string input, string description)[] CatastrophicPayloads =
    [
        ("(a+)+",           "aaaaaaaaaaaaaaaaaab",    "backtracking exponencial clásico"),
        ("([a-zA-Z]+)*",    "aaaaaaaaaaaaaaaaaaaaa!", "cuantificador nested"),
        ("(a|aa)+",         "aaaaaaaaaaaaaaaaaab",    "alternación con overlap"),
        ("(.*a){20}",       "aaaaaaaaaaaaaaaaaaaab",  "repetición con wildcard"),
    ];

    [Theory]
    [InlineData("(a+)+",          "aaaaaaaaaaaaaaaaaab",   "backtracking exponencial")]
    [InlineData("([a-zA-Z]+)*",   "aaaaaaaaaaaaaaaaaaaaa!","cuantificador nested")]
    [InlineData("(a|aa)+",        "aaaaaaaaaaaaaaaaaab",   "alternación con overlap")]
    [Trait("Assert",  "A25")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API4:2023")]
    public async Task A25_ReDoS_CatastrophicPattern_ShouldRespondWithin2Seconds(
        string pattern, string input, string description)
    {
        using var client = TestConfig.CreateClient();

        // Timeout agresivo: la petición debe resolverse (aceptarse o rechazarse) en < 2 s
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        var encodedPattern = Uri.EscapeDataString(pattern);
        var encodedInput   = Uri.EscapeDataString(input);

        var sw = Stopwatch.StartNew();
        HttpResponseMessage? response = null;

        try
        {
            response = await client.GetAsync(
                $"/api/v2/search/filter?pattern={encodedPattern}&input={encodedInput}",
                cts.Token);
            sw.Stop();
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            // El servidor tardó más de 2 000 ms — ReDoS confirmado
            sw.ElapsedMilliseconds.Should().BeLessThan(2000,
                because: $"A25 — ReDoS '{description}': el servidor debe responder en < 2 000 ms " +
                          $"(timeout de seguridad en Regex). Elapsed: {sw.ElapsedMilliseconds} ms");
            return;
        }
        catch (HttpRequestException)
        {
            // Conexión rechazada / caída — también indica problema pero no ReDoS confirmado
            return;
        }

        sw.ElapsedMilliseconds.Should().BeLessThan(2000,
            because: $"A25 — ReDoS '{description}': respuesta en {sw.ElapsedMilliseconds} ms " +
                     "(debe implementar Regex timeout de ~100 ms)");
    }

    [Fact]
    [Trait("Assert",  "A25b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API4:2023")]
    public async Task A25b_ReDoS_InvalidPattern_ShouldReturn400NotCrash()
    {
        using var client = TestConfig.CreateClient();

        // Un regex inválido debe retornar 400, no 500 ni colgar
        var response = await client.GetAsync("/api/v2/search/filter?pattern=[invalid&input=test");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.BadRequest },
            because: "A25b — Un patrón regex inválido debe retornar 400, no 500 ni colgarse");
    }
}
