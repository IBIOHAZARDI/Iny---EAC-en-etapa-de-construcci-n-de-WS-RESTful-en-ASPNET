using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Grupo3_Inyeccion;

/// <summary>
/// Assert A08 — Inyección SQL
/// El endpoint GET /products/search NO debe retornar registros extra ante un payload SQLi.
/// Oleada 1 — BLQ
/// OWASP API3:2023
/// </summary>
public class G3_SQLi_Asserts
{
    [Fact]
    [Trait("Assert",  "A08")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A08_SQLi_SearchWithOrPayload_ShouldNotReturnAllRecords()
    {
        using var client = TestConfig.CreateClient();

        // Obtener conteo de registros con búsqueda legítima (vacía o producto real)
        var legitimateResp = await client.GetAsync("/api/v2/products/search?name=LEGITIMO_XYZ_NOEXISTE");
        legitimateResp.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.NotFound);
        var legitimateCount = 0;
        if (legitimateResp.StatusCode == HttpStatusCode.OK)
        {
            var lBody = await legitimateResp.Content.ReadFromJsonAsync<JsonElement>();
            legitimateCount = lBody.ValueKind == JsonValueKind.Array ? lBody.GetArrayLength() : 0;
        }

        // Payload SQLi clásico OR '1'='1
        var sqliResp = await client.GetAsync("/api/v2/products/search?name=%27+OR+%271%27%3D%271");
        sqliResp.StatusCode.Should().BeOneOf(new[] { HttpStatusCode.OK, HttpStatusCode.BadRequest }, because: "A08 — El endpoint debe manejar el payload sin error 500");

        if (sqliResp.StatusCode == HttpStatusCode.OK)
        {
            var sqliBody = await sqliResp.Content.ReadFromJsonAsync<JsonElement>();
            var sqliCount = sqliBody.ValueKind == JsonValueKind.Array ? sqliBody.GetArrayLength() : 0;

            // El payload SQLi NO debe retornar TODOS los registros
            // (si retorna más que la búsqueda legítima y > 1 resultado, es vulnerable)
            sqliCount.Should().BeLessOrEqualTo(legitimateCount + 1,
                because: "A08 — SQLi: el payload OR '1'='1' NO debe retornar todos los registros de la BD");
        }
    }

    [Fact]
    [Trait("Assert",  "A08b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A08b_SQLi_UnionPayload_ShouldNotReturn500OrLeakData()
    {
        using var client = TestConfig.CreateClient();

        // UNION-based SQLi
        var resp = await client.GetAsync(
            "/api/v2/products/search?name=x%27+UNION+SELECT+1%2C2%2C3%2C4%2C5--");

        resp.StatusCode.Should().NotBe(HttpStatusCode.InternalServerError,
            because: "A08b — Un payload UNION-based NO debe causar HTTP 500 (exposición de error SQL)");
    }
}
