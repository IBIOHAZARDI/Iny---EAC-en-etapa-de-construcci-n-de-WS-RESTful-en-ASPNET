using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo1_ControlAcceso;

/// <summary>
/// Assert A19 — IDOR en actualización (usuarios actualizando recursos de otros)
/// Assert A20 — Enumeración de recursos por ID secuencial
/// Oleada 1 — BLQ
/// OWASP API1:2023
/// </summary>
public class G1_IDOR_Asserts
{
    // ──────────────────────────────────────────────────────
    // A19: Un usuario NO puede actualizar el perfil de otro
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A19")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API1:2023")]
    public async Task A19_IDOR_UpdateOtherUserProfile_ShouldReturn403()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        // UserA intenta actualizar el perfil de UserB
        var payload = new { name = "Hacked by UserA", email = TestConfig.UserBEmail };
        var response = await client.PutAsJsonAsync($"/api/v2/users/{TestConfig.UserBId}", payload);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Forbidden, HttpStatusCode.Unauthorized, HttpStatusCode.NotFound },
            because: "A19 — IDOR: un usuario NO debe poder actualizar el perfil de otro usuario");
    }

    // ──────────────────────────────────────────────────────
    // A20: Enumeración de IDs secuenciales — debe haber control de acceso, no solo 404
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A20")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API1:2023")]
    public async Task A20_IDOR_EnumerateUsers_ShouldReturn403NotMixOf200And404()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var successCount = 0;
        // Intentar acceder a IDs 1..10 — solo el propio debe ser accesible
        for (int i = 1; i <= 10; i++)
        {
            var resp = await client.GetAsync($"/api/v2/users/{i}");
            if (resp.StatusCode == HttpStatusCode.OK) successCount++;
        }

        // Si puede acceder a más de 1 usuario (el suyo propio), hay enumeración BOLA
        successCount.Should().BeLessOrEqualTo(1,
            because: "A20 — Enumeración: un usuario solo debe poder acceder a SU propio recurso (máx 1 hit de 10 IDs)");
    }

    // ──────────────────────────────────────────────────────
    // A21: Delete de orden propia debe ser 204; de orden ajena debe ser 403/404
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A21")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API1:2023")]
    public async Task A21_IDOR_DeleteOtherUserOrder_ShouldReturn403Or404()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        // UserA intenta eliminar una orden de UserB
        var response = await client.DeleteAsync($"/api/v2/orders/{TestConfig.UserBOrderId}");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Forbidden, HttpStatusCode.NotFound, HttpStatusCode.MethodNotAllowed },
            because: "A21 — IDOR: un usuario NO debe poder eliminar órdenes de otro usuario");
    }
}
