using System.Net;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo1_ControlAcceso;

/// <summary>
/// Asserts A01 y A02 — BOLA (Broken Object Level Authorization)
/// Oleada 1 — BLQ (Bloqueante)
/// OWASP API1:2023
/// </summary>
public class G1_BOLA_Asserts
{
    // ──────────────────────────────────────────────────────
    // A01: Un usuario NO puede acceder al perfil de otro
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A01")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API1:2023")]
    public async Task A01_BOLA_GetUser_UserAAccessingUserBProfile_ShouldReturn403Or404()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.GetAsync($"/api/v2/users/{TestConfig.UserBId}");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Forbidden, HttpStatusCode.NotFound },
            because: "A01 — Un usuario NO debe acceder al perfil de otro usuario (BOLA)");
    }

    // ──────────────────────────────────────────────────────
    // A02: Un usuario NO puede acceder a órdenes de otro
    // ──────────────────────────────────────────────────────
    [Fact]
    [Trait("Assert",  "A02")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API1:2023")]
    public async Task A02_BOLA_GetOrder_UserAAccessingUserBOrder_ShouldReturn403Or404()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.GetAsync($"/api/v2/orders/{TestConfig.UserBOrderId}");

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.Forbidden, HttpStatusCode.NotFound },
            because: "A02 — Un usuario NO debe acceder a órdenes de otro usuario (BOLA)");
    }
}
