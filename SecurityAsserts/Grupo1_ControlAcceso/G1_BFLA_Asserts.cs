using System.Net;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo1_ControlAcceso;

/// <summary>
/// Assert A06 — BFLA (Broken Function Level Authorization)
/// Un usuario con rol "user" NO debe poder ejecutar funciones administrativas.
/// Oleada 1 — BLQ
/// OWASP API5:2023
/// </summary>
public class G1_BFLA_Asserts
{
    [Fact]
    [Trait("Assert",  "A06")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API5:2023")]
    public async Task A06_BFLA_UserRoleCannotDeleteOtherUser_ShouldReturn403()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        // UserA (rol=user) intenta eliminar UserB — función exclusiva de admin
        var response = await client.DeleteAsync($"/api/v2/admin/users/{TestConfig.UserBId}");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            because: "A06 — BFLA: un usuario con rol 'user' NO debe eliminar otros usuarios");
    }

    [Fact]
    [Trait("Assert",  "A06b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API5:2023")]
    public async Task A06b_BFLA_UserRoleCannotPromoteOtherUser_ShouldReturn403()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.PostAsync($"/api/v2/admin/users/{TestConfig.UserBId}/promote", null);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            because: "A06b — BFLA: un usuario con rol 'user' NO debe promover a otros a admin");
    }
}
