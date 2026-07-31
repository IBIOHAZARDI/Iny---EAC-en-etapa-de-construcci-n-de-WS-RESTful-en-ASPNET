using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo1_ControlAcceso;

/// <summary>
/// Assert A05 — Mass Assignment (Broken Object Property Level Authorization)
/// Un usuario NO debe poder modificar su propio rol o IsAdmin.
/// Oleada 1 — BLQ
/// OWASP API3:2023 — Broken Object Property Level Authorization (BOPLA)
/// CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
/// </summary>
public class G1_MassAssignment_Asserts
{
    [Fact]
    [Trait("Assert",  "A05")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A05_MassAssignment_UserCannotElevateOwnRole_ShouldNotPersistAdminRole()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        // Intentar auto-asignar rol admin y IsAdmin=true
        var payload = new
        {
            name    = "UserA Hacked",
            email   = TestConfig.UserAEmail,
            role    = "admin",
            isAdmin = true
        };
        var putResp = await client.PutAsJsonAsync($"/api/v2/users/{TestConfig.UserAId}", payload);

        // Si retorna 200 (vulnerable), verificar que el perfil no cambió el rol
        if (putResp.StatusCode == HttpStatusCode.OK)
        {
            var getResp = await client.GetAsync($"/api/v2/users/{TestConfig.UserAId}");
            getResp.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await getResp.Content.ReadFromJsonAsync<JsonElement>();
            var role = body.GetProperty("role").GetString();
            role.Should().NotBe("admin",
                because: "A05 — Mass Assignment: el campo 'role' NO debe ser vinculable por el cliente");
        }
        else
        {
            // 400, 403 son respuestas correctas (campo ignorado o rechazado)
            putResp.StatusCode.Should().BeOneOf(
                new[] { HttpStatusCode.BadRequest, HttpStatusCode.Forbidden },
                because: "A05 — La actualización de 'role' debe ser rechazada");
        }
    }
}
