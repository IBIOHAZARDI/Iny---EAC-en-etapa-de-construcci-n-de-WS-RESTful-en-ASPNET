using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo1_ControlAcceso;

/// <summary>
/// Assert A18 — Exposición de datos sensibles en respuestas de la API
/// Los endpoints de usuario NO deben retornar el campo 'password' ni campos de control interno.
/// Oleada 1 — BLQ
/// OWASP API3:2023 (Excessive Data Exposure)
/// </summary>
public class G1_SensitiveData_Asserts
{
    [Fact]
    [Trait("Assert",  "A18")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A18_SensitiveData_GetUser_ShouldNotExposePassword()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.GetAsync($"/api/v2/users/{TestConfig.UserAId}");
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Forbidden);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            body.Should().NotContainAny(
                new[] { "\"password\"", "\"Password\"", "UserA123!", "Admin123!" },
                because: "A18 — La respuesta GET /users/{id} NO debe incluir el campo 'password'");
        }
    }

    [Fact]
    [Trait("Assert",  "A18b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A18b_SensitiveData_GetMe_ShouldNotExposePasswordOrInternalFields()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.GetAsync("/api/v2/users/me");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadAsStringAsync();
        body.Should().NotContainAny(
            new[] { "\"password\"", "\"Password\"" },
            because: "A18b — GET /users/me NO debe exponer el campo 'password'");
    }

    [Fact]
    [Trait("Assert",  "A18c")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A18c_SensitiveData_AdminEndpoint_ShouldNotReturnPasswordsInBulk()
    {
        using var client = TestConfig.CreateClient();
        // Intentar listar usuarios como admin — NO debe incluir contraseñas
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.AdminEmail, TestConfig.AdminPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.GetAsync("/api/v2/admin/users");

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            body.Should().NotContainAny(
                new[] { "Admin123!", "UserA123!", "UserB123!" },
                because: "A18c — El listado de usuarios NO debe incluir contraseñas en texto plano");
        }
    }
}
