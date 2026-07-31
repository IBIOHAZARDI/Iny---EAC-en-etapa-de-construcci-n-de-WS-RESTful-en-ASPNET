using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo6_Archivos;

/// <summary>
/// Assert A17 — JWT aceptado vía query string (?token=...)
/// La API NO debe autenticar peticiones con el token en la URL — expone el JWT
/// en logs de servidor, caché de proxies e historial del navegador.
/// Oleada 2 — WRN
/// OWASP API2:2023 / API8:2023
/// </summary>
public class G6_JWTQueryString_Asserts
{
    [Fact]
    [Trait("Assert",  "A17")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API2:2023")]
    public async Task A17_JWT_TokenInQueryString_ShouldNotGrantAccess()
    {
        // 1. Obtener un token válido vía login normal
        using var loginClient = TestConfig.CreateClient();
        var loginResp = await loginClient.PostAsJsonAsync("/api/v2/auth/login",
            new { email = TestConfig.UserAEmail, password = TestConfig.UserAPassword });
        loginResp.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await loginResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        var token = body.GetProperty("token").GetString()!;

        // 2. Intentar acceder al endpoint usando el token en query string (sin cabecera Authorization)
        using var client = new HttpClient { BaseAddress = new Uri(TestConfig.BaseUrl) };
        var response = await client.GetAsync($"/api/v2/users/{TestConfig.UserAId}?token={token}");

        // El servidor NO debe autenticar via query string — debe retornar 401
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "A17 — El JWT NO debe ser aceptado vía query string ?token= (solo vía header Authorization: Bearer)");
    }

    [Fact]
    [Trait("Assert",  "A17b")]
    [Trait("Oleada",  "Oleada2")]
    [Trait("Category","WRN")]
    [Trait("OWASP",   "API8:2023")]
    public async Task A17b_JWT_TokenInQueryString_AuthHeaderStillWorks()
    {
        // Verificar que el Authorization header sigue funcionando correctamente
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        var response = await client.GetAsync($"/api/v2/users/{TestConfig.UserAId}");

        response.StatusCode.Should().BeOneOf(new[] { HttpStatusCode.OK, HttpStatusCode.Forbidden }, because: "A17b — El Authorization: Bearer header debe seguir siendo el mecanismo válido de autenticación");
    }
}
