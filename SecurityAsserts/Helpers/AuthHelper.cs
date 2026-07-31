using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using SecurityAsserts.Configuration;
using Xunit;

namespace SecurityAsserts.Helpers;

/// <summary>
/// Utilidades comunes para obtener tokens JWT de los usuarios de prueba.
/// </summary>
public static class AuthHelper
{
    public static async Task<string> GetTokenAsync(HttpClient client, string email, string password)
    {
        var response = await client.PostAsJsonAsync("/api/v2/auth/login",
            new { email, password });
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            $"Login de {email} debe retornar 200");
        var body = await response.Content.ReadFromJsonAsync<AuthResponse>();
        body.Should().NotBeNull();
        body!.Token.Should().NotBeNullOrWhiteSpace();
        return body.Token;
    }

    public static void SetBearer(HttpClient client, string token)
    {
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
    }

    private record AuthResponse(string Token);
}
