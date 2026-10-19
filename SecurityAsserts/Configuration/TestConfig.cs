namespace SecurityAsserts.Configuration;

/// <summary>
/// Centraliza la configuración del ambiente de prueba.
/// URL base: variable de entorno TEST_API_URL o http://localhost:5000.
/// </summary>
public static class TestConfig
{
    public static string BaseUrl =>
        Environment.GetEnvironmentVariable("TEST_API_URL")?.TrimEnd('/') ?? "http://localhost:5000";

    // Credenciales sembradas por DataSeeder
    public static string AdminEmail    => "admin@test.local";
    public static string AdminPassword => "Admin123!";
    public static string UserAEmail    => "usera@test.local";
    public static string UserAPassword => "UserA123!";
    public static string UserBEmail    => "userb@test.local";
    public static string UserBPassword => "UserB123!";

    // IDs conocidos (sembrados: userA tiene orderId=1, userB tiene orderId=3)
    public static int UserAId      => 2;
    public static int UserBId      => 3;
    public static int UserAOrderId => 1;
    public static int UserBOrderId => 3;

    // Endpoint HTTP en claro (A10). TEST_API_HTTP_URL, o BaseUrl si ya es http://.
    public static string? HttpUrl =>
        Environment.GetEnvironmentVariable("TEST_API_HTTP_URL")?.TrimEnd('/')
        ?? (BaseUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ? BaseUrl : null);

    // Endpoint HTTPS (C01/C02). TEST_API_HTTPS_URL, o BaseUrl si ya es https://.
    public static string? HttpsUrl =>
        Environment.GetEnvironmentVariable("TEST_API_HTTPS_URL")?.TrimEnd('/')
        ?? (BaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? BaseUrl : null);

    // Handler que acepta el certificado de desarrollo de ASP.NET Core solo para localhost.
    public static HttpClientHandler CreateHandler(bool allowAutoRedirect = true) => new()
    {
        AllowAutoRedirect = allowAutoRedirect,
        ServerCertificateCustomValidationCallback = (msg, _, _, errors) =>
            errors == System.Net.Security.SslPolicyErrors.None
            || msg?.RequestUri?.IsLoopback == true
    };

    public static HttpClient CreateClient() =>
        new HttpClient(CreateHandler()) { BaseAddress = new Uri(BaseUrl), Timeout = TimeSpan.FromSeconds(10) };
}
