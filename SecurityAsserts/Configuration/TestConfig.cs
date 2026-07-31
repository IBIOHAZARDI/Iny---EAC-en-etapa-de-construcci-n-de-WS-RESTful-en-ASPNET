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

    public static HttpClient CreateClient() =>
        new HttpClient { BaseAddress = new Uri(BaseUrl), Timeout = TimeSpan.FromSeconds(10) };
}
