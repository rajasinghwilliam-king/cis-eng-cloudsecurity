using System.Net;
using System.Reflection;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

namespace CisEng.FunctionApps.Api;

// Serves the single-page UST assessment UI at GET /api/ui.
public static class WebUi
{
    [Function("WebUi")]
    public static async Task<HttpResponseData> Serve(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "ui")] HttpRequestData req)
    {
        var res = req.CreateResponse(HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "text/html; charset=utf-8");
        await res.WriteStringAsync(LoadHtml());
        return res;
    }

    private static string LoadHtml()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("index.html", StringComparison.OrdinalIgnoreCase));

        if (name is null)
        {
            return "<html><body><h1>UI resource not found</h1></body></html>";
        }

        using var stream = asm.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
