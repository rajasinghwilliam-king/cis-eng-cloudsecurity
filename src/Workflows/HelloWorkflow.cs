using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.DurableTask;
using Microsoft.DurableTask.Client;

namespace CisEng.FunctionApps.Workflows;

// Sample Durable Functions "workflow". Add one class per workflow under src/Workflows/.
public static class HelloWorkflow
{
    [Function(nameof(HelloOrchestration))]
    public static async Task<List<string>> HelloOrchestration(
        [OrchestrationTrigger] TaskOrchestrationContext context)
    {
        return new List<string>
        {
            await context.CallActivityAsync<string>(nameof(SayHello), "Tokyo"),
            await context.CallActivityAsync<string>(nameof(SayHello), "Seattle"),
            await context.CallActivityAsync<string>(nameof(SayHello), "London"),
        };
    }

    [Function(nameof(SayHello))]
    public static string SayHello([ActivityTrigger] string city) => $"Hello, {city}!";

    [Function("HelloWorkflow_HttpStart")]
    public static async Task<HttpResponseData> HttpStart(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
        [DurableClient] DurableTaskClient client)
    {
        string instanceId = await client.ScheduleNewOrchestrationInstanceAsync(nameof(HelloOrchestration));
        return await client.CreateCheckStatusResponseAsync(req, instanceId);
    }
}
