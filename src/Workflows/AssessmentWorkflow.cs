using System.Net;
using CisEng.FunctionApps.Assessments;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.DurableTask;
using Microsoft.DurableTask.Client;

namespace CisEng.FunctionApps.Workflows;

public static class AssessmentWorkflow
{
    // Orchestrator: fan out over every check in the selected frameworks, then aggregate.
    [Function(nameof(AssessmentOrchestration))]
    public static async Task<AssessmentResult> AssessmentOrchestration(
        [OrchestrationTrigger] TaskOrchestrationContext context)
    {
        var request = context.GetInput<AssessmentRequest>() ?? new AssessmentRequest();
        var checkIds = AssessmentCatalog.ChecksFor(request.Frameworks).ToList();

        var tasks = checkIds
            .Select(id => context.CallActivityAsync<Finding>(nameof(RunCheck), new CheckInput(request, id)))
            .ToList();

        var findings = (await Task.WhenAll(tasks)).ToList();
        var failed = findings.Where(f => f.Status == "Fail").ToList();

        var summary = new SeveritySummary
        {
            High = failed.Count(f => f.Severity == Severity.High),
            Medium = failed.Count(f => f.Severity == Severity.Medium),
            Low = failed.Count(f => f.Severity == Severity.Low),
            Informational = failed.Count(f => f.Severity == Severity.Informational),
            Passed = findings.Count(f => f.Status == "Pass"),
            Failed = failed.Count,
            Total = findings.Count,
        };

        return new AssessmentResult
        {
            TargetTenantId = request.TargetTenantId,
            Cloud = request.Cloud,
            Frameworks = request.Frameworks,
            CompletedUtc = context.CurrentUtcDateTime,
            Summary = summary,
            Findings = findings
                .OrderBy(f => f.Severity)
                .ThenBy(f => f.Framework)
                .ToList(),
        };
    }

    // Activity: run a single check against the target environment.
    [Function(nameof(RunCheck))]
    public static async Task<Finding> RunCheck([ActivityTrigger] CheckInput input, FunctionContext ctx)
    {
        if (!AssessmentCatalog.ById.TryGetValue(input.CheckId, out var check))
        {
            return new Finding
            {
                CheckId = input.CheckId,
                Title = "Unknown check",
                Status = "NotApplicable",
                Severity = Severity.Informational,
            };
        }

        var connector = CloudConnectorFactory.Create(input.Request);
        await connector.ConnectAsync(CancellationToken.None);
        return await check.RunAsync(
            new AssessmentContext { Request = input.Request, Connector = connector },
            CancellationToken.None);
    }

    // HTTP starter: POST /api/assessments -> starts an orchestration, returns status URLs.
    [Function("StartAssessment")]
    public static async Task<HttpResponseData> StartAssessment(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "assessments")] HttpRequestData req,
        [DurableClient] DurableTaskClient client)
    {
        var request = await req.ReadFromJsonAsync<AssessmentRequest>() ?? new AssessmentRequest();

        if (request.Frameworks is null || request.Frameworks.Count == 0)
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Select at least one framework.");
            return bad;
        }

        if (request.Cloud != "aws" && string.IsNullOrWhiteSpace(request.TargetTenantId))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("targetTenantId is required for Azure assessments.");
            return bad;
        }

        string instanceId = await client.ScheduleNewOrchestrationInstanceAsync(
            nameof(AssessmentOrchestration), request);

        return await client.CreateCheckStatusResponseAsync(req, instanceId);
    }
}
