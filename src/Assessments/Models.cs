using System.Text.Json.Serialization;

namespace CisEng.FunctionApps.Assessments;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Severity
{
    High,
    Medium,
    Low,
    Informational
}

// Input submitted from the web UI to start an assessment against a target environment.
public sealed class AssessmentRequest
{
    public string TargetTenantId { get; set; } = string.Empty;
    public string Cloud { get; set; } = "azure"; // "azure" | "aws"
    public List<string> Frameworks { get; set; } = new();

    // Azure connection (service principal in the target tenant)
    public string? SubscriptionId { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; } // sensitive — never logged; prefer a Key Vault reference

    // AWS connection
    public string? AwsAccountId { get; set; }
    public string? AwsRoleArn { get; set; }
}

public sealed class Finding
{
    public string CheckId { get; set; } = string.Empty;
    public string Framework { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public string Status { get; set; } = "Fail"; // Pass | Fail | Warning | NotApplicable
    public string? Resource { get; set; }
    public string? Recommendation { get; set; }
    public string? Details { get; set; }
}

public sealed class SeveritySummary
{
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Informational { get; set; }
    public int Passed { get; set; }
    public int Failed { get; set; }
    public int Total { get; set; }
}

public sealed class AssessmentResult
{
    public string TargetTenantId { get; set; } = string.Empty;
    public string Cloud { get; set; } = string.Empty;
    public List<string> Frameworks { get; set; } = new();
    public DateTimeOffset CompletedUtc { get; set; } = DateTimeOffset.UtcNow;
    public SeveritySummary Summary { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();
}

// Input passed from the orchestrator to the RunCheck activity.
public record CheckInput(AssessmentRequest Request, string CheckId);
