namespace CisEng.FunctionApps.Assessments;

// Connects to a target cloud environment and evaluates individual checks.
// The stub below returns deterministic results so the app runs end-to-end today;
// replace it with real Azure (Azure.Identity + ARM/Microsoft Graph) and AWS (AWS SDK) logic.
public interface ICloudConnector
{
    Task ConnectAsync(CancellationToken ct);
    bool Evaluate(string checkId);
}

public sealed class AssessmentContext
{
    public required AssessmentRequest Request { get; init; }
    public required ICloudConnector Connector { get; init; }
}

public interface IAssessmentCheck
{
    string Id { get; }
    string Framework { get; }
    string Title { get; }
    Severity Severity { get; }
    Task<Finding> RunAsync(AssessmentContext ctx, CancellationToken ct);
}

// A metadata-driven check. Real checks that query cloud APIs can implement IAssessmentCheck directly.
public sealed class SimpleCheck : IAssessmentCheck
{
    public string Id { get; }
    public string Framework { get; }
    public string Title { get; }
    public Severity Severity { get; }
    public string Recommendation { get; }

    public SimpleCheck(string id, string framework, string title, Severity severity, string recommendation)
    {
        Id = id;
        Framework = framework;
        Title = title;
        Severity = severity;
        Recommendation = recommendation;
    }

    public Task<Finding> RunAsync(AssessmentContext ctx, CancellationToken ct)
    {
        bool pass = ctx.Connector.Evaluate(Id);
        return Task.FromResult(new Finding
        {
            CheckId = Id,
            Framework = Framework,
            Title = Title,
            Severity = Severity,
            Status = pass ? "Pass" : "Fail",
            Resource = ctx.Request.Cloud == "aws" ? ctx.Request.AwsAccountId : ctx.Request.TargetTenantId,
            Recommendation = pass ? null : Recommendation,
            Details = pass ? "Compliant." : "Non-compliant configuration detected."
        });
    }
}

public static class AssessmentCatalog
{
    public static readonly IReadOnlyList<(string Key, string Name)> Frameworks = new[]
    {
        ("zero-trust", "Zero Trust"),
        ("iso-27001", "ISO 27001"),
        ("cis-azure", "CIS Benchmark — Azure"),
        ("cis-aws", "CIS Benchmark — AWS"),
    };

    public static readonly IReadOnlyList<IAssessmentCheck> All = new List<IAssessmentCheck>
    {
        // --- Zero Trust ---
        new SimpleCheck("zt-mfa", "zero-trust", "Multi-factor authentication enforced for all users", Severity.High, "Enforce MFA for all users via a Conditional Access policy."),
        new SimpleCheck("zt-legacy-auth", "zero-trust", "Legacy authentication protocols blocked", Severity.High, "Block legacy authentication with Conditional Access."),
        new SimpleCheck("zt-pim", "zero-trust", "Privileged roles use just-in-time access (PIM)", Severity.Medium, "Enable Entra Privileged Identity Management for privileged roles."),
        new SimpleCheck("zt-device", "zero-trust", "Device compliance required for access", Severity.Low, "Require compliant or hybrid-joined devices in Conditional Access."),

        // --- ISO 27001 ---
        new SimpleCheck("iso-encryption", "iso-27001", "Data encrypted at rest", Severity.High, "Enable encryption at rest across all data stores."),
        new SimpleCheck("iso-access", "iso-27001", "Least-privilege access control enforced", Severity.Medium, "Apply least-privilege RBAC and review access regularly."),
        new SimpleCheck("iso-logging", "iso-27001", "Security logging and monitoring enabled", Severity.Medium, "Centralize logs and configure alerting."),
        new SimpleCheck("iso-backup", "iso-27001", "Backup and recovery configured and tested", Severity.Low, "Configure and periodically test backups for critical workloads."),

        // --- CIS Azure ---
        new SimpleCheck("cis-az-storage-public", "cis-azure", "Storage accounts disallow public blob access", Severity.High, "Set allowBlobPublicAccess=false on all storage accounts."),
        new SimpleCheck("cis-az-defender", "cis-azure", "Microsoft Defender for Cloud enabled", Severity.High, "Enable Defender for Cloud on all subscriptions."),
        new SimpleCheck("cis-az-kv-purge", "cis-azure", "Key Vaults have soft delete and purge protection", Severity.Medium, "Enable soft delete and purge protection on all Key Vaults."),
        new SimpleCheck("cis-az-nsg-flowlogs", "cis-azure", "NSG flow logs enabled", Severity.Low, "Enable NSG flow logs and send them to a Log Analytics workspace."),

        // --- CIS AWS ---
        new SimpleCheck("cis-aws-root-mfa", "cis-aws", "Root account has MFA enabled", Severity.High, "Enable hardware MFA on the AWS root account."),
        new SimpleCheck("cis-aws-s3-public", "cis-aws", "S3 buckets block public access", Severity.High, "Enable S3 Block Public Access at the account level."),
        new SimpleCheck("cis-aws-cloudtrail", "cis-aws", "CloudTrail enabled across all regions", Severity.Medium, "Enable a multi-region CloudTrail trail with log file validation."),
        new SimpleCheck("cis-aws-iam-password", "cis-aws", "Strong IAM password policy configured", Severity.Low, "Configure a strong IAM password policy."),
    };

    public static readonly IReadOnlyDictionary<string, IAssessmentCheck> ById =
        All.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);

    public static IEnumerable<string> ChecksFor(IEnumerable<string> frameworks)
    {
        var set = new HashSet<string>(frameworks, StringComparer.OrdinalIgnoreCase);
        return All.Where(c => set.Contains(c.Framework)).Select(c => c.Id);
    }
}

// Deterministic stub so demos are stable per target. Replace with real connectors.
public sealed class StubCloudConnector : ICloudConnector
{
    private readonly AssessmentRequest _request;

    public StubCloudConnector(AssessmentRequest request) => _request = request;

    public Task ConnectAsync(CancellationToken ct) => Task.CompletedTask;

    public bool Evaluate(string checkId)
    {
        var seed = $"{_request.TargetTenantId}:{_request.AwsAccountId}:{checkId}";
        int hash = 17;
        foreach (char ch in seed)
        {
            hash = unchecked(hash * 31 + ch);
        }
        return Math.Abs(hash) % 10 >= 4; // ~60% compliant
    }
}

public static class CloudConnectorFactory
{
    // TODO: return a real connector per request.Cloud using the supplied service principal
    // (Azure: Azure.Identity ClientSecretCredential + ARM/Graph) or role ARN (AWS: AWS SDK).
    public static ICloudConnector Create(AssessmentRequest request) => new StubCloudConnector(request);
}
