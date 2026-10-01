// =====================================================================================
//  UST Cloud Security Assessment - the whole Function App in one file.
//
//  Sections
//    1. Host                 - Functions isolated worker bootstrap (Program.Main)
//    2. Vocabulary           - enums and fixed lists mirrored from microsoft/zerotrustassessment
//    3. Models               - request, check, finding, summary, result
//    4. Catalog              - 336 Zero Trust checks + ISO 27001 / CIS checks
//    5. Connectors           - ICloudConnector abstraction + deterministic stub
//    6. Durable workflow     - orchestration (fan-out / fan-in) + RunCheck activity
//    7. HTTP API             - GET /api/ui, GET /api/catalog, POST /api/assessments,
//                              GET /api/assessments/{instanceId}
//
//  Parameter names follow the Zero Trust Assessment PowerShell module
//  (Connect-ZtAssessment / Invoke-ZtAssessment) so the request body reads the same way.
// =====================================================================================

using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.DurableTask;
using Microsoft.DurableTask.Client;
using Microsoft.Extensions.Hosting;

namespace CisEng.FunctionApps;

// ------------------------------------------------------------------------------------
// 1. Host
// ------------------------------------------------------------------------------------
public static class Program
{
    public const string Version = "1.0.0";

    public static void Main()
    {
        new HostBuilder()
            .ConfigureFunctionsWorkerDefaults()
            .Build()
            .Run();
    }
}

// ------------------------------------------------------------------------------------
// 2. Vocabulary (values taken from the Zero Trust Assessment module)
// ------------------------------------------------------------------------------------

// [ZtTest].RiskLevel / Add-ZtTestResultDetail -Risk
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Risk { Critical, High, Medium, Low, Unranked }

// [ZtTest].UserImpact and .ImplementationCost (Catastrophic exists only on -UserImpact)
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Level { Low, Medium, High, Catastrophic }

// TestStatus values written to the report JSON. Suppressed comes from the CIS audit tool:
// an accepted risk with a justification and expiry; it is excluded from the compliance score.
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TestStatus { Passed, Failed, Skipped, Planned, Investigate, Error, Suppressed }

// Add-ZtTestResultDetail -SkippedBecause
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SkipReason
{
    None,
    NotConnectedAzure, NotConnectedExchange, NotConnectedSecurityCompliance, NotConnectedToService,
    NotLicensedEntraIDP1, NotLicensedEntraIDP2, NotLicensedEntraIDGovernance, NotLicensedEntraWorkloadID,
    NotLicensedIntune, NotSupported, UnderConstruction, NoAzureAccess, NotApplicable, NotDotGovDomain,
    NoCompatibleLicenseFound, TimeoutReached
}

public static class Vocabulary
{
    // Invoke-ZtAssessment -Pillar (minus "All")
    public static readonly string[] Pillars = { "Identity", "Devices", "Network", "Data", "Infrastructure", "SecOps", "AI" };

    // Connect-ZtAssessment -Service (minus "All")
    public static readonly string[] Services = { "Graph", "Azure", "AipService", "ExchangeOnline", "SecurityCompliance", "SharePointOnline" };

    // Connect-ZtAssessment -Environment
    public static readonly string[] Environments = { "Global", "China", "Germany", "USGov", "USGovDoD" };

    // Connect-ZtAssessment -ExchangeEnvironmentName
    public static readonly string[] ExchangeEnvironments = { "O365Default", "O365China", "O365GermanyCloud", "O365USGovDoD", "O365USGovGCCHigh" };

    // Get-ZtTest -TenantType / [ZtTest].TenantType
    public static readonly string[] TenantTypes = { "Workforce", "External" };

    // Microsoft Secure Future Initiative pillars used by [ZtTest].SfiPillar
    public static readonly string[] SfiPillars =
    {
        "Protect identities and secrets",
        "Protect tenants and isolate production systems",
        "Protect tenants and production systems",
        "Protect networks",
        "Protect engineering systems",
        "Monitor and detect cyberthreats",
        "Accelerate response and remediation",
    };

    // Get-ZtGraphScope: read-only Microsoft Graph scopes the assessment identity needs.
    public static readonly string[] GraphScopes =
    {
        "Application.Read.All", "AuditLog.Read.All", "CopilotPackages.Read.All", "CrossTenantInformation.ReadBasic.All",
        "CustomSecAttributeAssignment.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All",
        "DeviceManagementManagedDevices.Read.All", "DeviceManagementRBAC.Read.All", "DeviceManagementServiceConfig.Read.All",
        "Directory.Read.All", "DirectoryRecommendations.Read.All", "EntitlementManagement.Read.All", "IdentityRiskEvent.Read.All",
        "IdentityRiskyServicePrincipal.Read.All", "IdentityRiskyUser.Read.All", "LifecycleWorkflows-Workflow.Read.All",
        "NetworkAccess.Read.All", "Policy.Read.All", "Policy.Read.ConditionalAccess", "Policy.Read.PermissionGrant",
        "PrivilegedAccess.Read.AzureAD", "PrivilegedAssignmentSchedule.Read.AzureADGroup", "PrivilegedEligibilitySchedule.Read.AzureADGroup",
        "Reports.Read.All", "RoleManagement.Read.All", "SecurityAlert.Read.All", "SecurityEvents.Read.All",
        "SecurityIdentitiesHealth.Read.All", "SecurityIdentitiesSensors.Read.All", "SecurityIncident.Read.All",
        "ThreatHunting.Read.All", "UserAuthenticationMethod.Read.All",
    };

    // Get-ZtSkippedReason: user-facing text for each skip reason. {0} is the detail (service list / licenses).
    public static string SkipText(SkipReason reason, string? detail = null) => reason switch
    {
        SkipReason.NotConnectedAzure => "Not connected to Azure.",
        SkipReason.NotConnectedExchange => "Not connected to Exchange Online.",
        SkipReason.NotConnectedSecurityCompliance => "Not connected to Security & Compliance.",
        SkipReason.NotDotGovDomain => "This test is only for federal, executive branch, departments and agencies.",
        SkipReason.NotLicensedEntraIDP1 => "This test is for tenants that are licensed for Entra ID P1.",
        SkipReason.NotLicensedEntraIDP2 => "This test is for tenants that are licensed for Entra ID P2.",
        SkipReason.NotLicensedEntraIDGovernance => "This test is for tenants that are licensed for Entra ID Governance.",
        SkipReason.NotLicensedEntraWorkloadID => "This test is for tenants that are licensed for Entra Workload ID.",
        SkipReason.NotLicensedIntune => "This test is for tenants that are licensed for Microsoft Intune.",
        SkipReason.NotSupported => "This test relies on capabilities not currently available in this environment.",
        SkipReason.NoAzureAccess => "The assessment identity does not have access to an Azure subscription to perform this test.",
        SkipReason.NotApplicable => "This test is not applicable to the current environment.",
        SkipReason.UnderConstruction => "This test is planned and not yet implemented.",
        SkipReason.NotConnectedToService => $"This test requires connection to the service(s) \"{detail}\" which are not connected. Add them under Services and run again.",
        SkipReason.NoCompatibleLicenseFound => $"This test requires one of the following licenses: (\"{detail}\"). Ensure the tenant has an appropriate license.",
        SkipReason.TimeoutReached => "This test was not completed because the assessment exceeded the configured timeout.",
        _ => string.Empty,
    };
}

// ------------------------------------------------------------------------------------
// 3. Models
// ------------------------------------------------------------------------------------

// Everything the web page submits. Property names mirror the PowerShell parameters.
public sealed class AssessmentRequest
{
    // --- Connect-ZtAssessment ---
    public string TenantId { get; set; } = string.Empty;                 // -TenantId (alias -Tenant)
    public string Environment { get; set; } = "Global";                  // -Environment
    public string? ClientId { get; set; }                                // -ClientId (app registration)
    public string? ClientSecret { get; set; }                            // sensitive: never logged; prefer a Key Vault reference
    public string? CertificateThumbprint { get; set; }                   // -Certificate (alternative to a secret)
    public List<string> Services { get; set; } = new() { "All" };        // -Service
    public string ExchangeEnvironmentName { get; set; } = "O365Default"; // -ExchangeEnvironmentName
    public string? UserPrincipalName { get; set; }                       // -UserPrincipalName (Security & Compliance)
    public string? SharePointAdminUrl { get; set; }                      // -SharePointAdminUrl

    // --- Invoke-ZtAssessment ---
    public List<string> Frameworks { get; set; } = new() { "zero-trust" }; // UST addition: which catalogs to run
    public List<string> Pillars { get; set; } = new() { "All" };           // -Pillar
    public List<string> Tests { get; set; } = new();                       // -Tests (specific IDs; empty = all)
    public string TenantType { get; set; } = "Workforce";                  // Get-ZtTest -TenantType
    public int Days { get; set; } = 30;                                    // -Days (1..30 sign-in log window)
    public int MaximumSignInLogQueryTime { get; set; } = 60;               // -MaximumSignInLogQueryTime (minutes, 0 = no limit)
    public int TestThrottleLimit { get; set; } = 5;                        // -TestThrottleLimit
    public int TestTimeoutMinutes { get; set; } = 60;                      // -TestTimeout (0 = disabled)
    public bool Preview { get; set; }                                      // -Preview

    // --- Infrastructure pillar (Defender for Cloud) and CIS AWS ---
    public List<string> SubscriptionIds { get; set; } = new();           // Azure subscriptions in scope (CIS: --subscription)
    public string? AwsAccountId { get; set; }
    public string? AwsRoleArn { get; set; }

    // --- CIS Microsoft Azure Foundations Benchmark (vegazbabz/CIS-Azure-Benchmark-Audit-Tool) ---
    public int? CisLevel { get; set; }                                    // --level 1|2 (null = both profiles)
    public List<Suppression> Suppressions { get; set; } = new();          // suppressions.toml entries (accepted risks)

    public bool ConnectsTo(string service) =>
        Services.Contains("All", StringComparer.OrdinalIgnoreCase) ||
        Services.Contains(service, StringComparer.OrdinalIgnoreCase);

    // Returns null when valid, otherwise a message for the caller.
    public string? Validate()
    {
        if (Frameworks.Count == 0) return "Select at least one framework.";
        bool needsTenant = Frameworks.Any(f => !f.Equals("cis-aws", StringComparison.OrdinalIgnoreCase));
        if (needsTenant && string.IsNullOrWhiteSpace(TenantId)) return "tenantId is required.";
        if (needsTenant && !Guid.TryParse(TenantId, out _)) return "tenantId must be a GUID.";
        if (!Vocabulary.Environments.Contains(Environment)) return "environment must be one of: " + string.Join(", ", Vocabulary.Environments);
        if (!Vocabulary.ExchangeEnvironments.Contains(ExchangeEnvironmentName)) return "exchangeEnvironmentName is not valid.";
        if (!Vocabulary.TenantTypes.Contains(TenantType)) return "tenantType must be Workforce or External.";
        if (Days is < 1 or > 30) return "days must be between 1 and 30 (sign-in logs are kept for 30 days).";
        if (MaximumSignInLogQueryTime < 0) return "maximumSignInLogQueryTime cannot be negative.";
        if (TestThrottleLimit < 1) return "testThrottleLimit must be at least 1.";
        if (TestTimeoutMinutes < 0) return "testTimeoutMinutes cannot be negative.";
        if (Pillars.Count == 0) return "Select at least one pillar.";
        foreach (var p in Pillars)
            if (p != "All" && !Vocabulary.Pillars.Contains(p)) return $"Unknown pillar '{p}'.";
        foreach (var s in Services)
            if (s != "All" && !Vocabulary.Services.Contains(s)) return $"Unknown service '{s}'.";
        if (Frameworks.Contains("cis-aws", StringComparer.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(AwsAccountId))
            return "awsAccountId is required for the CIS AWS framework.";
        if (CisLevel is not (null or 1 or 2)) return "cisLevel must be 1, 2 or empty.";
        foreach (var s in Suppressions)
        {
            if (string.IsNullOrWhiteSpace(s.ControlId)) return "Each suppression needs a controlId.";
            if (string.IsNullOrWhiteSpace(s.Justification)) return $"Suppression {s.ControlId} needs a justification.";
            if (!DateOnly.TryParse(s.Expires, out var exp)) return $"Suppression {s.ControlId} needs an ISO expiry date (YYYY-MM-DD).";
            if (exp > DateOnly.FromDateTime(DateTime.UtcNow).AddYears(1)) return $"Suppression {s.ControlId} may expire at most one year from today.";
        }
        return null;
    }
}

// An accepted risk, as in the CIS audit tool's suppressions.toml. Only Failed / Error results can be suppressed;
// expired entries are ignored and the finding reverts to its real status.
public sealed class Suppression
{
    public string ControlId { get; set; } = string.Empty;   // exact match on the check / control ID
    public string? Resource { get; set; }                   // optional, exact case-insensitive match
    public string? Subscription { get; set; }               // optional, exact case-insensitive match
    public string Justification { get; set; } = string.Empty;
    public string Expires { get; set; } = string.Empty;     // ISO date, at most one year ahead

    public bool IsActive(DateTime utcNow) => DateOnly.TryParse(Expires, out var exp) && exp >= DateOnly.FromDateTime(utcNow);

    public bool Matches(Finding f) =>
        string.Equals(ControlId, f.TestId, StringComparison.OrdinalIgnoreCase) &&
        (string.IsNullOrWhiteSpace(Resource) || string.Equals(Resource, f.Resource, StringComparison.OrdinalIgnoreCase));
}

// One entry of the check catalog. Field names mirror the [ZtTest] attribute.
public sealed record Check(
    string Id,
    string Framework,
    string[] Pillars,
    string Category,
    Risk Risk,
    Level UserImpact,
    Level ImplementationCost,
    string SfiPillar,
    string Title,
    string[] TenantType,
    string[] Service,
    string[] MinimumLicense,
    string[] CompatibleLicense,
    string? Recommendation = null,
    string? Profile = null,       // CIS profile applicability: "L1" or "L2"
    bool Manual = false);         // CIS: cannot be automated, needs human review

// One row of the report. Field names mirror the Zero Trust report JSON (Tests[]).
public sealed class Finding
{
    public string TestId { get; set; } = string.Empty;
    public string TestTitle { get; set; } = string.Empty;
    public string Framework { get; set; } = string.Empty;
    public string[] TestPillar { get; set; } = Array.Empty<string>();
    public string TestCategory { get; set; } = string.Empty;
    public Risk TestRisk { get; set; }
    public Level TestImpact { get; set; }
    public Level TestImplementationCost { get; set; }
    public string TestSfiPillar { get; set; } = string.Empty;
    public string[] TestMinimumLicense { get; set; } = Array.Empty<string>();
    public string[] TestService { get; set; } = Array.Empty<string>();
    public string? TestProfile { get; set; }          // CIS: "L1" / "L2"
    public bool TestManual { get; set; }              // CIS: manual control
    public string? SuppressionJustification { get; set; }
    public TestStatus TestStatus { get; set; }
    public SkipReason TestSkipped { get; set; } = SkipReason.None;
    public string? SkippedReason { get; set; }
    public string? TestResult { get; set; }          // markdown
    public string? TestDescription { get; set; }     // markdown
    public string? Recommendation { get; set; }
    public string? Resource { get; set; }
}

public sealed class PillarSummary
{
    public string Pillar { get; set; } = string.Empty;
    public int Passed { get; set; }
    public int Failed { get; set; }
    public int Skipped { get; set; }
    public int Planned { get; set; }
    public int Suppressed { get; set; }
    public int Total { get; set; }   // executed tests (Passed + Failed + Investigate + Error), as in the Microsoft report
}

public sealed class RiskSummary
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Unranked { get; set; }
}

// Tenant overview figures. Null means the connector could not read the value.
public sealed class TenantOverview
{
    public int? UserCount { get; set; }
    public int? GuestCount { get; set; }
    public int? GroupCount { get; set; }
    public int? DeviceCount { get; set; }
    public int? ManagedDeviceCount { get; set; }
    public int? ApplicationCount { get; set; }
}

public sealed class AssessmentResult
{
    public DateTimeOffset ExecutedAt { get; set; }
    public string TenantId { get; set; } = string.Empty;
    public string? TenantName { get; set; }
    public string? Domain { get; set; }
    public string? Account { get; set; }
    public string CurrentVersion { get; set; } = Program.Version;
    public List<string> Frameworks { get; set; } = new();
    public List<string> Pillars { get; set; } = new();
    public string TenantType { get; set; } = "Workforce";
    public List<PillarSummary> TestResultSummary { get; set; } = new();
    public RiskSummary FailedByRisk { get; set; } = new();
    public TenantOverview? TenantInfo { get; set; }
    public List<Finding> Tests { get; set; } = new();
}

// Input to the RunCheck activity.
public sealed record CheckInput(AssessmentRequest Request, string CheckId);

// ------------------------------------------------------------------------------------
// 4. Catalog
// ------------------------------------------------------------------------------------
public static class Catalog
{
    public static readonly IReadOnlyList<(string Key, string Name, string Source)> Frameworks = new[]
    {
        ("zero-trust", "Zero Trust Assessment (Microsoft)", "github.com/microsoft/zerotrustassessment"),
        ("iso-27001", "ISO 27001", "UST catalog"),
        ("cis-azure", "CIS Microsoft Azure Foundations Benchmark v5.0.0", "github.com/vegazbabz/CIS-Azure-Benchmark-Audit-Tool"),
        ("cis-aws", "CIS Benchmark - AWS", "UST catalog"),
    };

    public static readonly IReadOnlyList<Check> All = Build();

    public static readonly IReadOnlyDictionary<string, Check> ById =
        All.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);

    // Resolve the request's scope to concrete checks (frameworks, pillars, explicit IDs, tenant type).
    public static IEnumerable<Check> Select(AssessmentRequest r)
    {
        var frameworks = new HashSet<string>(r.Frameworks, StringComparer.OrdinalIgnoreCase);
        bool allPillars = r.Pillars.Contains("All", StringComparer.OrdinalIgnoreCase);
        var pillars = new HashSet<string>(r.Pillars, StringComparer.OrdinalIgnoreCase);
        var ids = new HashSet<string>(r.Tests.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()), StringComparer.OrdinalIgnoreCase);

        string? level = r.CisLevel is null ? null : $"L{r.CisLevel}";

        return All.Where(c =>
            frameworks.Contains(c.Framework) &&
            (allPillars || c.Pillars.Any(pillars.Contains)) &&
            (ids.Count == 0 || ids.Contains(c.Id)) &&
            (c.TenantType.Length == 0 || c.TenantType.Contains(r.TenantType, StringComparer.OrdinalIgnoreCase)) &&
            (level is null || c.Profile is null || c.Profile == level));
    }

    // CIS section number -> Zero Trust pillar, so CIS controls appear on the pillar pages.
    private static string CisPillar(string section) => section[0] switch
    {
        '2' => "Data",            // Azure Databricks
        '3' => "Infrastructure",  // Compute Services
        '5' => "Identity",        // Identity Services
        '6' => "SecOps",          // Logging and Monitoring
        '7' => "Network",         // Networking Services
        '8' => "Infrastructure",  // Security Services (Defender, Key Vault, Bastion, DDoS)
        '9' => "Data",            // Storage Services
        _ => "Infrastructure",
    };

    // A CIS Microsoft Azure Foundations Benchmark v5.0.0 control, from the audit tool's control catalog.
    // Level 1 is the baseline profile (mapped to High risk); Level 2 is defence in depth (Medium).
    private static Check Cis(string id, string section, int level, string title, bool manual) =>
        new(id, "cis-azure", new[] { CisPillar(section) }, section, level == 1 ? Risk.High : Risk.Medium,
            Level.Low, manual ? Level.Low : Level.Medium, string.Empty, title,
            Array.Empty<string>(), new[] { section.StartsWith('5') ? "Graph" : "Azure" }, Array.Empty<string>(), Array.Empty<string>(),
            null, $"L{level}", manual);

    private static string[] Split(string s) =>
        string.IsNullOrWhiteSpace(s) ? Array.Empty<string>() : s.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // A Zero Trust Assessment test. Arguments follow the [ZtTest] attribute; lists are '|' separated.
    private static Check Zt(int id, string pillars, string category, Risk risk, Level userImpact, Level cost,
        string sfiPillar, string title, string tenantTypes, string services, string minimumLicense, string compatibleLicense) =>
        new(id.ToString(), "zero-trust", Split(pillars), category, risk, userImpact, cost, sfiPillar, title,
            Split(tenantTypes), Split(services), Split(minimumLicense), Split(compatibleLicense));

    // A UST catalog check (ISO 27001 / CIS).
    private static Check Ust(string id, string framework, string pillar, string category, Risk risk, string title,
        string recommendation, string services) =>
        new(id, framework, Split(pillar), category, risk, Level.Low, Level.Medium, string.Empty, title,
            Array.Empty<string>(), Split(services), Array.Empty<string>(), Array.Empty<string>(), recommendation);

    private static List<Check> Build() => new()
    {
        // ---------------- Zero Trust Assessment: 336 tests, generated from tests/Test-Assessment.*.ps1 ----------------
            Zt(21770, "Identity", "Access control", Risk.Medium, Level.High, Level.Low, "Protect engineering systems", "Inactive applications don’t have highly privileged Microsoft Graph API permissions", "Workforce|External", "Graph", "", "AAD_PREMIUM"),
            Zt(21771, "Identity", "Application management", Risk.High, Level.Low, Level.Low, "Protect engineering systems", "Inactive applications don’t have highly privileged built-in roles", "Workforce|External", "Graph", "P1", ""),
            Zt(21772, "Identity", "Application management", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Applications don't have client secrets configured", "Workforce|External", "Graph", "Free", ""),
            Zt(21773, "Identity", "Application management", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Applications don't have certificates with expiration longer than 180 days", "Workforce|External", "", "Free", ""),
            Zt(21774, "Identity", "Application management", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Microsoft services applications don't have credentials configured", "Workforce|External", "", "Free", ""),
            Zt(21775, "Identity", "Application management", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Enforce standards for app secrets and certificates", "Workforce|External", "", "Free", ""),
            Zt(21776, "Identity", "Application management", Risk.High, Level.High, Level.Medium, "Protect identities and secrets", "User consent settings are restricted", "Workforce|External", "", "Free", ""),
            Zt(21777, "Identity", "Access control", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "App instance property lock is configured for all multitenant applications", "Workforce|External", "", "Free", ""),
            Zt(21778, "", "Application management", Risk.Medium, Level.Low, Level.High, "", "Line-of-business and partner apps use MSAL", "Workforce|External", "", "", ""),
            Zt(21779, "", "Application management", Risk.Medium, Level.Low, Level.Medium, "", "Use recent versions of Microsoft Applications", "Workforce|External", "", "", ""),
            Zt(21780, "Identity", "Application management", Risk.Medium, Level.Low, Level.High, "Protect identities and secrets", "No usage of ADAL in the tenant", "Workforce|External", "", "Free", ""),
            Zt(21781, "Identity", "Privileged access", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Privileged users sign in with phishing-resistant methods", "Workforce", "", "P1", ""),
            Zt(21782, "Identity", "Privileged access", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Privileged accounts have phishing-resistant methods registered", "Workforce", "", "P1", ""),
            Zt(21783, "Identity", "Access control", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Privileged Microsoft Entra built-in roles are targeted with Conditional Access policies to enforce phishing-resistant methods", "Workforce", "", "P1", ""),
            Zt(21784, "Identity", "Access control; Credential management", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "All user sign in activity uses phishing-resistant authentication methods", "Workforce|External", "", "P1", ""),
            Zt(21786, "Identity", "Access control", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "User sign-in activity uses token protection", "Workforce|External", "", "P1", ""),
            Zt(21787, "Identity", "Privileged access", Risk.High, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "Permissions to create new tenants are limited to the Tenant Creator role", "Workforce", "", "Free", ""),
            Zt(21788, "Identity", "Privileged access", Risk.High, Level.Low, Level.Low, "Protect engineering systems", "Global Administrators don't have standing access to Azure subscriptions", "Workforce", "", "Free", ""),
            Zt(21789, "Identity", "Monitoring", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Tenant creation events are triaged", "Workforce", "", "", ""),
            Zt(21790, "Identity", "Application management", Risk.High, Level.Medium, Level.High, "Protect tenants and isolate production systems", "Outbound cross-tenant access settings are configured", "Workforce|External", "", "Free", ""),
            Zt(21791, "Identity", "External collaboration", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Guests can’t invite other guests", "Workforce", "", "Free", ""),
            Zt(21792, "Identity", "External collaboration", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Guests have restricted access to directory objects", "Workforce", "", "Free", ""),
            Zt(21793, "Identity", "Application management", Risk.High, Level.Low, Level.Medium, "Protect networks", "Tenant restrictions v2 policy is configured", "Workforce|External", "", "P1", ""),
            Zt(21795, "Identity", "Monitoring", Risk.Medium, Level.High, Level.Low, "Monitor and detect cyberthreats", "No legacy authentication sign-in activity", "Workforce", "", "P1", ""),
            Zt(21796, "Identity", "Access control", Risk.Medium, Level.High, Level.Low, "Protect identities and secrets", "Block legacy authentication policy is configured", "Workforce", "", "P1", ""),
            Zt(21797, "Identity", "Access control", Risk.High, Level.High, Level.Medium, "Accelerate response and remediation", "Restrict access to high risk users", "Workforce|External", "", "P2", ""),
            Zt(21798, "Identity", "Access control", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "ID Protection notifications are enabled", "Workforce|External", "", "P2", ""),
            Zt(21799, "Identity", "Access control", Risk.High, Level.Medium, Level.Medium, "Accelerate response and remediation", "Restrict high risk sign-ins", "Workforce|External", "", "P2", ""),
            Zt(21800, "Identity", "Monitoring", Risk.Medium, Level.Medium, Level.Medium, "Monitor and detect cyberthreats", "All user sign-in activity uses strong authentication methods", "Workforce|External", "", "P1", ""),
            Zt(21801, "Identity", "Credential management", Risk.Medium, Level.Medium, Level.Medium, "Protect identities and secrets", "Users have strong authentication methods configured", "Workforce|External", "", "P1", ""),
            Zt(21802, "Identity", "Access control", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Microsoft Authenticator app shows sign-in context", "Workforce|External", "", "P1", ""),
            Zt(21803, "Identity", "Credential management", Risk.High, Level.Medium, Level.Medium, "Protect identities and secrets", "Migrate from legacy MFA and SSPR policies", "Workforce|External", "", "P1", ""),
            Zt(21804, "Identity", "Credential management", Risk.High, Level.Medium, Level.Medium, "Protect identities and secrets", "SMS and Voice Call authentication methods are disabled", "Workforce|External", "", "P1", ""),
            Zt(21806, "Identity", "Access control", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Secure the MFA registration (My Security Info) page", "Workforce|External", "", "P1", ""),
            Zt(21807, "Identity", "Application management", Risk.Medium, Level.Low, Level.Low, "Protect engineering systems", "Creating new applications and service principals is restricted to privileged users", "Workforce", "", "P1", ""),
            Zt(21808, "Identity", "Access control", Risk.High, Level.Medium, Level.Low, "Protect identities and secrets", "Restrict device code flow", "Workforce|External", "", "P1", ""),
            Zt(21809, "Identity", "Application management", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Admin consent workflow is enabled", "Workforce|External", "", "Free", ""),
            Zt(21810, "Identity", "Access control", Risk.Medium, Level.Medium, Level.Medium, "Protect engineering systems", "Resource-specific consent is restricted", "Workforce|External", "", "P1", ""),
            Zt(21811, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Password expiration is disabled", "Workforce|External", "", "P1", ""),
            Zt(21812, "Identity", "Privileged access", Risk.Low, Level.Low, Level.Low, "Protect engineering systems", "Maximum number of Global Administrators doesn't exceed eight users", "Workforce", "", "P1", ""),
            Zt(21813, "Identity", "Privileged access", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "High Global Administrator to privileged user ratio", "Workforce", "", "Free", ""),
            Zt(21814, "Identity", "Privileged access", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Privileged accounts are cloud native identities", "Workforce", "", "Free", ""),
            Zt(21815, "Identity", "Privileged access", Risk.High, Level.Low, Level.High, "Protect identities and secrets", "All privileged role assignments are activated just in time and not permanently active", "Workforce", "", "P2", ""),
            Zt(21816, "Identity", "Privileged access", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "All Microsoft Entra privileged role assignments are managed with PIM", "Workforce", "", "P2", ""),
            Zt(21817, "Identity", "Application management", Risk.High, Level.Low, Level.Medium, "Protect engineering systems", "Global Administrator role activation triggers an approval workflow", "Workforce", "", "P2", ""),
            Zt(21818, "Identity", "Monitoring", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Privileged role activations have monitoring and alerting configured", "Workforce", "", "P2", ""),
            Zt(21819, "Identity", "Privileged access", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Activation alert for Global Administrator role assignments", "Workforce", "", "P2", ""),
            Zt(21820, "Identity", "Privileged access", Risk.Low, Level.Low, Level.Medium, "Protect identities and secrets", "Activation alert for all privileged role assignments", "Workforce", "", "P2", ""),
            Zt(21821, "Identity", "Access control", Risk.Medium, Level.Medium, Level.Medium, "Protect identities and secrets", "Guest access is restricted", "Workforce", "", "", ""),
            Zt(21822, "Identity", "Access control", Risk.Medium, Level.Medium, Level.High, "Protect identities and secrets", "Guest access is limited to approved tenants", "Workforce", "", "Free", ""),
            Zt(21823, "Identity", "External collaboration", Risk.Medium, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Guest self-service sign-up via user flow is disabled", "Workforce", "", "Free", ""),
            Zt(21824, "Identity", "External collaboration", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Guests don't have long lived sign-in sessions", "Workforce", "", "P1", ""),
            Zt(21825, "Identity", "Access control", Risk.Medium, Level.Medium, Level.Low, "Protect identities and secrets", "Privileged users have short-lived sign-in sessions", "Workforce", "", "P1", ""),
            Zt(21828, "Identity", "Access control", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Authentication transfer is blocked", "Workforce|External", "", "P1", ""),
            Zt(21829, "Identity", "Access control", Risk.High, Level.High, Level.High, "Protect identities and secrets", "Use cloud authentication", "Workforce", "", "P1", ""),
            Zt(21830, "Identity", "Application management", Risk.High, Level.Low, Level.High, "Protect engineering systems", "Conditional Access policies for Privileged Access Workstations are configured", "Workforce", "", "P1", ""),
            Zt(21831, "Identity", "Privileged access", Risk.Medium, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Protected actions are enabled for high-impact management tasks", "Workforce", "", "P1", ""),
            Zt(21832, "Identity", "Access control", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "All groups in Conditional Access policies belong to a restricted management administrative unit", "Workforce", "", "P1", ""),
            Zt(21833, "Identity", "Privileged access", Risk.Low, Level.Low, Level.High, "Protect identities and secrets", "Directory Sync account credentials haven't been rotated recently", "Workforce", "", "", ""),
            Zt(21834, "Identity", "Access control", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Directory sync account is locked down to specific named location", "Workforce", "", "", ""),
            Zt(21835, "Identity", "Application management", Risk.High, Level.Low, Level.High, "Protect engineering systems", "Emergency access accounts are configured appropriately", "Workforce", "", "P1", ""),
            Zt(21836, "Identity", "Application management", Risk.High, Level.Low, Level.Medium, "Protect engineering systems", "Workload Identities are not assigned privileged roles", "Workforce|External", "", "P1", ""),
            Zt(21837, "Identity", "Devices", Risk.High, Level.Medium, Level.Low, "Protect engineering systems", "Limit the maximum number of devices per user to 10", "Workforce", "", "Free", ""),
            Zt(21838, "Identity", "Credential management", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Security key authentication method enabled", "Workforce|External", "", "Free", ""),
            Zt(21839, "Identity", "Credential management", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Passkey authentication method enabled", "Workforce|External", "", "Free", ""),
            Zt(21840, "Identity", "Credential management", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Security key attestation is enforced", "Workforce|External", "", "Free", ""),
            Zt(21841, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Microsoft Authenticator app report suspicious activity setting is enabled", "Workforce|External", "", "P1", ""),
            Zt(21842, "Identity", "Credential management, Privileged access", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Block administrators from using SSPR", "Workforce", "", "P1", ""),
            Zt(21843, "Identity", "Access control", Risk.Low, Level.Low, Level.High, "Protect identities and secrets", "Block legacy Microsoft Online PowerShell module", "Workforce", "", "", ""),
            Zt(21844, "Identity", "Access control", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Block legacy Azure AD PowerShell module", "Workforce", "", "Free", ""),
            Zt(21845, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Temporary access pass is enabled", "Workforce|External", "", "P1", ""),
            Zt(21846, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Restrict Temporary Access Pass to Single Use", "Workforce|External", "", "P1", ""),
            Zt(21847, "Identity", "Credential management", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Password protection for on-premises is enabled", "Workforce", "", "P1", ""),
            Zt(21848, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Add organizational terms to the banned password list", "Workforce|External", "", "P1", ""),
            Zt(21849, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Smart lockout duration is set to a minimum of 60", "Workforce|External", "", "P1", ""),
            Zt(21850, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Smart lockout threshold set to 10 or less", "Workforce|External", "", "P1", ""),
            Zt(21851, "Identity", "External collaboration", Risk.Medium, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "Guest access is protected by strong authentication methods", "Workforce", "", "Free", ""),
            Zt(21854, "Identity", "Privileged access", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Privileged roles aren't assigned to stale identities", "Workforce|External", "", "", ""),
            Zt(21855, "Identity", "Access control", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Privileged roles have access reviews", "Workforce|External", "", "", ""),
            Zt(21857, "Identity", "Access control", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Guest identities are lifecycle managed with access reviews", "Workforce|External", "", "", ""),
            Zt(21858, "Identity", "External collaboration", Risk.Medium, Level.Low, Level.Medium, "Protect tenants and isolate production systems", "Inactive guest identities are disabled or removed from the tenant", "Workforce|External", "", "Free", ""),
            Zt(21859, "Identity", "Access control", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "GDAP admin least privilege", "Workforce|External", "", "", ""),
            Zt(21860, "Identity", "Monitoring", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Diagnostic settings are configured for all Microsoft Entra logs", "Workforce|External", "Azure", "", ""),
            Zt(21861, "Identity", "Monitoring", Risk.High, Level.Low, Level.High, "Monitor and detect cyberthreats", "All high-risk users are triaged", "Workforce|External", "", "P2", ""),
            Zt(21862, "Identity", "Monitoring", Risk.High, Level.Low, Level.High, "Monitor and detect cyberthreats", "All risky workload identities are triaged", "Workforce|External", "", "P2", ""),
            Zt(21863, "Identity", "Monitoring", Risk.High, Level.Low, Level.High, "Monitor and detect cyberthreats", "All high-risk sign-ins are triaged", "Workforce|External", "", "P2", ""),
            Zt(21864, "Identity", "Access control", Risk.High, Level.Low, Level.High, "Protect identities and secrets", "All risk detections are triaged", "Workforce|External", "", "", ""),
            Zt(21865, "Identity", "Application management", Risk.Medium, Level.Low, Level.Low, "Protect networks", "Named locations are configured", "Workforce|External", "", "P1", ""),
            Zt(21866, "Identity", "Monitoring", Risk.Medium, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "All Microsoft Entra recommendations are addressed", "Workforce|External", "", "P1", ""),
            Zt(21867, "Identity", "Application management", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Enterprise applications with high privilege Microsoft Graph API permissions have owners", "Workforce|External", "", "P1", ""),
            Zt(21868, "Identity", "External collaboration", Risk.Medium, Level.Low, Level.Medium, "Protect tenants and isolate production systems", "Guests don't own apps in the tenant", "Workforce|External", "", "Free", ""),
            Zt(21869, "Identity", "Application management", Risk.Medium, Level.Medium, Level.Medium, "Protect engineering systems", "Enterprise applications must require explicit assignment or scoped provisioning", "Workforce|External", "", "P1", ""),
            Zt(21870, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Enable self-service password reset", "Workforce|External", "", "P1", ""),
            Zt(21872, "Identity", "Access control", Risk.High, Level.Medium, Level.Low, "Protect identities and secrets", "Require multifactor authentication for device join and device registration using user action", "Workforce", "", "P1", ""),
            Zt(21874, "Identity", "External collaboration", Risk.Medium, Level.Medium, Level.High, "Protect tenants and isolate production systems", "Guest access is limited to approved tenants", "Workforce|External", "", "Free", ""),
            Zt(21875, "Identity", "External collaboration", Risk.Medium, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "All entitlement management assignment policies that apply to external users require connected organizations", "Workforce|External", "", "P2|Governance", ""),
            Zt(21876, "Identity", "Access control", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Use PIM for Microsoft Entra privileged roles", "Workforce|External", "", "", ""),
            Zt(21877, "Identity", "Application management", Risk.Medium, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "All guests have a sponsor", "Workforce|External", "", "Free", ""),
            Zt(21878, "Identity", "Identity governance", Risk.Medium, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "All entitlement management policies have an expiration date", "Workforce|External", "", "P2|Governance", ""),
            Zt(21879, "Identity", "External collaboration", Risk.Medium, Level.Medium, Level.Medium, "Protect identities and secrets", "All entitlement management assignment policies that apply to external users require approval", "Workforce|External", "", "P2", ""),
            Zt(21881, "Identity", "Access control", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Azure subscriptions used by Identity Governance are secured consistently with Identity Governance roles", "Workforce|External", "", "", ""),
            Zt(21882, "Identity", "Access control", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "No nested groups in PIM for groups", "Workforce|External", "", "", ""),
            Zt(21883, "Identity", "Access control", Risk.Medium, Level.High, Level.Low, "Accelerate response and remediation", "Workload Identities are configured with risk-based policies", "Workforce|External", "", "Workload", ""),
            Zt(21884, "Identity", "External collaboration", Risk.High, Level.Low, Level.Medium, "Protect tenants and production systems", "Conditional Access policies for workload identities based on known networks are configured", "Workforce|External", "", "P1", ""),
            Zt(21885, "Identity", "Application management", Risk.High, Level.Low, Level.High, "Protect engineering systems", "App registrations use safe redirect URIs", "Workforce|External", "", "P1", ""),
            Zt(21886, "Identity", "Applications management", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Applications are configured for automatic user provisioning", "Workforce|External", "", "P1", ""),
            Zt(21887, "Identity", "Access control", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "All registered redirect URIs must have proper DNS records and ownerships", "Workforce|External", "", "", ""),
            Zt(21888, "Identity", "Application management", Risk.High, Level.Low, Level.Low, "Protect engineering systems", "App registrations must not have dangling or abandoned domain redirect URIs", "Workforce|External", "", "P1", ""),
            Zt(21889, "Identity", "Authentication", Risk.High, Level.Medium, Level.Medium, "Protect identities and secrets", "Reduce the user-visible password surface area", "Workforce|External", "", "P1", ""),
            Zt(21890, "Identity", "Access control", Risk.Medium, Level.Medium, Level.Low, "Protect identities and secrets", "Require password reset notifications for user roles", "Workforce|External", "", "", ""),
            Zt(21891, "Identity", "Access control", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Require password reset notifications for administrator roles", "Workforce|External", "", "P1", ""),
            Zt(21892, "Identity", "Access control", Risk.High, Level.High, Level.High, "Protect identities and secrets", "All sign-in activity comes from managed devices", "Workforce|External", "", "P1", ""),
            Zt(21893, "Identity", "Access control", Risk.Low, Level.Medium, Level.Medium, "Protect identities and secrets", "All users are required to register for MFA", "Workforce|External", "", "P2", ""),
            Zt(21894, "Identity", "Access control", Risk.Low, Level.Low, Level.Medium, "Protect identities and secrets", "All certificates Microsoft Entra Application Registrations and Service Principals must be issued by an approved certification authority", "Workforce|External", "", "", ""),
            Zt(21895, "Identity", "Access control", Risk.Low, Level.Low, Level.High, "Protect identities and secrets", "Application Certificate Credentials are managed using HSM", "Workforce|External", "", "", ""),
            Zt(21896, "Identity", "Application management", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Service principals don't have certificates or credentials associated with them", "Workforce|External", "", "Free", ""),
            Zt(21897, "Identity", "Access control", Risk.Medium, Level.High, Level.High, "Protect identities and secrets", "All app assignment and group membership is governed", "Workforce|External", "", "", ""),
            Zt(21898, "Identity", "Access control", Risk.Medium, Level.Medium, Level.High, "Protect identities and secrets", "All supported access lifecycle resources are managed with entitlement management packages", "Workforce|External", "", "", ""),
            Zt(21899, "Identity", "Access control", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "All privileged role assignments have a recipient that can receive notifications", "Workforce|External", "", "", ""),
            Zt(21912, "Identity", "Access control", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Azure resources used by Microsoft Entra only allow access from privileged roles", "Workforce|External", "", "", ""),
            Zt(21929, "Identity", "Identity governance", Risk.Medium, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "All entitlement management packages that apply to guests have expirations or access reviews configured in their assignment policies", "Workforce|External", "", "P2|Governance", ""),
            Zt(21941, "Identity", "Access control", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Token protection policies are configured", "Workforce|External", "", "P1", ""),
            Zt(21953, "Identity", "Devices", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Local Admin Password Solution is deployed", "Workforce|External", "", "P1", ""),
            Zt(21954, "Identity", "Devices", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Restrict nonadministrator users from recovering the BitLocker keys for their owned devices", "Workforce|External", "", "Free", ""),
            Zt(21955, "Identity", "Devices", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Manage the local administrators on Microsoft Entra joined devices", "Workforce|External", "", "P1", ""),
            Zt(21964, "Identity", "Access control", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Enable protected actions to secure Conditional Access policy creation and changes", "Workforce|External", "", "P1", ""),
            Zt(21983, "Identity", "Access control", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "No Active Medium priority Entra recommendations found", "Workforce|External", "", "", ""),
            Zt(21984, "Identity", "Access control", Risk.Low, Level.Low, Level.Low, "Protect identities and secrets", "No Active low priority Entra recommendations found", "Workforce|External", "", "", ""),
            Zt(21985, "Identity", "Credential management", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Turn off Seamless SSO if there is no usage", "Workforce|External", "", "P1", ""),
            Zt(21992, "Identity", "Application management", Risk.High, Level.Low, Level.High, "Protect identities and secrets", "Application certificates must be rotated on a regular basis", "Workforce|External", "", "Free", ""),
            Zt(22072, "Identity", "Credential management", Risk.Medium, Level.Medium, Level.Medium, "Protect identities and secrets", "Self-service password reset doesn't use security questions", "Workforce|External", "", "P1", ""),
            Zt(22124, "Identity", "Monitoring", Risk.High, Level.Medium, Level.Medium, "Monitor and detect cyberthreats", "High priority Microsoft Entra recommendations are addressed", "Workforce|External", "", "P1", ""),
            Zt(22128, "Identity", "Application management", Risk.High, Level.Low, Level.Medium, "Protect tenants and isolate production systems", "Guests are not assigned high privileged directory roles", "Workforce|External", "", "Free", ""),
            Zt(22659, "Identity", "Monitoring", Risk.High, Level.Low, Level.High, "Protect identities and secrets", "All risky workload identity sign-ins are triaged", "Workforce|External", "", "P2", ""),
            Zt(23183, "Identity", "Application management", Risk.High, Level.Low, Level.High, "Protect engineering systems", "Service principals use safe redirect URIs", "Workforce|External", "", "P1", ""),
            Zt(24518, "Identity", "Application management", Risk.Medium, Level.Low, Level.Medium, "Protect engineering systems", "Enterprise applications have owners", "Workforce", "", "Free", ""),
            Zt(24540, "Devices", "Devices", Risk.High, Level.Medium, Level.Low, "Protect networks", "Windows Firewall policies protect against unauthorized network access", "Workforce", "", "Intune", ""),
            Zt(24541, "Devices", "Tenant", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Compliance policies protect Windows devices", "Workforce", "", "Intune", ""),
            Zt(24542, "Devices", "Tenant", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Compliance policies protect macOS devices", "Workforce", "", "Intune", ""),
            Zt(24543, "Devices", "Tenant", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Compliance policies protect iOS/iPadOS devices", "Workforce", "", "Intune", ""),
            Zt(24545, "Devices", "Tenant", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Compliance policies protect fully managed and corporate-owned Android devices", "Workforce", "", "Intune", ""),
            Zt(24546, "Devices", "Tenant", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Windows automatic device enrollment is enforced to eliminate risks from unmanaged endpoints", "Workforce", "", "P1", ""),
            Zt(24547, "Devices", "Tenant", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Compliance policies protect personally owned Android devices", "Workforce", "", "Intune", ""),
            Zt(24548, "Devices", "Data", Risk.High, Level.High, Level.Low, "Protect identities and secrets", "Data on iOS/iPadOS is protected by app protection policies", "Workforce", "", "Intune", ""),
            Zt(24549, "Devices", "Data", Risk.High, Level.High, Level.Low, "Protect identities and secrets", "Data on Android is protected by app protection policies", "Workforce", "", "Intune", ""),
            Zt(24550, "Devices", "Devices", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Data on Windows is protected by BitLocker encryption", "Workforce", "", "", "INTUNE_A"),
            Zt(24551, "Devices", "Devices", Risk.High, Level.Medium, Level.Medium, "Protect identities and secrets", "Authentication on Windows uses Windows Hello for Business", "Workforce", "", "Intune", ""),
            Zt(24552, "Devices", "Devices", Risk.Medium, Level.High, Level.Low, "Protect networks", "macOS Firewall policies protect against unauthorized network access", "Workforce", "", "Intune", ""),
            Zt(24553, "Devices", "Devices", Risk.High, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "Windows Update policies are enforced to reduce risk from unpatched vulnerabilities", "Workforce", "", "Intune", ""),
            Zt(24554, "Devices", "Devices", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Update policies for iOS/iPadOS are enforced to reduce risk from unpatched vulnerabilities", "Workforce", "", "Intune", ""),
            Zt(24555, "Devices", "Tenant", Risk.Medium, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Scope tag configuration is enforced to support delegated administration and least-privilege access", "Workforce", "", "Intune", ""),
            Zt(24560, "Devices", "Devices", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Local administrator credentials on Windows are protected by Windows LAPS", "Workforce", "", "Intune", ""),
            Zt(24561, "Devices", "Devices", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Local administrator credentials on macOS are protected during enrollment by macOS LAPS", "Workforce", "", "Intune", ""),
            Zt(24564, "Devices", "Devices", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Local account usage on Windows is restricted to reduce unauthorized access", "Workforce", "", "Intune", ""),
            Zt(24568, "Devices", "Tenant", Risk.Medium, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "Platform SSO is configured to strengthen authentication on macOS devices", "Workforce", "", "Intune", ""),
            Zt(24569, "Devices", "Devices", Risk.High, Level.Medium, Level.Low, "Protect identities and secrets", "FileVault encryption protects data on macOS devices", "Workforce", "", "Intune", ""),
            Zt(24570, "Identity", "Hybrid infrastructure", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Entra Connect Sync is configured with Service Principal Credentials", "Workforce", "", "Free", ""),
            Zt(24572, "Devices", "Tenant", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Device enrollment notifications are enforced to ensure user awareness and secure onboarding", "Workforce", "", "Intune", ""),
            Zt(24573, "Devices", "Tenant", Risk.High, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "Security baselines are applied to Windows devices to strengthen security posture", "Workforce", "", "Intune", ""),
            Zt(24574, "Devices", "Devices", Risk.High, Level.Medium, Level.Medium, "Protect networks", "Attack Surface Reduction rules are applied to Windows devices to prevent exploitation of vulnerable system components", "Workforce", "", "Intune", ""),
            Zt(24575, "Devices", "Devices", Risk.High, Level.Low, Level.Medium, "Protect networks", "Defender Antivirus policies protect Windows devices from malware", "Workforce", "", "Intune", ""),
            Zt(24576, "Devices", "Tenant", Risk.Low, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Endpoint Analytics is enabled to help identify risks on Windows devices", "Workforce", "", "Intune", ""),
            Zt(24690, "Devices", "Devices", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Update policies for macOS are enforced to reduce risk from unpatched vulnerabilities", "Workforce", "", "Intune", ""),
            Zt(24784, "Devices", "Devices", Risk.High, Level.Low, Level.Low, "Protect networks", "Defender Antivirus policies protect macOS devices from malware", "Workforce", "", "Intune", ""),
            Zt(24794, "Devices", "Tenant", Risk.Medium, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Terms and Conditions policies protect access to sensitive data", "Workforce", "", "Intune", ""),
            Zt(24802, "Devices", "Tenant", Risk.Low, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Device cleanup rules maintain tenant hygiene by hiding inactive devices", "Workforce", "", "Intune", ""),
            Zt(24823, "Devices", "Tenant", Risk.Medium, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Company Portal branding and support settings enhance user experience and trust", "Workforce", "", "Intune", ""),
            Zt(24824, "Devices", "Data", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Conditional Access policies block access from noncompliant devices", "Workforce", "", "Intune", ""),
            Zt(24827, "Devices", "Data", Risk.High, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Conditional Access policies block access from unmanaged apps", "Workforce", "", "Intune", ""),
            Zt(24839, "Devices", "Data", Risk.High, Level.Low, Level.Medium, "Protect networks", "Secure Wi-Fi profiles protect iOS devices from unauthorized network access", "Workforce", "", "Intune", ""),
            Zt(24840, "Devices", "Data", Risk.High, Level.Low, Level.Low, "Protect networks", "Secure Wi-Fi profiles protect Android devices from unauthorized network access", "Workforce", "", "Intune", ""),
            Zt(24870, "Devices", "Data", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Secure Wi-Fi profiles protect macOS devices from unauthorized network access", "Workforce", "", "Intune", ""),
            Zt(24871, "Devices", "Tenant", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Defender for Endpoint automatic enrollment is enforced to reduce risk from unmanaged Android threats", "Workforce", "", "Intune", ""),
            Zt(25370, "Network", "Network", Risk.Medium, Level.Low, Level.Low, "Protect networks", "Source IP restoration is enabled", "Workforce|External", "Graph", "", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access"),
            Zt(25371, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Low, "Protect networks", "Network validation is configured through Universal Continuous Access Evaluation", "Workforce", "Graph", "AAD_PREMIUM", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access"),
            Zt(25372, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Medium, "Protect networks", "Global Secure Access client is deployed on all managed endpoints", "Workforce", "Graph", "AAD_PREMIUM|Entra_Premium_Internet_Access|Entra_Premium_Private_Access", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access"),
            Zt(25375, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Low, "Protect networks", "The tenant holds the licenses required to operate Global Secure Access", "Workforce", "Graph", "", "AAD_PREMIUM|AAD_PREMIUM_P2"),
            Zt(25376, "Network", "Network security", Risk.High, Level.Low, Level.Medium, "Protect networks", "Microsoft 365 traffic is actively flowing through Global Secure Access", "Workforce", "Graph", "Entra_Suite", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access"),
            Zt(25377, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Medium, "Protect networks", "Universal tenant restrictions block unauthorized external tenant access", "Workforce|External", "Graph", "AAD_PREMIUM|Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(25379, "Network", "Global Secure Access", Risk.Medium, Level.Medium, Level.Medium, "Protect networks", "Conditional Access policies use compliant network controls", "Workforce|External", "Graph", "AAD_PREMIUM", "AAD_PREMIUM|AAD_PREMIUM_P2"),
            Zt(25380, "Network", "Global Secure Access", Risk.Medium, Level.High, Level.Low, "Protect networks", "Global Secure Access signaling for Conditional Access is enabled", "Workforce", "Graph", "AAD_PREMIUM|Entra_Premium_Internet_Access", ""),
            Zt(25381, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Medium, "Protect networks", "Network traffic is routed through Global Secure Access for security policy enforcement", "Workforce", "Graph", "Entra_Suite|Entra_Premium_Private_Access|Entra_Premium_Internet_Access|P2", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access"),
            Zt(25382, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Low, "Protect networks", "Traffic forwarding profiles are scoped to appropriate users and groups for controlled deployment", "Workforce", "Graph", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access|Entra_Premium_Private_Access"),
            Zt(25383, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Administrative privileges are tightly limited to prevent compromise", "Workforce", "Graph", "AAD_PREMIUM", "AAD_PREMIUM|AAD_PREMIUM_P2"),
            Zt(25384, "Network", "Role management", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Application admin rights are constrained to specific Private Access apps", "Workforce", "Graph", "P1", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access"),
            Zt(25391, "Network", "Global Secure Access", Risk.Medium, Level.Medium, Level.Low, "Protect networks", "Private network connectors are active and healthy to maintain Zero Trust access to internal resources", "Workforce", "Graph", "Entra_Premium_Private_Access", "Entra_Premium_Private_Access"),
            Zt(25392, "Network", "Private Access", Risk.Medium, Level.Low, Level.Low, "Protect networks", "Private network connectors are running the latest version", "Workforce", "Graph", "Entra_Premium_Private_Access", "Entra_Premium_Private_Access"),
            Zt(25393, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.Medium, "Protect networks", "Quick Access is enabled and bound to a connector", "Workforce", "Graph", "AAD_PREMIUM|Entra_Premium_Private_Access", ""),
            Zt(25394, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.Low, "Protect networks", "Quick Access is bound to a Conditional Access policy", "Workforce|External", "Graph", "Entra_Premium_Private_Access|AAD_PREMIUM", "Entra_Premium_Private_Access"),
            Zt(25395, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.High, "Protect networks", "Entra Private Access Application segments are defined to enforce least-privilege access", "Workforce", "Graph", "Entra_Premium_Private_Access", "Entra_Premium_Private_Access"),
            Zt(25396, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.Medium, "Protect identities and secrets", "Conditional Access policies enforce strong authentication for private apps", "Workforce", "Graph", "Entra_Premium_Private_Access|AAD_PREMIUM", "Entra_Premium_Private_Access"),
            Zt(25398, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Medium, "Protect networks", "Domain controller RDP access is protected by phishing-resistant authentication through Global Secure Access", "Workforce|External", "Graph", "AAD_PREMIUM|Entra_Premium_Private_Access", "Entra_Premium_Private_Access"),
            Zt(25399, "Network", "Global Secure Access", Risk.Medium, Level.Low, Level.Medium, "Protect networks", "Private DNS is configured for internal name resolution", "Workforce|External", "Graph", "Entra_Premium_Private_Access", "Entra_Premium_Private_Access"),
            Zt(25400, "Network", "Private Access", Risk.Low, Level.Low, Level.Low, "Protect networks", "DNS traffic for internal domains is routed through Private Access", "Workforce", "Graph", "AAD_PREMIUM|Entra_Premium_Private_Access", ""),
            Zt(25401, "Network", "Application Proxy", Risk.High, Level.Medium, Level.Medium, "Protect identities and secrets", "Application Proxy applications require preauthentication to block anonymous access", "Workforce", "Graph", "AAD_PREMIUM", "AAD_PREMIUM|AAD_PREMIUM_P2"),
            Zt(25403, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.Medium, "Protect networks", "Private Access sensors are enforcing strong authentication policies on domain controllers", "Workforce", "Graph", "Entra_Suite|Entra_Premium_Private_Access", "Entra_Premium_Private_Access"),
            Zt(25405, "Network", "Global Secure Access", Risk.Medium, Level.Medium, Level.Medium, "Protect networks", "Intelligent Local Access is enabled and configured", "Workforce", "Graph", "P1", ""),
            Zt(25406, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.Low, "Protect networks", "Internet access forwarding profile is enabled", "Workforce", "Graph", "Entra_Premium_Global_Secure_Access", "Entra_Premium_Internet_Access"),
            Zt(25407, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Medium, "Protect networks", "Web content filtering integrates with Conditional Access", "Workforce|External", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(25408, "Network", "Global Secure Access", Risk.Medium, Level.Medium, Level.Medium, "Protect networks", "Web content filtering policies are configured", "Workforce|External", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(25409, "Network", "Global Secure Access", Risk.Medium, Level.Medium, Level.Medium, "Protect networks", "Web content filtering uses category-based rules", "Workforce|External", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(25410, "Network", "Global Secure Access", Risk.Medium, Level.Low, Level.Medium, "Protect networks", "Web content filtering policies are linked to security profiles", "Workforce|External", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(25411, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.High, "Protect networks", "TLS inspection is enabled and correctly configured for outbound traffic", "Workforce", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(25413, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.High, "Protect networks", "File transfer policies are configured to prevent data exfiltration", "Workforce", "Graph", "Entra_Premium_Internet_Access", ""),
            Zt(25415, "Network|AI", "Global Secure Access", Risk.High, Level.Low, Level.Medium, "Protect networks", "AI Gateway protects enterprise generative AI applications from prompt injection attacks", "Workforce", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(25416, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Medium, "Protect networks", "Global Secure Access cloud firewall protects branch office internet traffic", "Workforce|External", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(25419, "Network", "Global Secure Access", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Network access activity is visible to security operations for threat detection and response", "Workforce", "Azure", "AAD_PREMIUM|Entra_Premium_Internet_Access|Entra_Premium_Private_Access", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access"),
            Zt(25420, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Network access logs are retained for security analysis and compliance requirements", "Workforce", "Azure", "AAD_PREMIUM|Entra_Premium_Internet_Access|Entra_Premium_Private_Access", "Entra_Premium_Private_Access|Entra_Premium_Internet_Access"),
            Zt(25422, "Network", "Global Secure Access", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Global Secure Access deployment logs are populated and reviewed", "Workforce|External", "Graph", "Entra_Premium_Internet_Access|Entra_Premium_Private_Access", "Entra_Premium_Internet_Access|Entra_Premium_Private_Access"),
            Zt(25466, "Network", "Private Access", Risk.High, Level.Medium, Level.Low, "Protect networks", "At least two Private Access connectors are active and healthy per connector group", "Workforce", "Graph", "Entra_Premium_Private_Access", ""),
            Zt(25480, "Network", "Global Secure Access", Risk.Medium, Level.Low, Level.Low, "Protect networks", "Quick Access has user or group assignments", "Workforce|External", "Graph", "Entra_Private_Access", "Entra_Premium_Private_Access"),
            Zt(25481, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.Low, "Protect networks", "All Private Access apps have user or group assignments", "Workforce|External", "Graph", "Entra_Private_Access", "Entra_Premium_Private_Access"),
            Zt(25533, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "DDoS Protection is enabled for all Public IP Addresses in VNETs", "Workforce|External", "Azure", "DDoS_Network_Protection|DDoS_IP_Protection", ""),
            Zt(25535, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Medium, "Protect networks", "Outbound traffic from VNET integrated workloads is routed through Azure Firewall", "Workforce|External", "Azure", "Azure_Firewall_Basic|Azure_Firewall_Standard|Azure_Firewall_Premium", ""),
            Zt(25537, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Threat intelligence is Enabled in Deny Mode on Azure Firewall", "Workforce", "Azure", "Azure_Firewall_Standard|Azure_Firewall_Premium", ""),
            Zt(25539, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "IDPS Inspection is Enabled in Deny Mode on Azure Firewall", "Workforce|External", "Azure", "Azure_Firewall_Premium", ""),
            Zt(25541, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Application Gateway WAF is Enabled in Prevention mode", "Workforce", "Azure", "Azure WAF|Azure Application Gateway Standard SKU", ""),
            Zt(25543, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Azure Front Door WAF is Enabled in Prevention Mode", "Workforce", "Azure", "Azure WAF on Azure Front Door Premium SKU|Azure Standard SKU", ""),
            Zt(25550, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Inspection of Outbound TLS Traffic is Enabled on Azure Firewall", "Workforce|External", "Azure", "Azure_Firewall_Premium", ""),
            Zt(26879, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Request Body Inspection is enabled in Application Gateway WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(26880, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Request Body Inspection is enabled in Azure Front Door WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(26881, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Default Ruleset is enabled in Application Gateway WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(26882, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Bot protection ruleset is enabled and assigned in Application Gateway WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(26883, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Default rule set is assigned in Azure Front Door WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(26884, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "Bot protection rule set is enabled and assigned in Azure Front Door WAF", "Workforce", "Azure", "Azure_Front_Door_Premium", ""),
            Zt(26885, "Network", "Azure Network Security", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Metrics are enabled for DDoS-protected public IPs", "Workforce", "Azure", "DDoS_Network_Protection|DDoS_IP_Protection", ""),
            Zt(26886, "Network", "Azure Network Security", Risk.Medium, Level.Low, Level.Low, "Protect networks", "Diagnostic logging is enabled for DDoS-protected public IPs", "Workforce", "Azure", "DDoS_Network_Protection|DDoS_IP_Protection", ""),
            Zt(26887, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Diagnostic logging is enabled in Azure Firewall", "Workforce", "Azure", "Azure_Firewall_Standard|Azure_Firewall_Premium", ""),
            Zt(26888, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Diagnostic logging is enabled in Application Gateway WAF", "Workforce", "Azure", "Azure_Application_Gateway_WAF", ""),
            Zt(26889, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Diagnostic logging is enabled in Azure Front Door WAF", "Workforce", "Azure", "Azure_FrontDoor_Standard|Azure_FrontDoor_Premium", ""),
            Zt(27000, "Network", "Global Secure Access", Risk.High, Level.Low, Level.Low, "Protect networks", "Web content filtering blocks high-risk categories", "Workforce", "Graph", "Entra_Premium_Internet_Access", ""),
            Zt(27001, "Network", "Global Secure Access", Risk.Medium, Level.Low, Level.Medium, "Protect networks", "TLS inspection bypass rules are regularly reviewed", "Workforce", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(27002, "Network", "Global Secure Access", Risk.High, Level.High, Level.Low, "Protect networks", "TLS inspection certificates have a sufficient validity period", "Workforce|External", "Graph", "Entra_Premium_Internet_Access", ""),
            Zt(27003, "Network", "Global Secure Access", Risk.High, Level.Medium, Level.Medium, "Protect networks", "TLS inspection failure rate is below 1%", "Workforce", "Graph|Azure", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(27004, "Network", "Global Secure Access", Risk.Low, Level.Low, Level.Low, "Protect networks", "TLS inspection custom bypass rules don't duplicate system bypass destinations", "Workforce", "Graph", "Entra_Premium_Internet_Access", "Entra_Premium_Internet_Access"),
            Zt(27015, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "HTTP DDoS Protection Ruleset is Enabled in Application Gateway WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(27016, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Medium, "Protect networks", "Rate Limiting is Enabled in Application Gateway WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(27017, "Network", "Azure Network Security", Risk.Medium, Level.Low, Level.Low, "Protect networks", "JavaScript Challenge is Enabled in Application Gateway WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(27018, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Medium, "Protect networks", "Rate Limiting is Enabled in Azure Front Door WAF", "Workforce", "Azure", "Azure_WAF", ""),
            Zt(27019, "Network", "Azure Network Security", Risk.Medium, Level.Low, Level.Low, "Protect networks", "JavaScript Challenge is Enabled in Azure Front Door WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(27020, "Network", "Azure Network Security", Risk.Medium, Level.Medium, Level.Low, "Protect networks", "CAPTCHA challenge is enabled in Azure Front Door WAF", "Workforce", "Azure", "Azure WAF", ""),
            Zt(27024, "Network", "Azure Network Security", Risk.High, Level.Low, Level.Low, "Protect networks", "HTTP DDoS protection rule set is enabled in Azure Front Door WAF", "Workforce", "Azure", "Consumption-based: Azure WAF on Azure Front Door Premium", ""),
            Zt(35001, "Data", "Entra", Risk.High, Level.Low, Level.Low, "", "Conditional Access policies don't exclude Rights Management workloads", "Workforce|External", "Graph", "Microsoft 365 E5", "RMS_S_PREMIUM2"),
            Zt(35003, "Data|AI", "sensitivity-labels", Risk.High, Level.Low, Level.Medium, "Protect tenants and production systems", "Sensitivity labels are configured", "Workforce", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35004, "Data|AI", "Sensitivity Labels", Risk.Low, Level.Medium, Level.Low, "Protect tenants and production systems", "Sensitivity label policies are published to users", "Workforce", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35005, "Data|AI", "SharePoint Online", Risk.High, Level.Low, Level.Low, "Protect tenants and production systems", "Sensitivity labels are enabled for SharePoint and OneDrive", "Workforce", "SharePointOnline", "MIP_P1", "RMS_S_PREMIUM"),
            Zt(35006, "Data|AI", "SharePoint Online", Risk.Medium, Level.Low, Level.Low, "Protect tenants and production systems", "PDF labeling is enabled in SharePoint", "Workforce", "SharePointOnline", "MIP_P1", "RMS_S_PREMIUM"),
            Zt(35007, "Data|AI", "SharePoint Online", Risk.Low, Level.Low, Level.Low, "", "Information Rights Management is enabled in SharePoint Online", "Workforce", "SharePointOnline", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35008, "Data|AI", "SharePoint Online", Risk.Medium, Level.Low, Level.Low, "Protect tenants and production systems", "Default sensitivity labels are configured for SharePoint document libraries", "Workforce", "SharePointOnline", "Microsoft 365 E5", "RMS_S_PREMIUM2"),
            Zt(35009, "Data", "Sensitivity Labels", Risk.Low, Level.High, Level.Low, "Protect tenants and production systems", "Co-authoring is enabled for files encrypted with sensitivity labels", "Workforce", "SecurityCompliance", "Microsoft 365 E5", "RMS_S_PREMIUM2"),
            Zt(35010, "Data|AI", "Encryption", Risk.Low, Level.High, Level.Medium, "Protect tenants and production systems", "Double Key Encryption labels are configured", "Workforce", "SecurityCompliance", "Microsoft 365 E5", "RMS_S_PREMIUM2"),
            Zt(35011, "Data|AI", "Advanced Label Features", Risk.Medium, Level.Low, Level.Medium, "Protect tenants and production systems", "Super user membership is configured for Microsoft Purview Information Protection", "Workforce|External", "AipService|Graph", "Microsoft 365 E5", "RMS_S_PREMIUM2"),
            Zt(35012, "Data|AI", "Sensitivity Labels Configuration", Risk.Medium, Level.High, Level.Medium, "Protect tenants and production systems", "Container labels are configured for collaborative workspaces", "Workforce", "SecurityCompliance", "Microsoft 365 E5", "RMS_S_PREMIUM2"),
            Zt(35013, "Data|AI", "Sensitivity Labels Configuration", Risk.High, Level.High, Level.Medium, "Protect tenants and production systems", "Sensitivity labels with encryption are configured", "Workforce|External", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35014, "Data|AI", "Label Policy Configuration", Risk.Medium, Level.High, Level.Low, "Protect tenants and production systems", "Email label policies inherit sensitivity from attachments", "Workforce", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35015, "Data|AI", "sensitivity-labels", Risk.Medium, Level.High, Level.Medium, "Protect tenants and production systems", "Globally published sensitivity labels don't exceed the recommended maximum", "Workforce", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35016, "Data|AI", "Information Protection", Risk.High, Level.High, Level.Medium, "Protect tenants and production systems", "Mandatory labeling is enabled in sensitivity label policies", "Workforce|External", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35017, "Data|AI", "Information Protection", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and production systems", "A default sensitivity label is configured in label policies", "Workforce", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35018, "Data", "Information Protection", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and production systems", "Users must provide justification to downgrade sensitivity labels", "Workforce", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35019, "Data|AI", "Information Protection", Risk.High, Level.Low, Level.Medium, "Protect tenants and production systems", "Auto-labeling policies are configured for all Microsoft 365 workloads", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35020, "Data|AI", "Information Protection", Risk.High, Level.Low, Level.Low, "Protect tenants and production systems", "Auto-labeling policies are in enforcement mode", "Workforce|External", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35021, "Data|AI", "Information Protection", Risk.High, Level.Low, Level.Medium, "Protect tenants and production systems", "Auto-labeling policies are enabled for SharePoint and OneDrive", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35022, "Data|AI", "Information Protection", Risk.Medium, Level.Low, Level.Medium, "Protect tenants and production systems", "On-demand scans are configured for sensitive information discovery", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35023, "Data|AI", "Information Protection", Risk.Medium, Level.Low, Level.Medium, "Protect tenants and production systems", "OCR is enabled for sensitive information detection", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35024, "Data|AI", "Rights Management Service", Risk.High, Level.High, Level.Low, "Protect tenants and production systems", "Azure Rights Management service is activated", "Workforce", "ExchangeOnline", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35025, "Data|AI", "Rights Management Service (RMS)", Risk.High, Level.High, Level.Low, "Protect tenants and production systems", "Internal Rights Management licensing is enabled", "Workforce", "ExchangeOnline", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35026, "Data", "Microsoft Purview Message Encryption", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and production systems", "Microsoft Purview Message Encryption is configured with simplified client access", "Workforce|External", "ExchangeOnline", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35027, "Data", "Information Protection", Risk.Low, Level.Low, Level.Low, "Protect tenants and production systems", "Custom branding templates are configured for Microsoft Purview Message Encryption", "Workforce", "ExchangeOnline", "Microsoft 365 E3|Microsoft 365 E5|Advanced Message Encryption add-on", "RMS_S_PREMIUM"),
            Zt(35028, "Data", "Information Protection", Risk.Medium, Level.Medium, Level.Medium, "Protect tenants and production systems", "Email retention policies are configured", "Workforce|External", "SecurityCompliance", "Microsoft 365 E3", "RMS_S_PREMIUM"),
            Zt(35029, "Data", "Information Protection", Risk.Medium, Level.Medium, Level.Medium, "Protect tenants and production systems", "Mail flow rules apply rights protection to sensitive messages", "Workforce", "ExchangeOnline", "Microsoft 365 E5", "RMS_S_PREMIUM2"),
            Zt(35030, "Data|AI", "Data Loss Prevention (DLP)", Risk.High, Level.Medium, Level.Medium, "Protect tenants and production systems", "Data loss prevention policies are enabled", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35032, "Data|AI", "Data Loss Prevention (DLP)", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and production systems", "Adaptive Protection is enabled in data loss prevention policies", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35033, "Data|AI", "Advanced Classification", Risk.High, Level.Medium, Level.High, "Protect tenants and production systems", "Custom sensitive information types are configured", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35034, "Data|AI", "Advanced Classification", Risk.High, Level.Medium, Level.Medium, "Protect tenants and production systems", "Exact Data Match is configured for sensitive information detection", "Workforce|External", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35035, "Data|AI", "Advanced Classification", Risk.High, Level.Medium, Level.Low, "Protect tenants and production systems", "Named entity sensitive information types are used in auto-labeling and data loss prevention policies", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35036, "Data|AI", "Advanced Classification", Risk.Medium, Level.Medium, Level.High, "Protect tenants and production systems", "Trainable classifiers are used in data loss prevention and auto-labeling policies", "Workforce|External", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35038, "Data|AI", "Data Security Posture Management", Risk.High, Level.Medium, Level.Medium, "Protect tenants and production systems", "Insider Risk Management policies are enabled for risky AI usage", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35039, "Data|AI", "Data Security Posture Management", Risk.High, Level.Medium, Level.Medium, "Protect tenants and production systems", "Communication compliance monitoring is configured for Microsoft Copilot", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35040, "Data|AI", "Data Security Posture Management", Risk.High, Level.Medium, Level.Medium, "Protect tenants and production systems", "Communication compliance monitoring is configured for enterprise AI tools", "Workforce", "SecurityCompliance", "", "EXCHANGE_S_ENTERPRISE"),
            Zt(35041, "Data|AI", "Data Security Posture Management", Risk.Medium, Level.Medium, Level.High, "Protect tenants and production systems", "Browser data loss prevention is enabled for AI apps via Edge for Business", "Workforce", "SecurityCompliance", "Microsoft 365 E5|Microsoft Purview PAYG", "RMS_S_PREMIUM2"),
            Zt(41002, "SecOps", "Identity threat protection", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Microsoft Defender for Identity sensor is installed and healthy on every domain controller", "Workforce", "Graph", "", "ATA"),
            Zt(41003, "SecOps", "Identity threat protection", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Microsoft Defender for Identity sensors are installed and healthy on AD FS, AD CS, and Microsoft Entra Connect servers", "Workforce", "Graph", "", "ATA"),
            Zt(41009, "SecOps", "Identity threat protection", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Dormant accounts have been removed from sensitive Active Directory groups", "Workforce", "Graph", "", "ATA"),
            Zt(41018, "SecOps", "Identity threat protection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "No open Microsoft Defender for Identity health issues are present in the tenant", "Workforce", "Graph", "", "ATA"),
            Zt(41019, "SecOps", "Identity threat protection", Risk.High, Level.Medium, Level.Low, "Accelerate response and remediation", "Compromised identities surfaced by Microsoft Defender for Identity have been remediated", "Workforce", "Graph", "", "ATA"),
            Zt(41020, "SecOps", "Identity threat protection", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft Defender for Identity sensor deployment is validated by reviewing the Health Issues page", "Workforce", "Graph", "", "ATA"),
            Zt(41022, "SecOps", "Identity threat protection", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft Defender for Identity security alerts have been triaged and tuned", "Workforce", "Graph", "", "ATA"),
            Zt(41029, "SecOps", "Email and collaboration security", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Anti-malware policies are configured according to recommended settings", "Workforce", "ExchangeOnline", "", "EXCHANGE_S_STANDARD"),
            Zt(41031, "SecOps", "Email and collaboration security", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Safe Attachments policies in Microsoft Defender for Office 365 are configured to detonate and block", "Workforce", "ExchangeOnline", "", "ATP_ENTERPRISE"),
            Zt(41032, "SecOps", "Email and collaboration security", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Safe Links policies in Microsoft Defender for Office 365 are configured to scan and block malicious URLs", "Workforce", "ExchangeOnline", "", "ATP_ENTERPRISE"),
            Zt(41033, "SecOps", "Email and collaboration security", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Anti-phishing policies in Microsoft Defender for Office 365 are configured with impersonation and spoof protection", "Workforce", "ExchangeOnline", "", "ATP_ENTERPRISE"),
            Zt(41034, "SecOps", "Email and collaboration security", Risk.Medium, Level.Medium, Level.Low, "Protect tenants and isolate production systems", "Anti-spam (hosted content filter) policies are configured with recommended thresholds and actions", "Workforce", "ExchangeOnline", "", "EXCHANGE_S_STANDARD"),
            Zt(41041, "SecOps", "Email and collaboration security", Risk.High, Level.Low, Level.Medium, "Accelerate response and remediation", "Automated Investigation and Response (AIR) recommendations are reviewed and actioned", "Workforce", "Graph", "", "THREAT_INTELLIGENCE"),
            Zt(41045, "SecOps", "Endpoint threat protection", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "All eligible endpoints are onboarded to Microsoft Defender for Endpoint", "Workforce", "Graph", "", "WINDEFATP|MDE_LITE"),
            Zt(41052, "SecOps", "Endpoint threat protection", Risk.High, Level.Medium, Level.High, "Monitor and detect cyberthreats", "Application control (WDAC / App Control for Business) is enforced via Intune", "Workforce", "Graph", "", "INTUNE_A"),
            Zt(41053, "SecOps", "Endpoint threat protection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Network protection is enabled in block mode", "Workforce", "Graph", "", "ATA"),
            Zt(41059, "SecOps", "Endpoint threat protection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "EDR in block mode is enabled when Microsoft Defender Antivirus is not the primary antivirus", "Workforce", "Graph", "", "WINDEFATP"),
            Zt(41060, "SecOps", "Endpoint threat protection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Cloud-delivered protection is enabled in Microsoft Defender Antivirus", "Workforce", "Graph", "", "ATA"),
            Zt(41061, "SecOps", "Threat investigation and response", Risk.High, Level.Low, Level.Medium, "Accelerate response and remediation", "All active Microsoft Defender XDR incidents are triaged and remediated", "Workforce", "Graph", "", "WINDEFATP|MDE_LITE|ATP_ENTERPRISE|THREAT_INTELLIGENCE|ATA|ADALLOM_S_STANDALONE|MDE_SMB"),
            Zt(41062, "SecOps", "Threat investigation and response", Risk.High, Level.Low, Level.Low, "Accelerate response and remediation", "Automated Investigation and Response (AIR) recommendations are reviewed and actioned", "Workforce", "Graph", "", "WINDEFATP"),
            Zt(41081, "SecOps", "SaaS threat detection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "At least one Microsoft Defender for Cloud Apps anomaly detection policy is generating alerts", "Workforce", "Graph", "", "ADALLOM_S_STANDALONE|ADALLOM_S_O365"),
            Zt(41114, "SecOps", "Email and collaboration security", Risk.High, Level.Low, Level.Low, "Protect tenants and isolate production systems", "Microsoft Teams protection policies are configured to block malicious messages, links, and attachments", "Workforce", "Graph|ExchangeOnline", "", "ATP_ENTERPRISE"),
            Zt(41116, "SecOps", "Email and collaboration security", Risk.Medium, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Threat hunting against Email and Collaboration tables in Microsoft 365 Defender Advanced Hunting is operational", "Workforce", "Graph", "", "THREAT_INTELLIGENCE"),
            Zt(41121, "SecOps", "Incident response operations", Risk.High, Level.Low, Level.Low, "Accelerate response and remediation", "Every open Microsoft Defender XDR alert is triaged across all Defender services, with no high-severity alert left unassigned or unworked past its triage window", "Workforce", "Graph", "", "WINDEFATP|MDE_LITE|ATP_ENTERPRISE|THREAT_INTELLIGENCE|ATA|ADALLOM_S_STANDALONE"),
            Zt(41206, "SecOps", "Security information and event management", Risk.Low, Level.Low, Level.Low, "Monitor and detect cyberthreats", "At least one workbook is deployed in every Microsoft Sentinel workspace for visualization and operational reporting", "Workforce", "Azure", "Consumption-based: Microsoft Sentinel", ""),
            Zt(41207, "SecOps", "Security information and event management", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Active analytics rules are configured in Microsoft Sentinel to detect threats", "Workforce", "Azure", "Consumption-based: Microsoft Sentinel", ""),
            Zt(41208, "SecOps", "Security information and event management", Risk.Low, Level.Low, Level.Low, "Monitor and detect cyberthreats", "At least one watchlist is configured in Microsoft Sentinel for correlation against high-value entities", "Workforce", "Azure", "Consumption-based: Microsoft Sentinel", ""),
            Zt(41209, "SecOps", "Security information and event management", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "User and Entity Behavior Analytics (UEBA) is enabled in Microsoft Sentinel", "Workforce", "Azure", "Consumption-based: Microsoft Sentinel", ""),
            Zt(41211, "SecOps", "Security information and event management", Risk.Medium, Level.Low, Level.Low, "Accelerate response and remediation", "Auditing and health monitoring is enabled for Microsoft Sentinel", "Workforce", "Azure", "Consumption-based: Microsoft Sentinel", ""),
            Zt(41213, "SecOps", "Security information and event management", Risk.Medium, Level.Low, Level.Low, "Accelerate response and remediation", "At least one automation rule is configured in Microsoft Sentinel to manage incident response", "Workforce", "Azure", "Consumption-based: Microsoft Sentinel", ""),
            Zt(41215, "SecOps", "AI for security", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft Security Copilot capacity (Security Compute Units) is provisioned in the tenant", "Workforce", "Azure", "Consumption-based: Microsoft Security Copilot", ""),
            Zt(50001, "Infrastructure", "Microsoft Defender for Cloud", Risk.High, Level.Medium, Level.Medium, "Protect tenants and isolate production systems", "Microsoft Defender for Cloud Recommendations", "Workforce", "Azure", "N/A", ""),
            Zt(51001, "Devices", "Devices", Risk.High, Level.Medium, Level.Medium, "Protect engineering systems", "Windows Endpoint Privilege Management is configured and assigned", "Workforce", "Graph", "", ""),
            Zt(51013, "Devices", "Devices", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "App Protection Policies block managed-app access when user re-authentication fails (disabled Entra ID accounts, blocked sign-ins, expired tokens)", "Workforce", "", "", "INTUNE_A"),
            Zt(51014, "Devices", "Devices", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "App Protection Policies block managed-app access on jailbroken or rooted mobile devices", "Workforce", "Graph", "", "INTUNE_A"),
            Zt(51015, "Devices", "Devices", Risk.High, Level.Low, Level.Medium, "Protect identities and secrets", "Multi Admin Approval is enabled in Intune to require a second admin to approve sensitive tenant changes", "Workforce", "", "", "INTUNE_A"),
            Zt(51016, "Devices", "Devices", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Privileged Identity Management is enforced for Intune Administrator role assignments", "Workforce", "", "", "INTUNE_A&AAD_PREMIUM_P2"),
            Zt(51018, "Devices", "Devices", Risk.High, Level.Medium, Level.Medium, "Protect engineering systems", "Windows App Control for Business (WDAC) is configured and assigned via Intune", "Workforce", "", "", "INTUNE_A"),
            Zt(51019, "Devices", "Devices", Risk.Medium, Level.Medium, Level.Low, "Protect identities and secrets", "MAM app access timeout and re-authentication are enforced after idle period", "Workforce", "", "", "INTUNE_A"),
            Zt(61002, "AI|SecOps", "AI Threat Detection", Risk.High, Level.Low, Level.Medium, "Monitor and detect cyberthreats", "Microsoft Sentinel is onboarded on at least one Log Analytics workspace", "Workforce", "Azure", "Microsoft_Sentinel", ""),
            Zt(61004, "AI", "AI Cloud Posture", Risk.High, Level.Low, Level.Medium, "Protect tenants and production systems", "Microsoft Defender for Cloud CSPM plan is enabled on all Azure subscriptions", "Workforce", "Azure", "Microsoft_Defender_for_Cloud", ""),
            Zt(61005, "AI", "AI Inventory & Lifecycle", Risk.High, Level.Low, Level.Low, "Protect tenants and production systems", "Agents deployed to Microsoft 365 Copilot are discoverable in the Agent Registry", "Workforce", "Graph", "", "Microsoft_365_Copilot|AGENT_365"),
            Zt(61006, "AI", "AI Authentication & Access", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "AI administrative roles have assigned principals", "Workforce", "Graph", "", "AAD_BASIC|AAD_PREMIUM"),
            Zt(61008, "AI", "Secure AI Authentication and Access", Risk.Medium, Level.Low, Level.Medium, "Protect identities and secrets", "Agent identity lifecycle tagging (customSecurityAttributes present)", "Workforce", "Graph", "", ""),
            Zt(61009, "AI", "AI Identity & Access", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Conditional Access policies cover both agent identities and agent users", "Workforce", "Graph", "AAD_PREMIUM|AGENT_365", "AAD_PREMIUM&AGENT_365|AAD_PREMIUM_P2&AGENT_365"),
            Zt(61011, "AI", "AI Authentication & Access", Risk.High, Level.Medium, Level.Medium, "Protect identities and secrets", "Require users to use Microsoft Entra ID auth to interact with agents", "Workforce", "Graph", "", "AAD_PREMIUM"),
            Zt(61012, "AI", "AI Authentication & Access", Risk.High, Level.Low, Level.Low, "Protect identities and secrets", "Risk-based Conditional Access blocks risky agent identities", "Workforce", "Graph", "AAD_PREMIUM_P2|AGENT_365", "AAD_PREMIUM_P2&AGENT_365"),
            Zt(61013, "AI", "AI Authentication & Access", Risk.Medium, Level.Low, Level.Low, "Protect identities and secrets", "Identity governance for agents — sponsors assigned, entitlement-management channel exists, and lifecycle automation in place", "Workforce", "Graph", "", "AAD_PREMIUM&AGENT_365"),
            Zt(61014, "AI", "Agent Lifecycle", Risk.High, Level.Medium, Level.Medium, "Protect identities and secrets", "Agent identities and blueprint principals have assigned technical owners and no disabled agents remain in the directory", "Workforce", "Graph", "", "AAD_PREMIUM"),
            Zt(61016, "AI", "AI Threat Detection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft Entra ID Protection risk events are flowing to the Microsoft Sentinel workspace", "Workforce", "Azure", "AAD_PREMIUM_P2|AGENT_365", "AAD_PREMIUM_P2&AGENT_365"),
            Zt(61017, "AI", "AI Threat Detection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft Defender for AI Services alerts are flowing to the Microsoft Sentinel workspace via a single connector path", "Workforce", "Azure", "Microsoft_Defender_for_AI_Services|Microsoft_Sentinel", ""),
            Zt(61018, "AI", "AI Threat Detection", Risk.Medium, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft Purview Information Protection data connector is enabled on the Microsoft Sentinel workspace", "Workforce", "Azure", "MIP_S_CLP1|Consumption-based: Microsoft Sentinel", "MIP_S_CLP1"),
            Zt(61021, "AI", "AI Threat Detection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft 365 Copilot data connector is enabled on the Microsoft Sentinel workspace", "Workforce", "Azure", "", "Microsoft_365_Copilot"),
            Zt(61022, "AI", "AI Threat Detection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft Defender for AI Services is enabled on every Azure subscription that hosts Azure OpenAI or Azure AI Services accounts", "Workforce", "Azure", "Microsoft_Defender_for_AI_Services", ""),
            Zt(61023, "AI", "AI Threat Detection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Agent 365 data connector is enabled on the Microsoft Sentinel workspace", "Workforce", "Azure", "AGENT_365|Consumption-based: Microsoft Sentinel", "AGENT_365"),
            Zt(61024, "AI", "AI Threat Detection", Risk.High, Level.Low, Level.Low, "Monitor and detect cyberthreats", "Microsoft Defender XDR (unified) data connector is enabled on the Microsoft Sentinel workspace", "Workforce", "Azure", "WIN_DEF_ATP|MDATP_XPLAT|ATA|ADALLOM_STANDALONE|THREAT_INTELLIGENCE|IDENTITY_THREAT_PROTECTION|IDENTITY_THREAT_PROTECTION_FOR_EMS_E5|SPE_E5|Consumption-based: Microsoft Sentinel", "WIN_DEF_ATP|MDATP_XPLAT|ATA|ADALLOM_STANDALONE|THREAT_INTELLIGENCE|IDENTITY_THREAT_PROTECTION|IDENTITY_THREAT_PROTECTION_FOR_EMS_E5|SPE_E5"),

        // ---------------- ISO 27001 ----------------
        Ust("iso-encryption", "iso-27001", "Data", "Cryptography", Risk.High, "Data encrypted at rest", "Enable encryption at rest across all data stores.", "Azure"),
        Ust("iso-access", "iso-27001", "Identity", "Access control", Risk.Medium, "Least-privilege access control enforced", "Apply least-privilege RBAC and review access regularly.", "Graph"),
        Ust("iso-logging", "iso-27001", "SecOps", "Monitoring", Risk.Medium, "Security logging and monitoring enabled", "Centralize logs and configure alerting.", "Azure"),
        Ust("iso-backup", "iso-27001", "Infrastructure", "Resilience", Risk.Low, "Backup and recovery configured and tested", "Configure and periodically test backups for critical workloads.", "Azure"),

        // ---------------- CIS Microsoft Azure Foundations Benchmark v5.0.0: 113 controls ----------------
        // Generated from the "Controls Covered" tables of vegazbabz/CIS-Azure-Benchmark-Audit-Tool (102 automated, 11 manual).
            Cis("2.1.1", "2 - Azure Databricks", 2, "Databricks deployed in customer-managed VNet", false),
            Cis("2.1.2", "2 - Azure Databricks", 1, "NSGs configured for Databricks subnets", false),
            Cis("2.1.7", "2 - Azure Databricks", 1, "Diagnostic logging configured", false),
            Cis("2.1.8", "2 - Azure Databricks", 2, "Databricks encryption uses customer-managed keys", false),
            Cis("2.1.9", "2 - Azure Databricks", 1, "No Public IP enabled", false),
            Cis("2.1.10", "2 - Azure Databricks", 1, "Public network access disabled", false),
            Cis("2.1.11", "2 - Azure Databricks", 2, "Private endpoints used to access workspaces", false),
            Cis("3.1.1", "3 - Compute Services", 2, "Only MFA-enabled identities can access privileged VMs", true),
            Cis("5.1.1", "5 - Identity Services", 1, "Security defaults enabled", false),
            Cis("5.1.2", "5 - Identity Services", 1, "MFA enabled for all users", false),
            Cis("5.1.3", "5 - Identity Services", 1, "Allow users to remember MFA on trusted devices disabled", true),
            Cis("5.2.2", "5 - Identity Services", 1, "Exclusionary geographic Conditional Access policy considered", true),
            Cis("5.3.2", "5 - Identity Services", 1, "Guest users reviewed on a regular basis", true),
            Cis("5.3.3", "5 - Identity Services", 1, "User Access Administrator role restricted", false),
            Cis("5.4", "5 - Identity Services", 1, "Restrict non-admin users from creating tenants", false),
            Cis("5.6", "5 - Identity Services", 1, "Account lockout threshold <= 10", false),
            Cis("5.14", "5 - Identity Services", 1, "Users cannot register applications", false),
            Cis("5.15", "5 - Identity Services", 1, "Guest access restricted to own directory objects", false),
            Cis("5.16", "5 - Identity Services", 2, "Guest invite restrictions set to admins or no one", false),
            Cis("5.23", "5 - Identity Services", 1, "No custom subscription administrator roles", false),
            Cis("5.27", "5 - Identity Services", 1, "Between 2 and 3 subscription owners", false),
            Cis("5.28", "5 - Identity Services", 1, "Privileged users protected by phishing-resistant MFA", true),
            Cis("6.1.1.1", "6 - Logging and Monitoring", 1, "Diagnostic Setting exists for Subscription Activity Logs", false),
            Cis("6.1.1.2", "6 - Logging and Monitoring", 1, "Diagnostic Setting captures required categories", false),
            Cis("6.1.1.3", "6 - Logging and Monitoring", 1, "Activity log retention >= 365 days", false),
            Cis("6.1.1.4", "6 - Logging and Monitoring", 1, "Key Vault diagnostic logging enabled", false),
            Cis("6.1.1.6", "6 - Logging and Monitoring", 2, "Azure AppService HTTP logs enabled", false),
            Cis("6.1.2.1", "6 - Logging and Monitoring", 1, "Activity Log Alert: Create Policy Assignment", false),
            Cis("6.1.2.2", "6 - Logging and Monitoring", 1, "Activity Log Alert: Delete Policy Assignment", false),
            Cis("6.1.2.3", "6 - Logging and Monitoring", 1, "Activity Log Alert: Create or Update NSG", false),
            Cis("6.1.2.4", "6 - Logging and Monitoring", 1, "Activity Log Alert: Delete NSG", false),
            Cis("6.1.2.5", "6 - Logging and Monitoring", 1, "Activity Log Alert: Create or Update Security Solution", false),
            Cis("6.1.2.6", "6 - Logging and Monitoring", 1, "Activity Log Alert: Delete Security Solution", false),
            Cis("6.1.2.7", "6 - Logging and Monitoring", 1, "Activity Log Alert: Create or Update SQL Firewall Rule", false),
            Cis("6.1.2.8", "6 - Logging and Monitoring", 1, "Activity Log Alert: Delete SQL Firewall Rule", false),
            Cis("6.1.2.9", "6 - Logging and Monitoring", 1, "Activity Log Alert: Create or Update Public IP", false),
            Cis("6.1.2.10", "6 - Logging and Monitoring", 1, "Activity Log Alert: Delete Public IP", false),
            Cis("6.1.2.11", "6 - Logging and Monitoring", 1, "Activity Log Alert: Service Health", false),
            Cis("6.1.3.1", "6 - Logging and Monitoring", 2, "Application Insights configured", false),
            Cis("6.1.4", "6 - Logging and Monitoring", 1, "Azure Monitor resource logging enabled for all services", true),
            Cis("6.1.5", "6 - Logging and Monitoring", 1, "SKU Basic/Consumption not used on production artifacts", true),
            Cis("6.2", "6 - Logging and Monitoring", 2, "Resource Locks set for mission-critical Azure resources", true),
            Cis("7.1", "7 - Networking Services", 1, "RDP (3389) not open to internet", false),
            Cis("7.2", "7 - Networking Services", 1, "SSH (22) not open to internet", false),
            Cis("7.3", "7 - Networking Services", 1, "UDP access from internet restricted", false),
            Cis("7.4", "7 - Networking Services", 1, "HTTP/HTTPS (80/443) from internet evaluated and restricted", false),
            Cis("7.5", "7 - Networking Services", 2, "NSG flow log retention >= 90 days", false),
            Cis("7.6", "7 - Networking Services", 2, "Network Watcher enabled for all regions in use", false),
            Cis("7.7", "7 - Networking Services", 1, "Public IP addresses evaluated on a periodic basis", true),
            Cis("7.8", "7 - Networking Services", 2, "VNet flow log retention >= 90 days", false),
            Cis("7.9", "7 - Networking Services", 2, "VPN Gateway P2S uses Azure AD authentication", false),
            Cis("7.10", "7 - Networking Services", 2, "WAF enabled on Azure Application Gateway", false),
            Cis("7.11", "7 - Networking Services", 1, "Subnets associated with NSGs", false),
            Cis("7.12", "7 - Networking Services", 1, "App Gateway SSL policy min TLS 1.2+", false),
            Cis("7.13", "7 - Networking Services", 1, "HTTP2 enabled on Application Gateway", false),
            Cis("7.14", "7 - Networking Services", 2, "WAF request body inspection enabled", false),
            Cis("7.15", "7 - Networking Services", 2, "WAF bot protection enabled", false),
            Cis("7.16", "7 - Networking Services", 2, "Azure Network Security Perimeter (NSP) is used", true),
            Cis("8.1.1.1", "8 - Security Services", 2, "Microsoft Defender CSPM", false),
            Cis("8.1.2.1", "8 - Security Services", 2, "Microsoft Defender for APIs", false),
            Cis("8.1.3.1", "8 - Security Services", 2, "Microsoft Defender for Servers", false),
            Cis("8.1.3.3", "8 - Security Services", 2, "Endpoint protection (WDATP) component", false),
            Cis("8.1.4.1", "8 - Security Services", 2, "Microsoft Defender for Containers", false),
            Cis("8.1.5.1", "8 - Security Services", 2, "Microsoft Defender for Storage", false),
            Cis("8.1.6.1", "8 - Security Services", 2, "Microsoft Defender for App Services", false),
            Cis("8.1.7.1", "8 - Security Services", 2, "Microsoft Defender for Azure Cosmos DB", false),
            Cis("8.1.7.2", "8 - Security Services", 2, "Microsoft Defender for Open-Source Relational DBs", false),
            Cis("8.1.7.3", "8 - Security Services", 2, "Microsoft Defender for SQL (Managed Instance)", false),
            Cis("8.1.7.4", "8 - Security Services", 2, "Microsoft Defender for SQL Servers on Machines", false),
            Cis("8.1.8.1", "8 - Security Services", 2, "Microsoft Defender for Key Vault", false),
            Cis("8.1.9.1", "8 - Security Services", 2, "Microsoft Defender for Resource Manager", false),
            Cis("8.1.10", "8 - Security Services", 1, "Defender configured to check VM OS updates", false),
            Cis("8.1.12", "8 - Security Services", 1, "Security alerts notify subscription Owners", false),
            Cis("8.1.13", "8 - Security Services", 1, "Additional email addresses for security contact", false),
            Cis("8.1.14", "8 - Security Services", 1, "Alert severity notifications configured", false),
            Cis("8.1.15", "8 - Security Services", 1, "Attack path notifications configured", false),
            Cis("8.3.1", "8 - Security Services", 1, "Key expiration set - RBAC Key Vaults", false),
            Cis("8.3.2", "8 - Security Services", 1, "Key expiration set - non-RBAC Key Vaults", false),
            Cis("8.3.3", "8 - Security Services", 1, "Secret expiration set - RBAC Key Vaults", false),
            Cis("8.3.4", "8 - Security Services", 1, "Secret expiration set - non-RBAC Key Vaults", false),
            Cis("8.3.5", "8 - Security Services", 1, "Key Vault purge protection enabled", false),
            Cis("8.3.6", "8 - Security Services", 2, "Key Vault RBAC authorization enabled", false),
            Cis("8.3.7", "8 - Security Services", 1, "Key Vault public network access disabled", false),
            Cis("8.3.8", "8 - Security Services", 2, "Private endpoints used to access Key Vault", false),
            Cis("8.3.9", "8 - Security Services", 2, "Automatic key rotation enabled", false),
            Cis("8.3.10", "8 - Security Services", 2, "Key Vault Managed HSM used when required", true),
            Cis("8.3.11", "8 - Security Services", 1, "Certificate validity period <= 12 months", false),
            Cis("8.4.1", "8 - Security Services", 2, "Azure Bastion Host exists", false),
            Cis("8.5", "8 - Security Services", 2, "DDoS Network Protection enabled on VNets", false),
            Cis("9.1.1", "9 - Storage Services", 1, "Azure Files soft delete enabled", false),
            Cis("9.1.2", "9 - Storage Services", 1, "SMB protocol version >= 3.1.1", false),
            Cis("9.1.3", "9 - Storage Services", 1, "SMB channel encryption AES-256-GCM or higher", false),
            Cis("9.2.1", "9 - Storage Services", 1, "Blob soft delete enabled", false),
            Cis("9.2.2", "9 - Storage Services", 1, "Container soft delete enabled", false),
            Cis("9.2.3", "9 - Storage Services", 2, "Blob versioning enabled", false),
            Cis("9.2.4", "9 - Storage Services", 2, "Storage logging enabled for Blob Service read requests", false),
            Cis("9.2.5", "9 - Storage Services", 2, "Storage logging enabled for Blob Service write requests", false),
            Cis("9.2.6", "9 - Storage Services", 2, "Storage logging enabled for Blob Service delete requests", false),
            Cis("9.3.1.1", "9 - Storage Services", 1, "Key rotation reminders enabled", false),
            Cis("9.3.1.2", "9 - Storage Services", 1, "Access keys regenerated within 90 days", false),
            Cis("9.3.1.3", "9 - Storage Services", 1, "Storage account key access disabled", false),
            Cis("9.3.2.1", "9 - Storage Services", 2, "Private endpoints used to access storage accounts", false),
            Cis("9.3.2.2", "9 - Storage Services", 1, "Public network access disabled", false),
            Cis("9.3.2.3", "9 - Storage Services", 1, "Default network access rule is Deny", false),
            Cis("9.3.3.1", "9 - Storage Services", 1, "Default to Microsoft Entra authorization in Azure portal", false),
            Cis("9.3.4", "9 - Storage Services", 1, "Secure transfer (HTTPS) required", false),
            Cis("9.3.5", "9 - Storage Services", 2, "Allow Azure trusted services to access storage", false),
            Cis("9.3.6", "9 - Storage Services", 1, "Minimum TLS version 1.2", false),
            Cis("9.3.7", "9 - Storage Services", 1, "Cross-tenant replication disabled", false),
            Cis("9.3.8", "9 - Storage Services", 1, "Blob anonymous access disabled", false),
            Cis("9.3.9", "9 - Storage Services", 1, "Storage account has CanNotDelete resource lock", false),
            Cis("9.3.10", "9 - Storage Services", 2, "Storage account has ReadOnly resource lock", false),
            Cis("9.3.11", "9 - Storage Services", 2, "Redundancy set to geo-redundant (GRS)", false),

        // ---------------- CIS Benchmark - AWS ----------------
        Ust("cis-aws-root-mfa", "cis-aws", "Identity", "IAM", Risk.High, "Root account has MFA enabled", "Enable hardware MFA on the AWS root account.", ""),
        Ust("cis-aws-s3-public", "cis-aws", "Data", "Storage", Risk.High, "S3 buckets block public access", "Enable S3 Block Public Access at the account level.", ""),
        Ust("cis-aws-cloudtrail", "cis-aws", "SecOps", "Logging", Risk.Medium, "CloudTrail enabled across all regions", "Enable a multi-region CloudTrail trail with log file validation.", ""),
        Ust("cis-aws-iam-password", "cis-aws", "Identity", "IAM", Risk.Low, "Strong IAM password policy configured", "Configure a strong IAM password policy.", ""),
    };
}

// ------------------------------------------------------------------------------------
// 5. Connectors
// ------------------------------------------------------------------------------------
public sealed record CheckOutcome(TestStatus Status, string? Result = null, SkipReason SkippedBecause = SkipReason.None, string? SkipDetail = null);

public interface ICloudConnector
{
    string? Account { get; }
    string? TenantName { get; }
    string? Domain { get; }
    Task ConnectAsync(CancellationToken ct);
    Task<CheckOutcome> EvaluateAsync(Check check, CancellationToken ct);
    Task<TenantOverview?> GetTenantOverviewAsync(CancellationToken ct);
}

// Deterministic stub so the app runs end to end today. Skip rules mirror the Microsoft module;
// pass/fail is a stable hash of (tenant, check). Replace with Microsoft Graph / ARM / AWS SDK logic.
public sealed class StubCloudConnector : ICloudConnector
{
    private readonly AssessmentRequest _r;
    public StubCloudConnector(AssessmentRequest request) => _r = request;

    public string? Account => _r.ClientId;
    public string? TenantName => null;   // a real connector reads this from Graph /organization
    public string? Domain => null;

    public Task ConnectAsync(CancellationToken ct) => Task.CompletedTask;

    public Task<TenantOverview?> GetTenantOverviewAsync(CancellationToken ct) => Task.FromResult<TenantOverview?>(null);

    public Task<CheckOutcome> EvaluateAsync(Check check, CancellationToken ct)
    {
        // Skip rules (same reasons the Microsoft module uses).
        if (check.Framework == "cis-aws" && string.IsNullOrWhiteSpace(_r.AwsAccountId))
            return Task.FromResult(new CheckOutcome(TestStatus.Skipped, null, SkipReason.NotApplicable));

        if (check.Pillars.Contains("Infrastructure") && check.Framework == "zero-trust" && _r.SubscriptionIds.Count == 0)
            return Task.FromResult(new CheckOutcome(TestStatus.Skipped, null, SkipReason.NoAzureAccess));

        var missing = check.Service.Where(s => !_r.ConnectsTo(s)).ToArray();
        if (missing.Length > 0)
            return Task.FromResult(new CheckOutcome(TestStatus.Skipped, null, SkipReason.NotConnectedToService, string.Join(", ", missing)));

        // CIS manual controls cannot be automated: report them for human review (the CIS tool's MANUAL status).
        if (check.Manual)
            return Task.FromResult(new CheckOutcome(TestStatus.Investigate,
                $"Manual review required. This CIS control cannot be audited from the Azure control plane; verify it per the CIS Microsoft Azure Foundations Benchmark v5.0.0.\n\n**Control**\n\n{check.Id} {check.Title} ({check.Profile})"));

        bool pass = Hash($"{_r.TenantId}:{_r.AwsAccountId}:{check.Id}") % 10 >= 4; // ~60% compliant
        string result = pass
            ? $"Passed. The target configuration satisfies this check.\n\n**Check**\n\n{check.Title}\n\n_Demo connector: results are deterministic placeholders until a real connector is wired in._"
            : $"Failed. A non-compliant configuration was detected for this check.\n\n**Check**\n\n{check.Title}\n\n**Remediation**\n\n- {check.Recommendation ?? "Review the setting named in the check title in the relevant admin center and bring it in line with the recommendation."}\n\n_Demo connector: results are deterministic placeholders until a real connector is wired in._";
        return Task.FromResult(new CheckOutcome(pass ? TestStatus.Passed : TestStatus.Failed, result));
    }

    private static int Hash(string s)
    {
        int h = 17;
        foreach (char c in s) h = unchecked(h * 31 + c);
        return Math.Abs(h);
    }
}

public static class CloudConnectorFactory
{
    // TODO: return a real connector (Azure.Identity ClientSecretCredential/Certificate + Graph/ARM; AWS SDK for CIS AWS).
    public static ICloudConnector Create(AssessmentRequest request) => new StubCloudConnector(request);
}

// ------------------------------------------------------------------------------------
// 6. Durable workflow
// ------------------------------------------------------------------------------------
public static class AssessmentWorkflow
{
    // Orchestrator: resolve scope, fan out one activity per check, then aggregate.
    [Function(nameof(AssessmentOrchestration))]
    public static async Task<AssessmentResult> AssessmentOrchestration([OrchestrationTrigger] TaskOrchestrationContext context)
    {
        var request = context.GetInput<AssessmentRequest>() ?? new AssessmentRequest();
        var checks = Catalog.Select(request).ToList();

        context.SetCustomStatus(new { phase = "running", total = checks.Count });

        var tasks = checks
            .Select(c => context.CallActivityAsync<Finding>(nameof(RunCheck), new CheckInput(request, c.Id)))
            .ToList();
        var findings = (await Task.WhenAll(tasks)).ToList();

        var overview = await context.CallActivityAsync<TenantOverview?>(nameof(ReadTenantOverview), request);

        var summary = Vocabulary.Pillars.Select(p =>
        {
            var inPillar = findings.Where(f => f.TestPillar.Contains(p)).ToList();
            return new PillarSummary
            {
                Pillar = p,
                Passed = inPillar.Count(f => f.TestStatus == TestStatus.Passed),
                Failed = inPillar.Count(f => f.TestStatus is TestStatus.Failed or TestStatus.Error or TestStatus.Investigate),
                Skipped = inPillar.Count(f => f.TestStatus == TestStatus.Skipped),
                Planned = inPillar.Count(f => f.TestStatus == TestStatus.Planned),
                Suppressed = inPillar.Count(f => f.TestStatus == TestStatus.Suppressed),
                Total = inPillar.Count(f => f.TestStatus is not (TestStatus.Skipped or TestStatus.Planned or TestStatus.Suppressed)),
            };
        }).ToList();

        var failed = findings.Where(f => f.TestStatus == TestStatus.Failed).ToList();

        return new AssessmentResult
        {
            ExecutedAt = context.CurrentUtcDateTime,
            TenantId = request.TenantId,
            Account = request.ClientId,
            Frameworks = request.Frameworks,
            Pillars = request.Pillars,
            TenantType = request.TenantType,
            TestResultSummary = summary,
            FailedByRisk = new RiskSummary
            {
                Critical = failed.Count(f => f.TestRisk == Risk.Critical),
                High = failed.Count(f => f.TestRisk == Risk.High),
                Medium = failed.Count(f => f.TestRisk == Risk.Medium),
                Low = failed.Count(f => f.TestRisk == Risk.Low),
                Unranked = failed.Count(f => f.TestRisk == Risk.Unranked),
            },
            TenantInfo = overview,
            Tests = findings.OrderBy(f => f.TestRisk).ThenBy(f => f.TestStatus).ThenBy(f => f.TestId).ToList(),
        };
    }

    // Activity: evaluate one check against the target.
    [Function(nameof(RunCheck))]
    public static async Task<Finding> RunCheck([ActivityTrigger] CheckInput input)
    {
        if (!Catalog.ById.TryGetValue(input.CheckId, out var check))
        {
            return new Finding { TestId = input.CheckId, TestTitle = "Unknown check", TestStatus = TestStatus.Error, TestRisk = Risk.Unranked };
        }

        var connector = CloudConnectorFactory.Create(input.Request);
        await connector.ConnectAsync(CancellationToken.None);

        CheckOutcome outcome;
        try
        {
            outcome = await connector.EvaluateAsync(check, CancellationToken.None);
        }
        catch (Exception ex)
        {
            outcome = new CheckOutcome(TestStatus.Error, $"Error while evaluating the check: {ex.GetType().Name}");
        }

        var finding = new Finding
        {
            TestId = check.Id,
            TestTitle = check.Title,
            Framework = check.Framework,
            TestPillar = check.Pillars,
            TestCategory = check.Category,
            TestRisk = check.Risk,
            TestImpact = check.UserImpact,
            TestImplementationCost = check.ImplementationCost,
            TestSfiPillar = check.SfiPillar,
            TestMinimumLicense = check.MinimumLicense,
            TestService = check.Service,
            TestProfile = check.Profile,
            TestManual = check.Manual,
            TestStatus = outcome.Status,
            TestSkipped = outcome.SkippedBecause,
            SkippedReason = outcome.SkippedBecause == SkipReason.None ? null : Vocabulary.SkipText(outcome.SkippedBecause, outcome.SkipDetail),
            TestResult = outcome.Result,
            Recommendation = outcome.Status == TestStatus.Failed ? check.Recommendation : null,
            Resource = check.Framework == "cis-aws" ? input.Request.AwsAccountId : input.Request.TenantId,
        };

        // Accepted risks (CIS suppressions): only Failed / Error can be suppressed, and only while the entry is unexpired.
        if (finding.TestStatus is TestStatus.Failed or TestStatus.Error)
        {
            var sup = input.Request.Suppressions.FirstOrDefault(s => s.IsActive(DateTime.UtcNow) && s.Matches(finding));
            if (sup is not null)
            {
                finding.TestStatus = TestStatus.Suppressed;
                finding.SuppressionJustification = sup.Justification;
                finding.TestResult = $"Suppressed as an accepted risk until {sup.Expires}.\n\n**Justification**\n\n{sup.Justification}\n\n---\n\n{finding.TestResult}";
            }
        }

        return finding;
    }

    // Activity: tenant overview figures for the Overview page.
    [Function(nameof(ReadTenantOverview))]
    public static async Task<TenantOverview?> ReadTenantOverview([ActivityTrigger] AssessmentRequest request)
    {
        var connector = CloudConnectorFactory.Create(request);
        await connector.ConnectAsync(CancellationToken.None);
        return await connector.GetTenantOverviewAsync(CancellationToken.None);
    }
}

// ------------------------------------------------------------------------------------
// 7. HTTP API
// ------------------------------------------------------------------------------------
public static class Api
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    // GET /api/ui : the single-page UST web app (index.html embedded in the assembly).
    [Function("WebUi")]
    public static async Task<HttpResponseData> WebUi(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "ui")] HttpRequestData req)
    {
        var res = req.CreateResponse(HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "text/html; charset=utf-8");
        res.Headers.Add("Cache-Control", "no-cache");
        await res.WriteStringAsync(LoadEmbedded("index.html") ?? "<html><body><h1>UI resource not found</h1></body></html>");
        return res;
    }

    // GET /api/catalog : vocabulary + the full check catalog, so the page can render before any run.
    [Function("GetCatalog")]
    public static Task<HttpResponseData> GetCatalog(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "catalog")] HttpRequestData req)
    {
        var payload = new
        {
            version = Program.Version,
            frameworks = Catalog.Frameworks.Select(f => new { key = f.Key, name = f.Name, source = f.Source }),
            pillars = Vocabulary.Pillars,
            services = Vocabulary.Services,
            environments = Vocabulary.Environments,
            exchangeEnvironments = Vocabulary.ExchangeEnvironments,
            tenantTypes = Vocabulary.TenantTypes,
            sfiPillars = Vocabulary.SfiPillars,
            graphScopes = Vocabulary.GraphScopes,
            skipReasons = Enum.GetNames<SkipReason>().Where(n => n != "None"),
            statuses = Enum.GetNames<TestStatus>(),
            cisLevels = new[] { 1, 2 },
            defaults = new AssessmentRequest(),
            checks = Catalog.All.Select(c => new
            {
                testId = c.Id, framework = c.Framework, testPillar = c.Pillars, testCategory = c.Category,
                testRisk = c.Risk, testImpact = c.UserImpact, testImplementationCost = c.ImplementationCost,
                testSfiPillar = c.SfiPillar, testTitle = c.Title, tenantType = c.TenantType, testService = c.Service,
                testMinimumLicense = c.MinimumLicense, compatibleLicense = c.CompatibleLicense,
                testProfile = c.Profile, testManual = c.Manual,
            }),
        };
        return WriteJson(req, HttpStatusCode.OK, payload);
    }

    // POST /api/assessments : validate, start the orchestration, return Durable status URLs (+ id).
    [Function("StartAssessment")]
    public static async Task<HttpResponseData> StartAssessment(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "assessments")] HttpRequestData req,
        [DurableClient] DurableTaskClient client)
    {
        AssessmentRequest? request;
        try
        {
            request = await JsonSerializer.DeserializeAsync<AssessmentRequest>(req.Body, Json);
        }
        catch (JsonException ex)
        {
            return await WriteJson(req, HttpStatusCode.BadRequest, new { error = "Invalid JSON: " + ex.Message });
        }
        request ??= new AssessmentRequest();

        var problem = request.Validate();
        if (problem is not null)
            return await WriteJson(req, HttpStatusCode.BadRequest, new { error = problem });

        int count = Catalog.Select(request).Count();
        if (count == 0)
            return await WriteJson(req, HttpStatusCode.BadRequest, new { error = "The selected scope contains no checks." });

        string instanceId = await client.ScheduleNewOrchestrationInstanceAsync(nameof(AssessmentWorkflow.AssessmentOrchestration), request);
        return await WriteJson(req, HttpStatusCode.Accepted, new
        {
            id = instanceId,
            checks = count,
            statusQueryGetUri = $"/api/assessments/{instanceId}",
        });
    }

    // GET /api/assessments/{instanceId} : { instanceId, runtimeStatus, customStatus, result } in camelCase.
    [Function("GetAssessment")]
    public static async Task<HttpResponseData> GetAssessment(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "assessments/{instanceId}")] HttpRequestData req,
        [DurableClient] DurableTaskClient client,
        string instanceId)
    {
        var meta = await client.GetInstanceAsync(instanceId, getInputsAndOutputs: true);
        if (meta is null)
            return await WriteJson(req, HttpStatusCode.NotFound, new { error = "instance not found" });

        bool completed = meta.RuntimeStatus == OrchestrationRuntimeStatus.Completed;
        object? customStatus = null;
        try { customStatus = meta.ReadCustomStatusAs<JsonElement?>(); } catch { /* no custom status yet */ }

        return await WriteJson(req, HttpStatusCode.OK, new
        {
            instanceId = meta.InstanceId,
            runtimeStatus = meta.RuntimeStatus.ToString(),
            createdAt = meta.CreatedAt,
            lastUpdatedAt = meta.LastUpdatedAt,
            customStatus,
            result = completed ? meta.ReadOutputAs<AssessmentResult>() : null,
        });
    }

    private static async Task<HttpResponseData> WriteJson(HttpRequestData req, HttpStatusCode status, object payload)
    {
        var res = req.CreateResponse(status);
        res.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await res.WriteStringAsync(JsonSerializer.Serialize(payload, Json));
        return res;
    }

    private static string? LoadEmbedded(string fileName)
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith(fileName, StringComparison.OrdinalIgnoreCase));
        if (name is null) return null;
        using var stream = asm.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
