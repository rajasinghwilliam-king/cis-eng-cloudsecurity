# Zero Trust Assessment: parameter reference

Source: [microsoft/zerotrustassessment](https://github.com/microsoft/zerotrustassessment) (PowerShell module `ZeroTrustAssessment`, cloned 2026-10-01).
This file lists every parameter, setting and metadata field the module exposes, and the full test catalog.
The UST app ([src/CloudSecurityAssessment.cs](../src/CloudSecurityAssessment.cs)) mirrors these names in its request body and catalog.

## 1. Public cmdlets

`FunctionsToExport`: Clear-ZtRequiredModule, Connect-ZtAssessment, Disconnect-ZtAssessment, Get-ZtCurrentLicense, Get-ZtExportStatistics, Get-ZtGraphScope, Get-ZtTest, Get-ZtTestStatistics, Invoke-ZtAssessment, Invoke-ZtAzureRequest, Invoke-ZtAzureResourceGraphRequest, Invoke-ZtGraphRequest. Alias: `Invoke-ZeroTrustAssessment`.

### Connect-ZtAssessment

| Parameter | Type | Default | Allowed values / notes |
|---|---|---|---|
| UseDeviceCode | switch | | Device-code sign-in |
| Environment | string | Global | China, Germany, Global, USGov, USGovDoD |
| UseTokenCache | switch (hidden) | | |
| TenantId (alias Tenant) | string | | Target tenant |
| ClientId | string | | App registration to sign in with |
| Certificate | CertificateParameter | | Certificate credential |
| Service | string[] | All | All, Graph, Azure, AipService, ExchangeOnline, SecurityCompliance, SharePointOnline |
| ExchangeEnvironmentName | string | O365Default | O365China, O365Default, O365GermanyCloud, O365USGovDoD, O365USGovGCCHigh |
| UserPrincipalName | string | | For Security & Compliance PowerShell |
| SharePointAdminUrl | string | | For SharePoint Online |
| Force | switch | | Reconnect even if connected |
| IgnoreLanguageMode | switch | | Bypass Constrained Language Mode check |

### Invoke-ZtAssessment

| Parameter | Type | Default | Allowed values / notes |
|---|---|---|---|
| Path | string | ./ZeroTrustReport | Output folder |
| Days | int | 30 | 1 to 30, sign-in log window |
| MaximumSignInLogQueryTime | int | 60 | Minutes; 0 = no limit |
| Resume | switch | | Reuse previously exported data |
| ShowLog | switch | | Summary log to console |
| ExportLog | switch | | Write log to file |
| DisableTelemetry | switch | false | Only the tenant id is collected |
| Tests | string[] | | Specific test IDs; empty = all |
| ConfigurationFile | string | | Path to a config file; CLI values override it |
| Pillar | string | All | All, Identity, Devices, Network, Data, Infrastructure, SecOps, AI |
| Preview | switch | | Preview features |
| ExportThrottleLimit | int | config `ThrottleLimit.Export` (5) | |
| TestThrottleLimit | int | config `ThrottleLimit.Tests` (5) | |
| Timeout | timespan | 1.00:00:00 | Whole run |
| TestTimeout | timespan | config `Tests.Timeout` (60 min) | Per test; 0 disables |
| NoBrowser | switch | | Do not open the dashboard / report |
| IgnoreLanguageMode | switch | | |

### Disconnect-ZtAssessment

| Parameter | Type | Default | Allowed values |
|---|---|---|---|
| Service | string[] | All | All, Azure, AipService, ExchangeOnline, Graph, SharePointOnline |
| IncludeCleanup | switch | | |

### Get-ZtTest

| Parameter | Type | Notes |
|---|---|---|
| Tests (alias ID) | string[] | Test IDs |
| Pillar | string[] | Argument completer `ZeroTrustAssessment.Tests.Pillar` |
| TenantType | string | Workforce, External |
| Current, Reload | switch (hidden) | |

### Other cmdlets

| Cmdlet | Parameters |
|---|---|
| Get-ZtCurrentLicense | Force (switch) |
| Get-ZtExportStatistics | Name (string[]) |
| Get-ZtTestStatistics | TestID (string[], pipeline) |
| Get-ZtGraphScope | none; returns the Graph scope list below |
| Clear-ZtRequiredModule | none |
| Invoke-ZtGraphRequest | RelativeUri, UniqueId, Select, Filter, Top, QueryParameters, ApiVersion (v1.0, beta), Method (GET, POST), Body, ConsistencyLevel, DisablePaging, DisableBatching, BatchSize, GraphBaseUri, SkipCache, OutputType (PSObject, PSCustomObject, Hashtable), ExportPath, Headers |
| Invoke-ZtAzureRequest | Path / Uri + ResourceId / SubscriptionId + ResourceGroupName + ResourceProviderName + ResourceType + Name + ApiVersion, Method (GET, POST), Payload, AsJob, DefaultProfile, WaitForCompletion, PollFrom, FinalResultFrom, NextLinkName, PageableItemName, MaxPageSize, Select, Filter, QueryParameters, pagination and cache switches |
| Invoke-ZtAzureResourceGraphRequest | Query (mandatory), SubscriptionId (string[]), ApiVersion (2024-04-01), MaxPages (1 to 1000, default 100) |

## 2. Module configuration (PSFramework `Set-PSFConfig -Module ZeroTrustAssessment`)

Azure.CacheLifetime, Azure.CacheMaxItems, Azure.DisableCache, Debug.KeepWorkflows, Export.DependencyWaitLimit, Export.SignInLog.MaxSizeBytes, Graph.CacheLifetime, Graph.CacheMaxItems, Graph.DisableCache, Logging.Database.IncludeQueryResults, Logging.InMemoryLog.MinSize, TabExpansion.TestLimit, Tests.RetryCount, Tests.RetryTimeout, Tests.Statistics.MessageCountSoftCap, Tests.Timeout, Tests.TimeoutType, ThrottleLimit.Export, ThrottleLimit.Tests, ZeroTrustAssessment.EmergencyAccessAccounts.

## 3. Graph scopes (Get-ZtGraphScope, all read-only)

Application.Read.All, AuditLog.Read.All, CopilotPackages.Read.All, CrossTenantInformation.ReadBasic.All, CustomSecAttributeAssignment.Read.All, DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementRBAC.Read.All, DeviceManagementServiceConfig.Read.All, Directory.Read.All, DirectoryRecommendations.Read.All, EntitlementManagement.Read.All, IdentityRiskEvent.Read.All, IdentityRiskyServicePrincipal.Read.All, IdentityRiskyUser.Read.All, LifecycleWorkflows-Workflow.Read.All, NetworkAccess.Read.All, Policy.Read.All, Policy.Read.ConditionalAccess, Policy.Read.PermissionGrant, PrivilegedAccess.Read.AzureAD, PrivilegedAssignmentSchedule.Read.AzureADGroup, PrivilegedEligibilitySchedule.Read.AzureADGroup, Reports.Read.All, RoleManagement.Read.All, SecurityAlert.Read.All, SecurityEvents.Read.All, SecurityIdentitiesHealth.Read.All, SecurityIdentitiesSensors.Read.All, SecurityIncident.Read.All, ThreatHunting.Read.All, UserAuthenticationMethod.Read.All.

## 4. Test metadata: the `[ZtTest]` attribute

| Field | Type | Allowed values |
|---|---|---|
| TestId | int | Unique ID (file `tests/Test-Assessment.<id>.ps1` + `.md`) |
| Title | string | |
| Pillar | string[] | Identity, Devices, Network, Data, Infrastructure, SecOps, AI |
| Category | string | Free text (53 distinct values) |
| RiskLevel | string | Critical, High, Medium, Low, Unranked |
| UserImpact | string | Low, Medium, High |
| ImplementationCost | string | Low, Medium, High |
| SfiPillar | string | Protect identities and secrets; Protect tenants and isolate production systems; Protect tenants and production systems; Protect networks; Protect engineering systems; Monitor and detect cyberthreats; Accelerate response and remediation |
| TenantType | string[] | Workforce, External |
| Service | string[] | Graph, Azure, AipService, ExchangeOnline, SecurityCompliance, SharePointOnline |
| MinimumLicense | string[] | Display names (Free, P1, P2, Microsoft 365 E3, ...) |
| CompatibleLicense | string[] | Service plan IDs (AAD_PREMIUM, INTUNE_A, ...); `&` joins plans that are all required |

### Add-ZtTestResultDetail (how a test reports)

| Parameter | Allowed values |
|---|---|
| Status | bool (true = Passed) |
| CustomStatus | Investigate, Error |
| SkippedBecause | NotConnectedAzure, NotConnectedExchange, NotConnectedSecurityCompliance, NotConnectedToService, NotLicensedEntraIDP1, NotLicensedEntraIDP2, NotLicensedEntraIDGovernance, NotLicensedEntraWorkloadID, NotSupported, UnderConstruction, NotLicensedIntune, NoAzureAccess, NotApplicable, NotDotGovDomain, NoCompatibleLicenseFound, TimeoutReached |
| NotConnectedService | Graph, Azure, AipService, ExchangeOnline, SecurityCompliance, SharePointOnline |
| Risk | Critical, High, Medium, Low, Unranked |
| UserImpact | Catastrophic, High, Medium, Low |
| ImplementationCost | High, Medium, Low |
| AppliesTo | Identity, Devices, Data |
| Tag | Credential, TenantPolicy, ExternalCollaboration, Application, User, PrivilegedIdentity, ConditionalAccess, Authentication, AccessControl, Identity, Devices |
| GraphObjectType | AuthenticationMethod, AuthorizationPolicy, ConditionalAccess, ConsentPolicy, Devices, DiagnosticSettings, Domains, Groups, IdentityProtection, Users, UserRole, External collaboration |
| Pillar, Category | Overrides for dynamic tests (Defender for Cloud) |
| Description, Result, Title, TestId, GraphObjects | Markdown text and objects shown in the report |

### Report JSON (`Tests[]` in the generated report)

TestId, TestTitle, TestPillar, TestCategory, TestRisk, TestImpact, TestImplementationCost, TestSfiPillar, TestMinimumLicense, TestAppliesTo, TestTags, TestStatus (Passed, Failed, Skipped, Planned, Investigate, Error), TestSkipped, SkippedReason, TestResult, TestDescription.
Top level: ExecutedAt, TenantId, TenantName, Domain, Account, CurrentVersion, LatestVersion, TestResultSummary (`<Pillar>Passed` / `<Pillar>Total` per pillar), TenantInfo (TenantOverview counts, DeviceOverview, Conditional Access and authentication-method Sankey data).

## 5. Catalog summary

Tests by pillar (a test can belong to more than one pillar):

| Pillar | Tests |
|---|---|| Identity | 135 |
| Network | 69 |
| AI | 49 |
| Devices | 43 |
| Data | 38 |
| SecOps | 32 |
|  | 2 |
| Infrastructure | 1 |

Tests by category:

| Category | Tests |
|---|---|
| Access control | 45 |
| Global Secure Access | 37 |
| Application management | 28 |
| Devices | 25 |
| Azure Network Security | 25 |
| Credential management | 17 |
| Tenant | 15 |
| Privileged access | 14 |
| Information Protection | 11 |
| External collaboration | 11 |
| Monitoring | 11 |
| Email and collaboration security | 8 |
| AI Threat Detection | 8 |
| Data | 7 |
| Identity threat protection | 7 |
| Security information and event management | 6 |
| Endpoint threat protection | 5 |
| Advanced Classification | 4 |
| SharePoint Online | 4 |
| Data Security Posture Management | 4 |
| AI Authentication & Access | 4 |
| Private Access | 3 |
| Threat investigation and response | 2 |
| Identity governance | 2 |
| Sensitivity Labels Configuration | 2 |
| Data Loss Prevention (DLP) | 2 |
| Sensitivity Labels | 2 |
| sensitivity-labels | 2 |
| Agent Lifecycle | 1 |
| Microsoft Defender for Cloud | 1 |
| AI Identity & Access | 1 |
| Secure AI Authentication and Access | 1 |
| AI Cloud Posture | 1 |
| AI for security | 1 |
| AI Inventory & Lifecycle | 1 |
| SaaS threat detection | 1 |
| Incident response operations | 1 |
| Network | 1 |
| Hybrid infrastructure | 1 |
| Role management | 1 |
| Network security | 1 |
| Credential management, Privileged access | 1 |
| Access control; Credential management | 1 |
| Authentication | 1 |
| Applications management | 1 |
| Rights Management Service | 1 |
| Label Policy Configuration | 1 |
| Microsoft Purview Message Encryption | 1 |
| Rights Management Service (RMS) | 1 |
| Entra | 1 |
| Application Proxy | 1 |
| Advanced Label Features | 1 |
| Encryption | 1 |

## 6. Full test catalog (336 tests)

| ID | Pillar | Category | Risk | User impact | Effort | SFI pillar | Tenant type | Service | License | Title |
|---|---|---|---|---|---|---|---|---|---|---|
| 21770 | Identity | Access control | Medium | High | Low | Protect engineering systems | Workforce, External | Graph | AAD_PREMIUM | Inactive applications don’t have highly privileged Microsoft Graph API permissions |
| 21771 | Identity | Application management | High | Low | Low | Protect engineering systems | Workforce, External | Graph | P1 | Inactive applications don’t have highly privileged built-in roles |
| 21772 | Identity | Application management | High | Low | Medium | Protect identities and secrets | Workforce, External | Graph | Free | Applications don't have client secrets configured |
| 21773 | Identity | Application management | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  | Free | Applications don't have certificates with expiration longer than 180 days |
| 21774 | Identity | Application management | High | Low | Low | Protect identities and secrets | Workforce, External |  | Free | Microsoft services applications don't have credentials configured |
| 21775 | Identity | Application management | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  | Free | Enforce standards for app secrets and certificates |
| 21776 | Identity | Application management | High | High | Medium | Protect identities and secrets | Workforce, External |  | Free | User consent settings are restricted |
| 21777 | Identity | Access control | High | Low | Low | Protect tenants and isolate production systems | Workforce, External |  | Free | App instance property lock is configured for all multitenant applications |
| 21778 |  | Application management | Medium | Low | High |  | Workforce, External |  |  | Line-of-business and partner apps use MSAL |
| 21779 |  | Application management | Medium | Low | Medium |  | Workforce, External |  |  | Use recent versions of Microsoft Applications |
| 21780 | Identity | Application management | Medium | Low | High | Protect identities and secrets | Workforce, External |  | Free | No usage of ADAL in the tenant |
| 21781 | Identity | Privileged access | High | Low | Medium | Monitor and detect cyberthreats | Workforce |  | P1 | Privileged users sign in with phishing-resistant methods |
| 21782 | Identity | Privileged access | High | Low | Medium | Protect identities and secrets | Workforce |  | P1 | Privileged accounts have phishing-resistant methods registered |
| 21783 | Identity | Access control | High | Low | Medium | Protect identities and secrets | Workforce |  | P1 | Privileged Microsoft Entra built-in roles are targeted with Conditional Access policies to enforce phishing-resistant methods |
| 21784 | Identity | Access control; Credential management | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  | P1 | All user sign in activity uses phishing-resistant authentication methods |
| 21786 | Identity | Access control | High | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | User sign-in activity uses token protection |
| 21787 | Identity | Privileged access | High | Medium | Medium | Protect tenants and isolate production systems | Workforce |  | Free | Permissions to create new tenants are limited to the Tenant Creator role |
| 21788 | Identity | Privileged access | High | Low | Low | Protect engineering systems | Workforce |  | Free | Global Administrators don't have standing access to Azure subscriptions |
| 21789 | Identity | Monitoring | Medium | Low | Low | Monitor and detect cyberthreats | Workforce |  |  | Tenant creation events are triaged |
| 21790 | Identity | Application management | High | Medium | High | Protect tenants and isolate production systems | Workforce, External |  | Free | Outbound cross-tenant access settings are configured |
| 21791 | Identity | External collaboration | Medium | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Free | Guests can’t invite other guests |
| 21792 | Identity | External collaboration | Medium | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Free | Guests have restricted access to directory objects |
| 21793 | Identity | Application management | High | Low | Medium | Protect networks | Workforce, External |  | P1 | Tenant restrictions v2 policy is configured |
| 21795 | Identity | Monitoring | Medium | High | Low | Monitor and detect cyberthreats | Workforce |  | P1 | No legacy authentication sign-in activity |
| 21796 | Identity | Access control | Medium | High | Low | Protect identities and secrets | Workforce |  | P1 | Block legacy authentication policy is configured |
| 21797 | Identity | Access control | High | High | Medium | Accelerate response and remediation | Workforce, External |  | P2 | Restrict access to high risk users |
| 21798 | Identity | Access control | High | Low | Low | Monitor and detect cyberthreats | Workforce, External |  | P2 | ID Protection notifications are enabled |
| 21799 | Identity | Access control | High | Medium | Medium | Accelerate response and remediation | Workforce, External |  | P2 | Restrict high risk sign-ins |
| 21800 | Identity | Monitoring | Medium | Medium | Medium | Monitor and detect cyberthreats | Workforce, External |  | P1 | All user sign-in activity uses strong authentication methods |
| 21801 | Identity | Credential management | Medium | Medium | Medium | Protect identities and secrets | Workforce, External |  | P1 | Users have strong authentication methods configured |
| 21802 | Identity | Access control | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Microsoft Authenticator app shows sign-in context |
| 21803 | Identity | Credential management | High | Medium | Medium | Protect identities and secrets | Workforce, External |  | P1 | Migrate from legacy MFA and SSPR policies |
| 21804 | Identity | Credential management | High | Medium | Medium | Protect identities and secrets | Workforce, External |  | P1 | SMS and Voice Call authentication methods are disabled |
| 21806 | Identity | Access control | High | Low | Medium | Protect identities and secrets | Workforce, External |  | P1 | Secure the MFA registration (My Security Info) page |
| 21807 | Identity | Application management | Medium | Low | Low | Protect engineering systems | Workforce |  | P1 | Creating new applications and service principals is restricted to privileged users |
| 21808 | Identity | Access control | High | Medium | Low | Protect identities and secrets | Workforce, External |  | P1 | Restrict device code flow |
| 21809 | Identity | Application management | High | Low | Low | Protect identities and secrets | Workforce, External |  | Free | Admin consent workflow is enabled |
| 21810 | Identity | Access control | Medium | Medium | Medium | Protect engineering systems | Workforce, External |  | P1 | Resource-specific consent is restricted |
| 21811 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Password expiration is disabled |
| 21812 | Identity | Privileged access | Low | Low | Low | Protect engineering systems | Workforce |  | P1 | Maximum number of Global Administrators doesn't exceed eight users |
| 21813 | Identity | Privileged access | High | Low | Medium | Protect identities and secrets | Workforce |  | Free | High Global Administrator to privileged user ratio |
| 21814 | Identity | Privileged access | High | Low | Medium | Protect identities and secrets | Workforce |  | Free | Privileged accounts are cloud native identities |
| 21815 | Identity | Privileged access | High | Low | High | Protect identities and secrets | Workforce |  | P2 | All privileged role assignments are activated just in time and not permanently active |
| 21816 | Identity | Privileged access | High | Low | Medium | Protect identities and secrets | Workforce |  | P2 | All Microsoft Entra privileged role assignments are managed with PIM |
| 21817 | Identity | Application management | High | Low | Medium | Protect engineering systems | Workforce |  | P2 | Global Administrator role activation triggers an approval workflow |
| 21818 | Identity | Monitoring | High | Low | Medium | Monitor and detect cyberthreats | Workforce |  | P2 | Privileged role activations have monitoring and alerting configured |
| 21819 | Identity | Privileged access | Medium | Low | Low | Protect identities and secrets | Workforce |  | P2 | Activation alert for Global Administrator role assignments |
| 21820 | Identity | Privileged access | Low | Low | Medium | Protect identities and secrets | Workforce |  | P2 | Activation alert for all privileged role assignments |
| 21821 | Identity | Access control | Medium | Medium | Medium | Protect identities and secrets | Workforce |  |  | Guest access is restricted |
| 21822 | Identity | Access control | Medium | Medium | High | Protect identities and secrets | Workforce |  | Free | Guest access is limited to approved tenants |
| 21823 | Identity | External collaboration | Medium | Low | Low | Protect tenants and isolate production systems | Workforce |  | Free | Guest self-service sign-up via user flow is disabled |
| 21824 | Identity | External collaboration | Medium | Medium | Low | Protect tenants and isolate production systems | Workforce |  | P1 | Guests don't have long lived sign-in sessions |
| 21825 | Identity | Access control | Medium | Medium | Low | Protect identities and secrets | Workforce |  | P1 | Privileged users have short-lived sign-in sessions |
| 21828 | Identity | Access control | High | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Authentication transfer is blocked |
| 21829 | Identity | Access control | High | High | High | Protect identities and secrets | Workforce |  | P1 | Use cloud authentication |
| 21830 | Identity | Application management | High | Low | High | Protect engineering systems | Workforce |  | P1 | Conditional Access policies for Privileged Access Workstations are configured |
| 21831 | Identity | Privileged access | Medium | Low | Low | Protect tenants and isolate production systems | Workforce |  | P1 | Protected actions are enabled for high-impact management tasks |
| 21832 | Identity | Access control | Medium | Low | Low | Protect identities and secrets | Workforce |  | P1 | All groups in Conditional Access policies belong to a restricted management administrative unit |
| 21833 | Identity | Privileged access | Low | Low | High | Protect identities and secrets | Workforce |  |  | Directory Sync account credentials haven't been rotated recently |
| 21834 | Identity | Access control | High | Low | Medium | Protect identities and secrets | Workforce |  |  | Directory sync account is locked down to specific named location |
| 21835 | Identity | Application management | High | Low | High | Protect engineering systems | Workforce |  | P1 | Emergency access accounts are configured appropriately |
| 21836 | Identity | Application management | High | Low | Medium | Protect engineering systems | Workforce, External |  | P1 | Workload Identities are not assigned privileged roles |
| 21837 | Identity | Devices | High | Medium | Low | Protect engineering systems | Workforce |  | Free | Limit the maximum number of devices per user to 10 |
| 21838 | Identity | Credential management | High | Low | Low | Protect identities and secrets | Workforce, External |  | Free | Security key authentication method enabled |
| 21839 | Identity | Credential management | High | Low | Medium | Protect identities and secrets | Workforce, External |  | Free | Passkey authentication method enabled |
| 21840 | Identity | Credential management | High | Low | Low | Protect identities and secrets | Workforce, External |  | Free | Security key attestation is enforced |
| 21841 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Microsoft Authenticator app report suspicious activity setting is enabled |
| 21842 | Identity | Credential management, Privileged access | High | Low | Low | Protect identities and secrets | Workforce |  | P1 | Block administrators from using SSPR |
| 21843 | Identity | Access control | Low | Low | High | Protect identities and secrets | Workforce |  |  | Block legacy Microsoft Online PowerShell module |
| 21844 | Identity | Access control | Medium | Low | Medium | Protect identities and secrets | Workforce |  | Free | Block legacy Azure AD PowerShell module |
| 21845 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Temporary access pass is enabled |
| 21846 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Restrict Temporary Access Pass to Single Use |
| 21847 | Identity | Credential management | High | Low | Low | Protect identities and secrets | Workforce |  | P1 | Password protection for on-premises is enabled |
| 21848 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Add organizational terms to the banned password list |
| 21849 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Smart lockout duration is set to a minimum of 60 |
| 21850 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Smart lockout threshold set to 10 or less |
| 21851 | Identity | External collaboration | Medium | Medium | Medium | Protect tenants and isolate production systems | Workforce |  | Free | Guest access is protected by strong authentication methods |
| 21854 | Identity | Privileged access | High | Low | Medium | Protect identities and secrets | Workforce, External |  |  | Privileged roles aren't assigned to stale identities |
| 21855 | Identity | Access control | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  |  | Privileged roles have access reviews |
| 21857 | Identity | Access control | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  |  | Guest identities are lifecycle managed with access reviews |
| 21858 | Identity | External collaboration | Medium | Low | Medium | Protect tenants and isolate production systems | Workforce, External |  | Free | Inactive guest identities are disabled or removed from the tenant |
| 21859 | Identity | Access control | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  |  | GDAP admin least privilege |
| 21860 | Identity | Monitoring | High | Low | Medium | Monitor and detect cyberthreats | Workforce, External | Azure |  | Diagnostic settings are configured for all Microsoft Entra logs |
| 21861 | Identity | Monitoring | High | Low | High | Monitor and detect cyberthreats | Workforce, External |  | P2 | All high-risk users are triaged |
| 21862 | Identity | Monitoring | High | Low | High | Monitor and detect cyberthreats | Workforce, External |  | P2 | All risky workload identities are triaged |
| 21863 | Identity | Monitoring | High | Low | High | Monitor and detect cyberthreats | Workforce, External |  | P2 | All high-risk sign-ins are triaged |
| 21864 | Identity | Access control | High | Low | High | Protect identities and secrets | Workforce, External |  |  | All risk detections are triaged |
| 21865 | Identity | Application management | Medium | Low | Low | Protect networks | Workforce, External |  | P1 | Named locations are configured |
| 21866 | Identity | Monitoring | Medium | Low | Medium | Monitor and detect cyberthreats | Workforce, External |  | P1 | All Microsoft Entra recommendations are addressed |
| 21867 | Identity | Application management | High | Low | Medium | Monitor and detect cyberthreats | Workforce, External |  | P1 | Enterprise applications with high privilege Microsoft Graph API permissions have owners |
| 21868 | Identity | External collaboration | Medium | Low | Medium | Protect tenants and isolate production systems | Workforce, External |  | Free | Guests don't own apps in the tenant |
| 21869 | Identity | Application management | Medium | Medium | Medium | Protect engineering systems | Workforce, External |  | P1 | Enterprise applications must require explicit assignment or scoped provisioning |
| 21870 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Enable self-service password reset |
| 21872 | Identity | Access control | High | Medium | Low | Protect identities and secrets | Workforce |  | P1 | Require multifactor authentication for device join and device registration using user action |
| 21874 | Identity | External collaboration | Medium | Medium | High | Protect tenants and isolate production systems | Workforce, External |  | Free | Guest access is limited to approved tenants |
| 21875 | Identity | External collaboration | Medium | Medium | Medium | Protect tenants and isolate production systems | Workforce, External |  | P2, Governance | All entitlement management assignment policies that apply to external users require connected organizations |
| 21876 | Identity | Access control | Medium | Low | Low | Protect identities and secrets | Workforce, External |  |  | Use PIM for Microsoft Entra privileged roles |
| 21877 | Identity | Application management | Medium | Medium | Medium | Protect tenants and isolate production systems | Workforce, External |  | Free | All guests have a sponsor |
| 21878 | Identity | Identity governance | Medium | Medium | Medium | Protect tenants and isolate production systems | Workforce, External |  | P2, Governance | All entitlement management policies have an expiration date |
| 21879 | Identity | External collaboration | Medium | Medium | Medium | Protect identities and secrets | Workforce, External |  | P2 | All entitlement management assignment policies that apply to external users require approval |
| 21881 | Identity | Access control | High | Low | Medium | Protect identities and secrets | Workforce, External |  |  | Azure subscriptions used by Identity Governance are secured consistently with Identity Governance roles |
| 21882 | Identity | Access control | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  |  | No nested groups in PIM for groups |
| 21883 | Identity | Access control | Medium | High | Low | Accelerate response and remediation | Workforce, External |  | Workload | Workload Identities are configured with risk-based policies |
| 21884 | Identity | External collaboration | High | Low | Medium | Protect tenants and production systems | Workforce, External |  | P1 | Conditional Access policies for workload identities based on known networks are configured |
| 21885 | Identity | Application management | High | Low | High | Protect engineering systems | Workforce, External |  | P1 | App registrations use safe redirect URIs |
| 21886 | Identity | Applications management | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  | P1 | Applications are configured for automatic user provisioning |
| 21887 | Identity | Access control | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  |  | All registered redirect URIs must have proper DNS records and ownerships |
| 21888 | Identity | Application management | High | Low | Low | Protect engineering systems | Workforce, External |  | P1 | App registrations must not have dangling or abandoned domain redirect URIs |
| 21889 | Identity | Authentication | High | Medium | Medium | Protect identities and secrets | Workforce, External |  | P1 | Reduce the user-visible password surface area |
| 21890 | Identity | Access control | Medium | Medium | Low | Protect identities and secrets | Workforce, External |  |  | Require password reset notifications for user roles |
| 21891 | Identity | Access control | High | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Require password reset notifications for administrator roles |
| 21892 | Identity | Access control | High | High | High | Protect identities and secrets | Workforce, External |  | P1 | All sign-in activity comes from managed devices |
| 21893 | Identity | Access control | Low | Medium | Medium | Protect identities and secrets | Workforce, External |  | P2 | All users are required to register for MFA |
| 21894 | Identity | Access control | Low | Low | Medium | Protect identities and secrets | Workforce, External |  |  | All certificates Microsoft Entra Application Registrations and Service Principals must be issued by an approved certification authority |
| 21895 | Identity | Access control | Low | Low | High | Protect identities and secrets | Workforce, External |  |  | Application Certificate Credentials are managed using HSM |
| 21896 | Identity | Application management | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  | Free | Service principals don't have certificates or credentials associated with them |
| 21897 | Identity | Access control | Medium | High | High | Protect identities and secrets | Workforce, External |  |  | All app assignment and group membership is governed |
| 21898 | Identity | Access control | Medium | Medium | High | Protect identities and secrets | Workforce, External |  |  | All supported access lifecycle resources are managed with entitlement management packages |
| 21899 | Identity | Access control | Medium | Low | Low | Protect identities and secrets | Workforce, External |  |  | All privileged role assignments have a recipient that can receive notifications |
| 21912 | Identity | Access control | High | Low | Low | Protect identities and secrets | Workforce, External |  |  | Azure resources used by Microsoft Entra only allow access from privileged roles |
| 21929 | Identity | Identity governance | Medium | Medium | Medium | Protect tenants and isolate production systems | Workforce, External |  | P2, Governance | All entitlement management packages that apply to guests have expirations or access reviews configured in their assignment policies |
| 21941 | Identity | Access control | Medium | Low | Medium | Protect identities and secrets | Workforce, External |  | P1 | Token protection policies are configured |
| 21953 | Identity | Devices | High | Low | Medium | Protect identities and secrets | Workforce, External |  | P1 | Local Admin Password Solution is deployed |
| 21954 | Identity | Devices | High | Low | Low | Protect tenants and isolate production systems | Workforce, External |  | Free | Restrict nonadministrator users from recovering the BitLocker keys for their owned devices |
| 21955 | Identity | Devices | High | Low | Low | Protect tenants and isolate production systems | Workforce, External |  | P1 | Manage the local administrators on Microsoft Entra joined devices |
| 21964 | Identity | Access control | High | Low | Low | Protect tenants and isolate production systems | Workforce, External |  | P1 | Enable protected actions to secure Conditional Access policy creation and changes |
| 21983 | Identity | Access control | Medium | Low | Low | Protect identities and secrets | Workforce, External |  |  | No Active Medium priority Entra recommendations found |
| 21984 | Identity | Access control | Low | Low | Low | Protect identities and secrets | Workforce, External |  |  | No Active low priority Entra recommendations found |
| 21985 | Identity | Credential management | Medium | Low | Low | Protect identities and secrets | Workforce, External |  | P1 | Turn off Seamless SSO if there is no usage |
| 21992 | Identity | Application management | High | Low | High | Protect identities and secrets | Workforce, External |  | Free | Application certificates must be rotated on a regular basis |
| 22072 | Identity | Credential management | Medium | Medium | Medium | Protect identities and secrets | Workforce, External |  | P1 | Self-service password reset doesn't use security questions |
| 22124 | Identity | Monitoring | High | Medium | Medium | Monitor and detect cyberthreats | Workforce, External |  | P1 | High priority Microsoft Entra recommendations are addressed |
| 22128 | Identity | Application management | High | Low | Medium | Protect tenants and isolate production systems | Workforce, External |  | Free | Guests are not assigned high privileged directory roles |
| 22659 | Identity | Monitoring | High | Low | High | Protect identities and secrets | Workforce, External |  | P2 | All risky workload identity sign-ins are triaged |
| 23183 | Identity | Application management | High | Low | High | Protect engineering systems | Workforce, External |  | P1 | Service principals use safe redirect URIs |
| 24518 | Identity | Application management | Medium | Low | Medium | Protect engineering systems | Workforce |  | Free | Enterprise applications have owners |
| 24540 | Devices | Devices | High | Medium | Low | Protect networks | Workforce |  | Intune | Windows Firewall policies protect against unauthorized network access |
| 24541 | Devices | Tenant | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Compliance policies protect Windows devices |
| 24542 | Devices | Tenant | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Compliance policies protect macOS devices |
| 24543 | Devices | Tenant | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Compliance policies protect iOS/iPadOS devices |
| 24545 | Devices | Tenant | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Compliance policies protect fully managed and corporate-owned Android devices |
| 24546 | Devices | Tenant | High | Low | Low | Protect tenants and isolate production systems | Workforce |  | P1 | Windows automatic device enrollment is enforced to eliminate risks from unmanaged endpoints |
| 24547 | Devices | Tenant | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Compliance policies protect personally owned Android devices |
| 24548 | Devices | Data | High | High | Low | Protect identities and secrets | Workforce |  | Intune | Data on iOS/iPadOS is protected by app protection policies |
| 24549 | Devices | Data | High | High | Low | Protect identities and secrets | Workforce |  | Intune | Data on Android is protected by app protection policies |
| 24550 | Devices | Devices | High | Low | Low | Protect identities and secrets | Workforce |  | INTUNE_A | Data on Windows is protected by BitLocker encryption |
| 24551 | Devices | Devices | High | Medium | Medium | Protect identities and secrets | Workforce |  | Intune | Authentication on Windows uses Windows Hello for Business |
| 24552 | Devices | Devices | Medium | High | Low | Protect networks | Workforce |  | Intune | macOS Firewall policies protect against unauthorized network access |
| 24553 | Devices | Devices | High | Medium | Medium | Protect tenants and isolate production systems | Workforce |  | Intune | Windows Update policies are enforced to reduce risk from unpatched vulnerabilities |
| 24554 | Devices | Devices | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Update policies for iOS/iPadOS are enforced to reduce risk from unpatched vulnerabilities |
| 24555 | Devices | Tenant | Medium | Low | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Scope tag configuration is enforced to support delegated administration and least-privilege access |
| 24560 | Devices | Devices | High | Low | Low | Protect identities and secrets | Workforce |  | Intune | Local administrator credentials on Windows are protected by Windows LAPS |
| 24561 | Devices | Devices | High | Low | Low | Protect identities and secrets | Workforce |  | Intune | Local administrator credentials on macOS are protected during enrollment by macOS LAPS |
| 24564 | Devices | Devices | High | Low | Low | Protect identities and secrets | Workforce |  | Intune | Local account usage on Windows is restricted to reduce unauthorized access |
| 24568 | Devices | Tenant | Medium | Medium | Medium | Protect tenants and isolate production systems | Workforce |  | Intune | Platform SSO is configured to strengthen authentication on macOS devices |
| 24569 | Devices | Devices | High | Medium | Low | Protect identities and secrets | Workforce |  | Intune | FileVault encryption protects data on macOS devices |
| 24570 | Identity | Hybrid infrastructure | High | Low | Medium | Protect identities and secrets | Workforce |  | Free | Entra Connect Sync is configured with Service Principal Credentials |
| 24572 | Devices | Tenant | Medium | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Device enrollment notifications are enforced to ensure user awareness and secure onboarding |
| 24573 | Devices | Tenant | High | Medium | Medium | Protect tenants and isolate production systems | Workforce |  | Intune | Security baselines are applied to Windows devices to strengthen security posture |
| 24574 | Devices | Devices | High | Medium | Medium | Protect networks | Workforce |  | Intune | Attack Surface Reduction rules are applied to Windows devices to prevent exploitation of vulnerable system components |
| 24575 | Devices | Devices | High | Low | Medium | Protect networks | Workforce |  | Intune | Defender Antivirus policies protect Windows devices from malware |
| 24576 | Devices | Tenant | Low | Low | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Endpoint Analytics is enabled to help identify risks on Windows devices |
| 24690 | Devices | Devices | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Update policies for macOS are enforced to reduce risk from unpatched vulnerabilities |
| 24784 | Devices | Devices | High | Low | Low | Protect networks | Workforce |  | Intune | Defender Antivirus policies protect macOS devices from malware |
| 24794 | Devices | Tenant | Medium | Low | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Terms and Conditions policies protect access to sensitive data |
| 24802 | Devices | Tenant | Low | Low | Low | Protect tenants and isolate production | Workforce |  | Intune | Device cleanup rules maintain tenant hygiene by hiding inactive devices |
| 24823 | Devices | Tenant | Medium | Low | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Company Portal branding and support settings enhance user experience and trust |
| 24824 | Devices | Data | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Conditional Access policies block access from noncompliant devices |
| 24827 | Devices | Data | High | Medium | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Conditional Access policies block access from unmanaged apps |
| 24839 | Devices | Data | High | Low | Medium | Protect networks | Workforce |  | Intune | Secure Wi-Fi profiles protect iOS devices from unauthorized network access |
| 24840 | Devices | Data | High | Low | Low | Protect networks | Workforce |  | Intune | Secure Wi-Fi profiles protect Android devices from unauthorized network access |
| 24870 | Devices | Data | High | Low | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Secure Wi-Fi profiles protect macOS devices from unauthorized network access |
| 24871 | Devices | Tenant | High | Low | Low | Protect tenants and isolate production systems | Workforce |  | Intune | Defender for Endpoint automatic enrollment is enforced to reduce risk from unmanaged Android threats |
| 25370 | Network | Network | Medium | Low | Low | Protect networks | Workforce, External | Graph | Entra_Premium_Private_Access, Entra_Premium_Internet_Access | Source IP restoration is enabled |
| 25371 | Network | Global Secure Access | High | Low | Low | Protect networks | Workforce | Graph | AAD_PREMIUM, Entra_Premium_Private_Access, Entra_Premium_Internet_Access | Network validation is configured through Universal Continuous Access Evaluation |
| 25372 | Network | Global Secure Access | High | Low | Medium | Protect networks | Workforce | Graph | AAD_PREMIUM, Entra_Premium_Internet_Access, Entra_Premium_Private_Access, Entra_Premium_Private_Access, Entra_Premium_Internet_Access | Global Secure Access client is deployed on all managed endpoints |
| 25375 | Network | Global Secure Access | High | Low | Low | Protect networks | Workforce | Graph | AAD_PREMIUM, AAD_PREMIUM_P2 | The tenant holds the licenses required to operate Global Secure Access |
| 25376 | Network | Network security | High | Low | Medium | Protect networks | Workforce | Graph | Entra_Suite, Entra_Premium_Private_Access, Entra_Premium_Internet_Access | Microsoft 365 traffic is actively flowing through Global Secure Access |
| 25377 | Network | Global Secure Access | High | Low | Medium | Protect networks | Workforce, External | Graph | AAD_PREMIUM, Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | Universal tenant restrictions block unauthorized external tenant access |
| 25379 | Network | Global Secure Access | Medium | Medium | Medium | Protect networks | Workforce, External | Graph | AAD_PREMIUM, AAD_PREMIUM, AAD_PREMIUM_P2 | Conditional Access policies use compliant network controls |
| 25380 | Network | Global Secure Access | Medium | High | Low | Protect networks | Workforce | Graph | AAD_PREMIUM, Entra_Premium_Internet_Access | Global Secure Access signaling for Conditional Access is enabled |
| 25381 | Network | Global Secure Access | High | Low | Medium | Protect networks | Workforce | Graph | Entra_Suite, Entra_Premium_Private_Access, Entra_Premium_Internet_Access, P2, Entra_Premium_Private_Access, Entra_Premium_Internet_Access | Network traffic is routed through Global Secure Access for security policy enforcement |
| 25382 | Network | Global Secure Access | High | Low | Low | Protect networks | Workforce | Graph | Entra_Premium_Private_Access, Entra_Premium_Internet_Access, Entra_Premium_Internet_Access, Entra_Premium_Private_Access | Traffic forwarding profiles are scoped to appropriate users and groups for controlled deployment |
| 25383 | Network | Global Secure Access | High | Low | Low | Protect identities and secrets | Workforce | Graph | AAD_PREMIUM, AAD_PREMIUM, AAD_PREMIUM_P2 | Administrative privileges are tightly limited to prevent compromise |
| 25384 | Network | Role management | High | Low | Low | Protect identities and secrets | Workforce | Graph | P1, Entra_Premium_Private_Access, Entra_Premium_Internet_Access | Application admin rights are constrained to specific Private Access apps |
| 25391 | Network | Global Secure Access | Medium | Medium | Low | Protect networks | Workforce | Graph | Entra_Premium_Private_Access, Entra_Premium_Private_Access | Private network connectors are active and healthy to maintain Zero Trust access to internal resources |
| 25392 | Network | Private Access | Medium | Low | Low | Protect networks | Workforce | Graph | Entra_Premium_Private_Access, Entra_Premium_Private_Access | Private network connectors are running the latest version |
| 25393 | Network | Global Secure Access | High | Medium | Medium | Protect networks | Workforce | Graph | AAD_PREMIUM, Entra_Premium_Private_Access | Quick Access is enabled and bound to a connector |
| 25394 | Network | Global Secure Access | High | Medium | Low | Protect networks | Workforce, External | Graph | Entra_Premium_Private_Access, AAD_PREMIUM, Entra_Premium_Private_Access | Quick Access is bound to a Conditional Access policy |
| 25395 | Network | Global Secure Access | High | Medium | High | Protect networks | Workforce | Graph | Entra_Premium_Private_Access, Entra_Premium_Private_Access | Entra Private Access Application segments are defined to enforce least-privilege access |
| 25396 | Network | Global Secure Access | High | Medium | Medium | Protect identities and secrets | Workforce | Graph | Entra_Premium_Private_Access, AAD_PREMIUM, Entra_Premium_Private_Access | Conditional Access policies enforce strong authentication for private apps |
| 25398 | Network | Global Secure Access | High | Low | Medium | Protect networks | Workforce, External | Graph | AAD_PREMIUM, Entra_Premium_Private_Access, Entra_Premium_Private_Access | Domain controller RDP access is protected by phishing-resistant authentication through Global Secure Access |
| 25399 | Network | Global Secure Access | Medium | Low | Medium | Protect networks | Workforce, External | Graph | Entra_Premium_Private_Access, Entra_Premium_Private_Access | Private DNS is configured for internal name resolution |
| 25400 | Network | Private Access | Low | Low | Low | Protect networks | Workforce | Graph | AAD_PREMIUM, Entra_Premium_Private_Access | DNS traffic for internal domains is routed through Private Access |
| 25401 | Network | Application Proxy | High | Medium | Medium | Protect identities and secrets | Workforce | Graph | AAD_PREMIUM, AAD_PREMIUM, AAD_PREMIUM_P2 | Application Proxy applications require preauthentication to block anonymous access |
| 25403 | Network | Global Secure Access | High | Medium | Medium | Protect networks | Workforce | Graph | Entra_Suite, Entra_Premium_Private_Access, Entra_Premium_Private_Access | Private Access sensors are enforcing strong authentication policies on domain controllers |
| 25405 | Network | Global Secure Access | Medium | Medium | Medium | Protect networks | Workforce | Graph | P1 | Intelligent Local Access is enabled and configured |
| 25406 | Network | Global Secure Access | High | Medium | Low | Protect networks | Workforce | Graph | Entra_Premium_Global_Secure_Access, Entra_Premium_Internet_Access | Internet access forwarding profile is enabled |
| 25407 | Network | Global Secure Access | High | Low | Medium | Protect networks | Workforce, External | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | Web content filtering integrates with Conditional Access |
| 25408 | Network | Global Secure Access | Medium | Medium | Medium | Protect networks | Workforce, External | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | Web content filtering policies are configured |
| 25409 | Network | Global Secure Access | Medium | Medium | Medium | Protect networks | Workforce, External | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | Web content filtering uses category-based rules |
| 25410 | Network | Global Secure Access | Medium | Low | Medium | Protect networks | Workforce, External | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | Web content filtering policies are linked to security profiles |
| 25411 | Network | Global Secure Access | High | Medium | High | Protect networks | Workforce | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | TLS inspection is enabled and correctly configured for outbound traffic |
| 25413 | Network | Global Secure Access | High | Medium | High | Protect networks | Workforce | Graph | Entra_Premium_Internet_Access | File transfer policies are configured to prevent data exfiltration |
| 25415 | Network | Global Secure Access | High | Low | Medium | Protect networks | Workforce | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | AI Gateway protects enterprise generative AI applications from prompt injection attacks |
| 25416 | Network | Global Secure Access | High | Low | Medium | Protect networks | Workforce, External | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | Global Secure Access cloud firewall protects branch office internet traffic |
| 25419 | Network | Global Secure Access | Medium | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | AAD_PREMIUM, Entra_Premium_Internet_Access, Entra_Premium_Private_Access, Entra_Premium_Private_Access, Entra_Premium_Internet_Access | Network access activity is visible to security operations for threat detection and response |
| 25420 | Network | Global Secure Access | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | AAD_PREMIUM, Entra_Premium_Internet_Access, Entra_Premium_Private_Access, Entra_Premium_Private_Access, Entra_Premium_Internet_Access | Network access logs are retained for security analysis and compliance requirements |
| 25422 | Network | Global Secure Access | Medium | Low | Low | Monitor and detect cyberthreats | Workforce, External | Graph | Entra_Premium_Internet_Access, Entra_Premium_Private_Access, Entra_Premium_Internet_Access, Entra_Premium_Private_Access | Global Secure Access deployment logs are populated and reviewed |
| 25466 | Network | Private Access | High | Medium | Low | Protect networks | Workforce | Graph | Entra_Premium_Private_Access | At least two Private Access connectors are active and healthy per connector group |
| 25480 | Network | Global Secure Access | Medium | Low | Low | Protect networks | Workforce, External | Graph | Entra_Private_Access, Entra_Premium_Private_Access | Quick Access has user or group assignments |
| 25481 | Network | Global Secure Access | High | Medium | Low | Protect networks | Workforce, External | Graph | Entra_Private_Access, Entra_Premium_Private_Access | All Private Access apps have user or group assignments |
| 25533 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce, External | Azure | DDoS_Network_Protection, DDoS_IP_Protection | DDoS Protection is enabled for all Public IP Addresses in VNETs |
| 25535 | Network | Azure Network Security | High | Low | Medium | Protect networks | Workforce, External | Azure | Azure_Firewall_Basic, Azure_Firewall_Standard, Azure_Firewall_Premium | Outbound traffic from VNET integrated workloads is routed through Azure Firewall |
| 25537 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure_Firewall_Standard, Azure_Firewall_Premium | Threat intelligence is Enabled in Deny Mode on Azure Firewall |
| 25539 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce, External | Azure | Azure_Firewall_Premium | IDPS Inspection is Enabled in Deny Mode on Azure Firewall |
| 25541 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure WAF, Azure Application Gateway Standard SKU | Application Gateway WAF is Enabled in Prevention mode |
| 25543 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure WAF on Azure Front Door Premium SKU, Azure Standard SKU | Azure Front Door WAF is Enabled in Prevention Mode |
| 25550 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce, External | Azure | Azure_Firewall_Premium | Inspection of Outbound TLS Traffic is Enabled on Azure Firewall |
| 26879 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure WAF | Request Body Inspection is enabled in Application Gateway WAF |
| 26880 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure WAF | Request Body Inspection is enabled in Azure Front Door WAF |
| 26881 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure WAF | Default Ruleset is enabled in Application Gateway WAF |
| 26882 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure WAF | Bot protection ruleset is enabled and assigned in Application Gateway WAF |
| 26883 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure WAF | Default rule set is assigned in Azure Front Door WAF |
| 26884 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure_Front_Door_Premium | Bot protection rule set is enabled and assigned in Azure Front Door WAF |
| 26885 | Network | Azure Network Security | Medium | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | DDoS_Network_Protection, DDoS_IP_Protection | Metrics are enabled for DDoS-protected public IPs |
| 26886 | Network | Azure Network Security | Medium | Low | Low | Protect networks | Workforce | Azure | DDoS_Network_Protection, DDoS_IP_Protection | Diagnostic logging is enabled for DDoS-protected public IPs |
| 26887 | Network | Azure Network Security | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Azure_Firewall_Standard, Azure_Firewall_Premium | Diagnostic logging is enabled in Azure Firewall |
| 26888 | Network | Azure Network Security | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Azure_Application_Gateway_WAF | Diagnostic logging is enabled in Application Gateway WAF |
| 26889 | Network | Azure Network Security | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Azure_FrontDoor_Standard, Azure_FrontDoor_Premium | Diagnostic logging is enabled in Azure Front Door WAF |
| 27000 | Network | Global Secure Access | High | Low | Low | Protect networks | Workforce | Graph | Entra_Premium_Internet_Access | Web content filtering blocks high-risk categories |
| 27001 | Network | Global Secure Access | Medium | Low | Medium | Protect networks | Workforce | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | TLS inspection bypass rules are regularly reviewed |
| 27002 | Network | Global Secure Access | High | High | Low | Protect networks | Workforce, External | Graph | Entra_Premium_Internet_Access | TLS inspection certificates have a sufficient validity period |
| 27003 | Network | Global Secure Access | High | Medium | Medium | Protect networks | Workforce | Graph, Azure | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | TLS inspection failure rate is below 1% |
| 27004 | Network | Global Secure Access | Low | Low | Low | Protect networks | Workforce | Graph | Entra_Premium_Internet_Access, Entra_Premium_Internet_Access | TLS inspection custom bypass rules don't duplicate system bypass destinations |
| 27015 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Azure WAF | HTTP DDoS Protection Ruleset is Enabled in Application Gateway WAF |
| 27016 | Network | Azure Network Security | High | Low | Medium | Protect networks | Workforce | Azure | Azure WAF | Rate Limiting is Enabled in Application Gateway WAF |
| 27017 | Network | Azure Network Security | Medium | Low | Low | Protect networks | Workforce | Azure | Azure WAF | JavaScript Challenge is Enabled in Application Gateway WAF |
| 27018 | Network | Azure Network Security | High | Low | Medium | Protect networks | Workforce | Azure | Azure_WAF | Rate Limiting is Enabled in Azure Front Door WAF |
| 27019 | Network | Azure Network Security | Medium | Low | Low | Protect networks | Workforce | Azure | Azure WAF | JavaScript Challenge is Enabled in Azure Front Door WAF |
| 27020 | Network | Azure Network Security | Medium | Medium | Low | Protect networks | Workforce | Azure | Azure WAF | CAPTCHA challenge is enabled in Azure Front Door WAF |
| 27024 | Network | Azure Network Security | High | Low | Low | Protect networks | Workforce | Azure | Consumption-based: Azure WAF on Azure Front Door Premium | HTTP DDoS protection rule set is enabled in Azure Front Door WAF |
| 35001 | Data | Entra | High | Low | Low |  | Workforce, External | Graph | Microsoft 365 E5, RMS_S_PREMIUM2 | Conditional Access policies don't exclude Rights Management workloads |
| 35003 | Data | sensitivity-labels | High | Low | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | Sensitivity labels are configured |
| 35004 | Data | Sensitivity Labels | Low | Medium | Low | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | Sensitivity label policies are published to users |
| 35005 | Data | SharePoint Online | High | Low | Low | Protect tenants and production systems | Workforce | SharePointOnline | MIP_P1, RMS_S_PREMIUM | Sensitivity labels are enabled for SharePoint and OneDrive |
| 35006 | Data | SharePoint Online | Medium | Low | Low | Protect tenants and production systems | Workforce | SharePointOnline | MIP_P1, RMS_S_PREMIUM | PDF labeling is enabled in SharePoint |
| 35007 | Data | SharePoint Online | Low | Low | Low |  | Workforce | SharePointOnline | Microsoft 365 E3, RMS_S_PREMIUM | Information Rights Management is enabled in SharePoint Online |
| 35008 | Data | SharePoint Online | Medium | Low | Low | Protect tenants and production systems | Workforce | SharePointOnline | Microsoft 365 E5, RMS_S_PREMIUM2 | Default sensitivity labels are configured for SharePoint document libraries |
| 35009 | Data | Sensitivity Labels | Low | High | Low | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E5, RMS_S_PREMIUM2 | Co-authoring is enabled for files encrypted with sensitivity labels |
| 35010 | Data | Encryption | Low | High | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E5, RMS_S_PREMIUM2 | Double Key Encryption labels are configured |
| 35011 | Data | Advanced Label Features | Medium | Low | Medium | Protect tenants and production systems | Workforce, External | AipService, Graph | Microsoft 365 E5, RMS_S_PREMIUM2 | Super user membership is configured for Microsoft Purview Information Protection |
| 35012 | Data | Sensitivity Labels Configuration | Medium | High | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E5, RMS_S_PREMIUM2 | Container labels are configured for collaborative workspaces |
| 35013 | Data | Sensitivity Labels Configuration | High | High | Medium | Protect tenants and production systems | Workforce, External | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | Sensitivity labels with encryption are configured |
| 35014 | Data | Label Policy Configuration | Medium | High | Low | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | Email label policies inherit sensitivity from attachments |
| 35015 | Data | sensitivity-labels | Medium | High | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | Globally published sensitivity labels don't exceed the recommended maximum |
| 35016 | Data | Information Protection | High | High | Medium | Protect tenants and production systems | Workforce, External | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | Mandatory labeling is enabled in sensitivity label policies |
| 35017 | Data | Information Protection | Medium | Medium | Low | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | A default sensitivity label is configured in label policies |
| 35018 | Data | Information Protection | Medium | Medium | Low | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | Users must provide justification to downgrade sensitivity labels |
| 35019 | Data | Information Protection | High | Low | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Auto-labeling policies are configured for all Microsoft 365 workloads |
| 35020 | Data | Information Protection | High | Low | Low | Protect tenants and production systems | Workforce, External | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Auto-labeling policies are in enforcement mode |
| 35021 | Data | Information Protection | High | Low | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Auto-labeling policies are enabled for SharePoint and OneDrive |
| 35022 | Data | Information Protection | Medium | Low | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | On-demand scans are configured for sensitive information discovery |
| 35023 | Data | Information Protection | Medium | Low | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | OCR is enabled for sensitive information detection |
| 35024 | Data | Rights Management Service | High | High | Low | Protect tenants and production systems | Workforce | ExchangeOnline | Microsoft 365 E3, RMS_S_PREMIUM | Azure Rights Management service is activated |
| 35025 | Data | Rights Management Service (RMS) | High | High | Low | Protect tenants and production systems | Workforce | ExchangeOnline | Microsoft 365 E3, RMS_S_PREMIUM | Internal Rights Management licensing is enabled |
| 35026 | Data | Microsoft Purview Message Encryption | Medium | Medium | Low | Protect tenants and production systems | Workforce, External | ExchangeOnline | Microsoft 365 E3, RMS_S_PREMIUM | Microsoft Purview Message Encryption is configured with simplified client access |
| 35027 | Data | Information Protection | Low | Low | Low | Protect tenants and production systems | Workforce | ExchangeOnline | Microsoft 365 E3, Microsoft 365 E5, Advanced Message Encryption add-on, RMS_S_PREMIUM | Custom branding templates are configured for Microsoft Purview Message Encryption |
| 35028 | Data | Information Protection | Medium | Medium | Medium | Protect tenants and production systems | Workforce, External | SecurityCompliance | Microsoft 365 E3, RMS_S_PREMIUM | Email retention policies are configured |
| 35029 | Data | Information Protection | Medium | Medium | Medium | Protect tenants and production systems | Workforce | ExchangeOnline | Microsoft 365 E5, RMS_S_PREMIUM2 | Mail flow rules apply rights protection to sensitive messages |
| 35030 | Data | Data Loss Prevention (DLP) | High | Medium | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Data loss prevention policies are enabled |
| 35032 | Data | Data Loss Prevention (DLP) | Medium | Medium | Low | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Adaptive Protection is enabled in data loss prevention policies |
| 35033 | Data | Advanced Classification | High | Medium | High | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Custom sensitive information types are configured |
| 35034 | Data | Advanced Classification | High | Medium | Medium | Protect tenants and production systems | Workforce, External | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Exact Data Match is configured for sensitive information detection |
| 35035 | Data | Advanced Classification | High | Medium | Low | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Named entity sensitive information types are used in auto-labeling and data loss prevention policies |
| 35036 | Data | Advanced Classification | Medium | Medium | High | Protect tenants and production systems | Workforce, External | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Trainable classifiers are used in data loss prevention and auto-labeling policies |
| 35038 | Data | Data Security Posture Management | High | Medium | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Insider Risk Management policies are enabled for risky AI usage |
| 35039 | Data | Data Security Posture Management | High | Medium | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Communication compliance monitoring is configured for Microsoft Copilot |
| 35040 | Data | Data Security Posture Management | High | Medium | Medium | Protect tenants and production systems | Workforce | SecurityCompliance | EXCHANGE_S_ENTERPRISE | Communication compliance monitoring is configured for enterprise AI tools |
| 35041 | Data | Data Security Posture Management | Medium | Medium | High | Protect tenants and production systems | Workforce | SecurityCompliance | Microsoft 365 E5, Microsoft Purview PAYG, RMS_S_PREMIUM2 | Browser data loss prevention is enabled for AI apps via Edge for Business |
| 41002 | SecOps | Identity threat protection | High | Low | Medium | Monitor and detect cyberthreats | Workforce | Graph | ATA | Microsoft Defender for Identity sensor is installed and healthy on every domain controller |
| 41003 | SecOps | Identity threat protection | High | Low | Medium | Monitor and detect cyberthreats | Workforce | Graph | ATA | Microsoft Defender for Identity sensors are installed and healthy on AD FS, AD CS, and Microsoft Entra Connect servers |
| 41009 | SecOps | Identity threat protection | High | Low | Low | Protect identities and secrets | Workforce | Graph | ATA | Dormant accounts have been removed from sensitive Active Directory groups |
| 41018 | SecOps | Identity threat protection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Graph | ATA | No open Microsoft Defender for Identity health issues are present in the tenant |
| 41019 | SecOps | Identity threat protection | High | Medium | Low | Accelerate response and remediation | Workforce | Graph | ATA | Compromised identities surfaced by Microsoft Defender for Identity have been remediated |
| 41020 | SecOps | Identity threat protection | Medium | Low | Low | Monitor and detect cyberthreats | Workforce | Graph | ATA | Microsoft Defender for Identity sensor deployment is validated by reviewing the Health Issues page |
| 41022 | SecOps | Identity threat protection | Medium | Low | Low | Monitor and detect cyberthreats | Workforce | Graph | ATA | Microsoft Defender for Identity security alerts have been triaged and tuned |
| 41029 | SecOps | Email and collaboration security | High | Low | Low | Protect tenants and isolate production systems | Workforce | ExchangeOnline | EXCHANGE_S_STANDARD | Anti-malware policies are configured according to recommended settings |
| 41031 | SecOps | Email and collaboration security | High | Low | Low | Protect tenants and isolate production systems | Workforce | ExchangeOnline | ATP_ENTERPRISE | Safe Attachments policies in Microsoft Defender for Office 365 are configured to detonate and block |
| 41032 | SecOps | Email and collaboration security | High | Low | Low | Protect tenants and isolate production systems | Workforce | ExchangeOnline | ATP_ENTERPRISE | Safe Links policies in Microsoft Defender for Office 365 are configured to scan and block malicious URLs |
| 41033 | SecOps | Email and collaboration security | High | Low | Low | Protect tenants and isolate production systems | Workforce | ExchangeOnline | ATP_ENTERPRISE | Anti-phishing policies in Microsoft Defender for Office 365 are configured with impersonation and spoof protection |
| 41034 | SecOps | Email and collaboration security | Medium | Medium | Low | Protect tenants and isolate production systems | Workforce | ExchangeOnline | EXCHANGE_S_STANDARD | Anti-spam (hosted content filter) policies are configured with recommended thresholds and actions |
| 41041 | SecOps | Email and collaboration security | High | Low | Medium | Accelerate response and remediation | Workforce | Graph | THREAT_INTELLIGENCE | Automated Investigation and Response (AIR) recommendations are reviewed and actioned |
| 41045 | SecOps | Endpoint threat protection | High | Low | Medium | Monitor and detect cyberthreats | Workforce | Graph | WINDEFATP, MDE_LITE | All eligible endpoints are onboarded to Microsoft Defender for Endpoint |
| 41052 | SecOps | Endpoint threat protection | High | Medium | High | Monitor and detect cyberthreats | Workforce | Graph | INTUNE_A | Application control (WDAC / App Control for Business) is enforced via Intune |
| 41053 | SecOps | Endpoint threat protection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Graph | ATA | Network protection is enabled in block mode |
| 41059 | SecOps | Endpoint threat protection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Graph | WINDEFATP | EDR in block mode is enabled when Microsoft Defender Antivirus is not the primary antivirus |
| 41060 | SecOps | Endpoint threat protection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Graph | ATA | Cloud-delivered protection is enabled in Microsoft Defender Antivirus |
| 41061 | SecOps | Threat investigation and response | High | Low | Medium | Accelerate response and remediation | Workforce | Graph | WINDEFATP, MDE_LITE, ATP_ENTERPRISE, THREAT_INTELLIGENCE, ATA, ADALLOM_S_STANDALONE, MDE_SMB | All active Microsoft Defender XDR incidents are triaged and remediated |
| 41062 | SecOps | Threat investigation and response | High | Low | Low | Accelerate response and remediation | Workforce | Graph | WINDEFATP | Automated Investigation and Response (AIR) recommendations are reviewed and actioned |
| 41081 | SecOps | SaaS threat detection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Graph | ADALLOM_S_STANDALONE, ADALLOM_S_O365 | At least one Microsoft Defender for Cloud Apps anomaly detection policy is generating alerts |
| 41114 | SecOps | Email and collaboration security | High | Low | Low | Protect tenants and isolate production systems | Workforce | Graph, ExchangeOnline | ATP_ENTERPRISE | Microsoft Teams protection policies are configured to block malicious messages, links, and attachments |
| 41116 | SecOps | Email and collaboration security | Medium | Low | Medium | Monitor and detect cyberthreats | Workforce | Graph | THREAT_INTELLIGENCE | Threat hunting against Email and Collaboration tables in Microsoft 365 Defender Advanced Hunting is operational |
| 41121 | SecOps | Incident response operations | High | Low | Low | Accelerate response and remediation | Workforce | Graph | WINDEFATP, MDE_LITE, ATP_ENTERPRISE, THREAT_INTELLIGENCE, ATA, ADALLOM_S_STANDALONE | Every open Microsoft Defender XDR alert is triaged across all Defender services, with no high-severity alert left unassigned or unworked past its triage window |
| 41206 | SecOps | Security information and event management | Low | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Consumption-based: Microsoft Sentinel | At least one workbook is deployed in every Microsoft Sentinel workspace for visualization and operational reporting |
| 41207 | SecOps | Security information and event management | High | Low | Medium | Monitor and detect cyberthreats | Workforce | Azure | Consumption-based: Microsoft Sentinel | Active analytics rules are configured in Microsoft Sentinel to detect threats |
| 41208 | SecOps | Security information and event management | Low | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Consumption-based: Microsoft Sentinel | At least one watchlist is configured in Microsoft Sentinel for correlation against high-value entities |
| 41209 | SecOps | Security information and event management | Medium | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Consumption-based: Microsoft Sentinel | User and Entity Behavior Analytics (UEBA) is enabled in Microsoft Sentinel |
| 41211 | SecOps | Security information and event management | Medium | Low | Low | Accelerate response and remediation | Workforce | Azure | Consumption-based: Microsoft Sentinel | Auditing and health monitoring is enabled for Microsoft Sentinel |
| 41213 | SecOps | Security information and event management | Medium | Low | Low | Accelerate response and remediation | Workforce | Azure | Consumption-based: Microsoft Sentinel | At least one automation rule is configured in Microsoft Sentinel to manage incident response |
| 41215 | SecOps | AI for security | Medium | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Consumption-based: Microsoft Security Copilot | Microsoft Security Copilot capacity (Security Compute Units) is provisioned in the tenant |
| 50001 | Infrastructure | Microsoft Defender for Cloud | High | Medium | Medium | Protect tenants and isolate production systems | Workforce | Azure | N/A | Microsoft Defender for Cloud Recommendations |
| 51001 | Devices | Devices | High | Medium | Medium | Protect engineering systems | Workforce | Graph |  | Windows Endpoint Privilege Management is configured and assigned |
| 51013 | Devices | Devices | High | Low | Low | Protect identities and secrets | Workforce |  | INTUNE_A | App Protection Policies block managed-app access when user re-authentication fails (disabled Entra ID accounts, blocked sign-ins, expired tokens) |
| 51014 | Devices | Devices | High | Low | Low | Protect identities and secrets | Workforce | Graph | INTUNE_A | App Protection Policies block managed-app access on jailbroken or rooted mobile devices |
| 51015 | Devices | Devices | High | Low | Medium | Protect identities and secrets | Workforce |  | INTUNE_A | Multi Admin Approval is enabled in Intune to require a second admin to approve sensitive tenant changes |
| 51016 | Devices | Devices | High | Low | Low | Protect identities and secrets | Workforce |  | INTUNE_A&AAD_PREMIUM_P2 | Privileged Identity Management is enforced for Intune Administrator role assignments |
| 51018 | Devices | Devices | High | Medium | Medium | Protect engineering systems | Workforce |  | INTUNE_A | Windows App Control for Business (WDAC) is configured and assigned via Intune |
| 51019 | Devices | Devices | Medium | Medium | Low | Protect identities and secrets | Workforce |  | INTUNE_A | MAM app access timeout and re-authentication are enforced after idle period |
| 61002 | AI | AI Threat Detection | High | Low | Medium | Monitor and detect cyberthreats | Workforce | Azure | Microsoft_Sentinel | Microsoft Sentinel is onboarded on at least one Log Analytics workspace |
| 61004 | AI | AI Cloud Posture | High | Low | Medium | Protect tenants and production systems | Workforce | Azure | Microsoft_Defender_for_Cloud | Microsoft Defender for Cloud CSPM plan is enabled on all Azure subscriptions |
| 61005 | AI | AI Inventory & Lifecycle | High | Low | Low | Protect tenants and production systems | Workforce | Graph | Microsoft_365_Copilot, AGENT_365 | Agents deployed to Microsoft 365 Copilot are discoverable in the Agent Registry |
| 61006 | AI | AI Authentication & Access | High | Low | Low | Protect identities and secrets | Workforce | Graph | AAD_BASIC, AAD_PREMIUM | AI administrative roles have assigned principals |
| 61008 | AI | Secure AI Authentication and Access | Medium | Low | Medium | Protect identities and secrets | Workforce | Graph |  | Agent identity lifecycle tagging (customSecurityAttributes present) |
| 61009 | AI | AI Identity & Access | High | Low | Low | Protect identities and secrets | Workforce | Graph | AAD_PREMIUM, AGENT_365, AAD_PREMIUM&AGENT_365, AAD_PREMIUM_P2&AGENT_365 | Conditional Access policies cover both agent identities and agent users |
| 61011 | AI | AI Authentication & Access | High | Medium | Medium | Protect identities and secrets | Workforce | Graph | AAD_PREMIUM | Require users to use Microsoft Entra ID auth to interact with agents |
| 61012 | AI | AI Authentication & Access | High | Low | Low | Protect identities and secrets | Workforce | Graph | AAD_PREMIUM_P2, AGENT_365, AAD_PREMIUM_P2&AGENT_365 | Risk-based Conditional Access blocks risky agent identities |
| 61013 | AI | AI Authentication & Access | Medium | Low | Low | Protect identities and secrets | Workforce | Graph | AAD_PREMIUM&AGENT_365 | Identity governance for agents — sponsors assigned, entitlement-management channel exists, and lifecycle automation in place |
| 61014 | AI | Agent Lifecycle | High | Medium | Medium | Protect identities and secrets | Workforce | Graph | AAD_PREMIUM | Agent identities and blueprint principals have assigned technical owners and no disabled agents remain in the directory |
| 61016 | AI | AI Threat Detection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | AAD_PREMIUM_P2, AGENT_365, AAD_PREMIUM_P2&AGENT_365 | Microsoft Entra ID Protection risk events are flowing to the Microsoft Sentinel workspace |
| 61017 | AI | AI Threat Detection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Microsoft_Defender_for_AI_Services, Microsoft_Sentinel | Microsoft Defender for AI Services alerts are flowing to the Microsoft Sentinel workspace via a single connector path |
| 61018 | AI | AI Threat Detection | Medium | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | MIP_S_CLP1, Consumption-based: Microsoft Sentinel, MIP_S_CLP1 | Microsoft Purview Information Protection data connector is enabled on the Microsoft Sentinel workspace |
| 61021 | AI | AI Threat Detection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Microsoft_365_Copilot | Microsoft 365 Copilot data connector is enabled on the Microsoft Sentinel workspace |
| 61022 | AI | AI Threat Detection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | Microsoft_Defender_for_AI_Services | Microsoft Defender for AI Services is enabled on every Azure subscription that hosts Azure OpenAI or Azure AI Services accounts |
| 61023 | AI | AI Threat Detection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | AGENT_365, Consumption-based: Microsoft Sentinel, AGENT_365 | Agent 365 data connector is enabled on the Microsoft Sentinel workspace |
| 61024 | AI | AI Threat Detection | High | Low | Low | Monitor and detect cyberthreats | Workforce | Azure | WIN_DEF_ATP, MDATP_XPLAT, ATA, ADALLOM_STANDALONE, THREAT_INTELLIGENCE, IDENTITY_THREAT_PROTECTION, IDENTITY_THREAT_PROTECTION_FOR_EMS_E5, SPE_E5, Consumption-based: Microsoft Sentinel, WIN_DEF_ATP, MDATP_XPLAT, ATA, ADALLOM_STANDALONE, THREAT_INTELLIGENCE, IDENTITY_THREAT_PROTECTION, IDENTITY_THREAT_PROTECTION_FOR_EMS_E5, SPE_E5 | Microsoft Defender XDR (unified) data connector is enabled on the Microsoft Sentinel workspace |
