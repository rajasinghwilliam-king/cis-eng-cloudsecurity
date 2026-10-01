# CIS Microsoft Azure Foundations Benchmark: parameter reference

Source: [vegazbabz/CIS-Azure-Benchmark-Audit-Tool](https://github.com/vegazbabz/CIS-Azure-Benchmark-Audit-Tool) v1.2.0
(Python, cloned 2026-10-01), which audits **CIS Microsoft Azure Foundations Benchmark v5.0.0** and covers 113 of its 155
controls (102 automated, 11 manual).

> The source repository is archived and marked superseded by
> [CISAzureBenchmark-PS](https://github.com/vegazbabz/CISAzureBenchmark-PS), a PowerShell rebuild for benchmark v6.0.0
> (April 2026, 93 automated controls). The UST app mirrors the v5.0.0 catalog you asked for; re-sync from the successor
> when you want v6.0.0.

The UST app ([src/Assessments/CloudSecurityAssessment.cs](../src/Assessments/CloudSecurityAssessment.cs)) carries these
controls as the `cis-azure` framework and maps them onto the Zero Trust pillar pages.

## 1. Command-line options (`cis_azure_audit.py`)

| Option | Type / default | Meaning | UST request field |
|---|---|---|---|
| `--tenant TENANT_ID` | string | Limit subscription discovery and tenant-level Graph checks to one tenant | `tenantId` |
| `--subscription`, `-s SUB ...` | string[] | Subscription names or IDs to audit (default: all enabled) | `subscriptionIds` |
| `--level`, `-l {1,2}` | int | Restrict to Level 1 or Level 2 controls | `cisLevel` |
| `--output`, `-o FILE` | string | HTML report filename | not applicable (JSON API) |
| `--output-dir DIR` | string | Directory for report and checkpoints | not applicable |
| `--parallel`, `-p N` | int, default 3 | Concurrent subscription workers (max recommended 5) | `testThrottleLimit` |
| `--executor {thread,process}` | string, thread | Worker backend | not applicable |
| `--no-adaptive-concurrency` | switch | Disable dynamic worker tuning on throttling | not applicable |
| `--fresh` | switch | Clear checkpoints and re-audit everything | every run is fresh |
| `--report-only` | switch | Regenerate the report from checkpoints | not applicable |
| `--quiet`, `-q` | switch | Hide subscription and resource names in console output | not applicable |
| `--log-level {TRACE,DEBUG,INFO,WARNING,ERROR,CRITICAL}` | string, INFO | Logging verbosity | not applicable |
| `--verbose`, `-v` / `--debug` | switch | DEBUG / TRACE logging | not applicable |
| `--log-file PATH` | string | Write logs to a file | not applicable |
| `--skip-preflight` | switch | Skip permission preflight checks | not applicable |
| `--suppressions FILE` | string, suppressions.toml | Accepted-risk file | `suppressions[]` |
| `--list-suppressions` | switch | Print active suppressions and exit | not applicable |
| `--preview` | switch | Print the control catalog and exit | `GET /api/catalog` |
| `--no-open` | switch | Do not open the report in a browser | not applicable |
| `--exit-code` | switch | Exit 2 when any FAIL or ERROR is found (CI gate) | not applicable |

## 2. Configuration file (`cis_audit.toml`)

| Section | Key | Default | Meaning | UST request field |
|---|---|---|---|---|
| `[audit]` | `parallel` | 3 | Subscriptions audited in parallel | `testThrottleLimit` |
| `[audit]` | `executor` | thread | thread or process | not applicable |
| `[audit]` | `checkpoint_dir` | cis_checkpoints | Checkpoint folder | not applicable |
| `[timeouts]` | `default` | 20 s | Azure CLI call timeout | `testTimeoutMinutes` |
| `[timeouts]` | `storage_list` | 30 s | `az storage account list` | `testTimeoutMinutes` |
| `[timeouts]` | `storage_svc` | 15 s | Per-account blob/file/table queries | `testTimeoutMinutes` |
| `[timeouts]` | `activity_log` | 25 s | Activity log queries (90-day window) | `testTimeoutMinutes` |
| `[timeouts]` | `graph` | 120 s | Resource Graph bulk queries | `testTimeoutMinutes` |
| `[graph_auth]` | `client_id` | | App registration with Policy.Read.All (needed for control 5.1.1) | `clientId` |
| `[graph_auth]` | `tenant_id` | auto | Tenant of the app registration | `tenantId` |
| `[graph_auth]` | `client_secret` | | Service principal secret, or env `CIS_GRAPH_CLIENT_SECRET` | `clientSecret` |

Environment variables: `CIS_AUDIT_CONFIG` (path to the TOML file), `CIS_GRAPH_CLIENT_SECRET`.

## 3. Azure permissions the audit identity needs

| Scope | Role | Purpose |
|---|---|---|
| Each subscription | Reader | Enumerate resources |
| Each subscription | Security Reader | Defender plans, security contacts |
| Microsoft Entra ID | Global Reader | Identity controls (section 5) |
| Key Vaults (optional) | Key Vault Reader or access policy | Data-plane controls 8.3.1 to 8.3.4, 8.3.9, 8.3.11 |

## 4. Result model

One finding per resource per control (`R` dataclass): `control_id`, `title`, `level` (1 or 2), `section`, `status`,
`details`, `remediation`, `subscription_id`, `subscription_name`, `resource`.

| Status | Meaning | UST status |
|---|---|---|
| PASS | Compliant | Passed |
| FAIL | Non-compliant, remediation hint provided | Failed |
| ERROR | Could not evaluate (permissions, timeout, API error); compliance unknown | Error |
| INFO | Not applicable (resource type absent or feature unsupported) | Skipped (NotApplicable) |
| MANUAL | Cannot be automated; verify per the CIS PDF | Investigate (shown as "Manual review") |
| SUPPRESSED | Accepted risk from suppressions.toml; excluded from the score | Suppressed |

Compliance score = PASS / (PASS + FAIL); INFO, MANUAL and SUPPRESSED are excluded, as in the UST Overview.

### Suppressions (`suppressions.toml`)

| Field | Required | Behaviour |
|---|---|---|
| `control_id` | Yes | Exact match on the CIS control number |
| `resource` | No | Exact case-insensitive match on the resource name; omit to match all |
| `subscription` | No | Exact case-insensitive match on the subscription name; omit to match all |
| `justification` | Yes | Shown next to the finding |
| `expires` | Yes | ISO date, at most one year ahead; expired entries revert the finding to FAIL / ERROR |

Only FAIL and ERROR findings can be suppressed. The UST request carries the same fields as `suppressions[]`
(`controlId`, `resource`, `subscription`, `justification`, `expires`).

## 5. How the UST app maps CIS controls onto Zero Trust pillars

| CIS section | Pillar | Connects to |
|---|---|---|
| 2 Azure Databricks | Data | Azure |
| 3 Compute Services | Infrastructure | Azure |
| 5 Identity Services | Identity | Graph |
| 6 Logging and Monitoring | SecOps | Azure |
| 7 Networking Services | Network | Azure |
| 8 Security Services | Infrastructure | Azure |
| 9 Storage Services | Data | Azure |

Risk: Level 1 (baseline profile) is shown as High, Level 2 (defence in depth) as Medium. The CIS benchmark itself has
no risk rating. The profile level and audit method (Automated / Manual) are shown on each row and in the detail sheet.

## 6. Control catalog (113 controls)

| Control | Section | Level | Audit | Title |
|---|---|---|---|---|| 2.1.1 | 2 - Azure Databricks | L2 | Automated | Databricks deployed in customer-managed VNet |
| 2.1.2 | 2 - Azure Databricks | L1 | Automated | NSGs configured for Databricks subnets |
| 2.1.7 | 2 - Azure Databricks | L1 | Automated | Diagnostic logging configured |
| 2.1.8 | 2 - Azure Databricks | L2 | Automated | Databricks encryption uses customer-managed keys |
| 2.1.9 | 2 - Azure Databricks | L1 | Automated | No Public IP enabled |
| 2.1.10 | 2 - Azure Databricks | L1 | Automated | Public network access disabled |
| 2.1.11 | 2 - Azure Databricks | L2 | Automated | Private endpoints used to access workspaces |
| 3.1.1 | 3 - Compute Services | L2 | Manual | Only MFA-enabled identities can access privileged VMs |
| 5.1.1 | 5 - Identity Services | L1 | Automated | Security defaults enabled |
| 5.1.2 | 5 - Identity Services | L1 | Automated | MFA enabled for all users |
| 5.1.3 | 5 - Identity Services | L1 | Manual | Allow users to remember MFA on trusted devices disabled |
| 5.2.2 | 5 - Identity Services | L1 | Manual | Exclusionary geographic Conditional Access policy considered |
| 5.3.2 | 5 - Identity Services | L1 | Manual | Guest users reviewed on a regular basis |
| 5.3.3 | 5 - Identity Services | L1 | Automated | User Access Administrator role restricted |
| 5.4 | 5 - Identity Services | L1 | Automated | Restrict non-admin users from creating tenants |
| 5.6 | 5 - Identity Services | L1 | Automated | Account lockout threshold <= 10 |
| 5.14 | 5 - Identity Services | L1 | Automated | Users cannot register applications |
| 5.15 | 5 - Identity Services | L1 | Automated | Guest access restricted to own directory objects |
| 5.16 | 5 - Identity Services | L2 | Automated | Guest invite restrictions set to admins or no one |
| 5.23 | 5 - Identity Services | L1 | Automated | No custom subscription administrator roles |
| 5.27 | 5 - Identity Services | L1 | Automated | Between 2 and 3 subscription owners |
| 5.28 | 5 - Identity Services | L1 | Manual | Privileged users protected by phishing-resistant MFA |
| 6.1.1.1 | 6 - Logging and Monitoring | L1 | Automated | Diagnostic Setting exists for Subscription Activity Logs |
| 6.1.1.2 | 6 - Logging and Monitoring | L1 | Automated | Diagnostic Setting captures required categories |
| 6.1.1.3 | 6 - Logging and Monitoring | L1 | Automated | Activity log retention >= 365 days |
| 6.1.1.4 | 6 - Logging and Monitoring | L1 | Automated | Key Vault diagnostic logging enabled |
| 6.1.1.6 | 6 - Logging and Monitoring | L2 | Automated | Azure AppService HTTP logs enabled |
| 6.1.2.1 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Create Policy Assignment |
| 6.1.2.2 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Delete Policy Assignment |
| 6.1.2.3 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Create or Update NSG |
| 6.1.2.4 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Delete NSG |
| 6.1.2.5 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Create or Update Security Solution |
| 6.1.2.6 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Delete Security Solution |
| 6.1.2.7 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Create or Update SQL Firewall Rule |
| 6.1.2.8 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Delete SQL Firewall Rule |
| 6.1.2.9 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Create or Update Public IP |
| 6.1.2.10 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Delete Public IP |
| 6.1.2.11 | 6 - Logging and Monitoring | L1 | Automated | Activity Log Alert: Service Health |
| 6.1.3.1 | 6 - Logging and Monitoring | L2 | Automated | Application Insights configured |
| 6.1.4 | 6 - Logging and Monitoring | L1 | Manual | Azure Monitor resource logging enabled for all services |
| 6.1.5 | 6 - Logging and Monitoring | L1 | Manual | SKU Basic/Consumption not used on production artifacts |
| 6.2 | 6 - Logging and Monitoring | L2 | Manual | Resource Locks set for mission-critical Azure resources |
| 7.1 | 7 - Networking Services | L1 | Automated | RDP (3389) not open to internet |
| 7.2 | 7 - Networking Services | L1 | Automated | SSH (22) not open to internet |
| 7.3 | 7 - Networking Services | L1 | Automated | UDP access from internet restricted |
| 7.4 | 7 - Networking Services | L1 | Automated | HTTP/HTTPS (80/443) from internet evaluated and restricted |
| 7.5 | 7 - Networking Services | L2 | Automated | NSG flow log retention >= 90 days |
| 7.6 | 7 - Networking Services | L2 | Automated | Network Watcher enabled for all regions in use |
| 7.7 | 7 - Networking Services | L1 | Manual | Public IP addresses evaluated on a periodic basis |
| 7.8 | 7 - Networking Services | L2 | Automated | VNet flow log retention >= 90 days |
| 7.9 | 7 - Networking Services | L2 | Automated | VPN Gateway P2S uses Azure AD authentication |
| 7.10 | 7 - Networking Services | L2 | Automated | WAF enabled on Azure Application Gateway |
| 7.11 | 7 - Networking Services | L1 | Automated | Subnets associated with NSGs |
| 7.12 | 7 - Networking Services | L1 | Automated | App Gateway SSL policy min TLS 1.2+ |
| 7.13 | 7 - Networking Services | L1 | Automated | HTTP2 enabled on Application Gateway |
| 7.14 | 7 - Networking Services | L2 | Automated | WAF request body inspection enabled |
| 7.15 | 7 - Networking Services | L2 | Automated | WAF bot protection enabled |
| 7.16 | 7 - Networking Services | L2 | Manual | Azure Network Security Perimeter (NSP) is used |
| 8.1.1.1 | 8 - Security Services | L2 | Automated | Microsoft Defender CSPM |
| 8.1.2.1 | 8 - Security Services | L2 | Automated | Microsoft Defender for APIs |
| 8.1.3.1 | 8 - Security Services | L2 | Automated | Microsoft Defender for Servers |
| 8.1.3.3 | 8 - Security Services | L2 | Automated | Endpoint protection (WDATP) component |
| 8.1.4.1 | 8 - Security Services | L2 | Automated | Microsoft Defender for Containers |
| 8.1.5.1 | 8 - Security Services | L2 | Automated | Microsoft Defender for Storage |
| 8.1.6.1 | 8 - Security Services | L2 | Automated | Microsoft Defender for App Services |
| 8.1.7.1 | 8 - Security Services | L2 | Automated | Microsoft Defender for Azure Cosmos DB |
| 8.1.7.2 | 8 - Security Services | L2 | Automated | Microsoft Defender for Open-Source Relational DBs |
| 8.1.7.3 | 8 - Security Services | L2 | Automated | Microsoft Defender for SQL (Managed Instance) |
| 8.1.7.4 | 8 - Security Services | L2 | Automated | Microsoft Defender for SQL Servers on Machines |
| 8.1.8.1 | 8 - Security Services | L2 | Automated | Microsoft Defender for Key Vault |
| 8.1.9.1 | 8 - Security Services | L2 | Automated | Microsoft Defender for Resource Manager |
| 8.1.10 | 8 - Security Services | L1 | Automated | Defender configured to check VM OS updates |
| 8.1.12 | 8 - Security Services | L1 | Automated | Security alerts notify subscription Owners |
| 8.1.13 | 8 - Security Services | L1 | Automated | Additional email addresses for security contact |
| 8.1.14 | 8 - Security Services | L1 | Automated | Alert severity notifications configured |
| 8.1.15 | 8 - Security Services | L1 | Automated | Attack path notifications configured |
| 8.3.1 | 8 - Security Services | L1 | Automated | Key expiration set - RBAC Key Vaults |
| 8.3.2 | 8 - Security Services | L1 | Automated | Key expiration set - non-RBAC Key Vaults |
| 8.3.3 | 8 - Security Services | L1 | Automated | Secret expiration set - RBAC Key Vaults |
| 8.3.4 | 8 - Security Services | L1 | Automated | Secret expiration set - non-RBAC Key Vaults |
| 8.3.5 | 8 - Security Services | L1 | Automated | Key Vault purge protection enabled |
| 8.3.6 | 8 - Security Services | L2 | Automated | Key Vault RBAC authorization enabled |
| 8.3.7 | 8 - Security Services | L1 | Automated | Key Vault public network access disabled |
| 8.3.8 | 8 - Security Services | L2 | Automated | Private endpoints used to access Key Vault |
| 8.3.9 | 8 - Security Services | L2 | Automated | Automatic key rotation enabled |
| 8.3.10 | 8 - Security Services | L2 | Manual | Key Vault Managed HSM used when required |
| 8.3.11 | 8 - Security Services | L1 | Automated | Certificate validity period <= 12 months |
| 8.4.1 | 8 - Security Services | L2 | Automated | Azure Bastion Host exists |
| 8.5 | 8 - Security Services | L2 | Automated | DDoS Network Protection enabled on VNets |
| 9.1.1 | 9 - Storage Services | L1 | Automated | Azure Files soft delete enabled |
| 9.1.2 | 9 - Storage Services | L1 | Automated | SMB protocol version >= 3.1.1 |
| 9.1.3 | 9 - Storage Services | L1 | Automated | SMB channel encryption AES-256-GCM or higher |
| 9.2.1 | 9 - Storage Services | L1 | Automated | Blob soft delete enabled |
| 9.2.2 | 9 - Storage Services | L1 | Automated | Container soft delete enabled |
| 9.2.3 | 9 - Storage Services | L2 | Automated | Blob versioning enabled |
| 9.2.4 | 9 - Storage Services | L2 | Automated | Storage logging enabled for Blob Service read requests |
| 9.2.5 | 9 - Storage Services | L2 | Automated | Storage logging enabled for Blob Service write requests |
| 9.2.6 | 9 - Storage Services | L2 | Automated | Storage logging enabled for Blob Service delete requests |
| 9.3.1.1 | 9 - Storage Services | L1 | Automated | Key rotation reminders enabled |
| 9.3.1.2 | 9 - Storage Services | L1 | Automated | Access keys regenerated within 90 days |
| 9.3.1.3 | 9 - Storage Services | L1 | Automated | Storage account key access disabled |
| 9.3.2.1 | 9 - Storage Services | L2 | Automated | Private endpoints used to access storage accounts |
| 9.3.2.2 | 9 - Storage Services | L1 | Automated | Public network access disabled |
| 9.3.2.3 | 9 - Storage Services | L1 | Automated | Default network access rule is Deny |
| 9.3.3.1 | 9 - Storage Services | L1 | Automated | Default to Microsoft Entra authorization in Azure portal |
| 9.3.4 | 9 - Storage Services | L1 | Automated | Secure transfer (HTTPS) required |
| 9.3.5 | 9 - Storage Services | L2 | Automated | Allow Azure trusted services to access storage |
| 9.3.6 | 9 - Storage Services | L1 | Automated | Minimum TLS version 1.2 |
| 9.3.7 | 9 - Storage Services | L1 | Automated | Cross-tenant replication disabled |
| 9.3.8 | 9 - Storage Services | L1 | Automated | Blob anonymous access disabled |
| 9.3.9 | 9 - Storage Services | L1 | Automated | Storage account has CanNotDelete resource lock |
| 9.3.10 | 9 - Storage Services | L2 | Automated | Storage account has ReadOnly resource lock |
| 9.3.11 | 9 - Storage Services | L2 | Automated | Redundancy set to geo-redundant (GRS) |
