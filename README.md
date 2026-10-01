# cis-eng-functionapps

Terraform IaC + CI/CD for a **privately networked Azure Function App** (Durable Functions host).
Everything is driven by per-environment JSON reference files and a global naming standard.

## Repository layout

```
.
├── .github/workflows/
│   └── deploy.yml            # single pipeline: build+zip src, deploy via Terraform
├── variable/                 # reusable per-environment references (JSON)
│   ├── dev.json              # DEV (develop branch)
│   └── prd.json              # PRD (main branch)
├── src/                      # function app project
│   ├── host.json
│   ├── cis-eng-functionapps.csproj
│   └── Assessments/          # the app itself: ONE C# file + ONE HTML file
│       ├── CloudSecurityAssessment.cs   # host, models, catalog, connectors, Durable workflow, HTTP API
│       └── index.html                   # the UST web app (embedded, served at GET /api/ui)
├── docs/
│   └── zero-trust-assessment-parameters.md  # every parameter + the 336-test catalog from microsoft/zerotrustassessment
├── terraform/                # ALL Terraform lives here
│   ├── versions.tf providers.tf backend.tf
│   ├── variables.tf config.tf locals.tf data.tf
│   ├── deploy.tf             # zips the package
│   ├── main.tf outputs.tf
│   └── modules/
│       ├── function_app/     # plan + storage + function app + vnet integration + run-from-package
│       └── private_endpoint/ # reusable private endpoint
├── README.md
└── .gitignore
```

## Branch → environment model

| Branch    | Environment | Reference file         | Terraform selection      |
| --------- | ----------- | ---------------------- | ------------------------ |
| `develop` | DEV         | `variable/dev.json`    | `-var="environment=dev"` |
| `main`    | PRD         | `variable/prd.json`    | `-var="environment=prd"` |

## 1. Reference files (`variable/*.json`)

Each JSON is the single reusable source of truth for an environment. Terraform reads it via
`jsondecode(file(...))` — see [terraform/config.tf](terraform/config.tf). Keys:

- `subscription_id`, `tenant_id`
- Naming: `workload`, `environment`, `location`, `instance`
- Plan/runtime: `app_service_plan_sku`, `os_type`, `functions_worker_runtime`, `dotnet_version`, …
- `network`: existing **virtual network** name + resource group, and the **integration** and
  **private endpoint** subnet names (resolved to IDs via data sources).
- `private_dns_zone_ids`: optional zone IDs (`sites/blob/file/queue/table`); empty values are skipped.
- `service_principal`: `client_id` / `tenant_id` used by the pipeline for deployment.
- `state`: remote-state backend location (resource group / storage account / container / key).
- `app_settings`: extra Function App settings.
- `tags`.

> Authentication uses **GitHub OIDC** — there is no client secret anywhere. `service_principal`
> only holds the app registration's (non-sensitive) `client_id` / `tenant_id`; access is granted by
> a federated credential on that app registration.

## 2. Application code (`src/`) — Cloud Security Assessment app

`src/` is the **.NET 10 isolated-worker** Durable Functions project (`FUNCTIONS_WORKER_RUNTIME=dotnet-isolated`,
`dotnet_version=v10.0`; Terraform rejects any non-.NET runtime and any .NET version other than 10, because
.NET 8 and .NET 9 leave support on 10 November 2026). It runs security assessments against a
**target** Microsoft tenant and returns results per Zero Trust pillar (Identity, Devices, Network, Data,
Infrastructure, SecOps, AI) with Risk / User impact / Implementation effort for every test.

The code is deliberately two files, both under `src/Assessments/`:

- `CloudSecurityAssessment.cs` — everything server-side, in numbered sections:
  1. host bootstrap, 2. vocabulary (enums and lists mirrored from
  [microsoft/zerotrustassessment](https://github.com/microsoft/zerotrustassessment)), 3. models,
  4. the check catalog (**336 Zero Trust tests** generated from the Microsoft module's `[ZtTest]`
  attributes, **113 CIS Microsoft Azure Foundations Benchmark v5.0.0 controls** from
  [vegazbabz/CIS-Azure-Benchmark-Audit-Tool](https://github.com/vegazbabz/CIS-Azure-Benchmark-Audit-Tool),
  plus UST ISO 27001 / CIS AWS checks), 5. `ICloudConnector` + a deterministic
  `StubCloudConnector` (skip rules mirror the Microsoft module; replace it via `CloudConnectorFactory`
  with Graph/ARM/AWS SDK logic), 6. the Durable orchestration (fan-out one activity per check, fan-in),
  7. the HTTP API.
- `index.html` — the UST-branded single-page app (vanilla JS, no build step, inline SVG charts).
  Layout follows the Microsoft Zero Trust Assessment report: an Overview with tenant info, metric
  tiles, a compliance-score donut, results-by-pillar stacked bars, a pillar-by-risk heatmap, a
  risk-by-effort "quick wins" matrix, pass rate by SFI pillar, top failing categories and a CIS
  section/level chart; one page per pillar with search, Risk / Status / SFI-pillar filters, column
  picker, sortable table, and a right-hand detail sheet per test. Every chart has a table view and
  hover tooltips. Light and dark themes, UST logo and tokens; chart palettes validated for
  colour-vision safety.

Request parameters follow `Connect-ZtAssessment` / `Invoke-ZtAssessment` (tenantId, environment,
clientId, services, pillars, tests, tenantType, days, maximumSignInLogQueryTime, testThrottleLimit,
testTimeoutMinutes, preview, exchangeEnvironmentName, userPrincipalName, sharePointAdminUrl,
subscriptionIds) plus the CIS audit tool's `cisLevel` (`--level`) and `suppressions[]`
(`suppressions.toml`). Full references, including the test catalogs:
[docs/zero-trust-assessment-parameters.md](docs/zero-trust-assessment-parameters.md) and
[docs/cis-azure-benchmark-parameters.md](docs/cis-azure-benchmark-parameters.md).

**Endpoints**
- `GET /api/ui` — the web app.
- `GET /api/catalog` — vocabulary + the full check catalog (the page renders this before any run).
- `POST /api/assessments` — validate and start an assessment; returns `{ id, checks, statusQueryGetUri }`.
- `GET /api/assessments/{instanceId}` — `{ runtimeStatus, customStatus, result }` in camelCase.

> **Credentials:** the target service-principal secret is used only to connect for the assessment.
> Use a least-privilege (read-only) principal and store secrets in Key Vault in production — never log them.
> The endpoints are `Anonymous` because the private endpoint is the network boundary; add Entra
> (Easy Auth) if you need user-level auth.

## 3. Pipeline (`.github/workflows/deploy.yml`)

On push to `develop`/`main` (or manual dispatch) the single job:

1. Resolves the environment from the branch.
2. Reads references (`service_principal`, `subscription_id`, `state`) from `variable/<env>.json` with `jq`.
3. Builds & publishes `src` (`dotnet publish` → `./publish`).
4. `terraform init` with the backend from JSON, then `terraform apply` with
   `-var environment=<env>` and `-var package_source_dir=./publish`.

Terraform authenticates to Azure via **GitHub OIDC** (`ARM_USE_OIDC=true`, no secret), zips the
published output ([terraform/deploy.tf](terraform/deploy.tf)), uploads it to a `deployments`
container, and points the Function App at it via `WEBSITE_RUN_FROM_PACKAGE` (SAS-less; authenticated
by the app's managed identity, which is granted **Storage Blob Data Reader**).

### One-time setup (GitHub OIDC)

1. Create GitHub **Environments** `dev` and `prd` (add required reviewers on `prd`).
2. Create an **Entra app registration** per environment (the deployment identity). Put its
   `client_id` / `tenant_id` in the matching `variable/<env>.json` `service_principal` block.
3. Add a **federated credential** to each app registration for this repo. Use entity type
   *Environment* and the matching environment name, e.g. subject
   `repo:<org>/cis-eng-functionapps:environment:dev` (and `:environment:prd`), issuer
   `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`.
4. Assign RBAC to each app registration on the target scope: **Contributor** *and*
   **Role Based Access Control Administrator** (or *User Access Administrator*) — the second is
   required because Terraform creates role assignments (Storage Blob Data Reader, Key Vault Secrets User).
5. Create the remote-state storage account/container referenced in each JSON's `state` block.

No `ARM_CLIENT_SECRET` (or any secret) is needed — the workflow requests an OIDC token via
`permissions: id-token: write`.

## What Terraform creates

- **Resource group** — `rg-<workload>-<env>-<region>-<instance>`
- **App Service Plan** — `asp-...` (Elastic Premium / Premium v3 for private networking)
- **Storage account** — `st...`, public access disabled, default-deny
- **Function App** — `func-...`, system identity, HTTPS-only, public access disabled, VNet integrated
- **Key Vault** — `kv-...`, RBAC-authorized, public access disabled; the Function App identity gets
  **Key Vault Secrets User** so it can read secrets / resolve `@Microsoft.KeyVault(...)` references
  (vault URI is injected as the `KEY_VAULT_URI` app setting)
- **Log Analytics + Application Insights** — `log-...` / `appi-...`
- **Private endpoints** — Function App (`sites`) + storage (`blob/file/queue/table`) + Key Vault (`vault`)

## Global naming standard

Defined in [terraform/locals.tf](terraform/locals.tf), CAF-style:

```
<type>-<workload>-<environment>-<region>-<instance>   e.g. func-ciseng-dev-eus-001
<type><workload><environment><region><instance>       e.g. stcisengdeveus001   (storage)
```

## Local usage

```bash
cd terraform
terraform init \
  -backend-config="resource_group_name=$(jq -r .state.resource_group_name ../variable/dev.json)" \
  -backend-config="storage_account_name=$(jq -r .state.storage_account_name ../variable/dev.json)" \
  -backend-config="container_name=$(jq -r .state.container_name ../variable/dev.json)" \
  -backend-config="key=$(jq -r .state.key ../variable/dev.json)"

# infra only (skip code deploy)
terraform apply -var="environment=dev" -var="deploy_package=false"

# infra + code (after `dotnet publish ../src -o ../publish`)
terraform apply -var="environment=dev" -var="package_source_dir=../publish"
```

## Important: deploying into a private network

Uploading the package blob is a **data-plane operation** a public GitHub-hosted runner can't reach on a
fully-private storage account. Storage public access is therefore a **per-environment toggle** in the
JSON `storage` block:

```json
"storage": {
  "public_network_access": true,   // dev: on so cloud runners can upload
  "allowed_ip_rules": []           // empty + public on => open (Allow); add CIDRs => Deny + allowlist
}
```

- **dev** → `public_network_access: true` for the demo (private endpoints still apply; the app uses them).
- **prd** → `public_network_access: false` — fully private.

> **Interim, for the demo only.** After architectural sign-off, dev switches to `false` too and
> deployments run on a **self-hosted runner with private-endpoint connectivity** (e.g. an Azure
> Container Apps job in the VNet), so no public access is ever needed. Check whether an Azure Policy
> blocks public storage accounts before relying on this.

Alternatively, set `deploy_package=false` to provision infra only and deploy the code from inside the network.

## Role assignments (RBAC) — created separately by default

The Function App accesses storage and Key Vault at runtime via its **managed identity**. The role
assignments that grant that access require `Microsoft.Authorization/roleAssignments/write`, which a
**deploy-only (Contributor) service principal cannot perform** (it's a privilege-escalation guard).

By design this repo therefore **does not** create those role assignments (`manage_role_assignments`
defaults to `false`). After deploying, an admin grants them to the Function App MI separately:

```bash
# principalId = terraform output function_app_principal_id
az role assignment create --assignee-object-id <MI_PRINCIPAL_ID> --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Reader" \
  --scope /subscriptions/<sub>/resourceGroups/rg-ciseng-dev-uks-001/providers/Microsoft.Storage/storageAccounts/stcisengdevuks001

az role assignment create --assignee-object-id <MI_PRINCIPAL_ID> --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" \
  --scope /subscriptions/<sub>/resourceGroups/rg-ciseng-dev-uks-001/providers/Microsoft.KeyVault/vaults/kv-ciseng-dev-uks-001
```

Run-from-package uses the MI to read the blob, so the app only starts successfully **after** the
Storage Blob Data Reader grant — grant it, then restart the Function App. If your deploy identity
*does* hold Role Based Access Control Administrator / User Access Administrator, set
`"manage_role_assignments": true` in the environment JSON and Terraform will create them instead.

## Notes

- Plan SKU must support private networking: Elastic Premium (`EP1`+) or Premium v3 (`P1v3`+).
  `always_on` stays `false` on Elastic Premium.
- Content-share validation is skipped (`WEBSITE_SKIP_CONTENTSHARE_VALIDATION=1`) because storage is private.
- Switch OS with `os_type` in the JSON — the module implements both Windows and Linux.
- For a script-based runtime (PowerShell/Python/Node v3), remove the `dotnet publish` step and set
  `package_source_dir` back to `../src`.
