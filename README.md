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
├── src/                      # function app code — one workflow per class under src/Workflows/
│   ├── host.json
│   ├── cis-eng-functionapps.csproj
│   ├── Program.cs
│   └── Workflows/
│       └── HelloWorkflow.cs
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

## 2. Application code (`src/`)

`src/` is the Function App project. Add one workflow per class under `src/Workflows/`
(`HelloWorkflow.cs` is a sample Durable Functions orchestration + activity + HTTP starter).

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

The Function App and its storage have **public access disabled**. Terraform's control-plane calls
(create resources, read subnets, create the blob *container*) work from anywhere, but **uploading the
package blob is a data-plane operation** a public GitHub-hosted runner can't reach on a private account.

**How this repo handles it (temporary IP exception):** the pipeline detects the runner's public IP and
passes it as `deploy_agent_ip`. The storage account then turns its public endpoint on but locked to
**only that IP** (`default_action = Deny`) for the upload, and a final `always()` step re-applies with
`deploy_agent_ip=""` to return the account to **fully private** (private endpoints only) — even if the
deploy failed. The app itself always reads the package over its blob **private endpoint**, so runtime
stays private throughout. See [deploy.yml](.github/workflows/deploy.yml) and `deploy_agent_ip` in
[terraform/variables.tf](terraform/variables.tf).

The deployment identity needs **Contributor** on the account (to list keys for the blob upload), which
the OIDC app registration already has. Alternatives if you'd rather not open any public window:

- Run the pipeline on a **self-hosted / VNet-injected runner** (e.g. Azure Container Apps job), or
- Set `deploy_package=false` to provision infra only and deploy code separately from inside the network.

## Notes

- Plan SKU must support private networking: Elastic Premium (`EP1`+) or Premium v3 (`P1v3`+).
  `always_on` stays `false` on Elastic Premium.
- Content-share validation is skipped (`WEBSITE_SKIP_CONTENTSHARE_VALIDATION=1`) because storage is private.
- Switch OS with `os_type` in the JSON — the module implements both Windows and Linux.
- For a script-based runtime (PowerShell/Python/Node v3), remove the `dotnet publish` step and set
  `package_source_dir` back to `../src`.
