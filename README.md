# AI Incident Commander

**Production-oriented, agentic incident-response system — work in progress.**

AI Incident Commander is an AI Engineering portfolio project for investigating production incidents, collecting evidence from operational systems, assessing root-cause hypotheses, and proposing controlled remediation. Its target architecture combines **LangGraph**, **custom MCP servers and clients**, **advanced RAG**, and a **Human-in-the-Loop security boundary**.

> **Current maturity (November 27, 2026):** The read-only LangGraph coordinator and nested Investigator Subgraph support validated planning, conditional and parallel evidence collection, deterministic aggregation, PostgreSQL checkpointing, tested manual recovery, optional analysis review via interrupts, and controlled retries for transient read-only failures. A custom Observability MCP server and its OAuth-authenticated client have been implemented and tested against local Keycloak, Alloy, and Loki. **The live MCP client is not yet wired into the LangGraph collectors.** Durable remediation security foundations are implemented separately; mutating MCP execution, advanced RAG, application-level production authentication/RBAC, and cloud deployment remain future work.

## Architecture evolution: `apv:v1` → `apv:v2`

**A concrete example of evolving security requirements, backward-compatible data migration, and regression engineering.**

This is part of the project's engineering history, not a feature added solely for a demo.

### The change

The first approval policy format, **`apv:v1`**, fingerprinted the trusted **Action Catalog**: available operations, their effects, risks, environments, and parameter rules. As the design evolved toward MCP-based execution, this proved insufficient. An approved business action could be remapped to a different MCP server or tool without changing the catalog-derived policy version.

The newer **`apv:v2`** incorporates both the trusted action catalog and the version of the **action-to-MCP-tool bindings**. Changing `action_name → server_id → tool_name` changes the policy version; fresh approval verification then rejects approvals bound to an earlier mapping.

| Concern | `apv:v1` | `apv:v2` |
|---|---|---|
| Trusted Action Catalog | Included | Included |
| MCP tool binding version | **Not included** | **Included** |
| Detects changes to action definitions | Yes | Yes |
| Detects remapping to a different MCP tool/server alias | No | Yes |
| Suitable for new MCP-mutating approval flows | **No** | Yes, **with** fresh verification and other execution safeguards |
| Historical records | Retained for compatibility | Supported |

### Why keep both formats?

The project was started from scratch. **With today's knowledge, binding-aware policy versioning could have been designed from the beginning.** The integration boundary made the gap apparent later. Rather than erasing that history, the implementation preserves it as an example of safely evolving a security-sensitive design.

The migration separates **historical data compatibility** from **permission to execute**:

- Existing `apv:v1` approval requests and execution claims remain structurally readable.
- New MCP-bound request creation and verification use `apv:v2` and trusted bindings; the MCP-bound verification path rejects legacy approvals.
- Alembic revision `e62b4f0c91ad` expands two PostgreSQL `CHECK` constraints to support both formats without rewriting historical migrations.
- Unit and PostgreSQL integration tests cover valid requests and rejection when the tool name, server alias, or resolved resource identity changes.

This is **not** a claim of end-to-end MCP safety. The real MCP executor, downstream idempotency, resource-version preconditions, handling of uncertain external outcomes, and reconciliation still need implementation. Infrastructure changes *behind* a `server_id` alias also require independent configuration-integrity controls.

**Engineering lessons:** version security-sensitive contracts explicitly; preserve historical audit data; make active execution paths fail closed; test migrations against existing behavior; and distinguish a database reservation from an external side effect.

## What the project aims to do

A representative incident:

> After a deployment, HTTP 500 responses increase and API latency rises.

The intended workflow is to classify the incident, plan an investigation, collect logs, metrics, and deployment evidence, retrieve runbooks and postmortems with RAG, rank root-cause hypotheses, propose remediation, obtain human approval, execute permitted operations through MCP, verify the outcome, and produce an incident report.

The project targets **Strong Mid / Mid+ AI Engineering**, with selected senior-level architectural concerns. It is **not** intended to be a single-agent chatbot.

## Architecture

### Implemented read-only investigation flow

```text
                 IncidentState (typed, serializable snapshots)
                                   |
                                   v
                      Main Incident Graph
                             START → intake
                                   |
                                   v
                       Investigator Subgraph
                       investigation_planner
                                   |
                          conditional routing
                          /               \
                 collect_logs         collect_metrics
                          \               /
                           evidence reducer
                                   |
                           aggregate_evidence
                                   |
                          workflow_phase: analyzing
                                   |
                                  END

             Optional LangGraph checkpoint persistence
                   InMemorySaver / AsyncPostgresSaver
                          PostgreSQL schema:
                           langgraph_checkpoint
```

The planner is injectable and currently deterministic by default. Log and metric collectors are asynchronous injected dependencies; **the independently implemented Observability MCP client is not yet connected to the log collector**. Live metrics collection is also pending. The evidence reducer deduplicates by stable evidence ID and rejects conflicting snapshots. The main graph retains state that does not belong to the Investigator Subgraph, including hypotheses.

PostgreSQL checkpointing uses a dedicated schema, an explicit schema-initialization operation, and a separate connection lifecycle. Manual resume has been verified across connections, graph instances, and separate processes, including a controlled process termination after the successful log collector's pending write was persisted. Completed work was not replayed in the tested scenarios.

An optional `analysis_review` node uses LangGraph `interrupt()` and `Command(resume=...)`, with validated review input and durable state across PostgreSQL connection lifecycles. This is diagnostic feedback, **not approval for remediation**. Read-only collectors support an opt-in `RetryPolicy` for `TransientEvidenceCollectionError`; permanent validation, authorization, and contract failures must not be blindly retried.

These tests do not establish automatic recovery at arbitrary crash points, concurrent resume safety, production checkpoint access control, or exactly-once external effects. Dedicated checkpoint-runtime database role isolation remains pending.

### Separately implemented remediation security foundation

```text
Trusted Action Catalog + MCP tool bindings
                   |
          MCP-bound policy (apv:v2)
                   |
    Persisted approval request / decision
                   |
          Fresh approval Guard
                   |
         Atomic execution claim
                   |
     Durable execution lifecycle
                   |
      Verified dispatch reservation
                   |
       Secure MCP executor [contract only]
                   |
      Mutating MCP operations [not implemented]
```

These are framework-independent domain and application services. **They are not yet connected into an end-to-end LangGraph remediation workflow.** Authorization decisions belong in trusted application and persistence layers, not in LLM prompts.

### Implemented standalone Observability MCP integration

```text
 Local OTLP producer → Alloy → Loki
                                ^
                                | bounded read-only log queries
                                |
 Keycloak ← HTTPS → Observability MCP Server
     ^                 ^         (introspection, ACL, redaction)
     |                 |
     | OAuth / TLS     | MCP Streamable HTTP / TLS
     |                 |
     +------ Observability MCP Client
                       |
               [LangGraph adapter pending]
```

The custom server exposes `search_service_logs` on a private HTTPS endpoint. It uses OAuth token introspection, scoped authorization, exact principal matching (`client_id` and `subject`), service-level ACLs, tenant/label restrictions, and log redaction. Its server-side introspection credentials are separate from the worker credentials.

The Python client uses the MCP SDK v2 and HTTPX2 with a managed asynchronous lifecycle, OAuth Client Credentials, an explicit issuer, a configurable CA bundle, bounded file-based secret loading, and in-memory token storage. Its outbound request policy constrains HTTPS destinations, methods, authorization schemes, and the token request's grant type and read-only scope (`observability:logs:read`). Tests cover untrusted discovery endpoints, unsafe redirects, scope escalation, malformed token forms, real TLS failures, authenticated calls, and service ACL denial.

The live integration test retrieves a uniquely identified synthetic log from Loki through the actual MCP client and verifies that the synthetic sensitive value is absent from the returned result. A separate raw HTTP/JSON-RPC suite checks the server contract independently of the SDK. No live mutating MCP executor is implemented.

## Implementation status

| Area | Status |
|---|---|
| Domain models, trusted action validation, target resolution, and action fingerprints | Implemented and tested |
| Persisted approval requests and human decisions | Implemented and tested with PostgreSQL |
| Fresh approval Guard, execution claims, and execution lifecycle | Implemented and tested |
| Limited remediation execution recovery and verified dispatch reservation | Implemented and tested; no external MCP effect |
| MCP action bindings and `apv:v2` approval integrity | Implemented and tested, including PostgreSQL integration |
| MCP-bound application composition root | Implemented and unit-tested |
| Typed LangGraph incident state and evidence reducer | Implemented and tested |
| Main Incident Graph + nested Investigator Subgraph | Implemented and tested |
| Deterministic planning, conditional routing, parallel read-only collectors | Implemented and tested with injected collectors |
| In-memory and PostgreSQL checkpointing | Implemented and tested; isolated schema and explicit setup |
| Manual durable resume for read-only investigation | Implemented and tested in controlled failure and process-restart scenarios |
| Optional graph-level analysis review and controlled read-only retries | Implemented and tested; not remediation approval |
| Secure mutating MCP executor | **Contract only**; no live mutating external calls |
| Local Keycloak, Alloy, Loki, and custom read-only Observability MCP server | Implemented and integration-tested |
| OAuth-authenticated Observability MCP client | Implemented and integration-tested independently of LangGraph |
| Live log collector adapter, live metrics and other MCP sources | Planned |
| Advanced RAG, hypothesis evaluation, and incident report generation | Planned |
| Full FastAPI application, production authentication/RBAC, application-wide observability, CI/CD, and cloud deployment | Planned / not yet verified as complete |

### Security invariants already represented in code

- Human approval decisions are persisted in PostgreSQL; a caller-provided `APPROVED` flag is not sufficient.
- A fresh Guard revalidates policy, action fingerprint, and resolved resource identity.
- Claim, execution start, and dispatch reservation have separate durable records and database-enforced uniqueness.
- A committed dispatch reservation is **not** a reusable capability or proof that MCP was called.
- `EXECUTING` / `UNKNOWN` states do **not** authorize blind retries after a crash or timeout.
- Checkpoint serialization is configured without a pickle fallback; checkpoint content still requires restricted access and appropriate trust boundaries.
- The system does **not** claim exactly-once external effects. Downstream idempotency and reconciliation remain future work.
- Read-only MCP connections require TLS verification and scoped OAuth credentials; discovery and token exchanges are constrained by trusted configuration. Service ACLs and redaction are enforced by the server, not by an LLM.
- Production authentication/RBAC and a privileged mutating MCP execution boundary remain future work; test-only authorization doubles are not production authentication.

## Development and verification

Development uses **Python 3.12**, `uv`, `pytest`, Ruff, Mypy, LangGraph, Psycopg 3, SQLAlchemy, Alembic, and PostgreSQL. PostgreSQL-backed integration tests are opt-in and require a running, explicitly provisioned local database. Credentials belong in an uncommitted `.env` file; do not commit secrets.

```bash
# Unit tests (do not require PostgreSQL)
uv run --no-sync pytest -q tests/unit/

# Regression including approval, schema, and checkpoint integration tests
# OAuth and MCP integration tests have separate opt-in runs.
RUN_DB_APPROVAL_TESTS=1 \
RUN_DB_SCHEMA_TESTS=1 \
RUN_DB_CHECKPOINT_TESTS=1 \
RUN_KEYCLOAK_OAUTH_TESTS=0 \
RUN_OBSERVABILITY_MCP_HTTP_TESTS=0 \
RUN_OBSERVABILITY_MCP_AUTH_TESTS=0 \
RUN_OBSERVABILITY_MCP_REDACTION_TESTS=0 \
RUN_OBSERVABILITY_MCP_CLIENT_TESTS=0 \
uv run --no-sync --env-file .env pytest -q

# Lint, formatting, strict type checks, and lockfile consistency
uv run --no-sync ruff check src/ tests/ migrations/versions/
uv run --no-sync ruff format --check src/ tests/ migrations/versions/
MYPYPATH=src uv run --no-sync mypy src/ai_incident_commander/
uv lock --check

# Application database migration state (requires PostgreSQL)
uv run --no-sync --env-file .env alembic current
```

### Local Observability MCP verification

The following instructions assume a provisioned local development stack. They are not a complete automated installation or production deployment procedure.

- Use `.env.example` as the environment variable reference. Keep actual credentials and deployment-managed TLS material outside Git.
- The local OAuth issuer is `https://auth.aic.test:8443/realms/incidents`. Resolve `auth.aic.test` to `127.0.0.1` on the WSL host and to Keycloak via the Docker network alias. Use a trusted local CA and a Keycloak certificate valid for that hostname.
- The private MCP endpoint is `https://observability-mcp:8000/mcp`, with a certificate valid for `observability-mcp`. Neither MCP nor Loki publishes a host port. Local OTLP HTTP ingress is authenticated and bound to host loopback.
- The Keycloak realm must contain the confidential `incident-worker` client, the separate `observability-mcp-introspection` client, the required read-only scope, and compatible token audiences for the MCP resource and introspection service.
- Copy the local template `deploy/observability/observability-mcp-runtime.local.example.json` to the external runtime path `$HOME/.config/ai-incident-commander/mcp/observability/runtime.json`. Replace the illustrative UUID in `grants[].subject` with the actual authorized service-account `sub` obtained through token introspection. Provision matching tenant and service labels, the secret files, certificates, and readable mounts required by the Compose configuration. Do not copy the resulting private configuration back into Git.
- `deploy/observability/observability-mcp-runtime.example.json` is a production-oriented reference, not a deployment-ready configuration. It requires environment-specific endpoints, credentials, trust settings, and grants. Plain HTTP to Loki is enabled only in the local example.

With the identity, observability, and MCP stacks running, build the test image from the repository root and run the local client suite:

```bash
docker build --target integration-test \
  --tag ai-incident-commander/observability-mcp-tests:local .

uv run --no-sync python tests/integration/_run_observability_mcp_client_tests.py
```

The runner prompts for the local OTLP `incident-collector` password without terminal echo, emits a synthetic log through `127.0.0.1:4318`, and passes its trace ID to the isolated container. The worker secret is read from `$HOME/.config/ai-incident-commander/keycloak/clients/incident-worker.secret` and passed through stdin to a temporary file on container tmpfs. The runner does not give the client container direct access to Alloy or Loki. The test image must be rebuilt when application code or dependencies change.

This is an interactive local test workflow, not an unattended CI pipeline. The separate HTTP suite uses its own runner and opt-in flags.

### Latest verified results (November 27, 2026)

| Verification | Result |
|---|---|
| Regression with PostgreSQL opt-ins | **1725 passed, 9 expected skips, 0 failed** |
| Separately executed OAuth / MCP integration cases | 1 Keycloak + 6 MCP client + 2 MCP HTTP passed |
| MCP client lifecycle/security tests | 25 passed (included in the regression) |
| Test runner unit tests | 11 passed (included in the regression) |
| Ruff lint / format | Passed; 152 files already formatted |
| Mypy (application source) | Passed; 66 source files |
| `uv lock --check` | Passed; 88 packages resolved |
| Gitleaks v8.30.1 | No findings in the scanned working-tree snapshot or 46 locally available commits after a narrow JDBC URL false-positive exception |
| Gitleaks allowlist checks | 5/5 passed |

The nine opt-in cases were verified separately, not as part of a single 1734-test run. Secret scanning uses `.gitleaks.toml` and a narrowly scoped exception for a non-secret JDBC URL. It does not guarantee absence of all secrets or replace dependency vulnerability scanning. A final staged scan is required after documentation and configuration changes.

These are local development/test results, not a claim of production deployment.
The LangGraph checkpoint schema is initialized **explicitly**, not automatically on application startup. Its integration tests do not run schema migrations or wipe existing checkpoint tables.

## Roadmap

**Next engineering milestone:** integrate the read-only Observability MCP client with the LangGraph log evidence collector, preserving trusted configuration, typed evidence, lifecycle management, bounded calls, and explicit transient versus permanent error classification.

Further work will add live metrics and deployment sources, additional custom MCP servers, advanced RAG, hypothesis ranking, and incident reporting. Later milestones include end-to-end remediation behind the existing approval/Guard/claim/dispatch boundary, downstream idempotency and reconciliation, outcome verification, production authentication/RBAC, evaluation, monitoring, CI/CD, and AWS deployment.

The existing durable remediation security foundation was developed ahead of the end-to-end remediation workflow. Its presence **does not** mean that external actions or the complete incident-response workflow are implemented.

## Project principles

Explicit trust boundaries, typed contracts, durable state, controlled side effects, testable failure handling, transactionally enforced constraints, Human-in-the-Loop for mutating operations, and transparent reporting of what has—and has not—been implemented.
