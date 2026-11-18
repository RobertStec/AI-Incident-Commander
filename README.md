# AI Incident Commander

**Production-oriented, agentic incident-response system — work in progress.**

AI Incident Commander is an AI Engineering portfolio project for investigating production incidents, collecting evidence from operational systems, assessing root-cause hypotheses, and proposing controlled remediation. Its target architecture combines **LangGraph**, **custom MCP servers and clients**, **advanced RAG**, and a **Human-in-the-Loop security boundary**.

> **Current maturity (November 2026):** A read-only LangGraph incident coordinator and nested Investigator Subgraph are implemented and tested. They support a validated investigation plan, conditional log/metric collection, parallel execution, and deterministic evidence aggregation. Checkpoint persistence is tested with both in-memory storage and PostgreSQL. Separately, the durable remediation approval, Guard, execution-claim, lifecycle, and dispatch-reservation foundations are implemented and tested. **End-to-end remediation, live MCP execution, advanced RAG, production authentication/RBAC, and recovery of interrupted graph execution are not implemented yet.**

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

The planner is injectable and currently deterministic by default. Log and metric collectors are asynchronous injected dependencies; **live observability integrations are not yet implemented**. The evidence reducer deduplicates by stable evidence ID and rejects conflicting snapshots. The main graph retains state that does not belong to the Investigator Subgraph, including hypotheses.

PostgreSQL checkpointing uses a dedicated schema, an explicit schema-initialization operation, and a separate connection lifecycle. It has been verified across independently opened connections and graph instances. **Checkpoint persistence does not yet imply safe crash recovery, automatic resumption of interrupted nodes, or exactly-once external effects.** The current local database setup does not yet provide dedicated checkpoint-runtime role isolation.

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
      Live MCP operations [not implemented]
```

These are framework-independent domain and application services. **They are not yet connected into an end-to-end LangGraph remediation workflow.** Authorization decisions belong in trusted application and persistence layers, not in LLM prompts.

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
| Safe resume after process interruption, retries, and graph-level Human-in-the-Loop interrupts | Not yet implemented or verified |
| Secure MCP executor | **Contract only**; no live external calls |
| Live observability integrations, custom MCP servers, and MCP client | Planned |
| Advanced RAG, hypothesis evaluation, and incident report generation | Planned |
| Full FastAPI application, production authentication/RBAC, observability, CI/CD, and cloud deployment | Planned / not yet verified as complete |

### Security invariants already represented in code

- Human approval decisions are persisted in PostgreSQL; a caller-provided `APPROVED` flag is not sufficient.
- A fresh Guard revalidates policy, action fingerprint, and resolved resource identity.
- Claim, execution start, and dispatch reservation have separate durable records and database-enforced uniqueness.
- A committed dispatch reservation is **not** a reusable capability or proof that MCP was called.
- `EXECUTING` / `UNKNOWN` states do **not** authorize blind retries after a crash or timeout.
- Checkpoint serialization is configured without a pickle fallback; checkpoint content still requires restricted access and appropriate trust boundaries.
- The system does **not** claim exactly-once external effects. Downstream idempotency and reconciliation remain future work.
- Production authentication/RBAC and a privileged MCP execution boundary remain future work; test-only authorization doubles are not production authentication.

## Development and verification

Development uses **Python 3.12**, `uv`, `pytest`, Ruff, Mypy, LangGraph, Psycopg 3, SQLAlchemy, Alembic, and PostgreSQL. PostgreSQL-backed integration tests are opt-in and require a running, explicitly provisioned local database. Credentials belong in an uncommitted `.env` file; do not commit secrets.

```bash
# Unit tests (do not require PostgreSQL)
uv run pytest -q tests/unit/

# Full regression, including approval, schema, and checkpoint integration tests
RUN_DB_APPROVAL_TESTS=1 \
RUN_DB_SCHEMA_TESTS=1 \
RUN_DB_CHECKPOINT_TESTS=1 \
uv run --env-file .env pytest -q

# Lint, formatting and strict type checks
uv run ruff check src/ tests/ migrations/versions/
uv run ruff format --check src/ tests/ migrations/versions/
uv run mypy src/ai_incident_commander/

# Application database migration state (requires PostgreSQL)
uv run --env-file .env alembic current
```

**Latest confirmed full regression (November 18, 2026): `1519 passed`**, with all three PostgreSQL test groups enabled. Latest static checks: Ruff lint passed, 128 files formatted, and Mypy strict found no issues in 58 source files. These are **local development/test results**, not a claim of production deployment.

The LangGraph checkpoint schema is initialized **explicitly**, not automatically on application startup. Its integration tests do not run schema migrations or wipe existing checkpoint tables.

## Roadmap

**Next milestone:** durable execution semantics — controlled recovery and resumption after interruption, including tests for re-execution boundaries and failure behavior.

Further work will extend the investigation flow with real observability and deployment sources, advanced RAG, hypothesis ranking, and incident reporting. Later milestones include integrating remediation behind a secure Human-in-the-Loop boundary, implementing MCP clients and servers, verifying results, and adding production-grade authentication, evaluation, observability, CI/CD, and deployment.

The existing durable remediation security foundation was developed ahead of the end-to-end remediation workflow. Its presence **does not** mean that external actions or the complete incident-response workflow are implemented.

## Project principles

Explicit trust boundaries, typed contracts, durable state, controlled side effects, testable failure handling, transactionally enforced constraints, Human-in-the-Loop for mutating operations, and transparent reporting of what has—and has not—been implemented.
