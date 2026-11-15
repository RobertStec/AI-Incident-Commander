# AI Incident Commander

**Production-oriented, agentic incident-response system — work in progress.**

AI Incident Commander is a portfolio project for investigating production incidents, collecting evidence from operational systems, assessing root-cause hypotheses, and proposing controlled remediation. Its target architecture combines **LangGraph**, **custom MCP servers and clients**, **advanced RAG**, and a **Human-in-the-Loop security boundary**.

> **Current maturity:** The durable remediation approval and dispatch-reservation foundation has been implemented and tested. The full LangGraph incident workflow, real MCP execution, RAG pipeline, production authentication/RBAC, and cloud deployment **are not implemented yet**. A dispatch reservation is **not** evidence that an external action was executed.

## Architecture evolution: `apv:v1` → `apv:v2`

**A real example of evolving security requirements, backward-compatible data migration, and regression engineering.**

This is a prominent part of the project's engineering story, rather than a feature added solely for a demo.

### The change

The first approval policy format, **`apv:v1`**, fingerprinted the trusted **Action Catalog**: the available operations, their effects, risks, environments, and parameter rules. As the design evolved toward execution through MCP, this was found to be insufficient. An approved business action could be remapped to a different MCP server or tool without changing the catalog-derived policy version.

The newer **`apv:v2`** incorporates both the trusted action catalog and the version of the **action-to-MCP-tool bindings**. In particular, changing `action_name → server_id → tool_name` changes the policy version. This changes the action fingerprint and causes fresh approval verification to reject an earlier approval bound to a different mapping.

| Concern | `apv:v1` | `apv:v2` |
|---|---|---|
| Trusted Action Catalog | Included | Included |
| MCP tool binding version | **Not included** | **Included** |
| Detects changes to action definitions | Yes | Yes |
| Detects remapping to a different MCP tool/server alias | No | Yes |
| Suitable for new MCP-mutating approval flows | **No** | Yes, **with** fresh verification and the other execution safeguards |
| Historical records | Retained for compatibility | Supported |

### Why keep both formats?

The project was started from scratch. **With today's knowledge, binding-aware policy versioning could have been designed from the beginning.** Instead, the need became clear as the integration boundary was developed. The initial choice was not the most efficient sequencing decision; the resulting migration is being preserved and documented as a concrete example of how an evolving architecture is changed safely.

The migration deliberately separates **historical data compatibility** from **permission to execute**:

- Existing `apv:v1` approval requests and execution claims remain structurally readable.
- New MCP-bound request creation and verification use `apv:v2` and trusted bindings; the MCP-bound verification path rejects legacy approvals.
- A new Alembic revision, `e62b4f0c91ad`, expands two PostgreSQL `CHECK` constraints to support both formats without rewriting old migration history.
- Unit and PostgreSQL integration tests cover the matching flow and rejection when tool name, server alias, or resolved resource identity changes.

This is **not** a claim of full end-to-end MCP safety. The actual MCP executor, downstream idempotency, resource-version preconditions, handling of uncertain external outcomes, and reconciliation still need implementation. Changes to the infrastructure configured *behind* a `server_id` alias also need independent configuration-integrity controls.

**Engineering lessons:** version security-sensitive contracts explicitly; preserve historic audit data; make active execution paths fail closed; test migrations against existing behavior; and distinguish a database reservation from an external side effect.

*A dedicated Architecture Decision Record (ADR) documenting the trade-offs and migration plan is being prepared as part of the current milestone.*

## What the project aims to do

A representative incident:

> After a deployment, HTTP 500 responses increase and API latency rises.

The intended incident workflow is to classify the incident, plan an investigation, collect logs/metrics/deployment evidence in parallel, retrieve runbooks and past postmortems with RAG, rank root-cause hypotheses, propose remediation, request human approval, execute approved operations through MCP, verify the outcome, and produce an incident report.

The project targets **Strong Mid / Mid+ AI Engineering**, with selected senior-level architectural concerns. It is **not** intended to be a single-agent chatbot.

## Target architecture

```text
                    Incident API / Human operator
                                |
                                v
                     LangGraph coordinator        [planned]
                /               |               \
         Investigation     Evidence + RAG      Remediation
          subgraphs          subgraphs           subgraph
            [planned]          [planned]          [planned]
                                                     |
                                                     v
                                        Trusted approval workflow
                                        [implemented + tested]
                                                     |
                                        Fresh MCP-bound Guard
                                                     |
                                        Durable execution claim
                                                     |
                                         Execution lifecycle
                                                     |
                                       Verified dispatch reservation
                                                     |
                                       Secure MCP executor [contract]
                                                     |
                                        MCP servers [planned]
                                                     |
                                         Verification [planned]
```

The current security components are framework-independent application and domain services. LangGraph orchestration will be built around them rather than embedding authorization logic in LLM prompts.

## Implementation status

| Area | Status |
|---|---|
| Domain models, trusted action validation, target resolution and action fingerprints | Implemented and tested |
| Persisted approval requests and human approval decisions | Implemented and tested with PostgreSQL |
| Trusted approval verification and execution claims | Implemented and tested |
| Durable execution lifecycle and limited crash recovery | Implemented and tested |
| Verified dispatch reservation and PostgreSQL concurrency protection | Implemented and tested |
| MCP action bindings and `apv:v2` approval integrity | Implemented and tested, including PostgreSQL integration |
| MCP-bound composition root | Implemented; unit-tested |
| Secure MCP executor | **Contract only**; no external calls |
| LangGraph coordinator and investigator subgraphs | Planned |
| Custom MCP servers and live MCP client | Planned |
| Advanced RAG and evidence evaluation | Planned |
| Incident Lab, full FastAPI application, authentication/RBAC, observability, CI/CD, deployment | Planned / not yet verified as complete |

### Security invariants already represented in code

- Human decisions are persisted and read from PostgreSQL; a caller-provided `APPROVED` flag is not sufficient.
- A fresh Guard revalidates policy, action fingerprint and resolved resource identity.
- Claim, execution start and dispatch reservation have separate durable records and database-enforced uniqueness.
- A committed dispatch reservation is **not** a reusable capability or proof that MCP was called.
- `EXECUTING` / `UNKNOWN` states do **not** authorize blind retries after a crash or timeout.
- The system does not claim **exactly-once external effects**. Downstream idempotency and reconciliation remain future work.
- Production authentication/RBAC and a privileged MCP execution boundary remain future work; test-only authorization doubles do not constitute production authentication.

## Development and verification

Development uses Python, `uv`, `pytest`, Ruff, Mypy, SQLAlchemy, Alembic, and PostgreSQL. PostgreSQL-backed integration tests are opt-in and require the local database to be running, with credentials configured through an uncommitted `.env` file. Do not commit `.env` or secrets.

```bash
# Unit tests (no database required for these tests)
uv run pytest -q tests/unit/

# Full regression including PostgreSQL integration tests
RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 \
  uv run --env-file .env pytest -q

# Static checks
uv run ruff check src/ tests/ migrations/versions/
uv run ruff format --check src/ tests/ migrations/versions/
uv run mypy src/ai_incident_commander/

# Database migration state (requires a running PostgreSQL instance)
uv run --env-file .env alembic current
```

**Last reported full regression:** `1400 passed` with PostgreSQL integration enabled, before the latest Secure MCP Executor contract and MCP-bound composition-root additions. **Latest reported focused checks:** 17 executor-contract tests passed, 25 composition-root tests passed; Ruff and Mypy passed on 114 formatted files and 52 source files respectively. A new full regression is still required before finalizing this milestone.

## Roadmap

The original roadmap is in [`PROJECT_BRIEF.md`](PROJECT_BRIEF.md). Work on durable remediation security was intentionally developed ahead of the planned remediation phase; it **does not** mean the end-to-end remediation feature is complete.

**Next milestone:** finish architecture documentation and regression checks, then start **Phase 2 — LangGraph Core** (typed incident state, coordinator graph, branching, subgraphs, parallel investigation and durable checkpointing).

Subsequent work includes MCP clients and servers, advanced RAG, incident intelligence, real remediation and verification, multi-user security, evaluation, CI/CD and deployment.

## Project documentation

- [`PROJECT_BRIEF.md`](PROJECT_BRIEF.md) — goals, architecture requirements, and roadmap.
- [`PROJECT_PROGRESS.md`](PROJECT_PROGRESS.md) — technical milestone journal; to be refreshed at the current checkpoint.
- [`SESSION_HANDOFF.md`](SESSION_HANDOFF.md) — session resume notes; to be refreshed at the current checkpoint.
- **ADR for `apv:v1` → `apv:v2`** — forthcoming, documenting the motivation, alternatives, decision, security boundaries, and rollout.

## Project principles

Explicit trust boundaries, typed contracts, durable state, testable failure handling, transactionally enforced constraints, Human-in-the-Loop for mutating actions, and transparent reporting of what has—and has not—been implemented.
