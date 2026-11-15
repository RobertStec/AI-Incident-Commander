# ADR-0001: Version remediation approval policies with trusted MCP tool bindings

- **Status:** Accepted
- **Date:** 2026-11-15
- **Decision owners:** AI Incident Commander project
- **Scope:** Remediation approval integrity and trusted MCP action routing

## Context and problem

AI Incident Commander requires a human decision before a mutating remediation action can proceed. The approved scope is identified using an Action Fingerprint (`afp:v2`) and an Action Policy Version (`apv`). A fresh `ApprovalExecutionGuard` compares the persisted approval against current trusted validation and target resolution.

The original `apv:v1` design hashes the trusted `ActionCatalog`, including action definitions, effects, risk levels, allowed environments, and parameter constraints. It does **not** include the operational mapping from an action to a particular MCP server alias and tool.

This creates a policy-integrity gap when MCP execution is introduced:

1. An operator approves `restart_service` for a particular resolved resource.
2. Trusted configuration maps `restart_service` to `deployment-mcp / restart_service`.
3. After approval, the mapping changes to `deployment-mcp / force_restart_service` (or another server alias).
4. The catalog-only `apv:v1` stays the same, so a fresh fingerprint check based only on the action catalog does not detect the routing change.

The project was developed from scratch, and the MCP requirement was known from the beginning. **With hindsight, binding-aware policy versioning could have been included in the initial design.** The initial implementation order was not optimal. We preserve the genuine evolution of the codebase as a documented example of handling a security-sensitive contract change without hiding or rewriting history. We do not claim the migration was a preplanned exercise.

## Decision

Introduce **`apv:v2`** as a separate, domain-separated hash of:

- the current trusted Action Catalog policy version (`apv:v1`), and
- the deterministic version of `TrustedMcpActionBindings`, reflecting the allowlisted `action_name → server_id → tool_name` mapping.

An `apv:v2` policy is calculated by `create_mcp_bound_action_policy_version()` from a matching `ActionCatalog` and a **trusted** `TrustedMcpActionBindings` registry. Neither bindings nor the destination MCP tool may be accepted as authorization from a user, LLM output, or untrusted request.

The existing `afp:v2` algorithm and envelope remain unchanged: the `policy_version` is already an input to the action fingerprint, alongside the validated step, resolved resource identity, and parameters. A different `apv:v2` therefore produces a different fingerprint.

The MCP-specific approval path is explicit:

```text
Trusted ActionCatalog + TrustedMcpActionBindings
                  |
                  v
       MCP-bound Preflight (apv:v2)
                  |
                  v
      Action Fingerprint (afp:v2)
                  |
                  v
      Persisted Approval Request
                  |
                  v
        Human Approval Decision
                  |
                  v
       Fresh MCP-bound Guard
                  |
                  v
     Execution Claim -> Execution
                  |
                  v
       Verified Dispatch Reservation
                  |
                  v
    Future restricted MCP executor
              [NOT IMPLEMENTED]
```

`mcp_approval_workflow_lifespan()` must be used to construct the intended MCP-bound approval services. It requires a nonempty, catalog-consistent binding registry and injects the **same** registry into request creation and Guard. The explicit MCP-specific operations have no implicit fallback to `apv:v1`.

The historical catalog-only workflow is retained separately for compatibility. **An `apv:v1` record can remain valid historical data, but it cannot authorize a new mutating MCP execution path.** That restriction must also be enforced at the future executor boundary, not merely assumed from the presence of a Python type or a properly constructed composition root.

## Data compatibility and rollout

We use an additive, backward-compatible migration rather than deleting or silently reinterpreting existing approval records:

1. Keep `apv:v1` generation for explicitly legacy, non-MCP contexts; add a separate `apv:v2` generator.
2. Allow domain models `RemediationApprovalRequest` and `ExecutionClaim` and the fingerprint validator to structurally recognize `apv:v1` and `apv:v2`.
3. Apply Alembic revision **`e62b4f0c91ad`**, extending the PostgreSQL `CHECK` constraints `ck_approval_request_policy_version` and `ck_execution_claims_policy_version` to both formats. Do not alter historical migrations or rewrite stored approvals.
4. Add MCP-bound Preflight, Approval Request creation and fresh Guard verification; reject missing/inconsistent mappings and changed approval scope.
5. Use the MCP-specific Composition Root to keep creation and verification on the same trusted binding configuration.
6. Retain historical `apv:v1` data for audit and reconstruction. Consider retiring the legacy creation path only after its callers and stored-data needs have been reviewed.

Downgrading the schema to v1-only constraints must not be attempted while `apv:v2` rows exist; the migration includes a refusal for that condition. A downgrade has **not** been demonstrated as part of the reported local verification.

The new policy versions are *content identifiers*, not permissions, signed authorizations, or secrets. The database still independently enforces durable execution/dispatch invariants, and the Guard still needs to revalidate the action and resolved resource.

## Alternatives considered

| Alternative | Assessment |
|---|---|
| Keep `apv:v1` and check only the action catalog | Rejected: changes to MCP routing could be invisible to approved scope verification |
| Change the hash behind the existing `apv:v1` prefix | Rejected: silently changes the meaning of existing persisted version identifiers |
| Replace `apv:v1` everywhere immediately | Rejected for this migration: risks breaking existing records, tests and historical audit access |
| Include MCP bindings directly in a new fingerprint algorithm | Possible, but duplicates versioning concerns: the fingerprint already contains the policy version |
| **Introduce `apv:v2` and preserve `apv:v1` for compatibility** | **Chosen:** explicit contract evolution and fail-closed MCP-specific verification |

## Consequences and trade-offs

**Benefits**

- Previously approved actions become invalid for the MCP-bound path when `tool_name`, `server_id`, or catalog content changes.
- Historic approvals and claims remain readable without data rewriting.
- Policy evolution is separately auditable and testable across application, domain and PostgreSQL layers.
- Request creation and Guard can use a single trusted binding registry through an explicit composition root.

**Costs**

- Two version formats, two intentional approval paths, an Alembic migration and additional regression tests must be maintained.
- Callers and future application assembly must distinguish legacy/non-MCP usage from the privileged mutating MCP path.
- Architectural compatibility is not authorization: code can still manually construct services outside the intended composition root, so deployment wiring and executor permissions require independent enforcement.

## Security boundaries and remaining work

This decision **does not complete the secure execution boundary**:

- `server_id` is a configured alias, not a pinned endpoint or authenticated server identity. Changing endpoint, credentials or tool semantics *behind the same alias* may not change `binding_version`. Trusted endpoint identity and configuration-version control are still required.
- `ResolvedTarget.resource_id` is bound in `afp:v2`, but the target's live version/ETag is not. The future tool may need resource-version preconditions.
- `VerifiedExecutionScope`, `VerifiedExecutionContext`, and a committed `RemediationDispatch` are **not bearer tokens** or reusable rights to invoke MCP.
- The future executor must have least-privilege credentials, prohibit untrusted tool selection, and handle restart/replay, timeout and ambiguous outcomes (`UNKNOWN`) without blind retries.
- PostgreSQL uniqueness and transactions do **not** provide exactly-once effects in an external system. Downstream idempotency and reconciliation remain future work.
- Production authentication/RBAC, actual MCP client/server, LangGraph orchestration and outcome verification have not yet been completed.

## Verification evidence and limits

Reported local results from the project iteration:

- Alembic `upgrade head` to `e62b4f0c91ad` succeeded; PostgreSQL schema tests: **6 passed**.
- MCP-bound Approval Flow PostgreSQL integration: **37 passed**, including rejection on tool/server alias changes, legacy policy in the MCP path, resource drift, and a full flow through durable dispatch reservation.
- Full suite after approval-integrity integration and regression test updates: **1400 passed**, **0 failed**, with opt-in PostgreSQL tests enabled.
- Subsequent focused tests: MCP-bound Composition Root **25 passed**; Secure MCP Executor contract **17 passed**. Ruff and Mypy passed after those changes; **the final full-suite regression and Git checkpoint are still pending**.

These results validate the described contracts and tested paths. They are not evidence of live MCP execution, production authentication, or external exactly-once delivery.

## Follow-up decisions

Before enabling mutating MCP execution, explicitly address:

1. Trusted MCP server identity, endpoint/configuration versioning and tool allowlisting.
2. Privileged executor wiring that cannot enter through catalog-only `apv:v1` services.
3. Downstream idempotency, resource preconditions and reconciliation for `UNKNOWN` outcomes.
4. LangGraph durable orchestration and safe resume behavior.
5. Production operator authentication, role-based authorization and audit/observability.

## Related implementation

- [`action_policy_version.py`](../../src/ai_incident_commander/application/action_policy_version.py) — policy version functions.
- [`mcp_action_binding.py`](../../src/ai_incident_commander/domain/mcp_action_binding.py) — trusted bindings and `binding_version`.
- [`remediation_preflight.py`](../../src/ai_incident_commander/application/remediation_preflight.py) — legacy and MCP-bound validation paths.
- [`approval_request_service.py`](../../src/ai_incident_commander/application/approval_request_service.py) — approval request creation.
- [`approval_execution_guard.py`](../../src/ai_incident_commander/application/approval_execution_guard.py) — fresh approval verification.
- [`bootstrap.py`](../../src/ai_incident_commander/bootstrap.py) — explicit composition roots.
- [`e62b4f0c91ad_allow_mcp_bound_policy_v2.py`](../../migrations/versions/e62b4f0c91ad_allow_mcp_bound_policy_v2.py) — compatibility migration.
- [`README.md`](../../README.md) — visible portfolio summary of this architectural evolution.
