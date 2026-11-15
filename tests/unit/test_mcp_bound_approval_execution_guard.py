"""Fail-closed tests for MCP-bound approval revalidation without MCP calls."""

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.action_fingerprint import create_action_fingerprint
from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionDeniedError,
    ApprovalExecutionGuard,
    ApprovalExecutionScopeMismatchError,
    VerifiedExecutionContext,
)
from ai_incident_commander.application.remediation_preflight import (
    validate_mcp_bound_remediation_preflight,
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
)
from ai_incident_commander.domain.mcp_action_binding import (
    McpActionBindingNotFoundError,
    TrustedMcpActionBindings,
    TrustedMcpToolBinding,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget

_NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


class RecordingResolver:
    def __init__(self) -> None:
        self.target = ResolvedTarget(
            target="payments-api",
            resource_id="service-123",
            environment="incident-lab",
            source="service-inventory",
        )
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, *, target: str, environment: str) -> ResolvedTarget:
        self.calls.append((target, environment))
        return self.target


class InMemoryApprovals:
    def __init__(
        self,
        request: RemediationApprovalRequest,
        decision: RemediationApprovalDecision | None,
    ) -> None:
        self.request = request
        self.decision = decision
        self.reads: list[str] = []

    async def create_request(self, request: RemediationApprovalRequest) -> None:
        self.request = request

    async def get_request(self, request_id: UUID) -> RemediationApprovalRequest | None:
        self.reads.append("request")
        return self.request if self.request.request_id == request_id else None

    async def get_decision(self, request_id: UUID) -> RemediationApprovalDecision | None:
        self.reads.append("decision")
        return self.decision

    async def record_decision_once(self, decision: RemediationApprovalDecision) -> None:
        self.decision = decision


@dataclass
class Scenario:
    step: RemediationStep
    catalog: ActionCatalog
    bindings: TrustedMcpActionBindings
    resolver: RecordingResolver
    approvals: InMemoryApprovals
    guard: ApprovalExecutionGuard

    def replace_guard(self, *, bindings: TrustedMcpActionBindings | None) -> None:
        self.guard = ApprovalExecutionGuard(
            repository=self.approvals,
            catalog=self.catalog,
            resolver=self.resolver,
            mcp_bindings=bindings,
        )


def _make_scenario() -> Scenario:
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )
    catalog = ActionCatalog(
        definitions=(
            ActionDefinition(
                action_name="restart_service",
                description="Restart the selected service.",
                effect=ActionEffect.MUTATING,
                risk_level=RemediationRiskLevel.HIGH,
                allowed_environments=("incident-lab",),
            ),
        )
    )
    bindings = TrustedMcpActionBindings(
        catalog=catalog,
        bindings=(
            TrustedMcpToolBinding(
                action_name="restart_service",
                server_id="deployment-mcp",
                tool_name="restart_service",
            ),
        ),
    )
    resolver = RecordingResolver()
    preflight = asyncio.run(
        validate_mcp_bound_remediation_preflight(step, catalog, resolver, bindings=bindings)
    )
    assert preflight.policy_version is not None
    assert preflight.policy_version.startswith("apv:v2:")
    request = RemediationApprovalRequest(
        plan_id=step.plan_id,
        step_id=step.step_id,
        action_fingerprint=create_action_fingerprint(step, preflight),
        policy_version=preflight.policy_version,
        requested_at=_NOW - timedelta(minutes=5),
        expires_at=_NOW + timedelta(minutes=20),
    )
    decision = RemediationApprovalDecision(
        request_id=request.request_id,
        operator_id="authorized-operator",
        outcome=RemediationApprovalOutcome.APPROVED,
        decided_at=_NOW,
        reason="Explicit operator approval for the MCP-bound action.",
    )
    approvals = InMemoryApprovals(request, decision)
    guard = ApprovalExecutionGuard(
        repository=approvals, catalog=catalog, resolver=resolver, mcp_bindings=bindings
    )
    resolver.calls.clear()
    return Scenario(step, catalog, bindings, resolver, approvals, guard)


def _verify(scenario: Scenario) -> VerifiedExecutionContext:
    return asyncio.run(
        scenario.guard.verify_mcp_execution_context_for_step(
            request_id=scenario.approvals.request.request_id,
            step=scenario.step,
        )
    )


def test_mcp_guard_accepts_matching_v2_approval_and_returns_one_target() -> None:
    scenario = _make_scenario()

    result = _verify(scenario)

    assert result.scope.request_id == scenario.approvals.request.request_id
    assert result.scope.policy_version == scenario.approvals.request.policy_version
    assert result.scope.action_fingerprint == scenario.approvals.request.action_fingerprint
    assert result.target is scenario.resolver.target
    assert scenario.approvals.reads == ["request", "decision"]
    assert scenario.resolver.calls == [("payments-api", "incident-lab")]


@pytest.mark.parametrize(
    "method",
    ["verify_execution_context_for_step", "verify_scope_for_step", "validate_for_step"],
)
def test_bound_guard_rejects_v1_even_via_existing_api(method: str) -> None:
    scenario = _make_scenario()
    scenario.approvals.request = replace(
        scenario.approvals.request, policy_version="apv:v1:" + "a" * 64
    )

    async def run() -> None:
        selected = getattr(scenario.guard, method)
        await selected(request_id=scenario.approvals.request.request_id, step=scenario.step)

    with pytest.raises(ApprovalExecutionScopeMismatchError, match="apv:v2"):
        asyncio.run(run())

    assert scenario.resolver.calls == []


def test_explicit_mcp_guard_rejects_missing_bindings_without_database_access() -> None:
    scenario = _make_scenario()
    scenario.replace_guard(bindings=None)

    with pytest.raises(ApprovalExecutionDeniedError, match="MCP-bound Guard configuration"):
        _verify(scenario)

    assert scenario.approvals.reads == []
    assert scenario.resolver.calls == []


@pytest.mark.parametrize(
    "replacement",
    [("deployment-mcp", "force_restart_service"), ("other-mcp", "restart_service")],
)
def test_mcp_guard_rejects_changed_binding_after_approval(
    replacement: tuple[str, str],
) -> None:
    scenario = _make_scenario()
    new_bindings = TrustedMcpActionBindings(
        catalog=scenario.catalog,
        bindings=(
            TrustedMcpToolBinding(
                action_name="restart_service",
                server_id=replacement[0],
                tool_name=replacement[1],
            ),
        ),
    )
    assert new_bindings.binding_version != scenario.bindings.binding_version
    scenario.replace_guard(bindings=new_bindings)

    with pytest.raises(ApprovalExecutionScopeMismatchError, match="policy version"):
        _verify(scenario)

    assert scenario.resolver.calls == [("payments-api", "incident-lab")]


def test_mcp_guard_rejects_missing_tool_binding_without_resolving_target() -> None:
    scenario = _make_scenario()
    scenario.replace_guard(bindings=TrustedMcpActionBindings(catalog=scenario.catalog, bindings=()))

    with pytest.raises(McpActionBindingNotFoundError):
        _verify(scenario)

    assert scenario.resolver.calls == []


def test_mcp_guard_rejects_changed_resolved_resource() -> None:
    scenario = _make_scenario()
    scenario.resolver.target = replace(scenario.resolver.target, resource_id="different-service")

    with pytest.raises(ApprovalExecutionScopeMismatchError, match="fingerprint"):
        _verify(scenario)

    assert scenario.resolver.calls == [("payments-api", "incident-lab")]


@pytest.mark.parametrize("outcome", [None, RemediationApprovalOutcome.REJECTED])
def test_mcp_guard_denies_unapproved_request_before_preflight(
    outcome: RemediationApprovalOutcome | None,
) -> None:
    scenario = _make_scenario()
    if outcome is None:
        scenario.approvals.decision = None
    else:
        assert scenario.approvals.decision is not None
        scenario.approvals.decision = replace(scenario.approvals.decision, outcome=outcome)

    with pytest.raises(ApprovalExecutionDeniedError):
        _verify(scenario)

    assert scenario.resolver.calls == []


def test_mcp_guard_denies_changed_step_identity_before_preflight() -> None:
    scenario = _make_scenario()
    scenario.step = replace(scenario.step, step_id=uuid4())

    with pytest.raises(ApprovalExecutionScopeMismatchError, match="step identity"):
        _verify(scenario)

    assert scenario.resolver.calls == []


def test_bound_guard_existing_api_uses_v2_and_preserves_verified_target() -> None:
    scenario = _make_scenario()
    result = asyncio.run(
        scenario.guard.verify_execution_context_for_step(
            request_id=scenario.approvals.request.request_id, step=scenario.step
        )
    )
    assert result.scope.policy_version.startswith("apv:v2:")
    assert result.target is scenario.resolver.target
    assert len(scenario.resolver.calls) == 1


def test_guard_rejects_bindings_from_another_catalog() -> None:
    scenario = _make_scenario()
    other_catalog = ActionCatalog(
        definitions=(replace(scenario.catalog.definitions[0], description="Changed action"),)
    )
    other_bindings = TrustedMcpActionBindings(
        catalog=other_catalog,
        bindings=(
            TrustedMcpToolBinding(
                action_name="restart_service",
                server_id="deployment-mcp",
                tool_name="restart_service",
            ),
        ),
    )
    with pytest.raises(ValueError, match="do not match"):
        scenario.replace_guard(bindings=other_bindings)


def test_guard_rejects_invalid_binding_configuration_type() -> None:
    scenario = _make_scenario()
    with pytest.raises(TypeError, match="trusted action bindings"):
        ApprovalExecutionGuard(
            repository=scenario.approvals,
            catalog=scenario.catalog,
            resolver=scenario.resolver,
            mcp_bindings="client-supplied-tool",  # type: ignore[arg-type]
        )
