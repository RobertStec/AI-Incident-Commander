"""Domain model for resolved remediation target identities."""

from dataclasses import dataclass
from re import fullmatch


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedTarget:
    """Identity of a resource resolved from an authoritative inventory."""

    target: str
    resource_id: str
    environment: str
    source: str

    def __post_init__(self) -> None:
        """Validate the structural invariants of a resolved target."""
        for field_name, value in (
            ("target", self.target),
            ("resource_id", self.resource_id),
            ("environment", self.environment),
            ("source", self.source),
        ):
            if type(value) is not str or not value.strip():
                raise ValueError(f"Resolved target {field_name} must be a non-empty string.")

        if fullmatch(r"[a-z][a-z0-9_-]*", self.environment) is None:
            raise ValueError(
                "Resolved target environment must use a lowercase environment identifier."
            )
