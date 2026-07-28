"""Typed, JSON-serializable contracts for the containment control plane."""
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any
import hashlib, json, uuid

def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def ident(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"

@dataclass(frozen=True)
class Source:
    type: str
    canonical_reference: str
    content_sha256: str
    retrieval_method: str = "isolated_fetcher"

@dataclass(frozen=True)
class Assertion:
    vendor: str
    product: str
    affected_versions: list[str]
    cve_ids: list[str]
    attack_vector: str = "unknown"
    required_access: str = "unknown"
    claimed_impact: list[str] = field(default_factory=list)

@dataclass(frozen=True)
class ThreatClaim:
    source: Source
    assertions: list[Assertion]
    indicators: dict[str, list[str]] = field(default_factory=dict)
    confidence: float = 0.0
    untrusted_instructions_detected: bool = False
    executed_content: bool = False
    schema_version: str = "nap.claim.v1"
    claim_id: str = field(default_factory=lambda: ident("clm"))
    observed_at: str = field(default_factory=now)

@dataclass(frozen=True)
class Evidence:
    evidence_type: str
    authority: str
    supports_claim: bool
    confidence: float
    independence_group: str
    claim_id: str
    artifact_sha256: str = ""
    schema_version: str = "nap.evidence.v1"
    evidence_id: str = field(default_factory=lambda: ident("evd"))
    observed_at: str = field(default_factory=now)

@dataclass(frozen=True)
class Asset:
    asset_id: str
    kind: str
    service: str
    component: str
    version: str
    environment: str
    reachable: bool
    owner: str = "unknown"
    criticality: str = "medium"
    rollback_target: str | None = None

@dataclass(frozen=True)
class MitigationPlan:
    claim_id: str
    primitive_type: str
    primitive_name: str
    target_selector: dict[str, str]
    parameters: dict[str, Any]
    initial_percent: int = 1
    maximum_percent: int = 100
    maximum_targets: int = 5000
    expires_at: str = ""
    automatic_rollback: bool = True
    rollback_seconds: int = 120
    plan_id: str = field(default_factory=lambda: ident("mit"))
    schema_version: str = "nap.mitigation.v1"

    def digest(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

