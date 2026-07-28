"""Fail-closed deterministic authorization gate."""
from dataclasses import dataclass
from .evidence import EvidenceScore
from .models import MitigationPlan

AUTONOMOUS = frozenset({"block_ioc_temporarily", "rate_limit_route", "disable_feature_flag", "quarantine_workload", "rollback_container_image"})
IRREVERSIBLE = frozenset({"modify_bootloader", "replace_trust_root", "flash_firmware", "destroy_encryption_key", "delete_persistent_data", "patch_kernel"})

@dataclass(frozen=True)
class Decision:
    allow: bool
    mode: str
    reasons: tuple[str, ...]

def authorize(plan: MitigationPlan, evidence: EvidenceScore, *, component_present: bool, version_affected: bool, path_reachable: bool, telemetry_coverage: float, baseline_available: bool, environment: str = "production") -> Decision:
    if plan.primitive_name in IRREVERSIBLE or plan.primitive_name not in AUTONOMOUS:
        return Decision(False, "escalate", ("primitive is outside autonomous containment scope",))
    reasons = []
    checks = [(evidence.independent_source_count >= 2, "requires two independent sources"), (evidence.maximum_confidence >= .90, "maximum evidence confidence below 0.90"), (component_present, "component not present"), (version_affected, "deployed version not affected"), (path_reachable, "attack path is not reachable"), (plan.automatic_rollback and plan.rollback_seconds <= 300, "rollback gate failed"), (plan.initial_percent <= 1 and plan.maximum_targets <= 5000, "scope gate failed"), (telemetry_coverage >= .95 and baseline_available, "telemetry gate failed"), (environment in {"development", "staging", "production"}, "unknown environment")]
    for ok, reason in checks:
        if not ok: reasons.append(reason)
    if reasons: return Decision(False, "escalate", tuple(reasons))
    return Decision(True, "canary", ("evidence, applicability, scope, telemetry, and rollback gates passed",))

