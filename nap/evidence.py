"""Deterministic evidence scoring; model confidence is never authorization."""
from dataclasses import dataclass
from .models import Evidence

@dataclass(frozen=True)
class EvidenceScore:
    score: float
    independent_source_count: int
    maximum_confidence: float
    band: str

def score_evidence(evidence: list[Evidence], *, applicable: bool, reachable: bool, telemetry_match: bool) -> EvidenceScore:
    supported = [e for e in evidence if e.supports_claim]
    groups = {e.independence_group for e in supported}
    vendor = max((e.confidence for e in supported if e.authority == "vendor"), default=0.0)
    kev = max((e.confidence for e in supported if e.authority == "cisa_kev"), default=0.0)
    telemetry = 1.0 if telemetry_match else 0.0
    applicability = 1.0 if applicable else 0.0
    reachability = 1.0 if reachable else 0.0
    reliability = max((e.confidence for e in supported), default=0.0)
    total = 0.30 * vendor + 0.20 * kev + 0.20 * telemetry + 0.15 * applicability + 0.10 * reachability + 0.05 * reliability
    band = "observe" if total < .45 else "notify" if total < .70 else "test" if total < .85 else "canary" if total < .95 else "rollout"
    return EvidenceScore(round(total, 4), len(groups), max((e.confidence for e in supported), default=0.0), band)

