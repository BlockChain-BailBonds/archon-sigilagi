from .evidence import score_evidence
from .models import Asset, Evidence, MitigationPlan
from .policy import authorize
from .registry import PRIMITIVES
from .contracts import validate_mitigation

def correlate(claim, assets: list[Asset], *, telemetry_match=False):
    matches = []
    for assertion in claim.assertions:
        for asset in assets:
            if asset.component.lower() == assertion.product.lower() and asset.reachable:
                matches.append(asset)
    return matches

def propose(claim, evidence: list[Evidence], asset: Asset, primitive_name: str, parameters: dict, telemetry_match=True):
    primitive = PRIMITIVES[primitive_name]; primitive.validate(parameters)
    plan = MitigationPlan(claim.claim_id, primitive.kind, primitive_name, {"service": asset.service, "environment": asset.environment, "version": asset.version}, parameters)
    validate_mitigation({"schema_version": plan.schema_version, "plan_id": plan.plan_id, "claim_id": plan.claim_id, "primitive": {"type": plan.primitive_type, "name": plan.primitive_name, "parameters": plan.parameters}, "scope": {"initial_percent": plan.initial_percent, "maximum_percent": plan.maximum_percent, "maximum_targets": plan.maximum_targets}, "rollback": {"automatic": plan.automatic_rollback, "maximum_rollback_seconds": plan.rollback_seconds}})
    scored = score_evidence(evidence, applicable=True, reachable=asset.reachable, telemetry_match=telemetry_match)
    decision = authorize(plan, scored, component_present=True, version_affected=True, path_reachable=asset.reachable, telemetry_coverage=.99, baseline_available=True, environment=asset.environment)
    return plan, scored, decision
