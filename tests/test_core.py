from pathlib import Path
from nap.models import *
from nap.engine import propose
from nap.audit import AuditLog
from nap.rollout import *

def fixture():
    claim = ThreatClaim(Source("vendor", "x", "a"), [Assertion("V", "Gateway", ["4.1.0"], ["CVE-1"])])
    ev = [Evidence("advisory", "vendor", True, .96, "vendor", claim.claim_id), Evidence("kev", "cisa_kev", True, .98, "cisa", claim.claim_id)]
    asset = Asset("a", "kubernetes", "gateway", "Gateway", "4.1.0", "production", True)
    return claim, ev, asset

def test_authorized_plan():
    claim, ev, asset = fixture(); plan, score, decision = propose(claim, ev, asset, "disable_feature_flag", {"feature":"legacy_parser", "enabled":False})
    assert decision.allow and decision.mode == "canary" and score.score >= .85

def test_untrusted_primitive_fails():
    claim, ev, asset = fixture()
    try: propose(claim, ev, asset, "shell", {"command":"rm -rf /"})
    except KeyError: pass
    else: assert False

def test_rolls_back_on_bad_health():
    events=[]; rolled=[]
    result=execute_progressive_rollout(lambda p: None, lambda p,s: (p < 5, "regression"), lambda: rolled.append(True), lambda e,p: events.append(e), (Stage(1, 1), Stage(5, 1)))
    assert result == RolloutResult.ROLLED_BACK and rolled and "rollout_rolled_back" in events

def test_audit_hash_chain(tmp_path: Path):
    log=AuditLog(tmp_path/"audit.jsonl"); first=log.emit("x", {}); second=log.emit("y", {})
    assert second["previous_hash"] == first["event_hash"]

