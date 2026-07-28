"""Continuous threat-to-rescue loop.

This is deliberately a guardian loop: it records every scan, never silently
drops an error, and only hands eligible plans to the deterministic policy gate.
"""
from __future__ import annotations
import json, time, traceback
from dataclasses import asdict
from .engine import propose
from .kubernetes import inventory
from .models import Asset, Evidence, now
from .storage import Store
from .threat_feeds import cisa_kev

def scan_once(store: Store, *, kubectl: str = "kubectl", cisa_url: str | None = None) -> dict:
    started=now(); claims, feed_evidence, artifact=cisa_kev(cisa_url) if cisa_url else cisa_kev()
    store.put_artifact(artifact.sha256, artifact.url, artifact.content_type, len(artifact.body), now(), artifact.body)
    assets=inventory(kubectl=kubectl)
    for asset in assets: store.put_asset(asset.asset_id, asset.__dict__, now())
    matches=[]
    for claim in claims:
        for claim_assertion in claim.assertions:
            for asset in assets:
                name=claim_assertion.product.lower(); component=asset.component.lower()
                if name != "unknown" and (name in component or component in name):
                    ev=[e for e in feed_evidence if e.claim_id == claim.claim_id]
                    # CISA alone identifies active exploitation but does not
                    # establish the exact deployed version. Escalate safely.
                    plan, score, decision=propose(claim, ev, asset, "quarantine_workload", {"workload":asset.service}, telemetry_match=False)
                    record={"claim_id":claim.claim_id,"asset_id":asset.asset_id,"plan":asdict(plan),"score":asdict(score),"decision":asdict(decision),"observed_at":now()}
                    store.put_detection(record)
                    matches.append(record)
    return {"started_at":started,"completed_at":now(),"claims":len(claims),"assets":len(assets),"matches":len(matches),"detections":matches}

def watch(store: Store, *, interval_seconds: int = 900, kubectl: str = "kubectl", cisa_url: str | None = None) -> None:
    while True:
        try: print(json.dumps(scan_once(store, kubectl=kubectl, cisa_url=cisa_url), default=str))
        except Exception as exc: print(json.dumps({"error":type(exc).__name__,"message":str(exc),"trace":traceback.format_exc()}), flush=True)
        time.sleep(interval_seconds)

