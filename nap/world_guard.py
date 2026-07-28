"""Global public-threat sentinel.

It watches the public internet's authoritative security feeds and publishes
alerts for every operator to consume. It never scans or changes systems that
have not explicitly enrolled; that is the boundary between defense and
unauthorized access.
"""
from __future__ import annotations
import json, time, traceback
from .models import now
from .storage import Store
from .threat_feeds import cisa_kev

def scan_public_threats(store: Store, *, cisa_url: str | None = None) -> dict:
    claims, evidence, artifact = cisa_kev(cisa_url) if cisa_url else cisa_kev()
    store.put_artifact(artifact.sha256, artifact.url, artifact.content_type, len(artifact.body), now(), artifact.body)
    alerts=[]
    for claim, ev in zip(claims, evidence):
        alert={
            "scope":"global_public_intelligence",
            "claim_id":claim.claim_id,
            "cve_ids":claim.assertions[0].cve_ids,
            "vendor":claim.assertions[0].vendor,
            "product":claim.assertions[0].product,
            "active_exploitation":True,
            "source":claim.source.__dict__,
            "evidence":ev.__dict__,
            "recommended_rescue":"enrolled_asset_correlation_then_reversible_containment",
            "observed_at":now(),
        }
        store.put_global_alert(alert); alerts.append(alert)
    return {"scope":"global_public_intelligence","feed":artifact.url,"feed_sha256":artifact.sha256,"alerts":len(alerts),"observed_at":now()}

def watch_public(store: Store, *, interval_seconds: int = 900, cisa_url: str | None = None) -> None:
    while True:
        try: print(json.dumps(scan_public_threats(store, cisa_url=cisa_url)), flush=True)
        except Exception as exc: print(json.dumps({"scope":"global_public_intelligence","error":type(exc).__name__,"message":str(exc),"trace":traceback.format_exc()}), flush=True)
        time.sleep(interval_seconds)

