"""Read-only demo against the live canonical Archon SigilAGI Git snapshot."""
from __future__ import annotations
import json
from .secure_ingest import fetch

CANONICAL_URL="https://raw.githubusercontent.com/BlockChain-BailBonds/archon-sigilagi/main/web/data/alerts.json"

def load_snapshot(url: str = CANONICAL_URL) -> dict:
    artifact=fetch(url, max_bytes=25_000_000, allowed_types=("application/json", "text/plain"))
    payload=json.loads(artifact.body)
    if payload.get("schema_version") != "archon.sigilagi.alerts.v1" or not isinstance(payload.get("alerts"), list):
        raise ValueError("canonical snapshot schema validation failed")
    payload["retrieved_sha256"]=artifact.sha256; payload["retrieved_url"]=artifact.url
    return payload

def rescue_report(snapshot: dict, enrolled_assets: list[dict]) -> dict:
    reports=[]
    for alert in snapshot["alerts"]:
        product=alert.get("product", "").lower()
        for asset in enrolled_assets:
            component=asset.get("component", "").lower()
            if product and component and (product in component or component in product):
                reports.append({"asset_id":asset["asset_id"],"service":asset.get("service"),"cve_ids":alert.get("cve_ids",[]),"primitive":"quarantine_workload","rollout":"1% canary","rollback":"automatic","decision":"escalate_until_exact_version_and_telemetry_are_verified"})
    return {"snapshot_updated_at":snapshot.get("updated_at"),"threat_reports":len(snapshot["alerts"]),"rescue_reports":reports,"snapshot_sha256":snapshot["retrieved_sha256"]}
