"""Read-only demo against the live canonical Archon SigilAGI Git snapshot."""
from __future__ import annotations
import base64, json, time, hashlib
from .secure_ingest import fetch

CANONICAL_URL="https://raw.githubusercontent.com/BlockChain-BailBonds/archon-sigilagi/main/web/data/alerts.json"
GITHUB_CONTENTS_URL="https://api.github.com/repos/BlockChain-BailBonds/archon-sigilagi/contents/web/data/alerts.json"

def load_snapshot(url: str = CANONICAL_URL) -> dict:
    if url == CANONICAL_URL:
        request_url=GITHUB_CONTENTS_URL + "?ref=main&archon_cachebust=" + str(time.time_ns())
        envelope=json.loads(fetch(request_url, max_bytes=1_000_000, allowed_types=("application/json",)).body)
        if envelope.get("content"):
            body=base64.b64decode(envelope["content"])
        else:
            blob_url=f"https://api.github.com/repos/BlockChain-BailBonds/archon-sigilagi/git/blobs/{envelope['sha']}?archon_cachebust={time.time_ns()}"
            blob=json.loads(fetch(blob_url, max_bytes=30_000_000, allowed_types=("application/json",)).body)
            body=base64.b64decode(blob["content"])
        payload=json.loads(body); retrieved_sha256=hashlib.sha256(body).hexdigest(); retrieved_url=GITHUB_CONTENTS_URL
    else:
        request_url=url + ("&" if "?" in url else "?") + "archon_cachebust=" + str(time.time_ns())
        artifact=fetch(request_url, max_bytes=25_000_000, allowed_types=("application/json", "text/plain")); body=artifact.body
        payload=json.loads(body); retrieved_sha256=artifact.sha256; retrieved_url=artifact.url
    if payload.get("schema_version") != "archon.sigilagi.alerts.v1" or not isinstance(payload.get("alerts"), list):
        raise ValueError("canonical snapshot schema validation failed")
    payload["retrieved_sha256"]=retrieved_sha256; payload["retrieved_url"]=retrieved_url
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
