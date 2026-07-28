import json, threading
from http.client import HTTPConnection
from nap.api import Handler
from nap.storage import Store
from nap.sbom import assets_from_sbom
from http.server import ThreadingHTTPServer

def test_cyclonedx_and_spdx_parsing():
    assert assets_from_sbom({"bomFormat":"CycloneDX","components":[{"name":"openssl","version":"3.0.0"}]}, environment="prod", service="edge")[0].component == "openssl"
    assert assets_from_sbom({"spdxVersion":"SPDX-2.3","packages":[{"name":"openssl","versionInfo":"3.0.0"}]}, environment="prod", service="edge")[0].version == "3.0.0"

def test_real_http_inventory_endpoint(tmp_path):
    Handler.store = Store(tmp_path / "nap.db")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", server.server_port)
        body = json.dumps({"bomFormat":"CycloneDX","components":[{"name":"gateway","version":"4.1.6"}]}).encode()
        conn.request("POST", "/api/v1/sboms", body, {"Content-Type":"application/json","Content-Length":str(len(body)),"X-NAP-Service":"gateway"})
        response = conn.getresponse(); assert response.status == 201; assert json.loads(response.read())["stored"] == 1
        conn.request("GET", "/api/v1/assets"); response = conn.getresponse(); assert response.status == 200; assert len(json.loads(response.read())["assets"]) == 1
    finally: server.shutdown(); thread.join()

def test_ingest_rejects_non_https():
    from nap.secure_ingest import fetch, IngestError
    try: fetch("http://127.0.0.1:8080/feed")
    except IngestError: pass
    else: assert False

def test_local_agent_writes_atomic_canonical_snapshot(tmp_path, monkeypatch):
    from nap.agent import AgentConfig, collect_once
    from nap.models import now
    def fake_scan(store, cisa_url=None):
        store.put_global_alert({"claim_id":"clm-test","cve_ids":["CVE-TEST"],"vendor":"Example","product":"Gateway","observed_at":now()})
        return {"alerts":1,"feed":"fixture"}
    monkeypatch.setattr("nap.agent.scan_public_threats", fake_scan)
    config=AgentConfig(db_path=str(tmp_path/"agent.db"), snapshot_path=str(tmp_path/"web/data/alerts.json"), github_token=None)
    result=collect_once(config)
    assert result["remote_synced"] is False
    payload=json.loads((tmp_path/"web/data/alerts.json").read_text())
    assert payload["schema_version"] == "archon.sigilagi.alerts.v1"
    assert payload["alerts"][0]["cve_ids"] == ["CVE-TEST"]
