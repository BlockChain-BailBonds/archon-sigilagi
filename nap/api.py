"""Runnable stdlib HTTP API for local deployment and integration testing."""
from __future__ import annotations
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from .models import Asset, now
from .sbom import assets_from_sbom
from .storage import Store

class Handler(BaseHTTPRequestHandler):
    store: Store | None = None
    server_version = "Archon-SigilAGI/0.1"
    def _send(self, status, payload):
        body = json.dumps(payload).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Access-Control-Allow-Origin", os.getenv("NAP_DASHBOARD_ORIGIN", "*")); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz": return self._send(200, {"status":"ok"})
        if path == "/api/v1/assets": return self._send(200, {"assets": self.store.list_assets()})
        if path == "/api/v1/claims": return self._send(200, {"claims": self.store.list_claims()})
        if path == "/api/v1/detections": return self._send(200, {"detections": self.store.list_detections()})
        if path == "/api/v1/global/alerts": return self._send(200, {"alerts": self.store.list_global_alerts()})
        return self._send(404, {"error":"not_found"})
    def do_POST(self):
        if urlparse(self.path).path != "/api/v1/sboms": return self._send(404, {"error":"not_found"})
        required_token = os.getenv("NAP_INGEST_TOKEN")
        if required_token and self.headers.get("Authorization") != f"Bearer {required_token}": return self._send(401, {"error":"authentication_required"})
        try:
            length = int(self.headers.get("content-length", "0"));
            if length <= 0 or length > 10_000_000: raise ValueError("invalid content length")
            payload = json.loads(self.rfile.read(length)); query = urlparse(self.path).query
            environment = self.headers.get("X-NAP-Environment", "staging"); service = self.headers.get("X-NAP-Service", "unknown")
            assets = assets_from_sbom(payload, environment=environment, service=service)
            for asset in assets: self.store.put_asset(asset.asset_id, asset.__dict__, now())
            return self._send(201, {"stored": len(assets), "assets": [a.__dict__ for a in assets]})
        except (ValueError, json.JSONDecodeError) as exc: return self._send(400, {"error": str(exc)})
    def log_message(self, format, *args): pass

def serve(host=None, port=None, db_path=None):
    host = host or os.getenv("NAP_HOST", "0.0.0.0")
    port = port or int(os.getenv("PORT", os.getenv("NAP_PORT", "7860")))
    db_path = db_path or os.getenv("NAP_DB_PATH", "nap.db")
    Handler.store = Store(db_path); server = ThreadingHTTPServer((host, port), Handler); print(f"Archon SigilAGI listening on http://{host}:{port}", flush=True); server.serve_forever()
