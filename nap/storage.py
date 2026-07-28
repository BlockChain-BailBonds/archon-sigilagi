"""Durable local control-plane storage.

SQLite is used for the single-node deployment and can be replaced by PostgreSQL
behind this small repository interface without changing control logic.
"""
from __future__ import annotations
import json, sqlite3, threading
from pathlib import Path
from typing import Any

class Store:
    def __init__(self, path: str | Path = "nap.db"):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, timeout=30.0, check_same_thread=False)
        self._write_lock = threading.RLock()
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS artifacts (
          sha256 TEXT PRIMARY KEY, source_url TEXT NOT NULL, content_type TEXT NOT NULL,
          size_bytes INTEGER NOT NULL, retrieved_at TEXT NOT NULL, body BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS claims (
          claim_id TEXT PRIMARY KEY, artifact_sha256 TEXT NOT NULL, claim_json TEXT NOT NULL,
          created_at TEXT NOT NULL, FOREIGN KEY(artifact_sha256) REFERENCES artifacts(sha256)
        );
        CREATE TABLE IF NOT EXISTS assets (
          asset_id TEXT PRIMARY KEY, asset_json TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
          event_id TEXT PRIMARY KEY, event_hash TEXT NOT NULL, event_json TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS detections (
          detection_id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL,
          claim_id TEXT NOT NULL, detection_json TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS global_alerts (
          alert_id INTEGER PRIMARY KEY AUTOINCREMENT, cve_key TEXT NOT NULL,
          alert_json TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """)
        self.db.commit()

    def put_artifact(self, sha256: str, source_url: str, content_type: str, size: int, retrieved_at: str, body: bytes) -> None:
        with self._write_lock:
            self.db.execute("INSERT OR IGNORE INTO artifacts VALUES (?, ?, ?, ?, ?, ?)", (sha256, source_url, content_type, size, retrieved_at, body)); self.db.commit()

    def put_claim(self, claim_id: str, artifact_sha256: str, claim_json: dict[str, Any], created_at: str) -> None:
        with self._write_lock:
            self.db.execute("INSERT OR REPLACE INTO claims VALUES (?, ?, ?, ?)", (claim_id, artifact_sha256, json.dumps(claim_json, sort_keys=True), created_at)); self.db.commit()

    def put_asset(self, asset_id: str, asset_json: dict[str, Any], updated_at: str) -> None:
        with self._write_lock:
            self.db.execute("INSERT OR REPLACE INTO assets VALUES (?, ?, ?)", (asset_id, json.dumps(asset_json, sort_keys=True), updated_at)); self.db.commit()

    def list_assets(self):
        return [json.loads(row["asset_json"]) for row in self.db.execute("SELECT asset_json FROM assets ORDER BY asset_id")]

    def list_claims(self):
        return [json.loads(row["claim_json"]) for row in self.db.execute("SELECT claim_json FROM claims ORDER BY created_at")]

    def put_detection(self, detection: dict[str, Any]) -> None:
        with self._write_lock:
            self.db.execute("INSERT INTO detections(asset_id, claim_id, detection_json, created_at) VALUES (?, ?, ?, ?)", (detection["asset_id"], detection["claim_id"], json.dumps(detection, sort_keys=True), detection["observed_at"])); self.db.commit()

    def list_detections(self):
        return [json.loads(row["detection_json"]) for row in self.db.execute("SELECT detection_json FROM detections ORDER BY detection_id DESC")]

    def put_global_alert(self, alert: dict[str, Any]) -> None:
        cve_key=",".join(sorted(alert.get("cve_ids", []))) or alert["claim_id"]
        with self._write_lock:
            self.db.execute("DELETE FROM global_alerts WHERE cve_key = ?", (cve_key,))
            self.db.execute("INSERT INTO global_alerts(cve_key, alert_json, created_at) VALUES (?, ?, ?)", (cve_key, json.dumps(alert, sort_keys=True), alert["observed_at"])); self.db.commit()

    def list_global_alerts(self, limit: int = 1000):
        return [json.loads(row["alert_json"]) for row in self.db.execute("SELECT alert_json FROM global_alerts ORDER BY alert_id DESC LIMIT ?", (limit,))]
