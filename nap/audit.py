import json, time, hashlib
from pathlib import Path

class AuditLog:
    """Append-only hash-chained JSONL audit log."""
    def __init__(self, path: str | Path): self.path = Path(path); self.previous = self._last_hash()
    def _last_hash(self):
        if not self.path.exists(): return "0" * 64
        lines = self.path.read_text().splitlines()
        return json.loads(lines[-1])["event_hash"] if lines else "0" * 64
    def emit(self, event_type: str, payload: dict) -> dict:
        event = {"event_id": hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest()[:20], "event_type": event_type, "observed_at": time.time(), "previous_hash": self.previous, "payload": payload}
        event["event_hash"] = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True); with_open = self.path.open("a"); with_open.write(json.dumps(event, sort_keys=True) + "\n"); with_open.close(); self.previous = event["event_hash"]; return event

