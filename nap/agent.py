"""Archon SigilAGI local collector and canonical-feed synchronizer."""
from __future__ import annotations
import base64, hashlib, json, os, tempfile, time, traceback
from dataclasses import dataclass
from pathlib import Path
import requests
from .models import now
from .storage import Store
from .world_guard import scan_public_threats

@dataclass(frozen=True)
class AgentConfig:
    db_path: str = "nap.db"
    snapshot_path: str = "web/data/alerts.json"
    interval_seconds: int = 60
    cisa_url: str | None = None
    github_owner: str | None = None
    github_repo: str | None = None
    github_branch: str = "main"
    github_path: str = "web/data/alerts.json"
    github_token: str | None = None

    @classmethod
    def from_env(cls) -> "AgentConfig":
        return cls(
            db_path=os.getenv("ARCHON_DB_PATH", "nap.db"),
            snapshot_path=os.getenv("ARCHON_SNAPSHOT_PATH", "web/data/alerts.json"),
            interval_seconds=max(30, int(os.getenv("ARCHON_INTERVAL_SECONDS", "60"))),
            cisa_url=os.getenv("ARCHON_CISA_URL"),
            github_owner=os.getenv("ARCHON_GITHUB_OWNER", "BlockChain-BailBonds"),
            github_repo=os.getenv("ARCHON_GITHUB_REPO", "archon-sigilagi"),
            github_branch=os.getenv("ARCHON_GITHUB_BRANCH", "main"),
            github_path=os.getenv("ARCHON_GITHUB_PATH", "web/data/alerts.json"),
            github_token=os.getenv("ARCHON_GITHUB_TOKEN"),
        )

def atomic_write(path: str | Path, payload: dict) -> str:
    target=Path(path); target.parent.mkdir(parents=True, exist_ok=True)
    encoded=json.dumps(payload, indent=2, sort_keys=True).encode()
    with tempfile.NamedTemporaryFile(dir=target.parent, prefix=f".{target.name}.", delete=False) as handle:
        handle.write(encoded); temporary=Path(handle.name)
    temporary.replace(target)
    return hashlib.sha256(encoded).hexdigest()

def build_snapshot(store: Store, *, limit: int = 2000) -> dict:
    alerts=store.list_global_alerts(limit)
    return {"schema_version":"archon.sigilagi.alerts.v1", "updated_at":now(), "alerts":alerts}

class GitHubContentsSync:
    def __init__(self, config: AgentConfig, session: requests.Session | None = None):
        if not config.github_token: raise ValueError("ARCHON_GITHUB_TOKEN is required for remote synchronization")
        if not config.github_owner or not config.github_repo: raise ValueError("GitHub owner and repo are required")
        self.config=config; self.session=session or requests.Session(); self.session.headers.update({"Authorization":f"Bearer {config.github_token}","Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"archon-sigilagi-agent"})

    def sync(self, payload: dict, *, commit_message: str) -> dict:
        path=self.config.github_path.strip("/"); base=f"https://api.github.com/repos/{self.config.github_owner}/{self.config.github_repo}/contents/{path}"
        encoded=base64.b64encode(json.dumps(payload, indent=2, sort_keys=True).encode()).decode()
        for attempt in range(4):
            existing=self.session.get(base, params={"ref":self.config.github_branch}, timeout=20)
            sha=existing.json().get("sha") if existing.status_code == 200 else None
            body={"message":commit_message,"content":encoded,"branch":self.config.github_branch}
            if sha: body["sha"]=sha
            response=self.session.put(base, json=body, timeout=20)
            if response.status_code in (200,201): return response.json()
            if response.status_code == 409: time.sleep(2 ** attempt); continue
            raise RuntimeError(f"GitHub sync failed: HTTP {response.status_code} {response.text[:300]}")
        raise RuntimeError("GitHub sync conflicted after four retries")

def collect_once(config: AgentConfig) -> dict:
    store=Store(config.db_path); result=scan_public_threats(store, cisa_url=config.cisa_url)
    snapshot=build_snapshot(store); digest=atomic_write(config.snapshot_path, snapshot)
    synced=False; remote=None
    if config.github_token:
        remote=GitHubContentsSync(config).sync(snapshot, commit_message=f"Archon SigilAGI refresh {snapshot['updated_at']}"); synced=True
    return {"agent":"archon-sigilagi-local", "collected":result, "snapshot_sha256":digest, "snapshot_path":str(config.snapshot_path), "remote_synced":synced, "remote_url":remote.get("content",{}).get("html_url") if remote else None, "completed_at":now()}

def run(config: AgentConfig, *, once: bool = False) -> None:
    while True:
        try: print(json.dumps(collect_once(config)), flush=True)
        except Exception as exc: print(json.dumps({"agent":"archon-sigilagi-local","error":type(exc).__name__,"message":str(exc),"trace":traceback.format_exc()}), flush=True)
        if once: return
        time.sleep(config.interval_seconds)

