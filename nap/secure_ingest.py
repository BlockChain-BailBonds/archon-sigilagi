"""Real network fetcher with explicit hostile-content controls."""
from __future__ import annotations
import hashlib, ipaddress, socket
from dataclasses import dataclass
from urllib.parse import urlparse
import requests

class IngestError(ValueError): pass

@dataclass(frozen=True)
class RetrievedArtifact:
    url: str
    content_type: str
    body: bytes
    sha256: str

def _public_host(host: str) -> None:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise IngestError(f"DNS resolution failed: {host}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise IngestError("private, loopback, link-local, or special address blocked")

def fetch(url: str, *, max_bytes: int = 2_000_000, timeout: tuple[float, float] = (3.0, 10.0), allowed_types: tuple[str, ...] = ("application/json", "application/rss+xml", "application/xml", "text/xml", "text/plain", "text/html")) -> RetrievedArtifact:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise IngestError("only HTTPS URLs with a hostname are accepted")
    _public_host(parsed.hostname)
    try:
        response = requests.get(url, timeout=timeout, stream=True, allow_redirects=False, headers={"Accept": ", ".join(allowed_types), "User-Agent": "neural-auto-patch/0.1"})
        response.raise_for_status()
        content_type = response.headers.get("content-type", "application/octet-stream").split(";", 1)[0].lower()
        if content_type not in allowed_types:
            raise IngestError(f"content type not allowed: {content_type}")
        declared = int(response.headers.get("content-length", "0") or 0)
        if declared > max_bytes: raise IngestError("content-length exceeds maximum")
        chunks, total = [], 0
        for chunk in response.iter_content(64 * 1024):
            total += len(chunk)
            if total > max_bytes: raise IngestError("response exceeds maximum size")
            chunks.append(chunk)
    except requests.RequestException as exc:
        raise IngestError(str(exc)) from exc
    body = b"".join(chunks)
    return RetrievedArtifact(url, content_type, body, hashlib.sha256(body).hexdigest())

