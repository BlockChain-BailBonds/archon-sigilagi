"""Telemetry client. The evaluator consumes externally collected metrics."""
from dataclasses import dataclass
import requests

@dataclass(frozen=True)
class TelemetrySnapshot:
    coverage_percent: float
    baseline_available: bool
    exploit_indicator_delta_percent: float
    error_rate_delta_points: float
    latency_delta_percent: float

class TelemetryClient:
    def __init__(self, base_url: str, timeout: float = 5.0): self.base_url, self.timeout = base_url.rstrip("/"), timeout
    def snapshot(self, selector: dict[str, str]) -> TelemetrySnapshot:
        response = requests.get(self.base_url + "/api/nap/telemetry", params=selector, timeout=self.timeout); response.raise_for_status()
        data = response.json()
        required = {"coverage_percent", "baseline_available", "exploit_indicator_delta_percent", "error_rate_delta_points", "latency_delta_percent"}
        if not required <= data.keys(): raise ValueError("telemetry response missing required fields")
        return TelemetrySnapshot(**{key: data[key] for key in required})

