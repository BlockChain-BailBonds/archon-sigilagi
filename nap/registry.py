"""Approved mitigation primitive registry. No arbitrary command execution exists here."""
from dataclasses import dataclass
from typing import Any, Callable

@dataclass(frozen=True)
class Primitive:
    name: str
    kind: str
    reversible: bool
    requires_canary: bool
    max_duration_minutes: int
    allowed_parameters: dict[str, type]
    executor: Callable[[dict[str, Any]], dict[str, Any]]

    def validate(self, parameters: dict[str, Any]) -> None:
        unknown = set(parameters) - set(self.allowed_parameters)
        if unknown:
            raise ValueError(f"unknown parameters for {self.name}: {sorted(unknown)}")
        for key, typ in self.allowed_parameters.items():
            if key in parameters and not isinstance(parameters[key], typ):
                raise TypeError(f"{key} must be {typ.__name__}")

def _accepted(parameters: dict[str, Any]) -> dict[str, Any]:
    return {"status": "accepted_by_adapter", "parameters": parameters}

PRIMITIVES = {
    "block_ioc_temporarily": Primitive("block_ioc_temporarily", "network", True, True, 1440, {"ioc": str}, _accepted),
    "rate_limit_route": Primitive("rate_limit_route", "network", True, True, 1440, {"route": str, "requests_per_second": int}, _accepted),
    "disable_feature_flag": Primitive("disable_feature_flag", "feature_flag", True, True, 1440, {"feature": str, "enabled": bool}, _accepted),
    "quarantine_workload": Primitive("quarantine_workload", "kubernetes", True, True, 1440, {"workload": str}, _accepted),
    "rollback_container_image": Primitive("rollback_container_image", "rollback", True, True, 60, {"deployment": str, "image_digest": str}, _accepted),
    "revoke_machine_credential": Primitive("revoke_machine_credential", "identity", True, True, 1440, {"credential_id": str}, _accepted),
}

