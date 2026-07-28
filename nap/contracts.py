"""Runtime JSON Schema validation for data crossing service boundaries."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent

def validate_mitigation(payload: dict) -> None:
    schema = json.loads((ROOT / "schemas" / "mitigation-plan.schema.json").read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        raise ValueError("invalid nap.mitigation.v1: " + "; ".join(error.message for error in errors))

