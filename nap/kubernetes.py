"""Kubernetes inventory adapter using explicit kubectl argv and bounded execution."""
import json, os, subprocess
from .models import Asset

def inventory(*, namespace: str | None = None, kubectl: str = "kubectl") -> list[Asset]:
    args = [kubectl, "get", "deployments", "-o", "json"]
    if namespace: args[2:2] = ["-n", namespace]
    env = {"PATH": os.environ.get("PATH", "")}
    completed = subprocess.run(args, capture_output=True, text=True, timeout=20, check=True, env=env)
    data = json.loads(completed.stdout); assets=[]
    for item in data.get("items", []):
        name=item["metadata"]["name"]; ns=item["metadata"].get("namespace", namespace or "default")
        for container in item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []):
            image=container.get("image", "unknown"); assets.append(Asset(f"k8s:{ns}:{name}:{container.get('name','container')}", "kubernetes", name, image, image.split(":")[-1], "production", True))
    return assets

