"""Fork-only, read-only diagnostic; never print runtime argv/env values."""
import json
import os
import uuid
from pathlib import Path


def differences(left, right, prefix=""):
    if isinstance(left, dict) and isinstance(right, dict):
        result = []
        for key in sorted(left.keys() | right.keys()):
            result.extend(differences(left.get(key), right.get(key), f"{prefix}/{key}"))
        return result
    return [] if left == right else [prefix]


def read(path):
    if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("invalid bounded metadata file")
    return json.loads(path.read_text())


def main():
    if os.environ.get("GITHUB_REPOSITORY") != "kelchm/vonk-forge":
        raise SystemExit("snapshot is restricted to the evaluation fork")
    root = Path("/var/lib/vonk-forge-agent")
    rows = []
    for path in sorted((root / "run-metadata").glob("*/lifecycle.json"))[:8]:
        try:
            run_id = str(uuid.UUID(path.parent.name))
            lifecycle = read(path)
            installation_id = str(uuid.UUID(lifecycle["installation_id"]))
            installed = read(root / "installations" / installation_id / "spec.json")
            launched = read(path.parent / "runtime.json")
            rows.append({"run_id": run_id,
                         "changed_fields": differences(installed, launched)[:100],
                         "installed_placement": installed["runtime"]["placement"],
                         "launched_placement": launched["runtime"]["placement"],
                         "installed_network": installed["security"]["network_mode"],
                         "launched_network": launched["security"]["network_mode"]})
        except (OSError, ValueError, KeyError, TypeError) as error:
            rows.append({"error_class": type(error).__name__})
    print(json.dumps(rows, sort_keys=True))


if __name__ == "__main__":
    main()
