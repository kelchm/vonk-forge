from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-controller-skopeo"


def test_controller_skopeo_verification_is_digest_bound_and_rootless() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "0e392474a4383b733038b85eff26ade929d2ff10e8deead25a6add3ed79fb362" in source
    assert "807f42a95c0f05f397eb505b577b6de49048b865c4e29146d1231324c27e1e59" in source
    assert "source_reference" in source
    assert "@sha256:" in source
    assert "quay.io/skopeo/stable:v1.22.2-immutable@sha256:4a16d57b37617a04b3d643079a477a2848efe892dffcdf0ce56df4262b65f810" in source
    assert "--read-only" in source
    assert "--tmpfs /var/tmp:rw,nosuid,nodev,noexec,size=256m" in source
    assert "--user 10001:10001" in source
    assert "--privileged" not in source
    assert "docker.sock" not in source
    assert "source_child=$(skopeo inspect" in source
    assert "test \"$source_child\" = \"$expected_child\"" in source
    assert '"docker://${skopeo_source}"' in source
    assert '"docker://${SOURCE_REFERENCE}"' in source
    assert "oci-archive:/tmp/controller-skopeo.oci" in source
    assert "--tls-verify=true" in source


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_verifier_passes_digest_only_source_to_transport(
    tmp_path: Path, architecture: str
) -> None:
    index = "sha256:4a16d57b37617a04b3d643079a477a2848efe892dffcdf0ce56df4262b65f810"
    children = {
        "amd64": "sha256:0e392474a4383b733038b85eff26ade929d2ff10e8deead25a6add3ed79fb362",
        "arm64": "sha256:807f42a95c0f05f397eb505b577b6de49048b865c4e29146d1231324c27e1e59",
    }
    calls = tmp_path / "calls.jsonl"
    executable = tmp_path / "transport"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['CALLS'], 'a') as stream:\n"
        "    stream.write(json.dumps([Path(sys.argv[0]).name, *args]) + '\\n')\n"
        "if Path(sys.argv[0]).name == 'skopeo':\n"
        "    assert args[-1] == 'docker://quay.io/skopeo/stable@' + os.environ['INDEX']\n"
        "    print(json.dumps({'manifests': [{'platform': {'os': 'linux', "
        "'architecture': os.environ['ARCH']}, 'digest': os.environ['CHILD']}]}))\n"
        "elif args[:2] == ['image', 'inspect']:\n"
        "    print(os.environ['ARCH'] if args[3] == '{{.Architecture}}' else "
        "os.environ['INDEX'] + ' ' + os.environ['CHILD'])\n"
        "else:\n"
        "    assert args[0] == 'run'\n"
        "    assert 'SOURCE_REFERENCE=quay.io/skopeo/stable@' + os.environ['INDEX'] in args\n"
    )
    executable.chmod(0o755)
    for name in ("docker", "skopeo"):
        (tmp_path / name).symlink_to(executable)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "CALLS": str(calls),
        "INDEX": index,
        "CHILD": children[architecture],
        "ARCH": architecture,
    }
    source = f"quay.io/skopeo/stable:v1.22.2-immutable@{index}"
    result = subprocess.run(
        [str(SCRIPT), "reviewed-controller", source, f"linux/{architecture}"],
        env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    recorded = [json.loads(line) for line in calls.read_text().splitlines()]
    assert [call[0] for call in recorded] == ["docker", "docker", "skopeo", "docker"]
    calls.unlink()
    rejected = subprocess.run(
        [str(SCRIPT), "reviewed-controller", source.replace("immutable", "mutable"),
         f"linux/{architecture}"],
        env=env, capture_output=True, text=True, check=False,
    )
    assert rejected.returncode != 0
    assert not calls.exists()
