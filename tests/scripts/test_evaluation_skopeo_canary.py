from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
loader = SourceFileLoader("skopeo_canary", str(ROOT / "scripts/evaluation-skopeo-canary"))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
canary = importlib.util.module_from_spec(spec)
loader.exec_module(canary)


def producer() -> dict:
    return {
        "id": canary.PRODUCER, "head_sha": canary.SOURCE,
        "head_branch": canary.SOURCE_BRANCH,
        "head_repository": {"full_name": canary.REPOSITORY},
        "path": ".github/workflows/evaluation-controller-images.yml",
        "event": "push", "status": "completed", "conclusion": "success",
    }


@pytest.mark.parametrize("field,value", [
    ("id", 1), ("head_sha", "a" * 40), ("head_branch", "main"),
    ("head_repository", {"full_name": "other/fork"}),
    ("path", ".github/workflows/ci.yml"), ("event", "pull_request"),
    ("status", "in_progress"), ("conclusion", "failure"),
])
def test_rejects_unqualified_or_different_producer(field: str, value: object) -> None:
    document = producer()
    document[field] = value
    with pytest.raises(ValueError, match="successful exact"):
        canary.validate_producer(document)


def test_index_requires_unique_platform_and_actual_digest() -> None:
    raw = b'{"manifests":[]}'
    with pytest.raises(ValueError, match="digest mismatch"):
        canary.verified_json(raw, "sha256:" + "0" * 64)
    assert canary.verified_json(raw, "sha256:" + hashlib.sha256(raw).hexdigest()) == {"manifests": []}
    entry = {"platform": {"os": "linux", "architecture": "arm64"}, "digest": "sha256:" + "a" * 64}
    for entries in ([], [entry, entry]):
        with pytest.raises(ValueError, match="exactly one"):
            canary.selected_child({"manifests": entries}, "arm64")
    assert canary.selected_child({"manifests": [entry]}, "arm64") == entry["digest"]


@pytest.mark.parametrize("role", ["api", "worker"])
@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
@pytest.mark.parametrize("failure", [None, "producer", "receipt", "platform", "transport"])
def test_exact_image_pipeline_retains_success_or_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    role: str, architecture: str, failure: str | None,
) -> None:
    candidate = tmp_path / "candidate"
    (candidate / "scripts").mkdir(parents=True)
    verifier = b"reviewed source verifier bytes"
    (candidate / "scripts/verify-controller-skopeo").write_bytes(verifier)
    child = {"config": {"digest": "sha256:" + "c" * 64}}
    child_raw = json.dumps(child).encode()
    child_digest = "sha256:" + hashlib.sha256(child_raw).hexdigest()
    index_raw = json.dumps({"manifests": [{
        "platform": {"os": "linux", "architecture": architecture},
        "digest": child_digest,
    }]}).encode()
    image = f"ghcr.io/kelchm/vonk-forge-evaluation-{role}:dev-sha-{canary.SOURCE}@sha256:" + hashlib.sha256(index_raw).hexdigest()
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(argv)
        output = b""
        code = 0
        if argv == ["skopeo", "--version"]:
            output = b"skopeo version test\n"
        elif argv[0] == "dpkg-query":
            output = b"test-package-version"
        elif argv[:2] == ["docker", "version"]:
            output = b'{"Client":{"Version":"test"},"Server":{"Version":"test"}}'
        elif argv[0] == "git":
            if "rev-parse" in argv:
                output = (canary.SOURCE + "\n").encode()
            elif "show" in argv:
                output = verifier
        elif argv[:2] == ["gh", "api"]:
            if "artifacts?" in argv[-1]:
                output = json.dumps({"total_count": 1, "artifacts": [{
                    "id": 123, "name": f"evaluation-image-{role}-{canary.SOURCE}",
                    "expired": False, "size_in_bytes": 100, "digest": "sha256:" + "d" * 64,
                }]}).encode()
            else:
                document = producer()
                if failure == "producer":
                    document["conclusion"] = "failure"
                output = json.dumps(document).encode()
        elif argv[:3] == ["gh", "run", "download"]:
            directory = Path(argv[-1])
            directory.mkdir()
            (directory / "evaluation-image.json").write_text(json.dumps({
                "role": role, "source": "bad" if failure == "receipt" else canary.SOURCE,
                "image": image,
            }))
        elif argv[:4] == ["docker", "buildx", "imagetools", "inspect"]:
            output = index_raw if argv[-1] == image else child_raw
        elif argv[:3] == ["docker", "image", "inspect"]:
            output = json.dumps([{
                "Architecture": "wrong" if failure == "platform" else architecture,
                "Os": "linux", "Id": child["config"]["digest"],
                "Config": {"Labels": {
                    "org.opencontainers.image.revision": canary.SOURCE,
                    "org.opencontainers.image.source": "https://github.com/kelchm/vonk-forge",
                }},
            }]).encode()
        elif argv[:2] == ["docker", "pull"]:
            assert argv == ["docker", "pull", "--platform", f"linux/{architecture}", image]
        elif argv[0] == str(candidate / "scripts/verify-controller-skopeo"):
            assert argv[1:] == [image, canary.SKOPEO, f"linux/{architecture}"]
            code = 1 if failure == "transport" else 0
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, code, output, b"bounded test stderr")

    monkeypatch.setattr(canary.subprocess, "run", run)
    monkeypatch.setattr(canary.platform, "system", lambda: "Linux")
    monkeypatch.setattr(canary.platform, "machine", lambda: {"amd64": "x86_64", "arm64": "aarch64"}[architecture])
    for key, value in {
        "GITHUB_REPOSITORY": canary.REPOSITORY, "GITHUB_REF": canary.HARNESS_BRANCH,
        "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": "e" * 40, "GITHUB_RUN_ID": "999",
    }.items():
        monkeypatch.setenv(key, value)
    output = tmp_path / "proof"
    result = canary.execute(argparse.Namespace(candidate=candidate, output=output, role=role, architecture=architecture))
    report = json.loads((output / "report.json").read_text())
    assert result == (0 if failure is None else 1)
    assert report["ok"] is (failure is None)
    assert report["candidate_source"] == canary.SOURCE
    assert report["harness_source"] == "e" * 40
    assert report["host"]["skopeo_package_version"] == "test-package-version"
    assert report["host"]["skopeo_version"] == "skopeo version test"
    assert report["host"]["docker_version"]["Server"]["Version"] == "test"
    if failure is None:
        assert report["platform_manifest_digest"] == child_digest
        assert report["container_config_digest"] == child["config"]["digest"]
        assert report["rootless_tls_inspect_copy_archive"] is True
        assert (output / "image-index.stdout").read_bytes() == index_raw
    elif failure in {"producer", "receipt"}:
        assert not any(command[0] == "docker" and command[1] != "version" for command in calls)
    elif failure == "platform":
        assert not any(command[0].endswith("verify-controller-skopeo") for command in calls)
    else:
        assert report["commands"][-1]["exit_code"] == 1
        assert "rootless-transport failed" in report["error"]


def test_workflow_runs_only_exact_harness_without_building_or_mutating_release() -> None:
    path = ROOT / ".github/workflows/evaluation-skopeo-canary.yml"
    source = path.read_text()
    document = yaml.safe_load(source)
    triggers = document.get("on", document.get(True))
    assert triggers["push"]["branches"] == ["patch/evaluation-skopeo-canary"]
    assert "workflow_dispatch" in triggers
    assert set(document["permissions"].values()) == {"read"}
    job = document["jobs"]["transport"]
    assert job["strategy"]["matrix"]["role"] == ["api", "worker"]
    assert job["strategy"]["matrix"]["architecture"] == ["amd64", "arm64"]
    assert {entry["runner"] for entry in job["strategy"]["matrix"]["include"]} == {"ubuntu-latest", "ubuntu-24.04-arm"}
    assert canary.SOURCE in source
    assert canary.HARNESS_BRANCH in job["if"]
    assert "persist-credentials: false" in source
    assert "docker/build-push-action" not in source
    assert "gh release" not in source
    assert "ssh " not in source
