from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.acceptance.evaluation_native_recovery import (
    BASELINE_BUNDLE_SCHEMA,
    CHECKPOINT,
    DENIED,
    KIND,
    PACKAGE,
    apt_install,
    depend_names,
    extract_archive,
    load_baseline,
    parse_apt_changes,
    recover,
    restore_argv,
    run,
    staging_file,
    verify_host_signature,
)
from tests.acceptance.test_spark_lifecycle import LifecycleError
from tests.scripts.test_evaluation_native_checkpoint import (
    load_module as load_checkpoint,
)
from tests.test_evaluation_local_release import _allow_disposable

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/evaluation-native-recovery.yml"
HARNESS = ROOT / "tests/acceptance/evaluation_native_recovery.py"
CANDIDATE_SOURCE = "a" * 40
BASELINE_SOURCE = "b" * 40
HARNESS_HEAD = "c" * 40
CANDIDATE_VERSION = f"0.1.1~dev.546+g{CANDIDATE_SOURCE[:12]}"
BASELINE_VERSION = f"0.1.1~dev.540+g{BASELINE_SOURCE[:12]}"


def _canonical(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )


def _write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, mode)


def _tar(path: Path, members: dict[str, bytes]) -> str:
    with tarfile.open(path, "w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, fileobj=io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_extract_archive_rejects_symlinks_and_digest_mismatch(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.tar"
    digest = _tar(archive, {"manifest.json": b"{}\n"})
    extract_archive(archive, digest, tmp_path / "ok")
    assert (tmp_path / "ok/manifest.json").is_file()
    assert not (tmp_path / "ok/manifest.json").is_symlink()

    with pytest.raises(LifecycleError, match="digest"):
        extract_archive(archive, "a" * 64, tmp_path / "bad-digest")

    linked = tmp_path / "linked.tar"
    with tarfile.open(linked, "w") as tar:
        info = tarfile.TarInfo("evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "manifest.json"
        tar.addfile(info)
    with pytest.raises(LifecycleError, match="unsafe"):
        extract_archive(
            linked, hashlib.sha256(linked.read_bytes()).hexdigest(), tmp_path / "sym"
        )


def test_staging_file_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.write_bytes(b"payload\n")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(LifecycleError, match="unsafe"):
        staging_file(link, "input", maximum=1024)


def test_parse_apt_changes_refuses_non_vonk_packages() -> None:
    only = "Inst vonk-forge-agent (0.1.1~dev.540+gbbbbbbbbbbbb local [arm64])\n"
    assert parse_apt_changes(only) == {PACKAGE}
    mixed = only + "Inst curl [8.5.0-1] (8.5.0-1 Ubuntu [arm64])\n"
    assert parse_apt_changes(mixed) == {PACKAGE, "curl"}
    assert depend_names("acl, adduser, podman (>= 4.9), crun | runc") == {
        "acl",
        "adduser",
        "podman",
        "crun",
    }


def test_restore_argv_binds_digest_identity_and_current_hashes(tmp_path: Path) -> None:
    report = {"checkpoint_digest": "d" * 64, "trusted_identity": "e" * 64}
    argv = restore_argv(
        tmp_path,
        report,
        current_version=CANDIDATE_VERSION,
        current_agent="f" * 64,
        current_helper="a" * 64,
        apply=True,
    )
    assert argv[0] == "/usr/bin/python3"
    assert argv[1] == os.fspath(CHECKPOINT)
    assert (
        "--checkpoint-digest" in argv
        and argv[argv.index("--checkpoint-digest") + 1] == "d" * 64
    )
    assert (
        "--trusted-identity" in argv
        and argv[argv.index("--trusted-identity") + 1] == "e" * 64
    )
    assert argv[argv.index("--current-package-version") + 1] == CANDIDATE_VERSION
    assert argv[argv.index("--current-agent-sha256") + 1] == "f" * 64
    assert argv[argv.index("--current-helper-sha256") + 1] == "a" * 64
    assert "--apply" in argv
    assert "--force-downgrade" not in argv


def test_run_refuses_force_downgrade() -> None:
    with pytest.raises(LifecycleError, match="force-downgrade"):
        run(["/usr/bin/dpkg", "--force-downgrade", "x.deb"], sudo=True)


def test_host_signature_uses_existing_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deb = tmp_path / "vonk-forge-agent.deb"
    _write(deb, b"fake-deb-bytes\n")
    digest = hashlib.sha256(deb.read_bytes()).hexdigest()
    seen: list[tuple[bytes, Path, str]] = []

    class Verifier:
        class VerificationError(Exception):
            pass

        @staticmethod
        def _verify_package_signature(
            public_key: bytes, package: Path, value: str
        ) -> str:
            seen.append((public_key, package, value))
            if value != digest:
                raise Verifier.VerificationError("mismatch")
            return "ok"

    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.load_script",
        lambda *_args: Verifier,
    )
    verify_host_signature(deb, b"\x11" * 32, digest)
    assert seen == [(b"\x11" * 32, deb, digest)]
    with pytest.raises(LifecycleError, match="host signature"):
        verify_host_signature(deb, b"\x11" * 32, "0" * 64)


def test_load_baseline_accepts_540_and_rejects_other_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "baseline"
    deb = root / f"vonk-forge-agent_{BASELINE_VERSION}_arm64.deb"
    payload = b"old-signed-deb\n"
    _write(deb, payload)
    digest = hashlib.sha256(payload).hexdigest()
    _write(Path(str(deb) + ".sha256"), f"{digest}  {deb.name}\n".encode())
    _write(Path(str(deb) + ".host.sig"), ("ab" * 64 + "\n").encode())
    public = b"\x11" * 32
    _write(root / "vonk-forge-release.pub", (public.hex() + "\n").encode())
    key_digest = hashlib.sha256(public).hexdigest()
    _canonical(
        root / "manifest.json",
        {
            "architecture": "arm64",
            "kind": "evaluation-native-baseline-bundle",
            "package": PACKAGE,
            "package_sha256": digest,
            "release_key_sha256": key_digest,
            "schema_version": 2,
            "source_sha": BASELINE_SOURCE,
            "version": BASELINE_VERSION,
        },
    )
    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.verify_host_signature",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.deb_field",
        lambda _deb, name: {
            "Package": PACKAGE,
            "Version": BASELINE_VERSION,
            "Architecture": "arm64",
            "Depends": "acl, podman (>= 4.9)",
        }[name],
    )

    loaded = load_baseline(root, BASELINE_SOURCE)
    assert loaded.version == BASELINE_VERSION
    assert loaded.release_key_sha256 == key_digest

    document = json.loads((root / "manifest.json").read_text())
    document["version"] = f"0.1.1~dev.541+g{BASELINE_SOURCE[:12]}"
    _canonical(root / "manifest.json", document)
    with pytest.raises(LifecycleError, match="baseline identity"):
        load_baseline(root, BASELINE_SOURCE)


def test_apt_install_refuses_non_vonk_simulation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deb = tmp_path / "pkg.deb"
    _write(deb, b"deb\n")
    calls: list[list[str]] = []

    def fake_run(argv, *, sudo=False, timeout=120):
        del timeout
        calls.append(list(argv))
        assert sudo is True
        stdout = (
            b"Inst vonk-forge-agent (1 local [arm64])\nInst curl (8 Ubuntu [arm64])\n"
        )
        return subprocess.CompletedProcess(argv, 0, stdout, b"")

    monkeypatch.setattr("tests.acceptance.evaluation_native_recovery.run", fake_run)
    with pytest.raises(LifecycleError, match="non-Vonk"):
        apt_install(deb)
    assert any(item[0].endswith("apt-get") and "--simulate" in item for item in calls)
    assert not any(item[0].endswith("apt-get") and "-y" in item for item in calls)


def test_harness_source_stays_on_the_package_filesystem_boundary() -> None:
    text = HARNESS.read_text()
    assert KIND in text
    assert "package-filesystem" in text
    assert "native_bootstrap_acceptance" in text
    assert "EvaluationLocalLifecycle" not in text
    # Only its existing diagnostic redactor is reused; no lifecycle is created.
    assert "SparkLifecycle(" not in text
    assert "SparkLifecycle._redact_diagnostics(" in text
    assert "--force-downgrade" in text
    assert "force-downgrade is refused" in text
    assert "ssh" not in text.lower() or "no ssh" in text.lower()
    assert "docker compose" not in text
    assert "/usr/bin/nvidia-smi" not in text
    for denied in DENIED:
        assert denied in text
    assert BASELINE_BUNDLE_SCHEMA["archive"] == "evaluation-native-baseline.tar"
    assert "native_bootstrap_acceptance" in DENIED


def test_stop_units_match_checkpoint_helper() -> None:
    module = load_checkpoint()
    source = HARNESS.read_text()
    for unit in module.NATIVE_UNITS:
        assert unit in source or "helper.NATIVE_UNITS" in source
    assert "helper.NATIVE_UNITS" in source
    assert "helper.SQLITE_PATHS" in source


def test_recover_mocked_success_is_not_native_bootstrap_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Fixture-only orchestration; not physical native recovery evidence."""
    _allow_disposable(monkeypatch)
    output = tmp_path / "proof.json"
    checkpoint_dir = tmp_path / "ckpt"
    baseline = SimpleNamespace(
        deb=tmp_path / "old.deb",
        version=BASELINE_VERSION,
        source_sha=BASELINE_SOURCE,
        package_sha256="1" * 64,
        release_key_sha256="2" * 64,
        key_file_sha256="3" * 64,
        depends="acl, podman (>= 4.9)",
    )
    artifacts = SimpleNamespace(
        package=tmp_path / "new.deb",
        artifact_digests={"agent-package-linux-arm64": "4" * 64},
    )
    captured = {
        "ok": True,
        "agent_sha256": "5" * 64,
        "helper_sha256": "6" * 64,
        "release_key_sha256": "3" * 64,
        "package_version": BASELINE_VERSION,
        "checkpoint_digest": "7" * 64,
        "trusted_identity": "8" * 64,
    }
    fixture_toml = hashlib.sha256(
        b'node_id = "spk_00000000000000000000000000000001"\n'
    ).hexdigest()
    candidate_hashes = {
        "/usr/lib/vonk-forge/vonk-agent": "9" * 64,
        "/usr/lib/vonk-forge/vonk-agent-helper": "a" * 64,
        "/usr/share/keyrings/vonk-forge-release.pub": "b" * 64,
        "/etc/vonk-forge-agent/agent.toml": fixture_toml,
        "/var/lib/vonk-forge-agent/state.sqlite": "c" * 64,
    }
    restored_hashes = {
        "/usr/lib/vonk-forge/vonk-agent": captured["agent_sha256"],
        "/usr/lib/vonk-forge/vonk-agent-helper": captured["helper_sha256"],
        "/usr/share/keyrings/vonk-forge-release.pub": captured["release_key_sha256"],
        "/etc/vonk-forge-agent/agent.toml": fixture_toml,
        "/var/lib/vonk-forge-agent/state.sqlite": "c" * 64,
    }
    state = {"phase": "absent"}
    calls: list[list[str]] = []

    def fake_run(argv, *, sudo=False, timeout=120):
        del timeout
        calls.append(list(argv))
        assert sudo is True or Path(argv[0]).name == "dpkg-query"
        program = Path(argv[0]).name
        joined = " ".join(argv)
        if program == "dpkg-query" and "-f=" not in joined:
            return subprocess.CompletedProcess(argv, 1, b"", b"")
        if program == "dpkg-query":
            version = (
                CANDIDATE_VERSION if state["phase"] == "candidate" else BASELINE_VERSION
            )
            return subprocess.CompletedProcess(argv, 0, f"ii |{version}".encode(), b"")
        if program == "apt-get" and "--simulate" in argv:
            return subprocess.CompletedProcess(
                argv, 0, b"Inst vonk-forge-agent (local [arm64])\n", b""
            )
        if program == "apt-get" and "-y" in argv and os.fspath(baseline.deb) in argv:
            state["phase"] = "baseline"
        if (
            program == "apt-get"
            and "-y" in argv
            and os.fspath(artifacts.package) in argv
        ):
            state["phase"] = "candidate"
        if program == "systemctl" and "show" in argv:
            return subprocess.CompletedProcess(
                argv, 0, b"LoadState=not-found\nActiveState=inactive\n", b""
            )
        if program == "python3" and "--restore" in argv and "--apply" in argv:
            state["phase"] = "restored"
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(captured).encode(), b""
            )
        if program == "python3":
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(captured).encode(), b""
            )
        if program == "sha256sum":
            table = (
                restored_hashes if state["phase"] == "restored" else candidate_hashes
            )
            return subprocess.CompletedProcess(
                argv, 0, f"{table[argv[-1]]}  {argv[-1]}\n".encode(), b""
            )
        if program == "cat":
            return subprocess.CompletedProcess(argv, 0, b"11" * 32 + b"\n", b"")
        if program in {"install", "apt-get", "test"}:
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(argv)

    monkeypatch.setattr("tests.acceptance.evaluation_native_recovery.run", fake_run)
    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.load_current",
        lambda *_args: (artifacts, CANDIDATE_VERSION, "d" * 64),
    )
    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.load_baseline",
        lambda *_args: baseline,
    )
    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.load_script",
        lambda *_args: SimpleNamespace(
            NATIVE_UNITS=("vonk-forge-agent.service",),
            PENDING_RECOVERY_PATHS=(),
            SQLITE_PATHS=("/var/lib/vonk-forge-agent/state.sqlite",),
        ),
    )
    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.deb_field",
        lambda *_args: "acl, podman (>= 4.9)",
    )
    proof = recover(
        argparse.Namespace(
            current_bundle=tmp_path / "current",
            installer_public_key=tmp_path / "installer.pem",
            candidate_source=CANDIDATE_SOURCE,
            baseline_root=tmp_path / "baseline",
            baseline_source=BASELINE_SOURCE,
            harness_head=HARNESS_HEAD,
            output=output,
            checkpoint_dir=checkpoint_dir,
        )
    )

    assert proof["ok"] is True
    assert proof["proof_boundary"] == KIND
    assert proof["native_bootstrap_acceptance"] is False
    assert proof["controller_upgrade_acceptance"] is False
    assert proof["synthetic_canary"] is False
    assert proof["physical_gpu_acceptance"] is False
    assert proof["harness_head"] == HARNESS_HEAD
    assert proof["candidate"]["source_sha"] == CANDIDATE_SOURCE
    assert proof["baseline"]["source_sha"] == BASELINE_SOURCE
    assert proof["harness_head"] != proof["candidate"]["source_sha"]
    assert proof["checkpoint"]["trusted_identity"] == "8" * 64
    assert any("--restore" in call and "--apply" in call for call in calls)
    assert any("--simulate" in call for call in calls)
    assert "--force-downgrade" not in {part for call in calls for part in call}
    assert state["phase"] == "restored"
    assert (tmp_path / "native-recovery-fixtures/agent.toml").is_file()
    assert not (tmp_path / "native-recovery-fixtures/agent.toml").is_symlink()


def test_recover_refuses_identical_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _allow_disposable(monkeypatch)
    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.load_current",
        lambda *_args: (
            SimpleNamespace(package=tmp_path / "n.deb", artifact_digests={}),
            "v",
            "g",
        ),
    )
    monkeypatch.setattr(
        "tests.acceptance.evaluation_native_recovery.load_baseline",
        lambda *_args: SimpleNamespace(source_sha=CANDIDATE_SOURCE),
    )
    arguments = argparse.Namespace(
        current_bundle=tmp_path,
        installer_public_key=tmp_path / "k.pem",
        candidate_source=CANDIDATE_SOURCE,
        baseline_root=tmp_path,
        baseline_source=CANDIDATE_SOURCE,
        harness_head=HARNESS_HEAD,
        output=tmp_path / "out.json",
        checkpoint_dir=tmp_path / "ckpt",
    )
    with pytest.raises(LifecycleError, match="not distinct"):
        recover(arguments)


def test_workflow_is_fork_only_manual_and_pins_both_sources() -> None:
    text = WORKFLOW.read_text()
    assert text.startswith("name: Fork evaluation native recovery\n")
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text
    assert "workflow_call:" not in text
    assert "branches: [patch/evaluation-recovery-canary]" in text
    assert "kelchm/vonk-forge" in text
    assert "refs/heads/patch/evaluation-" in text
    assert "runs-on: ubuntu-24.04-arm" in text
    assert 'VONK_EVALUATION_DISPOSABLE: "1"' in text
    assert "contents: read" in text
    assert "secrets." not in text
    assert "PRIVATE_KEY" not in text
    assert "evaluation-bundle.tar" in text
    assert "evaluation-native-baseline.tar" in text
    assert "current_source_sha" in text
    assert "baseline_source_sha" in text
    assert (
        "evaluation/$CURRENT_SOURCE_SHA" in text
        or "evaluation/$CURRENT_SOURCE_SHA" in text
    )
    assert "GITHUB_SHA" in text
    assert 'test "$CURRENT_SOURCE_SHA" = "$GITHUB_SHA"' not in text
    assert "--candidate-source" in text
    assert "--harness-head" in text
    assert "--baseline-source" in text
    assert "report.json" in text
    assert "controller.log" not in text
    assert "id-token: write" not in text
    assert "nvidia" not in text.lower()
    invalid = [
        match.group(1)
        for match in re.finditer(r"^\s*uses:\s*(\S+)", text, re.MULTILINE)
        if not match.group(1).startswith("./")
        and re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", match.group(1)) is None
    ]
    assert invalid == []


def test_real_checkpoint_module_loads_without_host_mutation():
    from tests.acceptance.evaluation_native_recovery import CHECKPOINT, load_script

    module = load_script("evaluation_checkpoint_import_test", CHECKPOINT)
    assert callable(module.create_checkpoint)
