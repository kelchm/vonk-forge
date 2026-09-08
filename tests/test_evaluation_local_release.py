from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.acceptance.evaluation_local_release import (
    EVALUATION_ORIGIN,
    EvaluationLocalLifecycle,
    assert_fork_images,
    assert_fork_overlay,
    is_evaluation_fork_image,
    native_nas_setup_command,
    native_spark_setup_command,
    require_disposable_evaluation_context,
    verify_local_signed_release,
)
from tests.acceptance.test_spark_lifecycle import LifecycleError

SOURCE_SHA = "b" * 40
GENERATION = "c" * 64
DIGEST = "d" * 64
VERSION = "1.2.3"


def _canonical(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")


def _rsa_keys(tmp_path: Path) -> tuple[Path, Path]:
    private_key = tmp_path / "installer-private.pem"
    public_key = tmp_path / "installer-public.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            private_key,
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key],
        check=True,
        capture_output=True,
    )
    return private_key, public_key


def _sign(private_key: Path, source: Path, destination: Path) -> None:
    raw = destination.with_suffix(".raw")
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", private_key, "-out", raw, source],
        check=True,
        capture_output=True,
    )
    destination.write_bytes(base64.b64encode(raw.read_bytes()) + b"\n")


def _record(
    root: Path, relative: str, content: bytes, *, mode: int = 0o644
) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    os.chmod(path, mode)
    return {
        "path": relative,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def _fork_image(role: str, digest: str = DIGEST) -> str:
    return f"ghcr.io/kelchm/vonk-forge-evaluation-{role}:dev-sha-{SOURCE_SHA}@sha256:{digest}"


def _overlay_text(images: dict[str, str]) -> str:
    lines = ["services:"]
    mapping = {
        "api": ("control-api",),
        "worker": ("control-worker",),
        "hermes": ("hermes-agent",),
        "litellm": ("litellm", "hermes-litellm-key-provisioner"),
    }
    for role, names in mapping.items():
        for name in names:
            lines.extend((f"  {name}:", f"    image: {images[role]}"))
    return "\n".join(lines) + "\n"


def _signed_release(tmp_path: Path) -> argparse.Namespace:
    private_key, public_key = _rsa_keys(tmp_path)
    objects = tmp_path / "objects"
    prefix = f"artifacts/dev/releases/{GENERATION}"
    package_path = f"{prefix}/spark/current/linux-arm64/vonk-forge-agent.deb"
    artifacts = {
        "agent-package-linux-arm64": _record(objects, package_path, b"candidate-deb\n")
        | {
            "architecture": "linux-arm64",
            "host_signature": "e" * 128,
            "package_version": VERSION,
            "target_binary_digest": "f" * 64,
            "target_build_digest": "sha256:" + "a" * 64,
        },
        "agent-package-signature-linux-arm64": _record(
            objects, f"{package_path}.host.sig", ("e" * 128 + "\n").encode()
        ),
        "nas-payload": _record(
            objects, f"{prefix}/nas/current/payload.json", b'{"schema_version":2}\n'
        ),
        "nas-setup-linux-arm64": _record(
            objects,
            f"{prefix}/nas/current/linux-arm64/vonk-nas-setup",
            b"#!/bin/sh\nexit 0\n",
            mode=0o755,
        ),
        "spark-setup-linux-arm64": _record(
            objects,
            f"{prefix}/spark/current/linux-arm64/vonk-spark-setup",
            b"#!/bin/sh\nexit 0\n",
            mode=0o755,
        ),
        "spark-setup-signature-linux-arm64": _record(
            objects,
            f"{prefix}/spark/current/linux-arm64/vonk-spark-setup.sig",
            b"c" * 88 + b"\n",
        ),
    }
    images = {
        role: _fork_image(role) for role in ("api", "worker", "hermes", "litellm")
    }
    release = objects / prefix / "release.json"
    _canonical(
        release,
        {
            "artifacts": artifacts,
            "bootstraps": {
                "nas": _record(objects, f"{prefix}/bootstraps/nas", b"nas-bootstrap\n"),
                "spark": _record(
                    objects, f"{prefix}/bootstraps/spark", b"spark-bootstrap\n"
                ),
            },
            "channel": "dev",
            "generation": GENERATION,
            "images": images,
            "schema_version": 2,
            "source_sha": SOURCE_SHA,
            "version": VERSION,
        },
    )
    _sign(private_key, release, release.with_name("release.sig"))
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(_overlay_text(images), encoding="utf-8")
    return argparse.Namespace(
        candidate_release=release,
        object_root=objects,
        installer_public_key=public_key,
        compose_overlay=overlay,
        channel="dev",
        version=VERSION,
        source_sha=SOURCE_SHA,
        generation=GENERATION,
        platform="linux-arm64",
        origin=EVALUATION_ORIGIN,
        signing_private_key=private_key,
    )


def _allow_disposable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VONK_EVALUATION_DISPOSABLE", "1")
    monkeypatch.setenv("GITHUB_REPOSITORY", "kelchm/vonk-forge")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr("platform.machine", lambda: "aarch64")
    monkeypatch.setattr(
        "tests.acceptance.evaluation_local_release._os_release_text",
        lambda: 'ID=ubuntu\nVERSION_ID="24.04"\n',
    )
    monkeypatch.setattr(
        "tests.acceptance.evaluation_local_release._lab_spark_marker_present",
        lambda: False,
    )


def test_disposable_context_accepts_hosted_fork_ci(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_disposable(monkeypatch)

    require_disposable_evaluation_context()


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("VONK_EVALUATION_DISPOSABLE", None),
        ("VONK_EVALUATION_DISPOSABLE", "true"),
        ("GITHUB_REPOSITORY", "CarstVaartjes/vonk-forge"),
        ("GITHUB_ACTIONS", None),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
    ),
)
def test_disposable_context_refuses_non_disposable_env(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str | None
) -> None:
    _allow_disposable(monkeypatch)
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)

    with pytest.raises(LifecycleError):
        require_disposable_evaluation_context()


def test_disposable_context_refuses_root_non_ubuntu_and_lab_sparks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_disposable(monkeypatch)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    with pytest.raises(LifecycleError, match="non-root"):
        require_disposable_evaluation_context()

    _allow_disposable(monkeypatch)
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    with pytest.raises(LifecycleError, match="ARM64"):
        require_disposable_evaluation_context()

    _allow_disposable(monkeypatch)
    monkeypatch.setattr(
        "tests.acceptance.evaluation_local_release._os_release_text",
        lambda: 'ID="darwin"\n',
    )
    with pytest.raises(LifecycleError, match="Ubuntu"):
        require_disposable_evaluation_context()

    _allow_disposable(monkeypatch)
    monkeypatch.setattr(
        "tests.acceptance.evaluation_local_release._lab_spark_marker_present",
        lambda: True,
    )
    with pytest.raises(LifecycleError, match="lab Sparks"):
        require_disposable_evaluation_context()


def test_native_setup_commands_use_local_files_and_enroll(tmp_path: Path) -> None:
    nas_setup = tmp_path / "vonk-nas-setup"
    payload = tmp_path / "payload.json"
    output = tmp_path / "controller"
    answers = tmp_path / "answers"
    spark_setup = tmp_path / "vonk-spark-setup"
    package = tmp_path / "vonk-forge-agent.deb"
    release = tmp_path / "release.json"
    signature = tmp_path / "release.sig"
    setup_signature = tmp_path / "vonk-spark-setup.sig"
    for path in (
        nas_setup,
        payload,
        output,
        answers,
        spark_setup,
        package,
        release,
        signature,
        setup_signature,
    ):
        path.write_text("x\n")

    nas = native_nas_setup_command(
        nas_setup=nas_setup,
        payload=payload,
        output=output,
        answers=answers,
    )
    spark = native_spark_setup_command(
        spark_setup=spark_setup,
        package=package,
        release=release,
        signature=signature,
        setup_signature=setup_signature,
    )

    assert nas == [
        os.fspath(nas_setup),
        "--template",
        os.fspath(payload),
        "--output",
        os.fspath(output),
        "--answers-file",
        os.fspath(answers),
        "--disable-hermes",
    ]
    assert spark == [
        os.fspath(spark_setup),
        "--package",
        os.fspath(package),
        "--release-manifest",
        os.fspath(release),
        "--release-signature",
        os.fspath(signature),
        "--setup-signature",
        os.fspath(setup_signature),
        "--enroll",
    ]
    assert "https://" not in " ".join(nas)
    assert "https://" not in " ".join(spark)
    assert "--enroll" in spark
    with pytest.raises(LifecycleError, match="absolute"):
        native_spark_setup_command(
            spark_setup=Path("vonk-spark-setup"),
            package=package,
            release=release,
            signature=signature,
            setup_signature=setup_signature,
        )


def test_fork_image_validation_accepts_only_immutable_evaluation_pins() -> None:
    images = {
        role: _fork_image(role) for role in ("api", "worker", "hermes", "litellm")
    }

    assert is_evaluation_fork_image(images["api"], role="api", source_sha=SOURCE_SHA)
    assert assert_fork_images(images, SOURCE_SHA) == images
    with pytest.raises(LifecycleError, match="fork pin"):
        assert_fork_images(
            {
                **images,
                "api": (
                    "ghcr.io/carstvaartjes/vonk-forge-api:"
                    f"dev-sha-{SOURCE_SHA}@sha256:{DIGEST}"
                ),
            },
            SOURCE_SHA,
        )
    with pytest.raises(LifecycleError, match="fork pin"):
        assert_fork_images(
            {**images, "api": images["api"].replace("@sha256:", ":")},
            SOURCE_SHA,
        )
    with pytest.raises(LifecycleError, match="fork pin"):
        assert_fork_images(
            {
                **images,
                "api": (
                    f"ghcr.io/kelchm/vonk-forge-evaluation-api:dev@sha256:{DIGEST}"
                ),
            },
            SOURCE_SHA,
        )


def test_fork_overlay_must_pin_the_release_images(tmp_path: Path) -> None:
    images = {
        role: _fork_image(role) for role in ("api", "worker", "hermes", "litellm")
    }
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(_overlay_text(images), encoding="utf-8")

    assert_fork_overlay(overlay, images, SOURCE_SHA)

    overlay.write_text(
        _overlay_text({**images, "api": _fork_image("api", digest="e" * 64)}),
        encoding="utf-8",
    )
    with pytest.raises(LifecycleError, match="overlay differs"):
        assert_fork_overlay(overlay, images, SOURCE_SHA)


def test_verify_rejects_an_invalid_release_signature(tmp_path: Path) -> None:
    arguments = _signed_release(tmp_path)
    signature = arguments.candidate_release.with_name("release.sig")
    raw = bytearray(base64.b64decode(signature.read_bytes().strip(), validate=True))
    raw[0] ^= 0x01
    signature.write_bytes(base64.b64encode(bytes(raw)) + b"\n")

    with pytest.raises(LifecycleError, match="signature"):
        verify_local_signed_release(arguments)


def test_verify_rejects_a_digest_mismatch(tmp_path: Path) -> None:
    arguments = _signed_release(tmp_path)
    package = (
        arguments.object_root
        / f"artifacts/dev/releases/{GENERATION}/spark/current/linux-arm64/"
        "vonk-forge-agent.deb"
    )
    package.write_bytes(b"tampered-deb\n")

    with pytest.raises(LifecycleError, match="digest"):
        verify_local_signed_release(arguments)


def test_verify_accepts_a_bounded_local_signed_fork_release(tmp_path: Path) -> None:
    arguments = _signed_release(tmp_path)

    artifacts = verify_local_signed_release(arguments)

    assert artifacts.release == arguments.candidate_release
    assert artifacts.graph["candidate_version"] == VERSION
    assert artifacts.graph["source_sha"] == SOURCE_SHA
    assert "baseline_package_sha256" not in artifacts.proof()
    assert (
        artifacts.proof()["agent_package_sha256"]
        == hashlib.sha256(b"candidate-deb\n").hexdigest()
    )


def test_verify_refuses_an_upstream_origin_and_missing_bootstraps(
    tmp_path: Path,
) -> None:
    arguments = _signed_release(tmp_path)
    arguments.origin = "https://install.vonkforge.ai"
    with pytest.raises(LifecycleError, match="identity"):
        verify_local_signed_release(arguments)

    arguments = _signed_release(tmp_path)
    document = json.loads(arguments.candidate_release.read_text())
    document["bootstraps"] = {}
    _canonical(arguments.candidate_release, document)
    _sign(
        arguments.signing_private_key,
        arguments.candidate_release,
        arguments.candidate_release.with_name("release.sig"),
    )
    with pytest.raises(LifecycleError, match="bootstraps"):
        verify_local_signed_release(arguments)


def test_evaluation_compose_command_always_includes_the_fork_overlay(
    tmp_path: Path,
) -> None:
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("services: {}\n", encoding="utf-8")
    run = EvaluationLocalLifecycle.__new__(EvaluationLocalLifecycle)
    run.project = "vonk-spark-7-arm64"
    run.compose_overlay = overlay

    command = run._compose("config", "--format", "json")

    assert command[:8] == [
        "docker",
        "compose",
        "--project-name",
        "vonk-spark-7-arm64",
        "-f",
        "docker-compose.yaml",
        "-f",
        os.fspath(overlay),
    ]


def test_native_spark_setup_invocation_keeps_the_pairing_token_in_tty_answers(
    tmp_path: Path,
) -> None:
    run = EvaluationLocalLifecycle.__new__(EvaluationLocalLifecycle)
    run.temporary_root = tmp_path
    run.firewall_environment = {"VONK_NAS_MANAGEMENT_IP": "172.31.20.2"}
    run.artifacts = SimpleNamespace(
        spark_setup=tmp_path / "vonk-spark-setup",
        package=tmp_path / "vonk-forge-agent.deb",
        release=tmp_path / "release.json",
        signature=tmp_path / "release.sig",
        spark_setup_signature=tmp_path / "vonk-spark-setup.sig",
    )
    for path in (
        run.artifacts.spark_setup,
        run.artifacts.package,
        run.artifacts.release,
        run.artifacts.signature,
        run.artifacts.spark_setup_signature,
    ):
        path.write_text("x\n")
    observed: dict[str, object] = {}
    token = "single-use-pairing-secret"

    def interactive(command, **kwargs):
        observed.update(command=command, **kwargs)
        return "installed"

    run._run_native_spark_setup(
        "https://enroll.spark.localhost:8443",
        "a" * 64,
        token,
        interactive=interactive,
    )

    assert observed["command"][:2] == [
        os.fspath(run.artifacts.spark_setup),
        "--package",
    ]
    assert observed["command"][-1] == "--enroll"
    assert "https://install.vonkforge.ai" not in repr(observed["command"])
    assert "VONK_INSTALL_BASE_URL" not in observed["environment"]
    assert observed["environment"]["VONK_CONTROLLER_ADDRESS"] == "127.0.0.1"
    assert observed["responses"] == [
        ("Enrollment URL: ", "https://enroll.spark.localhost:8443"),
        ("Controller CA SHA-256: ", "a" * 64),
        ("Pairing token: ", token),
    ]
    assert observed["forbidden_values"] == [token]
    assert token not in repr(observed["command"])
    assert token not in repr(observed["environment"])
