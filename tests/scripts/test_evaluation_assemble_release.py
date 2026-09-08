"""Real signature checks at the local evaluation bootstrap boundary."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import platform
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader(
    "evaluation_assemble_release", str(ROOT / "scripts/evaluation-assemble-release")
)
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
assembler = importlib.util.module_from_spec(spec)
loader.exec_module(assembler)


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def local_bundle(tmp_path, signing_key):
    platforms = {
        ("Darwin", "arm64"): "darwin-arm64",
        ("Darwin", "x86_64"): "darwin-amd64",
        ("Linux", "aarch64"): "linux-arm64",
        ("Linux", "x86_64"): "linux-amd64",
    }
    selected = platforms[(platform.system(), platform.machine())]
    public = signing_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    root = tmp_path / "release"
    (root / "bootstraps").mkdir(parents=True)
    program = root / "nas/current" / selected / "vonk-nas-setup"
    program.parent.mkdir(parents=True)
    program.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$VONK_TEST_MARKER"\n')
    program.chmod(0o755)
    Path(str(program) + ".sig").write_bytes(
        assembler.sign(signing_key, program.read_bytes())
    )
    payload = root / "nas/current/payload.json"
    payload.write_text('{"schema_version":2}\n')
    Path(str(payload) + ".sig").write_bytes(
        assembler.sign(signing_key, payload.read_bytes())
    )
    script = root / "bootstraps/nas"
    script.write_bytes(assembler.bootstrap("nas", public))
    generation = "a" * 64
    prefix = f"artifacts/dev/releases/{generation}/"
    artifacts = {
        str(path.relative_to(root)): {
            "path": prefix + str(path.relative_to(root)),
            **assembler.record(path.read_bytes()),
        }
        for path in (
            program,
            Path(str(program) + ".sig"),
            payload,
            Path(str(payload) + ".sig"),
        )
    }
    release = root / "release.json"
    release.write_bytes(
        assembler.canonical(
            {
                "schema_version": 2,
                "channel": "dev",
                "generation": generation,
                "artifacts": artifacts,
                "bootstraps": {
                    "nas": {
                        "path": prefix + "bootstraps/nas",
                        **assembler.record(script.read_bytes()),
                    }
                },
            }
        )
    )
    (root / "release.sig").write_bytes(
        assembler.sign(signing_key, release.read_bytes())
    )
    marker = tmp_path / "invocation"
    return script, program, payload, release, marker


@pytest.mark.parametrize("tamper", [None, "program", "payload", "release", "signature"])
def test_bootstrap_rejects_tampered_signed_input_before_execution(
    tmp_path, signing_key, tamper
):
    script, program, payload, release, marker = local_bundle(tmp_path, signing_key)
    targets = {
        "program": program,
        "payload": payload,
        "release": release,
        "signature": release.with_suffix(".sig"),
    }
    if tamper:
        target = targets[tamper]
        target.write_bytes(target.read_bytes() + b"tampered")
    environment = {"PATH": os.environ["PATH"], "VONK_TEST_MARKER": str(marker)}
    result = subprocess.run(
        ["/bin/sh", str(script), "--upgrade"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is (tamper is None), result.stderr
    assert marker.exists() is (tamper is None)
    if not tamper:
        assert marker.read_text().splitlines() == [
            "--template",
            str(payload),
            "--upgrade",
        ]


def test_image_receipt_cannot_substitute_source_or_repository(tmp_path):
    source = "a" * 40
    for role in assembler.ROLES:
        folder = tmp_path / f"evaluation-image-{role}-{source}"
        folder.mkdir()
        (folder / "evaluation-image.json").write_text(
            json.dumps(
                {
                    "source": source,
                    "role": role,
                    "image": f"ghcr.io/kelchm/vonk-forge-evaluation-{role}:dev-sha-{source}@sha256:"
                    + "b" * 64,
                }
            )
        )
    assert set(assembler.images_from(tmp_path, source)) == set(assembler.ROLES)
    path = tmp_path / f"evaluation-image-api-{source}/evaluation-image.json"
    original = path.read_text()
    for bad in (
        original.replace("ghcr.io/kelchm/", "ghcr.io/untrusted/"),
        original.replace('"source": "' + source, '"source": "' + "c" * 40),
    ):
        path.write_text(bad)
        with pytest.raises(ValueError, match="identity mismatch"):
            assembler.images_from(tmp_path, source)


def test_input_rejects_symlink_and_readable_private_key(tmp_path):
    target = tmp_path / "key"
    target.write_bytes(b"fixture")
    target.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe input"):
        assembler.read(target, private=True)
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="unsafe input"):
        assembler.read(link)
    assert assembler.read(target, private=True) == b"fixture"


def test_setup_uses_uploaded_platform_directory_and_rejects_checksum_drift(tmp_path):
    source = "e" * 40
    directory = tmp_path / f"installer-setup-{source}-linux-arm64" / "linux-arm64"
    directory.mkdir(parents=True)
    program = directory / "vonk-nas-setup"
    program.write_bytes(b"native setup fixture")
    checksum = assembler.record(program.read_bytes())["sha256"]
    sums = directory / "SHA256SUMS"
    sums.write_text(f"{checksum}  vonk-nas-setup\n")
    assert (
        assembler.nas_setup_from(tmp_path, source, "linux-arm64")
        == program.read_bytes()
    )
    program.write_bytes(b"substituted setup")
    with pytest.raises(ValueError, match="checksum mismatch"):
        assembler.nas_setup_from(tmp_path, source, "linux-arm64")
    sums.write_text(f"{checksum}  vonk-nas-setup\n" * 2)
    with pytest.raises(ValueError, match="checksum list"):
        assembler.setup_bytes(program)
