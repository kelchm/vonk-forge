from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from itertools import pairwise
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/evaluation-build-release"
BUILD = ROOT / "scripts/build-agent-deb"
SHA = "0123456789abcdef0123456789abcdef01234567"
VERSION_RE = re.compile(
    r"^0\.1\.1~dev\.554\+g[0-9a-f]{12}$"
)


def _load(path: Path, name: str):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


HELPER = _load(SCRIPT, "evaluation_build_release")
BUILD_MODULE = _load(BUILD, "build_agent_deb")


def run_helper(*arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if env:
        environment.update(env)
    return subprocess.run(
        [sys.executable, SCRIPT, *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def openssl_supports_ed25519() -> bool:
    result = subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519"],
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def generate_private_key(path: Path, algorithm: str) -> None:
    result = subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", algorithm, "-out", path],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    path.chmod(0o600)


def test_metadata_emits_cargo_version_with_fixed_sequence_and_source_sha() -> None:
    result = run_helper("metadata", "--source-sha", SHA, "--cargo-lock", str(ROOT / "Cargo.lock"))

    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert values["semantic_version"] == "0.1.1"
    assert values["sequence"] == "554"
    assert values["source_sha"] == SHA
    assert values["version"] == "0.1.1~dev.554+g0123456789ab"
    assert VERSION_RE.fullmatch(values["version"])
    assert values["source_repository"] == "https://github.com/kelchm/vonk-forge"
    assert values["github_repository"] == "kelchm/vonk-forge"
    assert values["architecture"] == "linux-arm64"
    assert values["arm64_package"] == (
        "vonk-forge-agent_0.1.1~dev.554+g0123456789ab_arm64.deb"
    )
    assert values["artifact_name"] == f"vonk-agent-evaluation-{SHA}"
    assert values["compiled_artifact_name"] == (
        f"vonk-agent-evaluation-{SHA}-compiled-arm64"
    )


def test_metadata_build_digest_matches_agent_package_v2_convention() -> None:
    lock = ROOT / "Cargo.lock"
    result = run_helper("metadata", "--source-sha", SHA, "--cargo-lock", str(lock))

    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in result.stdout.splitlines())
    lock_digest = hashlib.sha256(lock.read_bytes()).hexdigest()
    bash = subprocess.run(
        [
            "bash",
            "-c",
            "printf 'vonk-agent-build-v2\\0%s\\0%s\\0%s' \"$1\" linux-arm64 \"$2\" | sha256sum",
            "digest",
            SHA,
            lock_digest,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert values["build_digest"] == f"sha256:{bash.stdout.split()[0]}"
    assert values["build_digest"] == HELPER.v2_build_digest(SHA, "linux-arm64", lock_digest)


@pytest.mark.parametrize(
    "source_sha",
    (
        SHA.upper(),
        SHA[:-1],
        "g" * 40,
        "",
    ),
)
def test_metadata_rejects_noncanonical_source_sha(source_sha: str) -> None:
    result = run_helper(
        "metadata", "--source-sha", source_sha, "--cargo-lock", str(ROOT / "Cargo.lock")
    )

    assert result.returncode == 64
    assert result.stdout == ""
    assert "evaluation-build-release: evaluation input is invalid" in result.stderr


def test_same_sequence_distinguishes_source_sha() -> None:
    other = "fedcba9876543210fedcba9876543210fedcba98"
    first = HELPER.evaluation_version("0.1.1", SHA)
    second = HELPER.evaluation_version("0.1.1", other)

    assert first != second
    assert first.endswith("+g0123456789ab")
    assert second.endswith("+gfedcba987654")
    assert first.split("+", 1)[0] == second.split("+", 1)[0] == "0.1.1~dev.554"


def test_evaluation_version_sorts_between_physical_and_future_upstream() -> None:
    evaluation = HELPER.evaluation_version("0.1.1", SHA)
    physical_540 = "0.1.1~dev.540+gbbbbbbbbbbbb"
    physical_544 = "0.1.1~dev.544+gaaaaaaaaaaaa"
    # The latest ordinary upstream candidate this evaluation build is prepared
    # against; the explicit evaluation sequence must order strictly after it.
    upstream_553 = "0.1.1~dev.553+g2e8b2ec33b26"
    upstream_555 = "0.1.1~dev.555+gcccccccccccc"
    ordered = [physical_540, physical_544, upstream_553, evaluation, upstream_555]

    def key(version: str) -> tuple[int, str]:
        match = re.fullmatch(
            r"0\.1\.1~dev\.([0-9]+)\+g([0-9a-f]{12})", version
        )
        assert match is not None
        return int(match.group(1)), match.group(2)

    assert [key(item) for item in ordered] == sorted(key(item) for item in ordered)
    dpkg = shutil.which("dpkg") or ("/usr/bin/dpkg" if Path("/usr/bin/dpkg").exists() else None)
    if dpkg is None:
        return
    for lower, higher in pairwise(ordered):
        compared = subprocess.run(
            [dpkg, "--compare-versions", higher, "gt", lower],
            check=False,
            capture_output=True,
            text=True,
        )
        assert compared.returncode == 0, compared.stderr


def test_fingerprint_hashes_raw_ed25519_public_bytes() -> None:
    raw32 = bytes(range(32))

    assert HELPER.key_fingerprint(raw32) == hashlib.sha256(raw32).hexdigest()
    assert HELPER.ED25519_SPKI_PREFIX == BUILD_MODULE.ED25519_SPKI_PREFIX


def test_verify_key_rejects_world_readable_key(tmp_path: Path) -> None:
    key = tmp_path / "open.pem"
    key.write_text("not-a-key\n")
    key.chmod(0o644)

    result = run_helper(
        "verify-key",
        "--private-key",
        str(key),
        "--expected",
        "a" * 64,
    )

    assert result.returncode == 64
    assert result.stdout == ""
    assert "evaluation input is invalid" in result.stderr
    assert "not-a-key" not in result.stderr


def test_verify_key_rejects_non_ed25519(tmp_path: Path) -> None:
    key = tmp_path / "rsa.pem"
    generate_private_key(key, "RSA")

    result = run_helper(
        "verify-key",
        "--private-key",
        str(key),
        "--expected",
        "a" * 64,
    )

    assert result.returncode == 64
    assert result.stdout == ""
    assert key.read_text() not in result.stderr
    assert key.read_text() not in result.stdout


@pytest.mark.skipif(not openssl_supports_ed25519(), reason="runner OpenSSL cannot generate Ed25519")
def test_verify_key_matches_sign_agent_raw32_extraction(tmp_path: Path) -> None:
    key = tmp_path / "ed25519.pem"
    generate_private_key(key, "ED25519")
    public_der = subprocess.run(
        [
            "/usr/bin/openssl",
            "pkey",
            "-in",
            str(key),
            "-pubout",
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    ).stdout
    assert public_der.startswith(BUILD_MODULE.ED25519_SPKI_PREFIX)
    assert len(public_der) == 44
    expected = hashlib.sha256(public_der[-32:]).hexdigest()

    result = run_helper(
        "verify-key",
        "--private-key",
        str(key),
        "--expected",
        expected,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [f"fingerprint={expected}"]
    signature, public_hex = BUILD_MODULE.sign_agent(tmp_path, key, b"artifact")
    assert signature
    assert hashlib.sha256(bytes.fromhex(public_hex.strip().decode())).hexdigest() == expected
    mismatch = run_helper(
        "verify-key",
        "--private-key",
        str(key),
        "--expected",
        "b" * 64,
    )
    assert mismatch.returncode == 64
    assert mismatch.stdout == ""
