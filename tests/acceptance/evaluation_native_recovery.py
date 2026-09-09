#!/usr/bin/env python3
"""Disposable ARM64 package-filesystem native recovery proof.

Not native bootstrap, Controller upgrade, enrollment, synthetic canary, or
physical GPU acceptance. The baseline preinst blocks dpkg downgrade; restore
uses scripts/evaluation-native-checkpoint.py. Root runs bootstrap/canary
separately.

Baseline and candidate are explicitly pinned (source SHA plus exact package
version) and may share the same Ed25519 package key: candidate identity is
proven against the verified candidate package, never by key inequality.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time
from collections.abc import Mapping, Sequence
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path, PurePosixPath
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.acceptance.evaluation_local_release import (
    EVALUATION_ORIGIN,
    MAX_PACKAGE_BYTES,
    SOURCE_SHA,
    _read_canonical_document,
    require_disposable_evaluation_context,
    verify_local_signed_release,
)
from tests.acceptance.test_spark_lifecycle import (
    LifecycleError,
    SparkLifecycle,
    _atomic_write,
)

PACKAGE = "vonk-forge-agent"
KIND = "evaluation-native-package-filesystem-recovery"
CHECKPOINT = ROOT / "scripts/evaluation-native-checkpoint.py"
VERIFY_DEB = ROOT / "scripts/verify-agent-deb"
CHECKPOINT_DIR = Path("/var/backups/vonk-evaluation-native-checkpoint")
DEV_VERSION = re.compile(r"\A0\.1\.1~dev\.(0|[1-9][0-9]{0,6})\+g([0-9a-f]{12})\Z")
INSTALLED_AGENT = "/usr/lib/vonk-forge/vonk-agent"
INSTALLED_HELPER = "/usr/lib/vonk-forge/vonk-agent-helper"
INSTALLED_RELEASE_KEY = "/usr/share/keyrings/vonk-forge-release.pub"
APT_CHANGE = re.compile(r"^(Inst|Remv|Purg)\s+(\S+)")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
STOPPED, SKIP_LOAD = (
    frozenset({"inactive", "failed"}),
    frozenset({"not-found", "masked"}),
)
MAX_ARCHIVE_BYTES, MAX_MEMBERS = 1024**3, 128
FIXTURE_TOML = b'node_id = "spk_00000000000000000000000000000001"\n'
# Public RFC 8032 test-vector key; no private grant key or enrollment is used.
FIXTURE_AUTHORITY = (
    b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\n"
)
FIXTURE_FIREWALL = b"""VONK_NAS_MANAGEMENT_IP=198.18.250.2
VONK_NODE_MANAGEMENT_IP=198.18.250.1
VONK_NODE_FABRIC_IP=198.19.250.1
VONK_PEER_FABRIC_IP=198.19.250.2
VONK_ENDPOINT_HOST_PORTS=8000,8101
VONK_HOST_ENDPOINT_PORTS=8888
VONK_RENDEZVOUS_PORT=29500
"""
FIXTURE_CREDENTIAL = b"evaluation-native-recovery-fixture-credential\n"
DENIED = (
    "controller_started",
    "controller_upgrade_acceptance",
    "enrollment",
    "model_canary",
    "native_bootstrap_acceptance",
    "native_setup_executed",
    "old_native_started",
    "physical_gpu_acceptance",
    "publication_acceptance",
    "synthetic_canary",
)
BASELINE_BUNDLE_SCHEMA = {
    "archive": "evaluation-native-baseline.tar",
    "canonical_manifest": True,
    "files": [
        "manifest.json",
        "vonk-forge-agent_<version>_arm64.deb",
        "vonk-forge-agent_<version>_arm64.deb.sha256",
        "vonk-forge-agent_<version>_arm64.deb.host.sig",
        "vonk-forge-release.pub",
    ],
    "kind": "evaluation-native-baseline-bundle",
    "notes": [
        "Uncompressed tar of regular files; no symlinks or absolute paths.",
        "manifest.json is canonical JSON with exactly the documented keys.",
        "vonk-forge-release.pub is 64 hex chars of the Ed25519 package key.",
        "release_key_sha256 is SHA-256 of those 32 raw key bytes.",
        "host.sig is 128 hex chars over VONK-HOST-ARTIFACT-V1 NUL deb NUL sha256(deb).",
        ("The package key may be the same evaluation Ed25519 key as the candidate;"
         " it is never the installer RSA release key."),
        "version must equal the baseline version pinned by the caller.",
    ],
    "schema_version": 2,
    "version": "0.1.1~dev.<serial>+gSOURCE12 for the pinned baseline source",
}
CLEAN_ENV = {
    "DEBIAN_FRONTEND": "noninteractive",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}


class BaselineBundle(NamedTuple):
    deb: Path
    version: str
    serial: int
    source_sha: str
    package_sha256: str
    release_key_sha256: str
    key_file_sha256: str
    depends: str


class PackagePayload(NamedTuple):
    """Digests of the identity files carried by a verified agent package."""

    agent_sha256: str
    helper_sha256: str
    key_file_sha256: str
    release_key_sha256: str


def parse_dev_version(version: str, source_sha: str, label: str) -> int:
    """Return the dev serial of an exact version pinned to ``source_sha``."""
    match = DEV_VERSION.fullmatch(version)
    if (
        SOURCE_SHA.fullmatch(source_sha) is None
        or match is None
        or match.group(2) != source_sha[:12]
    ):
        raise LifecycleError(f"{label} version pin is invalid")
    return int(match.group(1))


def run(argv: Sequence[str], *, sudo: bool = False, timeout: int = 120):
    if "--force-downgrade" in argv:
        raise LifecycleError("force-downgrade is refused")
    command = ["sudo", "-n", "--", *argv] if sudo else list(argv)
    try:
        return subprocess.run(
            command, capture_output=True, check=False, env=CLEAN_ENV, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LifecycleError(f"command failed: {Path(argv[0]).name}") from error


def require(argv: Sequence[str], *, sudo: bool = False, timeout: int = 120) -> bytes:
    result = run(argv, sudo=sudo, timeout=timeout)
    if result.returncode != 0:
        raise LifecycleError(f"command rejected: {Path(argv[0]).name}")
    return result.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def staging_file(path: Path, label: str, *, maximum: int) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LifecycleError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= maximum
        or metadata.st_mode & 0o002
        or metadata.st_uid not in {0, os.geteuid()}
    ):
        raise LifecycleError(f"{label} is unsafe")
    return sha256_file(path)


def extract_archive(archive: Path, expected: str, destination: Path) -> None:
    if HEX64.fullmatch(expected) is None:
        raise LifecycleError("archive digest is invalid")
    if staging_file(archive, "signed archive", maximum=MAX_ARCHIVE_BYTES) != expected:
        raise LifecycleError("archive digest does not match the pin")
    if destination.exists():
        raise LifecycleError("extract destination already exists")
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, "r:") as tar:
        members = tar.getmembers()
        if (
            len(members) > MAX_MEMBERS
            or sum(item.size for item in members) > MAX_ARCHIVE_BYTES
        ):
            raise LifecycleError("archive member set is unsafe")
        names: set[str] = set()
        for member in members:
            name = member.name.removeprefix("./").rstrip("/")
            path = PurePosixPath(name)
            unsafe = (
                not name
                or path.is_absolute()
                or ".." in path.parts
                or str(path) != name
                or name in names
                or member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            )
            if unsafe:
                raise LifecycleError("archive member path is unsafe")
            names.add(name)
        tar.extractall(destination, filter="data")
    if any(path.is_symlink() for path in destination.rglob("*")):
        raise LifecycleError("extracted tree contains a symlink")


def parse_apt_changes(text: str) -> set[str]:
    return {
        match.group(2)
        for line in text.splitlines()
        if (match := APT_CHANGE.match(line))
    }


def depend_names(field: str) -> set[str]:
    names: set[str] = set()
    for clause in field.split(","):
        token = clause.split("|")[0].strip().split()
        if (
            token
            and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", token[0])
            and token[0] != PACKAGE
        ):
            names.add(token[0])
    return names


def restore_argv(
    checkpoint_dir: Path,
    report: Mapping[str, object],
    *,
    current_version: str,
    current_agent: str,
    current_helper: str,
    apply: bool,
) -> list[str]:
    argv = [
        "/usr/bin/python3",
        os.fspath(CHECKPOINT),
        "--checkpoint-dir",
        os.fspath(checkpoint_dir),
        "--restore",
        "--checkpoint-digest",
        str(report["checkpoint_digest"]),
        "--trusted-identity",
        str(report["trusted_identity"]),
        "--current-package-version",
        current_version,
        "--current-agent-sha256",
        current_agent,
        "--current-helper-sha256",
        current_helper,
    ]
    return [*argv, "--apply"] if apply else argv


def load_script(name: str, path: Path):
    loader = SourceFileLoader(name, str(path))
    spec = spec_from_loader(loader.name, loader)
    if spec is None:
        raise LifecycleError(f"{path.name} is unavailable")
    module = module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def ed25519_key(path: Path, label: str) -> tuple[bytes, str]:
    staging_file(path, label, maximum=16 * 1024)
    try:
        raw = bytes.fromhex(path.read_text(encoding="ascii").strip())
    except ValueError as error:
        raise LifecycleError(f"{label} is invalid") from error
    if len(raw) != 32:
        raise LifecycleError(f"{label} is invalid")
    return raw, hashlib.sha256(raw).hexdigest()


def verify_host_signature(deb: Path, public_key: bytes, digest: str) -> None:
    module = load_script("verify_agent_deb", VERIFY_DEB)
    try:
        module._verify_package_signature(public_key, deb, digest)
    except module.VerificationError as error:
        raise LifecycleError("package host signature is invalid") from error


def deb_field(deb: Path, name: str) -> str:
    return (
        require(["/usr/bin/dpkg-deb", "--field", os.fspath(deb), name]).decode().strip()
    )


def require_real_path(root: Path, absolute: str) -> Path:
    """Reject a symlinked component so identity digests cannot be redirected."""
    path = root
    for part in PurePosixPath(absolute).parts[1:]:
        path = path / part
        if path.is_symlink():
            raise LifecycleError(f"package payload path is unsafe: {absolute}")
    return path


def payload_digests(root: Path) -> PackagePayload:
    """Digest the identity files of an already extracted package tree."""
    for absolute in (INSTALLED_AGENT, INSTALLED_HELPER, INSTALLED_RELEASE_KEY):
        require_real_path(root, absolute)
    agent = staging_file(
        root / INSTALLED_AGENT.lstrip("/"), "package agent", maximum=MAX_PACKAGE_BYTES
    )
    helper = staging_file(
        root / INSTALLED_HELPER.lstrip("/"), "package helper", maximum=MAX_PACKAGE_BYTES
    )
    key_path = root / INSTALLED_RELEASE_KEY.lstrip("/")
    _raw, key_id = ed25519_key(key_path, "package release key")
    return PackagePayload(agent, helper, sha256_file(key_path), key_id)


def package_payload(deb: Path, destination: Path) -> PackagePayload:
    """Extract the verified package into a private tree and digest its identity."""
    if destination.exists():
        raise LifecycleError("package payload destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    require(
        ["/usr/bin/dpkg-deb", "--extract", os.fspath(deb), os.fspath(destination)],
        timeout=300,
    )
    return payload_digests(destination)


def load_baseline(
    root: Path, expected_source: str, expected_version: str
) -> BaselineBundle:
    if SOURCE_SHA.fullmatch(expected_source) is None:
        raise LifecycleError("baseline source is invalid")
    serial = parse_dev_version(expected_version, expected_source, "baseline")
    document = _read_canonical_document(root / "manifest.json", "baseline manifest")
    version = str(document.get("version", ""))
    digest, key_digest = (
        str(document.get("package_sha256", "")),
        str(document.get("release_key_sha256", "")),
    )
    required = {
        "architecture",
        "kind",
        "package",
        "package_sha256",
        "release_key_sha256",
        "schema_version",
        "source_sha",
        "version",
    }
    invalid = (
        set(document) != required
        or document.get("schema_version") != 2
        or document.get("kind") != "evaluation-native-baseline-bundle"
        or document.get("package") != PACKAGE
        or document.get("architecture") != "arm64"
        or document.get("source_sha") != expected_source
        or version != expected_version
        or HEX64.fullmatch(digest) is None
        or HEX64.fullmatch(key_digest) is None
    )
    if invalid:
        raise LifecycleError("baseline identity is invalid")
    deb = root / f"vonk-forge-agent_{version}_arm64.deb"
    package_digest = staging_file(deb, "baseline package", maximum=MAX_PACKAGE_BYTES)
    sidecar = Path(str(deb) + ".sha256")
    staging_file(sidecar, "baseline package digest", maximum=256)
    staging_file(
        Path(str(deb) + ".host.sig"), "baseline package signature", maximum=256
    )
    pub = root / "vonk-forge-release.pub"
    key, computed_key = ed25519_key(pub, "baseline release key")
    if (
        package_digest != digest
        or sidecar.read_text(encoding="ascii").strip().split() != [digest, deb.name]
        or computed_key != key_digest
    ):
        raise LifecycleError("baseline package identity does not match the manifest")
    verify_host_signature(deb, key, package_digest)
    if (
        deb_field(deb, "Package") != PACKAGE
        or deb_field(deb, "Version") != version
        or deb_field(deb, "Architecture") != "arm64"
    ):
        raise LifecycleError("baseline package fields are invalid")
    return BaselineBundle(
        deb,
        version,
        serial,
        expected_source,
        package_digest,
        key_digest,
        sha256_file(pub),
        deb_field(deb, "Depends"),
    )


def load_current(
    bundle: Path, public_key: Path, candidate_source: str, candidate_version: str
):
    if SOURCE_SHA.fullmatch(candidate_source) is None:
        raise LifecycleError("candidate source is invalid")
    serial = parse_dev_version(candidate_version, candidate_source, "candidate")
    trust = bundle / "installer-release-public.pem"
    staging_file(trust, "bundle installer public key", maximum=16 * 1024)
    staging_file(public_key, "checkout installer public key", maximum=16 * 1024)
    if trust.read_bytes() != public_key.read_bytes():
        raise LifecycleError(
            "installer public key does not match the bundle trust anchor"
        )
    assembly = _read_canonical_document(bundle / "assembly.json", "assembly receipt")
    version, generation = (
        str(assembly.get("version", "")),
        str(assembly.get("generation", "")),
    )
    if (
        assembly.get("source") != candidate_source
        or version != candidate_version
        or HEX64.fullmatch(generation) is None
    ):
        raise LifecycleError("candidate assembly identity is invalid")
    artifacts = verify_local_signed_release(
        argparse.Namespace(
            candidate_release=bundle
            / "objects"
            / f"artifacts/dev/releases/{generation}/release.json",
            object_root=bundle / "objects",
            installer_public_key=public_key,
            compose_overlay=bundle / "compose-overlay.yml",
            channel="dev",
            version=version,
            source_sha=candidate_source,
            generation=generation,
            platform="linux-arm64",
            origin=EVALUATION_ORIGIN,
        )
    )
    # Materialize the verifier sidecar from the already verified signed manifest.
    # It is a checksum projection, not a new package signing authority.
    checksum = Path(str(artifacts.package) + ".sha256")
    with checksum.open("x") as output:
        output.write(
            f"{artifacts.artifact_digests['agent-package-linux-arm64']}  "
            f"{artifacts.package.name}\n"
        )
    checksum.chmod(0o600)
    payload = json.loads(
        require(
            [
                sys.executable,
                os.fspath(VERIFY_DEB),
                "--json",
                os.fspath(artifacts.package),
            ],
            timeout=180,
        ).decode()
    )
    if payload.get("ok") is not True or payload.get("version") != version:
        raise LifecycleError("candidate package verification failed")
    return artifacts, version, serial, generation


def apt_install(deb: Path) -> None:
    result = run(
        [
            "/usr/bin/apt-get",
            "--simulate",
            "--no-install-recommends",
            "install",
            os.fspath(deb),
        ],
        sudo=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise LifecycleError("APT simulation was rejected")
    if parse_apt_changes(result.stdout.decode("utf-8", errors="replace")) != {PACKAGE}:
        raise LifecycleError("APT simulation would change a non-Vonk package")
    require(
        [
            "/usr/bin/apt-get",
            "install",
            "--no-install-recommends",
            "-y",
            os.fspath(deb),
        ],
        sudo=True,
        timeout=300,
    )


def stop_native_units(units: Sequence[str]) -> None:
    for unit in units:
        shown = require(
            [
                "/usr/bin/systemctl",
                "--system",
                "show",
                "--property=LoadState",
                "--property=ActiveState",
                unit,
            ],
            sudo=True,
        ).decode()
        values = dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)
        if values.get("LoadState") in SKIP_LOAD or values.get("ActiveState") in STOPPED:
            continue
        require(["/usr/bin/systemctl", "--system", "stop", "--", unit], sudo=True)


def wait_for_package_finisher(paths: Sequence[str]) -> None:
    # dpkg's postinst schedules helper activation after dpkg releases its lock.
    # Let that supported finisher complete before quiescing native services.
    deadline = time.monotonic() + 90
    while True:
        pending = [
            path
            for path in paths
            if run(["/usr/bin/test", "-e", path], sudo=True).returncode == 0
        ]
        if not pending:
            return
        if time.monotonic() >= deadline:
            journal = run(
                [
                    "/usr/bin/journalctl",
                    "--no-pager",
                    "-n",
                    "40",
                    "-u",
                    "vonk-forge-package-helper.service",
                    "-u",
                    "vonk-forge-package-helper.socket",
                    "-u",
                    "vonk-forge-docker-firewall.service",
                ],
                sudo=True,
            )
            diagnostic = SparkLifecycle._redact_diagnostics(
                journal.stdout.decode(errors="replace"),
                limit=4000,
            )
            raise LifecycleError(
                "package activation did not finish: "
                + ", ".join(pending)
                + "; helper journal: "
                + diagnostic
            )
        time.sleep(1)


def prepare_stopped_runtime() -> None:
    # systemd removes RuntimeDirectory when the agent stops. Offline rootless
    # Podman inspection still requires that private runtime directory.
    require(
        [
            "/usr/bin/install",
            "-d",
            "-o",
            "vonk-agent",
            "-g",
            "vonk-agent",
            "-m",
            "0700",
            "/run/vonk-forge-agent",
        ],
        sudo=True,
    )
    enabled = Path("/sys/module/apparmor/parameters/enabled")
    if enabled.exists() and enabled.read_text().strip() == "Y":
        profile = Path("/etc/apparmor.d/podman")
        staging_file(profile, "distribution Podman profile", maximum=1024 * 1024)
        require(["/usr/sbin/apparmor_parser", "--replace", str(profile)], sudo=True)


def require_quiescent(version: str, sqlite_paths: Sequence[str]) -> None:
    status = (
        require(
            ["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}|${Version}", PACKAGE]
        )
        .decode()
        .strip()
    )
    state, separator, observed_version = status.partition("|")
    if state.strip() != "ii" or not separator or observed_version != version:
        raise LifecycleError("native package is not fully configured")
    for database in sqlite_paths:
        for suffix in ("-wal", "-shm"):
            if run(
                ["/usr/bin/test", "!", "-e", database + suffix], sudo=True
            ).returncode:
                raise LifecycleError("sqlite is not quiescent")


def checkpoint_json(argv: Sequence[str]) -> dict[str, object]:
    result = run(argv, sudo=True, timeout=600)
    try:
        payload = json.loads(result.stdout.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleError("checkpoint helper output is invalid") from error
    if (
        isinstance(payload, dict)
        and not result.returncode
        and payload.get("ok") is True
    ):
        return payload
    reason = (
        payload.get("reason")
        if isinstance(payload, dict)
        else "checkpoint helper failed"
    )
    raise LifecycleError(str(reason))


def live_sha256(path: str) -> str:
    digest = require(["/usr/bin/sha256sum", "--", path], sudo=True).decode().split()[0]
    if HEX64.fullmatch(digest) is None:
        raise LifecycleError("live digest is invalid")
    return digest


def recover(arguments: argparse.Namespace) -> dict[str, object]:
    require_disposable_evaluation_context()
    if SOURCE_SHA.fullmatch(arguments.harness_head) is None:
        raise LifecycleError("harness head is invalid")
    artifacts, candidate_version, candidate_serial, generation = load_current(
        Path(os.path.abspath(os.fspath(arguments.current_bundle))),
        Path(os.path.abspath(os.fspath(arguments.installer_public_key))),
        arguments.candidate_source,
        arguments.candidate_version,
    )
    baseline = load_baseline(
        Path(os.path.abspath(os.fspath(arguments.baseline_root))),
        arguments.baseline_source,
        arguments.baseline_version,
    )
    if arguments.candidate_source == arguments.baseline_source:
        raise LifecycleError("old and new identities are not distinct")
    if candidate_serial <= baseline.serial or candidate_version == baseline.version:
        raise LifecycleError("candidate package version does not increase")
    helper = load_script("evaluation_native_checkpoint", CHECKPOINT)
    if run(["/usr/bin/dpkg-query", "-W", PACKAGE]).returncode == 0:
        raise LifecycleError("vonk-forge-agent is already installed")
    require(["/usr/bin/apt-get", "update"], sudo=True, timeout=180)
    union = sorted(
        depend_names(baseline.depends)
        | depend_names(deb_field(artifacts.package, "Depends"))
    )
    if union:
        require(
            [
                "/usr/bin/apt-get",
                "install",
                "--no-install-recommends",
                "-y",
                "--",
                *union,
            ],
            sudo=True,
            timeout=300,
        )
    apt_install(baseline.deb)
    wait_for_package_finisher(helper.PENDING_RECOVERY_PATHS)
    fixtures = Path(arguments.output).resolve().parent / "native-recovery-fixtures"
    fixtures.mkdir(mode=0o700, exist_ok=True)
    toml_path, cred_path, sqlite_path = (
        fixtures / "agent.toml",
        fixtures / "fixture.key",
        fixtures / "state.sqlite",
    )
    toml_path.write_bytes(FIXTURE_TOML)
    cred_path.write_bytes(FIXTURE_CREDENTIAL)
    authority_path = fixtures / "host-helper-authority.pub"
    authority_path.write_bytes(FIXTURE_AUTHORITY)
    firewall_path = fixtures / "docker-firewall.conf"
    firewall_path.write_bytes(FIXTURE_FIREWALL)
    # Disposable host only: provide the topology required by the unchanged
    # packaged firewall dependency. No model or Controller is started here.
    for interface, address in (
        ("vrec-mgmt", "198.18.250.1/24"),
        ("vrec-fabric", "198.19.250.1/24"),
    ):
        require(["/usr/sbin/ip", "link", "add", interface, "type", "dummy"], sudo=True)
        require(
            ["/usr/sbin/ip", "address", "add", address, "dev", interface], sudo=True
        )
        require(["/usr/sbin/ip", "link", "set", interface, "up"], sudo=True)
    connection = sqlite3.connect(sqlite_path)
    try:
        connection.execute("CREATE TABLE fixture (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO fixture VALUES ('kind', 'evaluation-native-recovery')"
        )
        connection.commit()
    finally:
        connection.close()
    for source, destination, mode in (
        (toml_path, "/etc/vonk-forge-agent/agent.toml", "0640"),
        (authority_path, "/etc/vonk-forge-agent/host-helper-authority.pub", "0644"),
        (firewall_path, "/etc/vonk-forge-agent/docker-firewall.conf", "0600"),
        (cred_path, "/var/lib/vonk-forge-agent/credentials/fixture.key", "0600"),
        (sqlite_path, "/var/lib/vonk-forge-agent/state.sqlite", "0600"),
    ):
        require(
            ["/usr/bin/install", "-D", "-m", mode, os.fspath(source), destination],
            sudo=True,
        )
    stop_native_units(helper.NATIVE_UNITS)
    prepare_stopped_runtime()
    require_quiescent(baseline.version, helper.SQLITE_PATHS)
    retained_link = Path(
        "/var/lib/vonk-forge-agent/runs/12345678-1234-4234-8234-123456789abc/outputs/model/weights"
    )
    require(["/usr/bin/install", "-d", "-m", "0700", str(retained_link.parent)], sudo=True)
    require(["/usr/bin/ln", "-s", "/models/weights", str(retained_link)], sudo=True)
    checkpoint_dir = Path(arguments.checkpoint_dir)
    require(
        [
            "/usr/bin/install",
            "-d",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0700",
            os.fspath(checkpoint_dir),
        ],
        sudo=True,
    )
    captured = checkpoint_json(
        [
            "/usr/bin/python3",
            os.fspath(CHECKPOINT),
            "--checkpoint-dir",
            os.fspath(checkpoint_dir),
        ]
    )
    if (
        captured.get("package_version") != baseline.version
        or captured.get("release_key_sha256") != baseline.key_file_sha256
    ):
        raise LifecycleError("checkpoint identity does not match the baseline package")
    apt_install(artifacts.package)
    wait_for_package_finisher(helper.PENDING_RECOVERY_PATHS)
    stop_native_units(helper.NATIVE_UNITS)
    prepare_stopped_runtime()
    require_quiescent(candidate_version, helper.SQLITE_PATHS)
    live_agent = live_sha256(INSTALLED_AGENT)
    live_helper = live_sha256(INSTALLED_HELPER)
    live_key = live_sha256(INSTALLED_RELEASE_KEY)
    try:
        live_key_id = hashlib.sha256(
            bytes.fromhex(
                require(["/usr/bin/cat", INSTALLED_RELEASE_KEY], sudo=True)
                .decode()
                .strip()
            )
        ).hexdigest()
    except ValueError as error:
        raise LifecycleError("installed candidate release key is invalid") from error
    # The baseline and the candidate may legitimately share the evaluation
    # package key, so identity is proven against the verified candidate package
    # itself rather than by inequality with the baseline key.
    expected = package_payload(artifacts.package, fixtures / "candidate-payload")
    if (
        live_agent != expected.agent_sha256
        or live_helper != expected.helper_sha256
        or live_key != expected.key_file_sha256
        or live_key_id != expected.release_key_sha256
    ):
        raise LifecycleError(
            "installed candidate identity does not match the verified package"
        )
    if (
        (live_agent == captured.get("agent_sha256")
         and live_helper == captured.get("helper_sha256"))
        or candidate_version == captured.get("package_version")
    ):
        raise LifecycleError("old and new payload identities are not distinct")
    checkpoint_json(
        restore_argv(
            checkpoint_dir,
            captured,
            current_version=candidate_version,
            current_agent=live_agent,
            current_helper=live_helper,
            apply=False,
        )
    )
    restored = checkpoint_json(
        restore_argv(
            checkpoint_dir,
            captured,
            current_version=candidate_version,
            current_agent=live_agent,
            current_helper=live_helper,
            apply=True,
        )
    )
    require_quiescent(baseline.version, helper.SQLITE_PATHS)
    restored_agent = live_sha256(INSTALLED_AGENT)
    restored_helper = live_sha256(INSTALLED_HELPER)
    restored_key = live_sha256(INSTALLED_RELEASE_KEY)
    restored_toml = live_sha256("/etc/vonk-forge-agent/agent.toml")
    restored_link = require(["/usr/bin/readlink", str(retained_link)], sudo=True)
    if restored_link.strip() != b"/models/weights":
        raise LifecycleError("retained container model link was not restored")
    if (
        restored_agent != captured.get("agent_sha256")
        or restored_helper != captured.get("helper_sha256")
        or restored_key != baseline.key_file_sha256
        or restored.get("package_version") != baseline.version
        or restored_toml != hashlib.sha256(FIXTURE_TOML).hexdigest()
        or restored.get("checkpoint_digest") != captured.get("checkpoint_digest")
    ):
        raise LifecycleError("restored baseline identity does not match the checkpoint")
    proof = {
        "baseline": {
            "agent_sha256": captured["agent_sha256"],
            "helper_sha256": captured["helper_sha256"],
            "package_sha256": baseline.package_sha256,
            "release_key_sha256": baseline.release_key_sha256,
            "source_sha": baseline.source_sha,
            "version": baseline.version,
        },
        "baseline_bundle_schema": BASELINE_BUNDLE_SCHEMA,
        "candidate": {
            "agent_sha256": live_agent,
            "generation": generation,
            "helper_sha256": live_helper,
            "package_sha256": artifacts.artifact_digests["agent-package-linux-arm64"],
            "release_key_file_sha256": live_key,
            "release_key_sha256": live_key_id,
            "release_key_shared_with_baseline": (
                live_key_id == baseline.release_key_sha256
            ),
            "source_sha": arguments.candidate_source,
            "version": candidate_version,
        },
        "checkpoint": {
            "checkpoint_digest": captured["checkpoint_digest"],
            "helper": "scripts/evaluation-native-checkpoint.py",
            "helper_sha256": sha256_file(CHECKPOINT),
            "package_version": captured["package_version"],
            "trusted_identity": captured["trusted_identity"],
        },
        "harness_head": arguments.harness_head,
        "kind": KIND,
        "ok": True,
        "proof_boundary": KIND,
        "restored": {
            "agent_sha256": restored_agent,
            "config_sha256": restored_toml,
            "helper_sha256": restored_helper,
            "package_version": baseline.version,
            "release_key_sha256": restored_key,
            "state_sha256": live_sha256("/var/lib/vonk-forge-agent/state.sqlite"),
        },
        "schema_version": 1,
    }
    proof.update(dict.fromkeys(DENIED, False))
    return proof


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    extract = commands.add_parser("extract")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--sha256", required=True)
    extract.add_argument("--destination", type=Path, required=True)
    run_cmd = commands.add_parser("run")
    run_cmd.add_argument("--current-bundle", type=Path, required=True)
    run_cmd.add_argument("--installer-public-key", type=Path, required=True)
    run_cmd.add_argument("--candidate-source", required=True)
    run_cmd.add_argument("--candidate-version", required=True)
    run_cmd.add_argument("--baseline-root", type=Path, required=True)
    run_cmd.add_argument("--baseline-source", required=True)
    run_cmd.add_argument("--baseline-version", required=True)
    run_cmd.add_argument("--harness-head", required=True)
    run_cmd.add_argument("--output", type=Path, required=True)
    run_cmd.add_argument("--checkpoint-dir", type=Path, default=CHECKPOINT_DIR)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        require_disposable_evaluation_context()
        if arguments.command == "extract":
            extract_archive(arguments.archive, arguments.sha256, arguments.destination)
            return 0
        if arguments.command != "run":
            raise LifecycleError("evaluation command is invalid")
        _atomic_write(arguments.output, recover(arguments))
    except LifecycleError as error:
        print(f"evaluation native recovery failed: {error}", file=sys.stderr)
        if arguments.command == "run":
            try:
                _atomic_write(
                    arguments.output,
                    {
                        "kind": KIND,
                        "native_bootstrap_acceptance": False,
                        "ok": False,
                        "proof_boundary": KIND,
                        "reason": str(error),
                        "schema_version": 1,
                    },
                )
            except (OSError, LifecycleError):
                return 1
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
