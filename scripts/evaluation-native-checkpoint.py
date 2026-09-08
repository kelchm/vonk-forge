#!/usr/bin/python3
"""Narrow native package checkpoint/restore helper for ext4 Linux hosts.

This is not a Debian downgrade bypass, not a full OS snapshot, and not
disaster recovery. It archives a prior filesystem and package-state
checkpoint and restores those exact captured bytes after a signed local
package transition. Model lifecycle stays Controller-owned. The helper
never stops workloads, never starts services, never restores Controller
CA/server state, and never invokes dpkg --force-downgrade or rewrites
package versions.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

PACKAGE = "vonk-forge-agent"
SCHEMA_VERSION = 1
KIND = "evaluation-native-checkpoint"
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 20_000
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$")
MACHINE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
PACKAGE_VERSION_RE = re.compile(r"^[0-9A-Za-z.+~:-]+$")
DIGEST_RE = HEX64

NATIVE_UNITS = (
    "vonk-forge-agent.service",
    "vonk-forge-package-helper.service",
    "vonk-forge-package-helper.socket",
    "vonk-forge-docker-firewall.service",
    "vonk-forge-package-upgrade-recover.service",
    "vonk-forge-package-upgrade-recover-capsule.service",
    "vonk-forge-package-helper-upgrade-finish.service",
    "vonk-forge-package-rollback.service",
)
SHARED_PARENTS = {
    "/",
    "/etc",
    "/lib",
    "/lib/systemd",
    "/lib/systemd/system",
    "/usr",
    "/usr/bin",
    "/usr/lib",
    "/usr/share",
    "/usr/share/doc",
    "/usr/share/keyrings",
    "/var",
    "/var/lib",
}
PACKAGE_OWNED_FILE_ROOTS = {
    "/etc/vonk-forge-agent/containers-storage.conf",
    "/lib/systemd/system/vonk-forge-agent.service",
    "/lib/systemd/system/vonk-forge-docker-firewall.service",
    "/lib/systemd/system/vonk-forge-package-helper.service",
    "/lib/systemd/system/vonk-forge-package-helper.socket",
    "/lib/systemd/system/vonk-forge-package-upgrade-recover.service",
    "/lib/systemd/system/vonk-forge-package-rollback.service",
    "/usr/share/keyrings/vonk-forge-release.pub",
}
PACKAGE_OWNED_DIR_ROOTS = {
    "/etc/systemd/system/vonk-forge-agent.service.d",
    "/etc/systemd/system/vonk-forge-docker-firewall.service.d",
    "/etc/systemd/system/vonk-forge-package-helper.service.d",
    "/etc/systemd/system/vonk-forge-package-helper.socket.d",
    "/lib/systemd/system/vonk-forge-agent.service.d",
    "/lib/systemd/system/vonk-forge-package-helper.socket.d",
    "/lib/systemd/system/vonk-forge-package-upgrade-recover.service.d",
    "/usr/lib/vonk-forge",
    "/usr/share/doc/vonk-forge-agent",
}
ADMIN_DROPIN_ROOTS = (
    "/etc/systemd/system/vonk-forge-agent.service.d",
    "/etc/systemd/system/vonk-forge-docker-firewall.service.d",
    "/etc/systemd/system/vonk-forge-package-helper.service.d",
    "/etc/systemd/system/vonk-forge-package-helper.socket.d",
)
CAPTURE_NAMESPACES = (
    "/etc/vonk-forge-agent",
    "/var/lib/vonk-forge",
)
AGENT_STATE_ROOT = "/var/lib/vonk-forge-agent"
AGENT_STATE_TREES = (
    ".config",
    "credentials",
    "state",
    "runs",
    "run-metadata",
    "installations",
    "workloads",
)
IMMUTABLE_TOPLEVEL = {
    "build-staging",
    "snap",
    "models",
    "builds",
    "base-images",
    "oci-archives",
    "image-imports",
    ".local",
    "containers",
    "distribution",
    "tmp",
}
DPKG_ROOT = "/var/lib/dpkg"
DPKG_SKIP_NAMES = {
    "lock",
    "lock-frontend",
    "lock-frontend.lock",
    "status-lock",
    "Lock",
}
DPKG_LOCK_PATHS = (
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
)
CP_PATH = "/usr/bin/cp"
STOPPED_ACTIVE_STATES = frozenset({"inactive", "failed"})
RUNNING_ACTIVE_STATES = frozenset({"active", "activating", "deactivating", "reloading"})
ACCEPTABLE_LOAD_STATES = frozenset({"loaded", "not-found", "masked"})
CAPTURED_XATTR_NAMES = frozenset({"security.capability"})
CAPTURED_XATTR_PREFIXES = ("user.", "system.posix_acl_")
TAR_METADATA_FLAGS = (
    "--acls",
    "--xattrs",
    "--xattrs-include=*",
    "--numeric-owner",
)
PENDING_RECOVERY_PATHS = (
    "/var/lib/vonk-forge/package-upgrade/intent",
    "/var/lib/vonk-forge/helper-upgrade.pending",
)
SQLITE_PATHS = (
    "/var/lib/vonk-forge-agent/state.sqlite",
    "/var/lib/vonk-forge-agent/telemetry-state.sqlite",
)
CA_OR_SERVER_PATHS = {
    "/etc/vonk-forge-agent/controller-ca.pem",
}
CREDENTIAL_SUFFIXES = (".pk8", ".pem", ".key", ".crt", ".p12", ".pfx")
SCOPE = {
    "full_os_snapshot": False,
    "disaster_recovery": False,
    "restores_ca_or_server_state": False,
    "starts_services": False,
    "downgrade_bypass": False,
    "model_lifecycle": "controller-owned",
}
NOTES = (
    "Not a full OS snapshot and not disaster recovery.",
    "Does not restore Controller CA/server state or start services.",
    "Does not use dpkg --force-downgrade or rewrite package versions.",
    "Immutable model/image caches stay in place.",
    "APT transitions that change non-Vonk packages are refused; root should apt-get --simulate before apply.",
)


class CheckpointError(RuntimeError):
    """Fail-closed checkpoint or restore refusal."""

    def __init__(self, message: str, *, mutated: bool = False) -> None:
        super().__init__(message)
        self.mutated = mutated


class UsageError(RuntimeError):
    """Invalid invocation."""


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
    ) -> RunResult:
        raise NotImplementedError


class SystemCommandRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
    ) -> RunResult:
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }
        if env:
            environment.update(env)
        try:
            completed = subprocess.run(
                list(argv),
                input=input_bytes,
                capture_output=True,
                env=environment,
                cwd="/",
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CheckpointError(f"command failed: {Path(argv[0]).name}") from error
        return RunResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass
class Runtime:
    runner: CommandRunner
    fs_root: Path = Path("/")
    geteuid: Callable[[], int] = os.geteuid
    forced_uid: int | None = None
    tar_path: str = "/usr/bin/tar"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def posix(absolute: str) -> str:
    text = absolute.strip()
    if not text.startswith("/"):
        raise CheckpointError("path is not absolute")
    return str(PurePosixPath(text))


def host_path(runtime: Runtime, absolute: str) -> Path:
    relative = posix(absolute).lstrip("/")
    if runtime.fs_root == Path("/"):
        return Path(posix(absolute))
    return runtime.fs_root / relative


def file_uid(runtime: Runtime, path: Path) -> int:
    if runtime.forced_uid is not None:
        return runtime.forced_uid
    return path.lstat().st_uid


def is_under(absolute: str, root: str) -> bool:
    path = PurePosixPath(posix(absolute))
    base = PurePosixPath(posix(root))
    return path == base or base in path.parents


def package_owned_path(absolute: str) -> bool:
    path = posix(absolute)
    if path in PACKAGE_OWNED_FILE_ROOTS:
        return True
    return any(is_under(path, root) for root in PACKAGE_OWNED_DIR_ROOTS)


def immutable_path(absolute: str) -> bool:
    path = posix(absolute)
    if not is_under(path, AGENT_STATE_ROOT) or path == AGENT_STATE_ROOT:
        return False
    relative = PurePosixPath(path).relative_to(AGENT_STATE_ROOT)
    parts = relative.parts
    if not parts:
        return False
    if parts[0] in IMMUTABLE_TOPLEVEL:
        return True
    return len(parts) >= 3 and parts[0] == "installations" and parts[2] == "models"


def credential_path(absolute: str) -> bool:
    path = posix(absolute).lower()
    name = PurePosixPath(path).name
    if "/credentials/" in path or path.endswith("/credentials"):
        return True
    if name.startswith("observation-receipt"):
        return True
    return name.endswith(CREDENTIAL_SUFFIXES)


def ca_or_server_path(absolute: str) -> bool:
    path = posix(absolute)
    if path in CA_OR_SERVER_PATHS:
        return True
    return any(
        is_under(path, root)
        for root in ("/etc/ssl", "/usr/share/ca-certificates", "/etc/ca-certificates")
    )


def unsafe_component(name: str) -> bool:
    return (
        name in {"", ".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or name.startswith("-")
    )


def captured_xattr_name(name: str) -> bool:
    return name in CAPTURED_XATTR_NAMES or name.startswith(CAPTURED_XATTR_PREFIXES)


def dpkg_lock_path(absolute: str) -> bool:
    path = posix(absolute)
    if path in DPKG_LOCK_PATHS:
        return True
    if not is_under(path, DPKG_ROOT):
        return False
    return PurePosixPath(path).name in DPKG_SKIP_NAMES


def canonical_archive_member_name(raw: str, *, is_dir: bool) -> str:
    if not raw or "\x00" in raw or "\\" in raw:
        raise CheckpointError("archive member path is unsafe")
    name = raw.removeprefix("./")
    if is_dir and name.endswith("/") and name not in {"", "/"}:
        name = name[:-1]
        if name.endswith("/"):
            raise CheckpointError("archive member path is unsafe")
    if (
        not name
        or name.startswith(("/", "./"))
        or name.endswith(("/", "."))
        or posixpath.normpath(name) != name
    ):
        raise CheckpointError("archive member path is unsafe")
    parts = PurePosixPath(name).parts
    if any(unsafe_component(part) for part in parts):
        raise CheckpointError("archive member path is unsafe")
    return name


def relative_member_name(absolute: str) -> str:
    path = posix(absolute).lstrip("/")
    return canonical_archive_member_name(path, is_dir=False)


def member_absolute(name: str) -> str:
    return "/" + canonical_archive_member_name(name, is_dir=False)


def symlink_destination(link_absolute: str, target: str) -> str:
    if not target or "\x00" in target or "\\" in target:
        raise CheckpointError("symlink target is unsafe")
    if target.startswith("/"):
        resolved = posixpath.normpath(target)
    else:
        resolved = posixpath.normpath(
            posixpath.join(posixpath.dirname(posix(link_absolute)), target)
        )
    if resolved.startswith("/"):
        return resolved
    raise CheckpointError("symlink target is unsafe")


def allowed_symlink(link_absolute: str, target: str) -> bool:
    resolved = symlink_destination(link_absolute, target)
    # Model adapters keep container-absolute links in retained run outputs.
    # Preserve these as inert links; never read or restore their target bytes.
    container_model_link = (
        re.fullmatch(
            r"/var/lib/vonk-forge-agent/runs/[0-9a-f-]{36}/outputs/.+",
            link_absolute,
        ) is not None
        and target.startswith("/models/")
        and resolved == target
        and ".." not in PurePosixPath(target).parts
    )
    return (
        container_model_link
        or package_owned_path(resolved)
        or any(is_under(resolved, root) for root in CAPTURE_NAMESPACES)
        or is_under(resolved, AGENT_STATE_ROOT)
        or is_under(resolved, DPKG_ROOT)
        or any(is_under(resolved, root) for root in ADMIN_DROPIN_ROOTS)
    )


def lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def require_inside(path: Path, root: Path) -> None:
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise CheckpointError("path escapes approved root") from error


@contextmanager
def debian_package_locks(runtime: Runtime) -> Iterator[None]:
    descriptors: list[int] = []
    try:
        for absolute in DPKG_LOCK_PATHS:
            path = host_path(runtime, absolute)
            parent = path.parent
            if parent.is_symlink() or not parent.is_dir():
                raise CheckpointError("dpkg lock directory is unsafe")
            flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags, 0o640)
            except OSError as error:
                raise CheckpointError("unable to open dpkg lock") from error
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise CheckpointError("dpkg lock is unsafe")
                fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                os.close(descriptor)
                raise CheckpointError("dpkg or apt lock is held") from error
            except OSError as error:
                os.close(descriptor)
                if error.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise CheckpointError("dpkg or apt lock is held") from error
                raise CheckpointError("unable to acquire dpkg lock") from error
            descriptors.append(descriptor)
        yield
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def require_root(runtime: Runtime) -> None:
    if runtime.geteuid() != 0:
        raise CheckpointError("native checkpoint requires root")


def require_private_dir(runtime: Runtime, path: Path, *, create: bool = False) -> None:
    if create and not lexists(path):
        path.mkdir(mode=0o700, parents=False)
        path.chmod(0o700)
    if path.is_symlink() or not path.is_dir():
        raise CheckpointError("checkpoint directory is unsafe")
    mode = stat.S_IMODE(path.lstat().st_mode)
    if mode & 0o077:
        raise CheckpointError("checkpoint directory is not root-private")
    if file_uid(runtime, path) != 0:
        raise CheckpointError("checkpoint directory is not root-owned")


def require_private_file(runtime: Runtime, path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise CheckpointError("checkpoint input is not a root-private regular file")
    metadata = path.lstat()
    if stat.S_IMODE(metadata.st_mode) & 0o177:
        raise CheckpointError("checkpoint input is not a root-private regular file")
    if file_uid(runtime, path) != 0:
        raise CheckpointError("checkpoint input is not root-owned")
    if metadata.st_nlink != 1:
        raise CheckpointError("checkpoint input has extra hard links")
    if metadata.st_size < 1 or metadata.st_size > MAX_ARCHIVE_BYTES:
        raise CheckpointError("checkpoint archive size is unsafe")


def command(
    runtime: Runtime,
    argv: Sequence[str],
    *,
    input_bytes: bytes | None = None,
    timeout: int = 120,
) -> RunResult:
    return runtime.runner.run(argv, input_bytes=input_bytes, timeout=timeout)


def require_command(
    runtime: Runtime,
    argv: Sequence[str],
    *,
    input_bytes: bytes | None = None,
    timeout: int = 120,
) -> bytes:
    result = command(runtime, argv, input_bytes=input_bytes, timeout=timeout)
    if not result.ok:
        raise CheckpointError(f"command rejected: {Path(argv[0]).name}")
    return result.stdout


def read_text(runtime: Runtime, absolute: str) -> str:
    path = host_path(runtime, absolute)
    if path.is_symlink() or not path.is_file():
        raise CheckpointError(
            f"required file is unsafe: {PurePosixPath(absolute).name}"
        )
    return path.read_text(encoding="utf-8")


def host_binding(hostname: str, machine_id: str) -> str:
    return sha256_bytes(f"{hostname}\n{machine_id}\n".encode())


def trusted_identity(
    *,
    package_version: str,
    agent_sha256: str,
    helper_sha256: str,
    release_key_sha256: str,
    binding: str,
) -> str:
    return sha256_bytes(
        canonical(
            {
                "agent_sha256": agent_sha256,
                "helper_sha256": helper_sha256,
                "host_binding": binding,
                "kind": KIND,
                "package": PACKAGE,
                "package_version": package_version,
                "release_key_sha256": release_key_sha256,
                "schema_version": SCHEMA_VERSION,
            }
        )
    )


def inspect_host_identity(runtime: Runtime) -> tuple[str, str, str]:
    hostname = require_command(runtime, ["/usr/bin/hostname", "-s"]).decode().strip()
    if HOSTNAME_RE.fullmatch(hostname) is None:
        raise CheckpointError("hostname is invalid")
    machine_id = read_text(runtime, "/etc/machine-id").strip()
    if MACHINE_ID_RE.fullmatch(machine_id) is None:
        raise CheckpointError("machine-id is invalid")
    return hostname, machine_id, host_binding(hostname, machine_id)


def dpkg_status(runtime: Runtime) -> tuple[str, str]:
    raw = require_command(
        runtime,
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${db:Status-Abbrev}|${Version}",
            PACKAGE,
        ],
    ).decode()
    status, separator, version = raw.partition("|")
    if not separator:
        raise CheckpointError("native package status is unavailable")
    abbrev = status.strip()
    version = version.strip()
    if abbrev != "ii" or PACKAGE_VERSION_RE.fullmatch(version) is None:
        raise CheckpointError("native package is not fully configured")
    return abbrev, version


def dpkg_file_list(runtime: Runtime) -> list[str]:
    raw = require_command(runtime, ["/usr/bin/dpkg-query", "-L", PACKAGE]).decode()
    paths: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line in {".", "/."}:
            continue
        # dpkg-query annotates a listed path when another package diverts it
        # (Ubuntu usr-merge reports /lib this way). The diversion database is
        # captured separately with all dpkg state; this line is not a file.
        diversion = re.fullmatch(
            r"diverted by [a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)? to: (/.*)", line
        )
        if diversion is not None and paths:
            posix(diversion.group(1))
            continue
        if not line.startswith("/"):
            raise CheckpointError("package file list is unsafe")
        paths.append(posix(line))
    if not paths:
        raise CheckpointError("package file list is empty")
    return paths


def non_vonk_inventory(runtime: Runtime) -> tuple[str, str]:
    raw = require_command(
        runtime,
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n",
        ],
    ).decode()
    lines: list[str] = []
    vonk_line = ""
    for line in raw.splitlines():
        if not line.strip():
            continue
        package, tab, rest = line.partition("\t")
        if not tab or not rest:
            raise CheckpointError("package inventory is malformed")
        if package == PACKAGE:
            vonk_line = line
            continue
        lines.append(line)
    lines.sort()
    return sha256_bytes(("\n".join(lines) + "\n").encode()), vonk_line


def unit_stopped(runtime: Runtime, unit: str) -> bool:
    if unsafe_component(unit) or not unit.endswith((".service", ".socket")):
        raise CheckpointError("native unit name is unsafe")
    result = command(
        runtime,
        [
            "/usr/bin/systemctl",
            "--system",
            "show",
            "--property=LoadState",
            "--property=ActiveState",
            unit,
        ],
    )
    if not result.ok:
        raise CheckpointError("native unit state is unavailable")
    text = result.stdout.decode("utf-8", errors="replace")
    if not text.strip():
        raise CheckpointError("native unit state is unavailable")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise CheckpointError("native unit state is unavailable")
        values[key] = value
    load_state = values.get("LoadState", "")
    active_state = values.get("ActiveState", "")
    if load_state not in ACCEPTABLE_LOAD_STATES:
        raise CheckpointError("native unit state is unavailable")
    if active_state in STOPPED_ACTIVE_STATES:
        return True
    if active_state in RUNNING_ACTIVE_STATES:
        return False
    raise CheckpointError("native unit state is unavailable")


def require_native_services_stopped(runtime: Runtime) -> None:
    running = [unit for unit in NATIVE_UNITS if not unit_stopped(runtime, unit)]
    if running:
        raise CheckpointError("native helper/agent/package services are not stopped")


def podman_running_names(runtime: Runtime, argv: Sequence[str]) -> list[str]:
    result = command(runtime, argv, timeout=30)
    if not result.ok:
        raise CheckpointError("Vonk container discovery failed")
    names: list[str] = []
    for line in result.stdout.decode().splitlines():
        name = line.strip()
        if name:
            names.extend(part.strip() for part in name.split(",") if part.strip())
    return names


def require_no_running_vonk_containers(runtime: Runtime) -> None:
    queries = (
        [
            "/usr/bin/podman",
            "ps",
            "--filter",
            "status=running",
            "--format",
            "{{.Names}}",
        ],
        [
            "/usr/sbin/runuser",
            "-u",
            "vonk-agent",
            "--",
            "/usr/bin/env",
            "XDG_RUNTIME_DIR=/run/vonk-forge-agent",
            "CONTAINERS_STORAGE_CONF=/etc/vonk-forge-agent/containers-storage.conf",
            "/usr/bin/podman",
            "ps",
            "--filter",
            "status=running",
            "--format",
            "{{.Names}}",
        ],
    )
    running: list[str] = []
    for argv in queries:
        running.extend(podman_running_names(runtime, argv))
    vonk = [name for name in running if name.startswith("vonk-")]
    if vonk:
        raise CheckpointError("running Vonk containers must be stopped by the caller")


def require_sqlite_quiescent(runtime: Runtime) -> None:
    for database in SQLITE_PATHS:
        for suffix in ("-wal", "-shm"):
            side = host_path(runtime, database + suffix)
            if lexists(side):
                raise CheckpointError("sqlite is not quiescent")


def require_no_pending_recovery(runtime: Runtime) -> None:
    for absolute in PENDING_RECOVERY_PATHS:
        if lexists(host_path(runtime, absolute)):
            raise CheckpointError("pending package recovery is present")


def current_payload_digests(runtime: Runtime) -> tuple[str, str, str]:
    agent = host_path(runtime, "/usr/lib/vonk-forge/vonk-agent")
    helper = host_path(runtime, "/usr/lib/vonk-forge/vonk-agent-helper")
    key = host_path(runtime, "/usr/share/keyrings/vonk-forge-release.pub")
    for path in (agent, helper, key):
        if path.is_symlink() or not path.is_file():
            raise CheckpointError("native payload path is unsafe")
    return sha256_file(agent), sha256_file(helper), sha256_file(key)


def lstat_kind(path: Path) -> str:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    if stat.S_ISREG(metadata.st_mode):
        return "file"
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    return "other"


def read_captured_xattrs(path: Path) -> dict[str, str]:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except (AttributeError, NotImplementedError):
        if sys.platform == "linux":
            raise CheckpointError("extended attribute support is unavailable")
        return {}
    except OSError as error:
        if error.errno not in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise CheckpointError("unable to enumerate extended attributes") from error
        return {}
    captured: dict[str, str] = {}
    for name in names:
        if not captured_xattr_name(name):
            continue
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError as error:
            raise CheckpointError("unable to read extended attributes") from error
        captured[name] = value.hex()
    return captured


def inspect_entry(runtime: Runtime, absolute: str) -> dict[str, object]:
    path = host_path(runtime, absolute)
    if not lexists(path):
        raise CheckpointError("captured path is missing")
    metadata = path.lstat()
    kind = lstat_kind(path)
    if kind == "other":
        raise CheckpointError("captured path type is unsupported")
    record: dict[str, object] = {
        "gid": metadata.st_gid,
        "kind": kind,
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtime": int(metadata.st_mtime),
        "mtime_ns": int(metadata.st_mtime_ns),
        "path": posix(absolute),
        "uid": metadata.st_uid if runtime.forced_uid is None else 0,
        "xattrs": read_captured_xattrs(path),
    }
    if kind == "symlink":
        target = os.readlink(path)
        if not allowed_symlink(absolute, target):
            raise CheckpointError("captured symlink escapes approved roots")
        record["target"] = target
        return record
    if kind == "file":
        if metadata.st_size > MAX_MEMBER_BYTES:
            raise CheckpointError("captured file exceeds size limit")
        if not credential_path(absolute):
            record["sha256"] = sha256_file(path)
            record["size"] = metadata.st_size
        return record
    return record


def add_path(
    seen: dict[str, dict[str, object]], runtime: Runtime, absolute: str
) -> None:
    path = posix(absolute)
    if (
        path in SHARED_PARENTS
        or immutable_path(path)
        or ca_or_server_path(path)
        or dpkg_lock_path(path)
    ):
        return
    if path in seen:
        return
    seen[path] = inspect_entry(runtime, path)


def walk_tree(
    seen: dict[str, dict[str, object]],
    runtime: Runtime,
    absolute: str,
) -> None:
    path = host_path(runtime, absolute)
    if not lexists(path):
        return
    if path.is_symlink():
        add_path(seen, runtime, absolute)
        return
    if not path.is_dir():
        add_path(seen, runtime, absolute)
        return
    add_path(seen, runtime, absolute)
    for entry in sorted(os.scandir(path), key=lambda item: item.name):
        if unsafe_component(entry.name):
            raise CheckpointError("captured directory entry is unsafe")
        child = posix(str(PurePosixPath(absolute) / entry.name))
        if immutable_path(child):
            continue
        if entry.is_symlink():
            add_path(seen, runtime, child)
            continue
        if entry.is_dir(follow_symlinks=False):
            walk_tree(seen, runtime, child)
            continue
        if entry.is_file(follow_symlinks=False):
            add_path(seen, runtime, child)


def collect_members(
    runtime: Runtime, package_files: Sequence[str]
) -> list[dict[str, object]]:
    seen: dict[str, dict[str, object]] = {}
    for absolute in package_files:
        path = posix(absolute)
        if path in SHARED_PARENTS or immutable_path(path):
            continue
        host = host_path(runtime, path)
        if not lexists(host):
            continue
        kind = lstat_kind(host)
        if kind == "directory":
            if path not in SHARED_PARENTS:
                add_path(seen, runtime, path)
            continue
        if kind in {"file", "symlink"}:
            add_path(seen, runtime, path)
    for owned_dir in PACKAGE_OWNED_DIR_ROOTS:
        walk_tree(seen, runtime, owned_dir)
    for namespace in CAPTURE_NAMESPACES:
        walk_tree(seen, runtime, namespace)
    for dropin in ADMIN_DROPIN_ROOTS:
        walk_tree(seen, runtime, dropin)
    agent_root = host_path(runtime, AGENT_STATE_ROOT)
    if lexists(agent_root):
        add_path(seen, runtime, AGENT_STATE_ROOT)
        for entry in sorted(os.scandir(agent_root), key=lambda item: item.name):
            if unsafe_component(entry.name):
                raise CheckpointError("agent state entry is unsafe")
            child = posix(str(PurePosixPath(AGENT_STATE_ROOT) / entry.name))
            if immutable_path(child) or entry.name in IMMUTABLE_TOPLEVEL:
                continue
            if entry.is_file(follow_symlinks=False) or entry.is_symlink():
                add_path(seen, runtime, child)
                continue
            if entry.name in AGENT_STATE_TREES and entry.is_dir(follow_symlinks=False):
                walk_tree(seen, runtime, child)
    dpkg = host_path(runtime, DPKG_ROOT)
    if not lexists(dpkg) or dpkg.is_symlink() or not dpkg.is_dir():
        raise CheckpointError("dpkg state is unavailable")
    add_path(seen, runtime, DPKG_ROOT)
    for entry in sorted(os.scandir(dpkg), key=lambda item: item.name):
        if entry.name in DPKG_SKIP_NAMES or unsafe_component(entry.name):
            continue
        child = posix(str(PurePosixPath(DPKG_ROOT) / entry.name))
        if entry.is_symlink():
            add_path(seen, runtime, child)
            continue
        if entry.is_dir(follow_symlinks=False):
            walk_tree(seen, runtime, child)
            continue
        if entry.is_file(follow_symlinks=False):
            add_path(seen, runtime, child)
    if len(seen) > MAX_MEMBERS:
        raise CheckpointError("checkpoint file set is too large")
    return [seen[key] for key in sorted(seen)]


def tar_create(
    runtime: Runtime, archive: Path, members: Sequence[dict[str, object]]
) -> None:
    names = [relative_member_name(str(item["path"])) for item in members]
    payload = ("\0".join(names) + "\0").encode()
    result = command(
        runtime,
        [
            runtime.tar_path,
            "--create",
            "--format=pax",
            "--file",
            str(archive),
            *TAR_METADATA_FLAGS,
            "--null",
            "--no-recursion",
            "-C",
            str(runtime.fs_root),
            "--files-from",
            "-",
        ],
        input_bytes=payload,
        timeout=600,
    )
    if not result.ok:
        raise CheckpointError("GNU tar create failed")
    if archive.is_symlink() or not archive.is_file():
        raise CheckpointError("checkpoint archive is unsafe")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise CheckpointError("checkpoint archive exceeds size limit")


def tar_extract(runtime: Runtime, archive: Path, staging: Path) -> None:
    result = command(
        runtime,
        [
            runtime.tar_path,
            "--extract",
            "-C",
            str(staging),
            "--file",
            str(archive),
            *TAR_METADATA_FLAGS,
            "--overwrite",
        ],
        timeout=600,
    )
    if not result.ok:
        raise CheckpointError("GNU tar extract failed")


def validate_archive_members(
    archive: Path, expected: Sequence[dict[str, object]]
) -> None:
    expected_names = {relative_member_name(str(item["path"])) for item in expected}
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise CheckpointError("archive member count is unsafe")
        seen: set[str] = set()
        for member in members:
            name = canonical_archive_member_name(member.name, is_dir=member.isdir())
            if name in seen:
                raise CheckpointError("archive member path is unsafe")
            absolute = member_absolute(name)
            if member.size > MAX_MEMBER_BYTES:
                raise CheckpointError("archive member exceeds size limit")
            if member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                raise CheckpointError("archive member type is unsafe")
            if member.issym():
                if not allowed_symlink(absolute, member.linkname):
                    raise CheckpointError("archive symlink escapes approved roots")
            elif not (member.isfile() or member.isdir()):
                raise CheckpointError("archive member type is unsafe")
            if immutable_path(absolute) or ca_or_server_path(absolute):
                raise CheckpointError("archive contains excluded state")
            seen.add(name)
        if seen != expected_names:
            raise CheckpointError("archive members do not match checkpoint metadata")


def public_report(metadata: Mapping[str, object], **extra: object) -> dict[str, object]:
    report = {
        "action": extra.get("action", metadata.get("action", "checkpoint")),
        "agent_sha256": metadata["agent_sha256"],
        "apply_available": extra.get("apply_available", False),
        "checkpoint_digest": metadata["checkpoint_digest"],
        "dpkg_snapshot": True,
        "dpkg_status": metadata["dpkg_status"],
        "file_count": len(metadata["members"]),
        "helper_sha256": metadata["helper_sha256"],
        "host_binding": metadata["host_binding"],
        "kind": KIND,
        "mutated": extra.get("mutated", False),
        "non_vonk_inventory_digest": metadata["non_vonk_inventory_digest"],
        "notes": list(NOTES),
        "ok": True,
        "package": PACKAGE,
        "package_version": metadata["package_version"],
        "release_key_sha256": metadata["release_key_sha256"],
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "trusted_identity": metadata["trusted_identity"],
    }
    for key, value in extra.items():
        if key not in {"action", "apply_available", "mutated"}:
            report[key] = value
    return report


def write_private(path: Path, data: bytes, mode: int) -> None:
    temporary = path.with_name(path.name + ".tmp")
    if lexists(temporary):
        temporary.unlink()
    temporary.write_bytes(data)
    temporary.chmod(mode)
    os.replace(temporary, path)
    path.chmod(mode)


def create_checkpoint(runtime: Runtime, checkpoint_dir: Path) -> dict[str, object]:
    require_root(runtime)
    require_private_dir(runtime, checkpoint_dir, create=True)
    if any(checkpoint_dir.iterdir()):
        raise CheckpointError("checkpoint directory is not empty")
    with debian_package_locks(runtime):
        require_no_pending_recovery(runtime)
        require_native_services_stopped(runtime)
        require_no_running_vonk_containers(runtime)
        require_sqlite_quiescent(runtime)
        if unmanaged_agent_state_paths(runtime):
            raise CheckpointError("checkpoint scope is uncertain")
        status, version = dpkg_status(runtime)
        package_files = dpkg_file_list(runtime)
        inventory_digest, _vonk_line = non_vonk_inventory(runtime)
        hostname, _machine_id, binding = inspect_host_identity(runtime)
        agent_sha256, helper_sha256, release_key_sha256 = current_payload_digests(
            runtime
        )
        members = collect_members(runtime, package_files)
        identity = trusted_identity(
            package_version=version,
            agent_sha256=agent_sha256,
            helper_sha256=helper_sha256,
            release_key_sha256=release_key_sha256,
            binding=binding,
        )
        archive = checkpoint_dir / "files.tar"
        tar_create(runtime, archive, members)
        archive.chmod(0o600)
        files_tar_sha256 = sha256_file(archive)
        body = {
            "agent_sha256": agent_sha256,
            "dpkg_status": status,
            "dpkg_version": version,
            "files_tar_sha256": files_tar_sha256,
            "helper_sha256": helper_sha256,
            "host_binding": binding,
            "hostname": hostname,
            "kind": KIND,
            "members": members,
            "native_units": list(NATIVE_UNITS),
            "non_vonk_inventory_digest": inventory_digest,
            "package": PACKAGE,
            "package_files": [
                path
                for path in package_files
                if path not in SHARED_PARENTS
                and lexists(host_path(runtime, path))
                and lstat_kind(host_path(runtime, path)) in {"file", "symlink"}
            ],
            "package_version": version,
            "release_key_sha256": release_key_sha256,
            "schema_version": SCHEMA_VERSION,
            "scope": SCOPE,
            "trusted_identity": identity,
        }
        digest = sha256_bytes(canonical(body))
        body["checkpoint_digest"] = digest
        write_private(checkpoint_dir / "metadata.json", canonical(body), 0o600)
        write_private(
            checkpoint_dir / "files.tar.sha256", f"{files_tar_sha256}\n".encode(), 0o600
        )
        return public_report(body, action="checkpoint", apply_available=False)


def load_metadata(runtime: Runtime, checkpoint_dir: Path) -> dict[str, object]:
    require_private_dir(runtime, checkpoint_dir)
    metadata_path = checkpoint_dir / "metadata.json"
    archive = checkpoint_dir / "files.tar"
    require_private_file(runtime, metadata_path)
    require_private_file(runtime, archive)
    metadata = json.loads(metadata_path.read_bytes().decode())
    if not isinstance(metadata, dict):
        raise CheckpointError("checkpoint metadata is invalid")
    required = {
        "agent_sha256",
        "checkpoint_digest",
        "dpkg_status",
        "files_tar_sha256",
        "helper_sha256",
        "host_binding",
        "kind",
        "members",
        "non_vonk_inventory_digest",
        "package",
        "package_files",
        "package_version",
        "release_key_sha256",
        "schema_version",
        "trusted_identity",
    }
    if not required.issubset(metadata):
        raise CheckpointError("checkpoint metadata is incomplete")
    if (
        metadata["kind"] != KIND
        or metadata["schema_version"] != SCHEMA_VERSION
        or metadata["package"] != PACKAGE
    ):
        raise CheckpointError("checkpoint identity is invalid")
    body = {key: value for key, value in metadata.items() if key != "checkpoint_digest"}
    digest = sha256_bytes(canonical(body))
    stored = metadata["checkpoint_digest"]
    if (
        not isinstance(stored, str)
        or not DIGEST_RE.fullmatch(stored)
        or stored != digest
    ):
        raise CheckpointError("checkpoint metadata digest is invalid")
    members = metadata["members"]
    package_files = metadata["package_files"]
    if not isinstance(members, list) or not isinstance(package_files, list):
        raise CheckpointError("checkpoint metadata file set is invalid")
    return metadata


def extra_candidate_files(
    runtime: Runtime, captured_package_files: Sequence[object]
) -> list[str]:
    old = {posix(str(path)) for path in captured_package_files}
    extras: list[str] = []
    for path in dpkg_file_list(runtime):
        if path in old or path in SHARED_PARENTS:
            continue
        host = host_path(runtime, path)
        if not lexists(host):
            continue
        kind = lstat_kind(host)
        if kind not in {"file", "symlink"}:
            continue
        if not package_owned_path(path) or immutable_path(path):
            continue
        extras.append(path)
    extras.sort()
    return extras


def allowed_extra_removal(absolute: str) -> bool:
    path = posix(absolute)
    if ca_or_server_path(path) or immutable_path(path) or dpkg_lock_path(path):
        return False
    if package_owned_path(path):
        return True
    if any(is_under(path, root) for root in CAPTURE_NAMESPACES):
        return True
    if any(is_under(path, root) for root in ADMIN_DROPIN_ROOTS):
        return True
    if is_under(path, DPKG_ROOT):
        return True
    if not is_under(path, AGENT_STATE_ROOT) or path == AGENT_STATE_ROOT:
        return False
    relative = PurePosixPath(path).relative_to(AGENT_STATE_ROOT)
    if not relative.parts:
        return False
    if relative.parts[0] in AGENT_STATE_TREES:
        return True
    return len(relative.parts) == 1


def unmanaged_agent_state_paths(runtime: Runtime) -> list[str]:
    agent_root = host_path(runtime, AGENT_STATE_ROOT)
    if not lexists(agent_root) or agent_root.is_symlink() or not agent_root.is_dir():
        return []
    unmanaged: list[str] = []
    for entry in sorted(os.scandir(agent_root), key=lambda item: item.name):
        if unsafe_component(entry.name):
            raise CheckpointError("agent state entry is unsafe")
        child = posix(str(PurePosixPath(AGENT_STATE_ROOT) / entry.name))
        if entry.name in IMMUTABLE_TOPLEVEL or immutable_path(child):
            continue
        if entry.name in AGENT_STATE_TREES:
            continue
        if entry.is_dir(follow_symlinks=False):
            unmanaged.append(child)
    return unmanaged


def extra_restore_paths(
    runtime: Runtime,
    metadata: Mapping[str, object],
) -> list[str]:
    members = metadata["members"]
    package_files = metadata["package_files"]
    if not isinstance(members, list) or not isinstance(package_files, list):
        raise CheckpointError("checkpoint metadata file set is invalid")
    captured = {
        posix(str(item["path"]))
        for item in members
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    unmanaged = unmanaged_agent_state_paths(runtime)
    if unmanaged:
        raise CheckpointError(
            "restore scope is uncertain: unmanaged agent directories "
            + ", ".join(unmanaged[:10])
        )
    live_package_files = dpkg_file_list(runtime)
    live = {item["path"] for item in collect_members(runtime, live_package_files)}
    extras: list[str] = []
    for path in sorted(live - captured):
        if ca_or_server_path(path) or immutable_path(path) or dpkg_lock_path(path):
            continue
        if not allowed_extra_removal(path):
            raise CheckpointError("restore scope is uncertain: extra path " + path)
        extras.append(path)
    extras.extend(extra_candidate_files(runtime, package_files))
    unique = sorted(
        set(extras), key=lambda item: (-len(PurePosixPath(item).parts), item)
    )
    return unique


def restore_plan(
    metadata: Mapping[str, object], extras: Sequence[str]
) -> dict[str, object]:
    members = metadata["members"]
    if not isinstance(members, list):
        raise CheckpointError("checkpoint member list is invalid")
    restore_paths = [
        item["path"]
        for item in members
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and not ca_or_server_path(str(item["path"]))
    ]
    return {
        "extra_candidate_files": list(extras),
        "remove_paths": list(extras),
        "restore_paths": restore_paths,
        "skip_ca_or_server": sorted(CA_OR_SERVER_PATHS),
        "start_services": False,
    }


def restore_ownership(runtime: Runtime, path: Path, uid: int, gid: int) -> None:
    try:
        os.lchown(path, uid, gid)
    except PermissionError:
        if runtime.forced_uid is None:
            raise


def unlink_nofollow(path: Path) -> None:
    if not lexists(path):
        return
    if path.is_dir() and not path.is_symlink():
        raise CheckpointError("refusing to unlink a directory")
    path.unlink()


def ensure_directory(path: Path, mode: int) -> None:
    if lexists(path):
        if path.is_symlink() or not path.is_dir():
            raise CheckpointError("restore destination directory is unsafe")
        return
    path.mkdir(mode=mode)
    path.chmod(mode)


def staging_member_path(staging: Path, absolute: str) -> Path:
    relative = relative_member_name(absolute)
    source = staging.joinpath(*PurePosixPath(relative).parts)
    try:
        source.relative_to(staging)
    except ValueError as error:
        raise CheckpointError("staged path is unsafe") from error
    return source


def apply_xattrs(runtime: Runtime, path: Path, xattrs: Mapping[object, object]) -> None:
    if not xattrs:
        return
    if not hasattr(os, "setxattr"):
        if runtime.forced_uid is not None:
            return
        raise CheckpointError("failed to restore extended attributes")
    for name in read_captured_xattrs(path):
        if name not in xattrs:
            try:
                os.removexattr(path, name, follow_symlinks=False)
            except OSError as error:
                raise CheckpointError(
                    "failed to remove changed extended attribute"
                ) from error
    for name, encoded in xattrs.items():
        if not isinstance(name, str) or not isinstance(encoded, str):
            raise CheckpointError("captured extended attributes are invalid")
        if not captured_xattr_name(name):
            continue
        try:
            os.setxattr(path, name, bytes.fromhex(encoded), follow_symlinks=False)
        except OSError as error:
            if runtime.forced_uid is not None and not name.startswith("user."):
                continue
            raise CheckpointError("failed to restore extended attributes") from error


def apply_captured_metadata(
    runtime: Runtime, path: Path, member: Mapping[str, object]
) -> None:
    restore_ownership(runtime, path, int(member["uid"]), int(member["gid"]))
    kind = str(member["kind"])
    if kind != "symlink":
        os.chmod(path, int(member["mode"]))
    mtime_ns = member.get("mtime_ns")
    if isinstance(mtime_ns, int):
        os.utime(path, ns=(mtime_ns, mtime_ns), follow_symlinks=False)
    elif isinstance(member.get("mtime"), int):
        seconds = int(member["mtime"])
        os.utime(path, (seconds, seconds), follow_symlinks=False)
    xattrs = member.get("xattrs")
    if isinstance(xattrs, dict):
        apply_xattrs(runtime, path, xattrs)


def copy_preserved(
    runtime: Runtime,
    source: Path,
    destination: Path,
    *,
    attributes_only: bool = False,
) -> None:
    argv = [
        CP_PATH,
        "--preserve=all",
        "--no-dereference",
        "--no-target-directory",
    ]
    if attributes_only:
        argv.append("--attributes-only")
    argv.extend(["--", str(source), str(destination)])
    require_command(runtime, argv, timeout=120)


def install_from_staging(
    runtime: Runtime,
    staging: Path,
    member: Mapping[str, object],
) -> None:
    absolute = posix(str(member["path"]))
    if (
        ca_or_server_path(absolute)
        or immutable_path(absolute)
        or dpkg_lock_path(absolute)
    ):
        return
    source = staging_member_path(staging, absolute)
    destination = host_path(runtime, absolute)
    # A captured symlink may name the container's /models mount. Check its
    # parent containment without dereferencing the leaf that we copy as a link.
    require_inside(source.parent, staging)
    if not source.is_symlink():
        require_inside(source, staging)
    require_inside(destination.parent, runtime.fs_root)
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise CheckpointError("restore destination parent is unsafe")
    kind = str(member["kind"])
    if kind == "directory":
        if source.is_symlink() or not source.is_dir():
            raise CheckpointError("staged directory is unsafe")
        ensure_directory(destination, int(member["mode"]))
        apply_captured_metadata(runtime, destination, member)
        return
    if kind == "symlink":
        target = str(member["target"])
        if not allowed_symlink(absolute, target) or not source.is_symlink():
            raise CheckpointError("restore symlink is unsafe")
        if lexists(destination):
            unlink_nofollow(destination)
        copy_preserved(runtime, source, destination)
        apply_captured_metadata(runtime, destination, member)
        return
    if kind != "file" or not source.is_file() or source.is_symlink():
        raise CheckpointError("restore member is unsafe")
    expected_hash = member.get("sha256")
    if isinstance(expected_hash, str) and sha256_file(source) != expected_hash:
        raise CheckpointError("restored file digest mismatch")
    temporary = destination.with_name(f".{destination.name}.vonk-restore-tmp")
    if lexists(temporary):
        if temporary.is_dir() and not temporary.is_symlink():
            raise CheckpointError("restore temporary path is unsafe")
        unlink_nofollow(temporary)
    try:
        copy_preserved(runtime, source, temporary)
        apply_captured_metadata(runtime, temporary, member)
        os.replace(temporary, destination)
    except Exception:
        if lexists(temporary):
            unlink_nofollow(temporary)
        raise


def remove_extra_files(runtime: Runtime, extras: Sequence[str]) -> None:
    for absolute in extras:
        path_name = posix(absolute)
        if not allowed_extra_removal(path_name):
            raise CheckpointError("restore extra path is outside removable scope")
        path = host_path(runtime, path_name)
        if not lexists(path):
            continue
        if path.is_dir() and not path.is_symlink():
            try:
                path.rmdir()
            except OSError as error:
                raise CheckpointError("unable to remove extra directory") from error
            continue
        unlink_nofollow(path)


def require_staging_safe(staging: Path, members: Sequence[object]) -> None:
    expected: set[str] = set()
    for member in members:
        if not isinstance(member, dict):
            raise CheckpointError("checkpoint member is invalid")
        expected.add(relative_member_name(str(member["path"])))
    for dirpath, dirnames, filenames in os.walk(staging, followlinks=False):
        for name in (*dirnames, *filenames):
            if unsafe_component(name):
                raise CheckpointError("staging contains unexpected path")
            full = Path(dirpath) / name
            relative = full.relative_to(staging).as_posix()
            if full.is_symlink() and not allowed_symlink(
                "/" + relative, os.readlink(full)
            ):
                raise CheckpointError("staged symlink is unsafe")
            if relative in expected:
                continue
            if (
                full.is_dir()
                and not full.is_symlink()
                and any(
                    item == relative or item.startswith(relative + "/")
                    for item in expected
                )
            ):
                continue
            raise CheckpointError("staging contains unexpected path")


def apply_restore(
    runtime: Runtime,
    archive: Path,
    metadata: Mapping[str, object],
    extras: Sequence[str],
) -> None:
    members = metadata["members"]
    if not isinstance(members, list):
        raise CheckpointError("checkpoint member list is invalid")
    validate_archive_members(archive, members)
    with tempfile.TemporaryDirectory(
        prefix="vonk-native-checkpoint-", dir=str(archive.parent)
    ) as raw:
        staging = Path(raw)
        staging.chmod(0o700)
        tar_extract(runtime, archive, staging)
        require_staging_safe(staging, members)
        for member in members:
            if not isinstance(member, dict):
                raise CheckpointError("checkpoint member is invalid")
            staged = staging_member_path(staging, str(member["path"]))
            if member["kind"] == "directory":
                if staged.is_symlink() or not staged.is_dir():
                    raise CheckpointError("staged directory is unsafe")
                continue
            if member["kind"] == "symlink":
                if not staged.is_symlink():
                    raise CheckpointError("staged symlink is missing")
                continue
            if staged.is_symlink() or not staged.is_file():
                raise CheckpointError("staged file is unsafe")
        remove_extra_files(runtime, extras)
        for member in members:
            if not isinstance(member, dict):
                raise CheckpointError("checkpoint member is invalid")
            install_from_staging(runtime, staging, member)
        directories = [
            member
            for member in members
            if isinstance(member, dict) and member.get("kind") == "directory"
        ]
        directories.sort(
            key=lambda item: (
                -len(PurePosixPath(posix(str(item["path"]))).parts),
                str(item["path"]),
            )
        )
        for member in directories:
            absolute = posix(str(member["path"]))
            if (
                ca_or_server_path(absolute)
                or immutable_path(absolute)
                or dpkg_lock_path(absolute)
            ):
                continue
            apply_captured_metadata(runtime, host_path(runtime, absolute), member)


def metadata_matches_live(
    member: Mapping[str, object], live: Mapping[str, object]
) -> bool:
    for key in ("kind", "mode", "uid", "gid", "mtime", "mtime_ns", "xattrs"):
        if live.get(key) != member.get(key):
            return False
    kind = member.get("kind")
    if kind == "symlink":
        return live.get("target") == member.get("target")
    if kind == "file" and "sha256" in member:
        return live.get("sha256") == member.get("sha256")
    return True


def verify_restored_checkpoint(
    runtime: Runtime, metadata: Mapping[str, object]
) -> None:
    members = metadata["members"]
    if not isinstance(members, list):
        raise CheckpointError("checkpoint member list is invalid")
    for member in members:
        if not isinstance(member, dict):
            raise CheckpointError("checkpoint member is invalid")
        absolute = posix(str(member["path"]))
        if ca_or_server_path(absolute):
            continue
        live = inspect_entry(runtime, absolute)
        if not metadata_matches_live(member, live):
            mismatched = [
                key
                for key in (
                    "kind",
                    "mode",
                    "uid",
                    "gid",
                    "mtime",
                    "mtime_ns",
                    "xattrs",
                    "sha256",
                    "target",
                )
                if live.get(key) != member.get(key)
                and (key != "sha256" or "sha256" in member)
            ]
            raise CheckpointError(
                "restored bytes or metadata do not match checkpoint: "
                f"{PurePosixPath(absolute).name}:{','.join(mismatched)}"
            )
    status, version = dpkg_status(runtime)
    if status != metadata["dpkg_status"] or version != metadata["package_version"]:
        raise CheckpointError("restored dpkg identity does not match checkpoint")
    agent_sha256, helper_sha256, release_key_sha256 = current_payload_digests(runtime)
    if (
        agent_sha256 != metadata["agent_sha256"]
        or helper_sha256 != metadata["helper_sha256"]
        or release_key_sha256 != metadata["release_key_sha256"]
    ):
        raise CheckpointError("restored native payload does not match checkpoint")


def restore_checkpoint(
    runtime: Runtime,
    *,
    checkpoint_dir: Path,
    checkpoint_digest: str,
    current_package_version: str,
    current_agent_sha256: str,
    current_helper_sha256: str,
    original_trusted_identity: str,
    apply: bool,
) -> dict[str, object]:
    require_root(runtime)
    if not DIGEST_RE.fullmatch(checkpoint_digest):
        raise UsageError("checkpoint digest is invalid")
    if not DIGEST_RE.fullmatch(current_agent_sha256):
        raise UsageError("current agent digest is invalid")
    if not DIGEST_RE.fullmatch(current_helper_sha256):
        raise UsageError("current helper digest is invalid")
    if not DIGEST_RE.fullmatch(original_trusted_identity):
        raise UsageError("trusted checkpoint identity is invalid")
    if PACKAGE_VERSION_RE.fullmatch(current_package_version) is None:
        raise UsageError("current package version is invalid")
    metadata = load_metadata(runtime, checkpoint_dir)
    archive = checkpoint_dir / "files.tar"
    if metadata["checkpoint_digest"] != checkpoint_digest:
        raise CheckpointError("checkpoint digest does not match metadata")
    if sha256_file(archive) != metadata["files_tar_sha256"]:
        raise CheckpointError("checkpoint archive digest does not match metadata")
    members = metadata["members"]
    if not isinstance(members, list):
        raise CheckpointError("checkpoint member list is invalid")
    validate_archive_members(archive, members)
    mutated = False
    try:
        with debian_package_locks(runtime):
            _hostname, _machine_id, binding = inspect_host_identity(runtime)
            if binding != metadata["host_binding"]:
                raise CheckpointError(
                    "hostname/machine-id binding does not match checkpoint"
                )
            if original_trusted_identity != metadata["trusted_identity"]:
                raise CheckpointError("trusted checkpoint identity does not match")
            status, version = dpkg_status(runtime)
            agent_sha256, helper_sha256, _key = current_payload_digests(runtime)
            if (
                version != current_package_version
                or agent_sha256 != current_agent_sha256
                or helper_sha256 != current_helper_sha256
            ):
                raise CheckpointError(
                    "current candidate package identity does not match"
                )
            if (
                version == metadata["package_version"]
                and agent_sha256 == metadata["agent_sha256"]
            ):
                raise CheckpointError(
                    "current candidate identity matches the checkpoint; "
                    "refuse no-op restore"
                )
            inventory_digest, _line = non_vonk_inventory(runtime)
            if inventory_digest != metadata["non_vonk_inventory_digest"]:
                raise CheckpointError(
                    "non-Vonk package inventory changed since checkpoint"
                )
            require_no_pending_recovery(runtime)
            require_native_services_stopped(runtime)
            require_no_running_vonk_containers(runtime)
            require_sqlite_quiescent(runtime)
            extras = extra_restore_paths(runtime, metadata)
            plan = restore_plan(metadata, extras)
            if not apply:
                return public_report(
                    metadata,
                    action="restore-dry-run",
                    apply_available=True,
                    mutated=False,
                    current_package_version=version,
                    current_dpkg_status=status,
                    plan=plan,
                )
            mutated = True
            apply_restore(runtime, archive, metadata, extras)
            verify_restored_checkpoint(runtime, metadata)
            return public_report(
                metadata,
                action="restore",
                apply_available=True,
                mutated=True,
                current_package_version=version,
                current_dpkg_status=status,
                plan=plan,
            )
    except CheckpointError as error:
        if mutated and not error.mutated:
            raise CheckpointError(str(error), mutated=True) from error
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Checkpoint or restore native vonk-forge-agent package state."
    )
    parser.add_argument(
        "--checkpoint-dir",
        required=True,
        type=Path,
        help="root-private directory that stores or supplies the checkpoint",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="validate restore; add --apply to mutate",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply a validated restore; refused without --restore",
    )
    parser.add_argument("--checkpoint-digest", default="")
    parser.add_argument("--current-package-version", default="")
    parser.add_argument("--current-agent-sha256", default="")
    parser.add_argument("--current-helper-sha256", default="")
    parser.add_argument("--trusted-identity", default="")
    return parser


def main(argv: Sequence[str] | None = None, runtime: Runtime | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    host = runtime or Runtime(runner=SystemCommandRunner())
    try:
        if args.apply and not args.restore:
            raise UsageError("--apply requires --restore")
        if args.restore:
            if not args.checkpoint_digest or not args.trusted_identity:
                raise UsageError(
                    "restore requires --checkpoint-digest and --trusted-identity"
                )
            if (
                not args.current_package_version
                or not args.current_agent_sha256
                or not args.current_helper_sha256
            ):
                raise UsageError(
                    "restore requires current candidate version and agent/helper digests"
                )
            report = restore_checkpoint(
                host,
                checkpoint_dir=args.checkpoint_dir,
                checkpoint_digest=args.checkpoint_digest,
                current_package_version=args.current_package_version,
                current_agent_sha256=args.current_agent_sha256,
                current_helper_sha256=args.current_helper_sha256,
                original_trusted_identity=args.trusted_identity,
                apply=args.apply,
            )
        else:
            report = create_checkpoint(host, args.checkpoint_dir)
    except UsageError as error:
        failure = {
            "mutated": False,
            "ok": False,
            "reason": str(error),
            "scope": SCOPE,
        }
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 2
    except CheckpointError as error:
        failure = {
            "mutated": bool(error.mutated),
            "ok": False,
            "reason": str(error),
            "scope": SCOPE,
        }
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
