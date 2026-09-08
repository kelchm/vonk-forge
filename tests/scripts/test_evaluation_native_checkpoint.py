from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from collections.abc import Mapping, Sequence
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/evaluation-native-checkpoint.py"
SECRET = b"credential-secret-do-not-log\n"
OLD_AGENT = b"old-agent-payload\n"
OLD_HELPER = b"old-helper-payload\n"
OLD_KEY = b"old-release-public-key\n"
OLD_CA = b"old-controller-ca\n"
OLD_TOML = b'node_id = "spk_old"\n'
OLD_VERSION = "0.1.1~dev.540+g0123456789ab"
NEW_VERSION = "0.1.1~dev.546+gabcdefabcdef"
OLD_STATUS = (
    b"Package: vonk-forge-agent\n"
    b"Status: install ok installed\n"
    b"Version: 0.1.1~dev.540+g0123456789ab\n"
)
OLD_STATE = b"old-agent-sqlite\n"
OLD_RUNTIME = b"old-installation-runtime\n"
OLD_WORKLOAD = b"old-workload-metadata\n"
MODEL_BYTES = b"immutable-model-projection\n"
INSTALL_MODEL = b"installation-models-must-stay\n"
NEW_AGENT = b"new-agent-payload\n"
NEW_HELPER = b"new-helper-payload\n"
NEW_KEY = b"new-release-public-key\n"
NEW_CA = b"new-controller-ca\n"
NEW_TOML = b'node_id = "spk_new"\n'
NEW_STATUS = (
    b"Package: vonk-forge-agent\n"
    b"Status: install ok installed\n"
    b"Version: 0.1.1~dev.546+gabcdefabcdef\n"
)
NEW_TOOL = b"candidate-only-tool\n"
MACHINE_ID = "0123456789abcdef0123456789abcdef"
PACKAGE_FILES = [
    "/",
    "/etc",
    "/etc/vonk-forge-agent",
    "/etc/vonk-forge-agent/containers-storage.conf",
    "/lib",
    "/lib/systemd",
    "/lib/systemd/system",
    "/lib/systemd/system/vonk-forge-agent.service",
    "/usr",
    "/usr/lib",
    "/usr/lib/vonk-forge",
    "/usr/lib/vonk-forge/agent-link",
    "/usr/lib/vonk-forge/vonk-agent",
    "/usr/lib/vonk-forge/vonk-agent-helper",
    "/usr/share",
    "/usr/share/doc",
    "/usr/share/doc/vonk-forge-agent",
    "/usr/share/doc/vonk-forge-agent/copyright",
    "/usr/share/keyrings",
    "/usr/share/keyrings/vonk-forge-release.pub",
]


def load_module() -> ModuleType:
    loaded = sys.modules.get("evaluation_native_checkpoint")
    if loaded is not None:
        return loaded
    loader = SourceFileLoader("evaluation_native_checkpoint", str(SCRIPT))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


@dataclass
class World:
    root: Path
    hostname: str = "spark-eval"
    package_version: str = OLD_VERSION
    status_abbrev: str = "ii"
    package_files: list[str] = field(default_factory=lambda: list(PACKAGE_FILES))
    inventory: list[tuple[str, str, str]] = field(
        default_factory=lambda: [
            ("acl", "2.3.2-1", "ii"),
            ("podman", "4.9.4-1", "ii"),
        ]
    )
    units: dict[str, str] = field(default_factory=dict)
    unit_load: dict[str, str] = field(default_factory=dict)
    running_containers: list[str] = field(default_factory=list)
    rootless_containers: list[str] = field(default_factory=list)
    fail_podman: bool = False
    systemctl_fail_code: int | None = None
    systemctl_fail_stdout: bytes = b""


class FakeRunner:
    def __init__(self, module: ModuleType, world: World) -> None:
        self.module = module
        self.world = world
        self.calls: list[list[str]] = []
        self.tar_extracts = 0

    def run(
        self,
        argv: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
    ) -> object:
        del env, timeout
        self.calls.append(list(argv))
        program = Path(argv[0]).name
        if program == "dpkg-query":
            return self._dpkg_query(argv)
        if program == "systemctl":
            return self._systemctl(argv)
        if program == "hostname":
            return self.module.RunResult(0, f"{self.world.hostname}\n".encode(), b"")
        if program == "podman" or any(Path(arg).name == "podman" for arg in argv):
            if self.world.fail_podman:
                return self.module.RunResult(1, b"", b"podman unavailable")
            names = self.world.running_containers
            if program == "runuser":
                names = self.world.rootless_containers
            return self.module.RunResult(0, ("\n".join(names) + "\n").encode(), b"")
        if program == "tar":
            return self._tar(argv, input_bytes or b"")
        if program == "cp":
            return self._cp(argv)
        raise AssertionError(f"unexpected command: {argv}")

    def _installed_vonk(self) -> tuple[str, str]:
        path = self.world.root / "var/lib/dpkg/status"
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            version_match = re.search(r"^Version:\s*(\S+)", text, re.MULTILINE)
            status_match = re.search(r"^Status:\s*(.+)$", text, re.MULTILINE)
            if (
                version_match
                and status_match
                and "install ok installed" in status_match.group(1)
            ):
                return "ii", version_match.group(1)
        return self.world.status_abbrev, self.world.package_version

    def _dpkg_query(self, argv: Sequence[str]) -> object:
        if "-L" in argv:
            return self.module.RunResult(
                0, ("\n".join(self.world.package_files) + "\n").encode(), b""
            )
        fmt = next(arg for arg in argv if arg.startswith("-f"))
        abbrev, version = self._installed_vonk()
        if "${Package}" in fmt:
            lines = [
                f"{name}\t{pkg_version}\t{pkg_abbrev}"
                for name, pkg_version, pkg_abbrev in self.world.inventory
            ]
            lines.append(f"vonk-forge-agent\t{version}\t{abbrev}")
            return self.module.RunResult(0, ("\n".join(lines) + "\n").encode(), b"")
        return self.module.RunResult(0, f"{abbrev}|{version}".encode(), b"")

    def _systemctl(self, argv: Sequence[str]) -> object:
        if self.world.systemctl_fail_code is not None:
            return self.module.RunResult(
                self.world.systemctl_fail_code,
                self.world.systemctl_fail_stdout,
                b"failed",
            )
        unit = argv[-1]
        active = self.world.units.get(unit, "inactive")
        load = self.world.unit_load.get(unit, "loaded")
        payload = f"LoadState={load}\nActiveState={active}\n"
        return self.module.RunResult(0, payload.encode(), b"")

    def _copy_meta(self, source: Path, dest: Path) -> None:
        metadata = source.lstat()
        if not dest.is_symlink():
            os.chmod(dest, stat.S_IMODE(metadata.st_mode))
        os.utime(
            dest,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
            follow_symlinks=False,
        )
        if not hasattr(os, "listxattr") or not hasattr(os, "setxattr"):
            return
        try:
            names = os.listxattr(source, follow_symlinks=False)
        except (AttributeError, NotImplementedError, OSError):
            return
        for name in names:
            try:
                value = os.getxattr(source, name, follow_symlinks=False)
                os.setxattr(dest, name, value, follow_symlinks=False)
            except OSError:
                continue

    def _cp(self, argv: Sequence[str]) -> object:
        assert "--preserve=all" in argv
        assert "--no-dereference" in argv
        assert "--" in argv
        operands = list(argv[argv.index("--") + 1 :])
        assert len(operands) == 2
        source = Path(operands[0])
        dest = Path(operands[1])
        attributes_only = "--attributes-only" in argv
        if attributes_only:
            if not dest.exists():
                dest.mkdir()
            self._copy_meta(source, dest)
            return self.module.RunResult(0, b"", b"")
        if source.is_symlink():
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            os.symlink(os.readlink(source), dest)
            self._copy_meta(source, dest)
            return self.module.RunResult(0, b"", b"")
        dest.write_bytes(source.read_bytes())
        self._copy_meta(source, dest)
        return self.module.RunResult(0, b"", b"")

    def _tar(self, argv: Sequence[str], input_bytes: bytes) -> object:
        archive = Path(argv[argv.index("--file") + 1])
        chdir = Path(argv[argv.index("-C") + 1])
        if "--create" in argv:
            assert argv.index("-C") < argv.index("--files-from")
            names = [name for name in input_bytes.decode().split("\0") if name]
            with tarfile.open(archive, "w") as tar:
                for name in names:
                    tar.add(chdir / name, arcname=name, recursive=False)
            return self.module.RunResult(0, b"", b"")
        self.tar_extracts += 1
        with tarfile.open(archive, "r") as tar:
            tar.extractall(chdir, filter="fully_trusted")
        return self.module.RunResult(0, b"", b"")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not path.is_symlink():
        path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(mode)


def populate_root(root: Path) -> None:
    write(root / "etc/hostname", b"spark-eval\n", 0o644)
    write(root / "etc/machine-id", f"{MACHINE_ID}\n".encode(), 0o644)
    write(root / "etc/vonk-forge-agent/agent.toml", OLD_TOML)
    write(root / "etc/vonk-forge-agent/controller-ca.pem", OLD_CA)
    write(
        root / "etc/vonk-forge-agent/containers-storage.conf",
        b'graphroot = "/var/lib/vonk-forge-agent/containers"\n',
        0o644,
    )
    write(root / "usr/lib/vonk-forge/vonk-agent", OLD_AGENT, 0o555)
    write(root / "usr/lib/vonk-forge/vonk-agent-helper", OLD_HELPER, 0o555)
    os.symlink("vonk-agent", root / "usr/lib/vonk-forge/agent-link")
    write(root / "usr/share/keyrings/vonk-forge-release.pub", OLD_KEY, 0o644)
    write(
        root / "lib/systemd/system/vonk-forge-agent.service",
        b"[Service]\nExecStart=/usr/lib/vonk-forge/vonk-agent\n",
        0o644,
    )
    write(
        root / "usr/share/doc/vonk-forge-agent/copyright",
        b"Copyright Vonk Forge\n",
        0o644,
    )
    write(root / "var/lib/vonk-forge/helper/observation-receipt.pk8", SECRET)
    write(root / "var/lib/vonk-forge-agent/machine-evidence", b"a" * 64 + b"\n")
    write(root / "var/lib/vonk-forge-agent/state.sqlite", OLD_STATE)
    write(root / "var/lib/vonk-forge-agent/credentials/current.key", SECRET)
    write(root / "var/lib/vonk-forge-agent/workloads/job.json", OLD_WORKLOAD)
    write(
        root / "var/lib/vonk-forge-agent/installations/inst-1/runtime.json",
        OLD_RUNTIME,
    )
    write(
        root / "var/lib/vonk-forge-agent/installations/inst-1/models/weights.bin",
        INSTALL_MODEL,
        0o644,
    )
    write(root / "var/lib/vonk-forge-agent/models/weights.bin", MODEL_BYTES, 0o644)
    write(root / "var/lib/vonk-forge-agent/builds/keep.bin", b"build-cache\n", 0o644)
    write(root / "var/lib/dpkg/status", OLD_STATUS, 0o644)
    write(root / "var/lib/dpkg/info/acl.list", b"/usr/bin/getfacl\n", 0o644)
    write(root / "var/lib/dpkg/lock", b"lock\n", 0o640)
    write(root / "var/lib/dpkg/lock-frontend", b"frontend-lock\n", 0o640)
    os.chmod(root / "etc/vonk-forge-agent", 0o750)
    os.utime(root / "usr/lib/vonk-forge/vonk-agent", (1_700_000_000, 1_700_000_000))


def make_runtime(module: ModuleType, world: World) -> object:
    checkpoint_dir = world.root.parent / "checkpoint"
    checkpoint_dir.mkdir()
    checkpoint_dir.chmod(0o700)
    return (
        module.Runtime(
            runner=FakeRunner(module, world),
            fs_root=world.root,
            geteuid=lambda: 0,
            forced_uid=0,
            tar_path="/usr/bin/tar",
        ),
        checkpoint_dir,
    )


def run_cli(
    module: ModuleType, runtime: object, argv: list[str]
) -> tuple[int, dict[str, object]]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = module.main(argv, runtime=runtime)
    payload = json.loads(buffer.getvalue())
    assert isinstance(payload, dict)
    return code, payload


def checkpoint_ok(
    module: ModuleType, runtime: object, checkpoint_dir: Path
) -> dict[str, object]:
    code, report = run_cli(module, runtime, ["--checkpoint-dir", str(checkpoint_dir)])
    assert code == 0, report
    assert report["ok"] is True
    return report


def upgrade(world: World) -> None:
    root = world.root
    world.package_version = NEW_VERSION
    world.package_files = [*PACKAGE_FILES, "/usr/lib/vonk-forge/new-tool"]
    write(root / "usr/lib/vonk-forge/vonk-agent", NEW_AGENT, 0o555)
    write(root / "usr/lib/vonk-forge/vonk-agent-helper", NEW_HELPER, 0o555)
    write(root / "usr/share/keyrings/vonk-forge-release.pub", NEW_KEY, 0o644)
    write(root / "usr/lib/vonk-forge/new-tool", NEW_TOOL, 0o555)
    write(root / "usr/lib/vonk-forge/not-in-dpkg", b"stray-owned-file\n", 0o555)
    write(root / "etc/vonk-forge-agent/agent.toml", NEW_TOML)
    write(root / "etc/vonk-forge-agent/controller-ca.pem", NEW_CA)
    write(
        root / "etc/vonk-forge-agent/extra-candidate.conf", b"candidate-only-config\n"
    )
    os.chmod(root / "etc/vonk-forge-agent", 0o755)
    write(root / "var/lib/dpkg/status", NEW_STATUS, 0o644)
    write(root / "var/lib/vonk-forge-agent/state.sqlite", b"new-sqlite\n")
    write(root / "var/lib/vonk-forge-agent/models/weights.bin", b"model-still-here\n")
    write(
        root / "var/lib/vonk-forge-agent/installations/inst-1/models/weights.bin",
        b"install-model-still-here\n",
    )


def restore_args(checkpoint_dir: Path, report: Mapping[str, object]) -> list[str]:
    return [
        "--restore",
        "--checkpoint-dir",
        str(checkpoint_dir),
        "--checkpoint-digest",
        str(report["checkpoint_digest"]),
        "--current-package-version",
        NEW_VERSION,
        "--current-agent-sha256",
        digest(NEW_AGENT),
        "--current-helper-sha256",
        digest(NEW_HELPER),
        "--trusted-identity",
        str(report["trusted_identity"]),
    ]


@pytest.fixture
def module() -> ModuleType:
    return load_module()


@pytest.fixture
def harness(module: ModuleType, tmp_path: Path) -> tuple[object, World, Path]:
    world = World(root=tmp_path / "root")
    populate_root(world.root)
    runtime, checkpoint_dir = make_runtime(module, world)
    return runtime, world, checkpoint_dir


def test_script_is_not_a_downgrade_bypass() -> None:
    source = SCRIPT.read_text()
    assert '"--force-downgrade"' not in source
    assert "'--force-downgrade'" not in source
    assert "dpkg --install" not in source
    assert "skip signature" not in source.lower()


def test_checkpoint_and_apply_restore_fixture_bytes(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    """Fixture-root byte restore only; not physical native recovery evidence."""
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    metadata = json.loads((checkpoint_dir / "metadata.json").read_text())
    member_paths = {item["path"] for item in metadata["members"]}
    assert "/usr/share/keyrings/vonk-forge-release.pub" in member_paths
    assert "/etc/vonk-forge-agent/controller-ca.pem" not in member_paths
    assert "/var/lib/vonk-forge-agent/models/weights.bin" not in member_paths
    assert (
        "/var/lib/vonk-forge-agent/installations/inst-1/models/weights.bin"
        not in member_paths
    )
    assert "/var/lib/dpkg/lock" not in member_paths
    assert "/var/lib/dpkg/lock-frontend" not in member_paths
    assert "/var/lib/vonk-forge-agent/installations/inst-1/runtime.json" in member_paths
    tar_creates = [
        argv
        for argv in runtime.runner.calls
        if Path(argv[0]).name == "tar" and "--create" in argv
    ]
    assert tar_creates
    assert tar_creates[0].index("-C") < tar_creates[0].index("--files-from")
    stdout = json.dumps(report)
    assert SECRET.decode().strip() not in stdout
    assert "credential-secret" not in stdout

    upgrade(world)
    code, dry_run = run_cli(module, runtime, restore_args(checkpoint_dir, report))
    assert code == 0, dry_run
    assert dry_run["mutated"] is False
    assert dry_run["apply_available"] is True
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == NEW_AGENT

    code, applied = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 0, applied
    assert applied["mutated"] is True
    assert applied["scope"]["full_os_snapshot"] is False
    assert applied["scope"]["disaster_recovery"] is False
    assert applied["scope"]["restores_ca_or_server_state"] is False
    root = world.root
    assert (root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == OLD_AGENT
    assert (root / "usr/lib/vonk-forge/vonk-agent-helper").read_bytes() == OLD_HELPER
    assert (root / "usr/share/keyrings/vonk-forge-release.pub").read_bytes() == OLD_KEY
    assert (root / "etc/vonk-forge-agent/agent.toml").read_bytes() == OLD_TOML
    assert (root / "var/lib/dpkg/status").read_bytes() == OLD_STATUS
    assert (root / "var/lib/vonk-forge-agent/state.sqlite").read_bytes() == OLD_STATE
    assert (
        root / "var/lib/vonk-forge-agent/installations/inst-1/runtime.json"
    ).read_bytes() == OLD_RUNTIME
    assert (root / "usr/lib/vonk-forge/agent-link").is_symlink()
    assert os.readlink(root / "usr/lib/vonk-forge/agent-link") == "vonk-agent"
    assert not (root / "usr/lib/vonk-forge/new-tool").exists()
    assert not (root / "usr/lib/vonk-forge/not-in-dpkg").exists()
    assert not (root / "etc/vonk-forge-agent/extra-candidate.conf").exists()
    assert (root / "var/lib/dpkg/lock").exists()
    assert (root / "var/lib/dpkg/lock-frontend").exists()
    assert stat.S_IMODE((root / "etc/vonk-forge-agent").stat().st_mode) == 0o750
    assert (root / "usr/lib/vonk-forge/vonk-agent").stat().st_mtime == 1_700_000_000
    assert (root / "etc/vonk-forge-agent/controller-ca.pem").read_bytes() == NEW_CA
    assert (root / "var/lib/vonk-forge-agent/models/weights.bin").read_bytes() == (
        b"model-still-here\n"
    )
    assert (
        root / "var/lib/vonk-forge-agent/installations/inst-1/models/weights.bin"
    ).read_bytes() == b"install-model-still-here\n"
    assert (root / "var/lib/vonk-forge-agent/builds/keep.bin").read_bytes() == (
        b"build-cache\n"
    )
    assert (
        root / "var/lib/vonk-forge/helper/observation-receipt.pk8"
    ).read_bytes() == (SECRET)


def test_binding_mismatch_refuses_without_mutation(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    world.hostname = "other-spark"
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    code, payload = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 1
    assert payload["ok"] is False
    assert payload["mutated"] is False
    assert "binding" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before


def test_tampered_archive_refuses_without_mutation(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    archive = checkpoint_dir / "files.tar"
    data = bytearray(archive.read_bytes())
    data[-1] ^= 0x01
    archive.write_bytes(bytes(data))
    upgrade(world)
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    code, payload = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 1
    assert payload["mutated"] is False
    assert "digest" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before


def test_unsafe_archive_paths_are_refused(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    archive = checkpoint_dir / "files.tar"
    with tarfile.open(archive, "a") as tar:
        info = tarfile.TarInfo("usr/lib/vonk-forge/evil-link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    metadata_path = checkpoint_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    body = {key: value for key, value in metadata.items() if key != "checkpoint_digest"}
    body["members"] = [
        *body["members"],
        {
            "gid": 0,
            "kind": "symlink",
            "mode": 0o777,
            "path": "/usr/lib/vonk-forge/evil-link",
            "target": "/etc/passwd",
            "uid": 0,
        },
    ]
    body["files_tar_sha256"] = digest(archive.read_bytes())
    digest_value = module.sha256_bytes(module.canonical(body))
    body["checkpoint_digest"] = digest_value
    metadata_path.write_bytes(module.canonical(body))
    upgrade(world)
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    args = restore_args(checkpoint_dir, report)
    args[args.index("--checkpoint-digest") + 1] = digest_value
    code, payload = run_cli(module, runtime, [*args, "--apply"])
    assert code == 1
    assert payload["mutated"] is False
    assert "symlink" in str(payload["reason"]) or "unsafe" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before


def test_current_identity_mismatch_refuses(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    args = restore_args(checkpoint_dir, report)
    args[args.index("--current-agent-sha256") + 1] = digest(OLD_AGENT)
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    code, payload = run_cli(module, runtime, [*args, "--apply"])
    assert code == 1
    assert payload["mutated"] is False
    assert "current candidate" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before


def test_non_vonk_package_change_refuses(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    world.inventory.append(("curl", "8.5.0-1", "ii"))
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    code, payload = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 1
    assert payload["mutated"] is False
    assert "non-Vonk" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before


def test_running_model_container_is_rejected(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    world.rootless_containers = ["vonk-11111111-1111-4111-8111-111111111111"]
    code, payload = run_cli(module, runtime, ["--checkpoint-dir", str(checkpoint_dir)])
    assert code == 1
    assert payload["ok"] is False
    assert "Vonk containers" in str(payload["reason"])
    world.rootless_containers = []
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    world.running_containers = ["vonk-22222222-2222-4222-8222-222222222222"]
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    code, payload = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 1
    assert payload["mutated"] is False
    assert "Vonk containers" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before


def test_trusted_identity_mismatch_refuses(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    args = restore_args(checkpoint_dir, report)
    args[args.index("--trusted-identity") + 1] = "b" * 64
    code, payload = run_cli(module, runtime, [*args, "--apply"])
    assert code == 1
    assert payload["mutated"] is False
    assert "trusted checkpoint identity" in str(payload["reason"])


def test_pending_recovery_and_active_unit_refuse_checkpoint(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    write(
        world.root / "var/lib/vonk-forge/package-upgrade/intent", b"schema_version=2\n"
    )
    code, payload = run_cli(module, runtime, ["--checkpoint-dir", str(checkpoint_dir)])
    assert code == 1
    assert "pending package recovery" in str(payload["reason"])
    (world.root / "var/lib/vonk-forge/package-upgrade/intent").unlink()
    world.units["vonk-forge-agent.service"] = "active"
    code, payload = run_cli(module, runtime, ["--checkpoint-dir", str(checkpoint_dir)])
    assert code == 1
    assert "services are not stopped" in str(payload["reason"])


def test_world_writable_checkpoint_inputs_are_rejected(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    archive = checkpoint_dir / "files.tar"
    archive.chmod(stat.S_IMODE(archive.stat().st_mode) | 0o077)
    code, payload = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 1
    assert payload["mutated"] is False
    assert "root-private" in str(payload["reason"])


def test_apply_requires_restore_flag(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, _world, checkpoint_dir = harness
    code, payload = run_cli(
        module,
        runtime,
        ["--apply", "--checkpoint-dir", str(checkpoint_dir)],
    )
    assert code == 2
    assert payload["ok"] is False
    assert payload["mutated"] is False


def test_unquiescent_sqlite_refuses_restore(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    write(world.root / "var/lib/vonk-forge-agent/state.sqlite-wal", b"wal\n")
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    code, payload = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 1
    assert payload["mutated"] is False
    assert "sqlite" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before


def test_unmanaged_agent_state_blocks_restore(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    write(world.root / "var/lib/vonk-forge-agent/mystery-dir/file", b"mixed\n")
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    code, payload = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 1
    assert payload["mutated"] is False
    assert "uncertain" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before
    assert (world.root / "var/lib/vonk-forge-agent/mystery-dir/file").read_bytes() == (
        b"mixed\n"
    )


def test_failed_systemctl_and_unknown_state_are_fail_closed(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    world.systemctl_fail_code = 1
    world.systemctl_fail_stdout = b""
    code, payload = run_cli(module, runtime, ["--checkpoint-dir", str(checkpoint_dir)])
    assert code == 1
    assert "unit state is unavailable" in str(payload["reason"])
    world.systemctl_fail_code = None
    world.units["vonk-forge-agent.service"] = "dead"
    code, payload = run_cli(module, runtime, ["--checkpoint-dir", str(checkpoint_dir)])
    assert code == 1
    assert "unit state is unavailable" in str(payload["reason"])
    world.units["vonk-forge-agent.service"] = "inactive"
    world.unit_load["vonk-forge-package-helper.socket"] = "not-found"
    world.units["vonk-forge-package-helper.socket"] = "inactive"
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    assert report["ok"] is True


def test_dotdot_archive_member_is_rejected_before_extract(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    runtime.runner.tar_extracts = 0
    archive = checkpoint_dir / "files.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo(
            "usr/lib/vonk-forge/../../../etc/vonk-forge-agent/agent.toml"
        )
        data = b"traversal-payload\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    metadata_path = checkpoint_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    body = {key: value for key, value in metadata.items() if key != "checkpoint_digest"}
    body["files_tar_sha256"] = digest(archive.read_bytes())
    digest_value = module.sha256_bytes(module.canonical(body))
    body["checkpoint_digest"] = digest_value
    metadata_path.write_bytes(module.canonical(body))
    upgrade(world)
    before = (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes()
    args = restore_args(checkpoint_dir, report)
    args[args.index("--checkpoint-digest") + 1] = digest_value
    code, payload = run_cli(module, runtime, [*args, "--apply"])
    assert code == 1
    assert payload["mutated"] is False
    assert runtime.runner.tar_extracts == 0
    assert "unsafe" in str(payload["reason"])
    assert (world.root / "usr/lib/vonk-forge/vonk-agent").read_bytes() == before


def test_canonical_archive_member_name_rejects_traversal(module: ModuleType) -> None:
    with pytest.raises(module.CheckpointError):
        module.canonical_archive_member_name(
            "usr/lib/vonk-forge/../../../etc/passwd", is_dir=False
        )
    with pytest.raises(module.CheckpointError):
        module.canonical_archive_member_name("../etc/passwd", is_dir=False)
    assert (
        module.canonical_archive_member_name("./usr/lib/vonk-forge/", is_dir=True)
        == "usr/lib/vonk-forge"
    )


def test_debian_lock_contention_refuses_checkpoint(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    lock_path = world.root / "var/lib/dpkg/lock-frontend"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl, os, sys, time\n"
                "fd = os.open(sys.argv[1], os.O_RDWR)\n"
                "fcntl.lockf(fd, fcntl.LOCK_EX)\n"
                "sys.stdout.write('locked\\n')\n"
                "sys.stdout.flush()\n"
                "time.sleep(30)\n"
            ),
            str(lock_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert holder.stdout is not None
        line = holder.stdout.readline()
        assert line == b"locked\n"
        code, payload = run_cli(
            module, runtime, ["--checkpoint-dir", str(checkpoint_dir)]
        )
        assert code == 1
        assert payload["mutated"] is False
        assert "lock" in str(payload["reason"]).lower()
    finally:
        holder.terminate()
        holder.wait(timeout=5)


def test_restore_preserves_captured_xattrs_when_supported(
    module: ModuleType, harness: tuple[object, World, Path]
) -> None:
    runtime, world, checkpoint_dir = harness
    agent = world.root / "usr/lib/vonk-forge/vonk-agent"
    if not hasattr(os, "setxattr"):
        pytest.skip("user xattrs are not supported on this Python")
    try:
        os.setxattr(agent, "user.vonk-eval", b"acl-like", follow_symlinks=False)
    except OSError:
        pytest.skip("user xattrs are not supported on this filesystem")
    report = checkpoint_ok(module, runtime, checkpoint_dir)
    upgrade(world)
    code, payload = run_cli(
        module, runtime, [*restore_args(checkpoint_dir, report), "--apply"]
    )
    assert code == 0, payload
    restored = world.root / "usr/lib/vonk-forge/vonk-agent"
    assert os.getxattr(restored, "user.vonk-eval", follow_symlinks=False) == b"acl-like"


def _gnu_tar_path() -> str | None:
    for candidate in ("/usr/bin/tar", "gtar", "tar"):
        try:
            completed = subprocess.run(
                [candidate, "--version"],
                capture_output=True,
                check=False,
                text=True,
            )
        except OSError:
            continue
        if completed.returncode == 0 and "GNU tar" in completed.stdout:
            return candidate
    return None


@pytest.mark.skipif(_gnu_tar_path() is None, reason="GNU tar is required")
def test_gnu_tar_create_honors_directory_before_files_from(
    module: ModuleType, tmp_path: Path
) -> None:
    tar_path = _gnu_tar_path()
    assert tar_path is not None
    root = tmp_path / "root"
    write(root / "usr/lib/vonk-forge/vonk-agent", b"payload-from-fs-root\n")
    archive = tmp_path / "files.tar"
    runtime = module.Runtime(
        runner=module.SystemCommandRunner(),
        fs_root=root,
        geteuid=lambda: 0,
        forced_uid=0,
        tar_path=tar_path,
    )
    module.tar_create(
        runtime,
        archive,
        [{"path": "/usr/lib/vonk-forge/vonk-agent"}],
    )
    with tarfile.open(archive, "r") as tar:
        names = tar.getnames()
        assert "usr/lib/vonk-forge/vonk-agent" in names
        extracted = tar.extractfile("usr/lib/vonk-forge/vonk-agent")
        assert extracted is not None
        assert extracted.read() == b"payload-from-fs-root\n"


def test_directory_metadata_restore_does_not_use_nonrecursive_cp(module, tmp_path):
    root = tmp_path / "root"
    staging = tmp_path / "staging"
    absolute = "/var/lib/vonk-forge"
    target = root / absolute.lstrip("/")
    source = staging / absolute.lstrip("/")
    target.mkdir(parents=True)
    source.mkdir(parents=True)
    source.chmod(0o750)
    runtime = module.Runtime(
        runner=module.SystemCommandRunner(), fs_root=root, geteuid=lambda: 0
    )
    member = module.inspect_entry(runtime, absolute)
    member["mode"] = 0o750
    module.install_from_staging(runtime, staging, member)
    assert (target.stat().st_mode & 0o777) == 0o750


def test_xattr_enumeration_error_is_not_empty_metadata(module, tmp_path, monkeypatch):
    import errno

    def denied(*args, **kwargs):
        raise OSError(errno.EACCES, "denied")

    monkeypatch.setattr(module.os, "listxattr", denied, raising=False)
    with pytest.raises(module.CheckpointError, match="enumerate extended attributes"):
        module.read_captured_xattrs(tmp_path)


def test_package_file_list_accepts_dpkg_usr_merge_annotation(module, harness):
    runtime, world, _ = harness
    world.package_files = [
        "/.",
        "/lib",
        "diverted by base-files to: /lib.usr-is-merged",
        "/usr/lib/vonk-forge/vonk-agent",
    ]
    assert module.dpkg_file_list(runtime) == ["/lib", "/usr/lib/vonk-forge/vonk-agent"]
    world.package_files.append("unrecognized dpkg output")
    with pytest.raises(module.CheckpointError, match="package file list is unsafe"):
        module.dpkg_file_list(runtime)
