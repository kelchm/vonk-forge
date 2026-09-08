#!/usr/bin/env python3
"""Fork-only disposable ARM64 candidate synthetic lifecycle.

Local signed files replace the DOWNLOAD boundary. Recipe operations, signature
checks, and the original synthetic canary remain normal Vonk. This is not
upstream publication acceptance.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

import yaml

from tests.acceptance.runtime import (
    AcceptanceError,
    assert_bundle_contract,
    run_interactive,
)
from tests.acceptance.test_fresh_nas_install import (
    is_immutable_image,
    nas_responses,
    tailscale_service_hostname,
)
from tests.acceptance.test_spark_lifecycle import (
    AGENT_HOST,
    CERTIFICATE_LIFETIME_SECONDS,
    CHANNEL,
    COMPOSE_IMAGE_ROLES,
    CONTROLLER_ADDRESS,
    DISABLED_TAILSCALE_CREDENTIAL,
    ENROLLMENT_HOST,
    LOCAL_CONTROL_SERVICE,
    LOCAL_CONTROLLER_SERVICES,
    LOCAL_DNS_SUFFIX,
    LOCAL_HERMES_API_SERVICE,
    LOCAL_HERMES_DASHBOARD_SERVICE,
    PLATFORMS,
    REGISTRY_HOST,
    SHA256,
    SOURCE_SHA,
    VERSION,
    LifecycleError,
    LocalBrowserController,
    SparkLifecycle,
    _atomic_write,
    _canonical,
    _canonical_canary_fixture,
    _configure_acceptance_renewal,
    _configure_canonical_canary_library,
    _object,
    _read_canonical_document,
    _require_loopback_controller_boundary,
    _spark_project_identity,
    assert_compose_services_healthy,
)

EVALUATION_ORIGIN = "https://vonk-release.home.kelch.io"
EVALUATION_REPOSITORY = "kelchm/vonk-forge"
FORK_IMAGE_REPOSITORIES = {
    "api": "ghcr.io/kelchm/vonk-forge-evaluation-api",
    "worker": "ghcr.io/kelchm/vonk-forge-evaluation-worker",
    "hermes": "ghcr.io/kelchm/vonk-forge-evaluation-hermes",
    "litellm": "ghcr.io/kelchm/vonk-forge-evaluation-litellm",
}
FORK_ROLE_SERVICES = {
    "api": ("control-api",),
    "worker": ("control-worker",),
    "hermes": ("hermes-agent",),
    "litellm": ("litellm", "hermes-litellm-key-provisioner"),
}
REQUIRED_ARTIFACTS = (
    "agent-package-linux-arm64",
    "agent-package-signature-linux-arm64",
    "nas-payload",
    "nas-setup-linux-arm64",
    "spark-setup-linux-arm64",
    "spark-setup-signature-linux-arm64",
)
LAB_SPARK_MARKERS = (Path("/usr/bin/nvidia-smi"), Path("/etc/nv_tegra_release"))
OPENSSL = Path("/usr/bin/openssl")
MAX_RELEASE_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
MAX_PACKAGE_BYTES = 1024 * 1024 * 1024
MAX_SETUP_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024


class LocalReleaseArtifacts(NamedTuple):
    overlay: Path
    package: Path
    nas_payload: Path
    nas_setup: Path
    spark_setup: Path
    spark_setup_signature: Path
    release: Path
    signature: Path
    public_key: Path
    graph: dict[str, object]
    artifact_digests: dict[str, str]

    def proof(self) -> dict[str, str]:
        return {
            "agent_package_sha256": self.artifact_digests["agent-package-linux-arm64"],
            "nas_payload_sha256": self.artifact_digests["nas-payload"],
            "nas_setup_sha256": self.artifact_digests["nas-setup-linux-arm64"],
            "spark_setup_sha256": self.artifact_digests["spark-setup-linux-arm64"],
            "spark_setup_signature_sha256": self.artifact_digests[
                "spark-setup-signature-linux-arm64"
            ],
        }


def _os_release_text() -> str:
    try:
        return Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError as error:
        raise LifecycleError("evaluation host identity is unavailable") from error


def _is_ubuntu(os_release: str) -> bool:
    for line in os_release.splitlines():
        if line.startswith("ID="):
            return line.partition("=")[2].strip().strip('"') == "ubuntu"
    return False


def _lab_spark_marker_present() -> bool:
    return any(path.exists() or path.is_symlink() for path in LAB_SPARK_MARKERS)


def require_disposable_evaluation_context() -> None:
    if os.environ.get("VONK_EVALUATION_DISPOSABLE") != "1":
        raise LifecycleError("evaluation harness is disposable-only")
    if os.environ.get("GITHUB_REPOSITORY") != EVALUATION_REPOSITORY:
        raise LifecycleError("evaluation harness is fork-only")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise LifecycleError("evaluation harness requires hosted CI")
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise LifecycleError("evaluation harness is not callable on lab Sparks")
    if os.geteuid() == 0:
        raise LifecycleError("evaluation harness must run as a non-root user")
    if platform.machine() not in {"aarch64", "arm64"}:
        raise LifecycleError("evaluation harness requires native ARM64")
    if not _is_ubuntu(_os_release_text()):
        raise LifecycleError("evaluation harness requires Ubuntu")
    if _lab_spark_marker_present():
        raise LifecycleError("evaluation harness is not callable on lab Sparks")


def _regular_file(path: Path, label: str, *, maximum: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LifecycleError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= maximum
    ):
        raise LifecycleError(f"{label} is unsafe")


def _digest_regular_file(path: Path, label: str, *, maximum: int) -> tuple[int, str]:
    _regular_file(path, label, maximum=maximum)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise LifecycleError(f"{label} is unsafe")
            digest.update(chunk)
    if size == 0:
        raise LifecycleError(f"{label} is unsafe")
    return size, digest.hexdigest()


def is_evaluation_fork_image(image: str, *, role: str, source_sha: str) -> bool:
    repository = FORK_IMAGE_REPOSITORIES.get(role)
    if (
        repository is None
        or SOURCE_SHA.fullmatch(source_sha) is None
        or not isinstance(image, str)
        or not is_immutable_image(image)
    ):
        return False
    expected = f"{repository}:dev-sha-{source_sha}@sha256:"
    digest = image.removeprefix(expected)
    return image.startswith(expected) and SHA256.fullmatch(digest) is not None


def assert_fork_images(images: Mapping[str, object], source_sha: str) -> dict[str, str]:
    if set(images) != set(FORK_IMAGE_REPOSITORIES):
        raise LifecycleError("evaluation image graph is incomplete")
    pinned: dict[str, str] = {}
    for role, repository in FORK_IMAGE_REPOSITORIES.items():
        image = images.get(role)
        if not isinstance(image, str) or not is_evaluation_fork_image(
            image, role=role, source_sha=source_sha
        ):
            raise LifecycleError("evaluation image is not an immutable fork pin")
        if not image.startswith(f"{repository}:"):
            raise LifecycleError("evaluation image is not an immutable fork pin")
        pinned[role] = image
    return pinned


def overlay_service_images(overlay: Path) -> dict[str, str]:
    _regular_file(overlay, "evaluation Compose overlay", maximum=1024 * 1024)
    try:
        document = yaml.safe_load(overlay.read_text(encoding="utf-8"))
        services = document["services"]
    except (OSError, UnicodeDecodeError, KeyError, TypeError, yaml.YAMLError) as error:
        raise LifecycleError("evaluation Compose overlay is invalid") from error
    if not isinstance(services, dict):
        raise LifecycleError("evaluation Compose overlay is invalid")
    images: dict[str, str] = {}
    for name, service in services.items():
        image = service.get("image") if isinstance(service, dict) else None
        if not isinstance(name, str) or not isinstance(image, str):
            raise LifecycleError("evaluation Compose overlay is invalid")
        images[name] = image
    return images


def assert_fork_overlay(
    overlay: Path, images: Mapping[str, str], source_sha: str
) -> None:
    assert_fork_images(images, source_sha)
    services = overlay_service_images(overlay)
    for role, names in FORK_ROLE_SERVICES.items():
        expected = images[role]
        for name in names:
            if services.get(name) != expected:
                raise LifecycleError("Compose overlay differs from the fork pin")


def native_nas_setup_command(
    *,
    nas_setup: Path,
    payload: Path,
    output: Path,
    answers: Path,
) -> list[str]:
    paths = (nas_setup, payload, output, answers)
    if any(not path.is_absolute() for path in paths):
        raise LifecycleError("native NAS setup arguments must be absolute")
    return [
        os.fspath(nas_setup),
        "--template",
        os.fspath(payload),
        "--output",
        os.fspath(output),
        "--answers-file",
        os.fspath(answers),
        "--disable-hermes",
    ]


def native_spark_setup_command(
    *,
    spark_setup: Path,
    package: Path,
    release: Path,
    signature: Path,
    setup_signature: Path,
) -> list[str]:
    paths = (spark_setup, package, release, signature, setup_signature)
    if any(not path.is_absolute() for path in paths):
        raise LifecycleError("native Spark setup arguments must be absolute")
    return [
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


def _artifact_record(
    artifacts: Mapping[str, object],
    key: str,
    *,
    expected_path: str,
    extra_fields: set[str] | None = None,
) -> dict[str, object]:
    record = _object(artifacts.get(key), f"candidate {key}")
    expected = {"path", "sha256", "size"} | (extra_fields or set())
    if set(record) != expected:
        raise LifecycleError(f"candidate {key} record is incomplete")
    size = record.get("size")
    digest = record.get("sha256")
    if (
        record.get("path") != expected_path
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(digest, str)
        or SHA256.fullmatch(digest) is None
    ):
        raise LifecycleError(f"candidate {key} record is invalid")
    return record


def _verify_release_signature(release: Path, signature: Path, public_key: Path) -> None:
    _regular_file(release, "candidate release object", maximum=MAX_RELEASE_BYTES)
    _regular_file(signature, "candidate release signature", maximum=MAX_SIGNATURE_BYTES)
    _regular_file(public_key, "installer public key", maximum=MAX_PUBLIC_KEY_BYTES)
    if not OPENSSL.is_file() or not os.access(OPENSSL, os.X_OK):
        raise LifecycleError("openssl is unavailable")
    try:
        encoded = signature.read_bytes().strip()
        decoded = base64.b64decode(encoded, validate=True)
        public = public_key.read_bytes()
    except (OSError, ValueError) as error:
        raise LifecycleError("candidate release signature is invalid") from error
    if (
        not public.startswith(b"-----BEGIN PUBLIC KEY-----\n")
        or not public.endswith(b"-----END PUBLIC KEY-----\n")
        or not decoded
    ):
        raise LifecycleError("candidate release signature is invalid")
    with tempfile.TemporaryDirectory(prefix="vonk-evaluation-release-") as directory:
        root = Path(directory)
        raw_signature = root / "release.sig"
        raw_signature.write_bytes(decoded)
        result = subprocess.run(
            [
                os.fspath(OPENSSL),
                "dgst",
                "-sha256",
                "-verify",
                os.fspath(public_key),
                "-signature",
                os.fspath(raw_signature),
                os.fspath(release),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        raise LifecycleError("candidate release signature is invalid")


def verify_local_signed_release(arguments: argparse.Namespace) -> LocalReleaseArtifacts:
    if (
        CHANNEL.fullmatch(arguments.channel) is None
        or VERSION.fullmatch(arguments.version) is None
        or SOURCE_SHA.fullmatch(arguments.source_sha) is None
        or SHA256.fullmatch(arguments.generation) is None
        or arguments.platform not in PLATFORMS
        or arguments.origin != EVALUATION_ORIGIN
    ):
        raise LifecycleError("evaluation release identity is invalid")
    object_root = Path(os.path.abspath(os.fspath(arguments.object_root)))
    release = Path(os.path.abspath(os.fspath(arguments.candidate_release)))
    overlay = Path(os.path.abspath(os.fspath(arguments.compose_overlay)))
    public_key = Path(os.path.abspath(os.fspath(arguments.installer_public_key)))
    prefix = f"artifacts/{arguments.channel}/releases/{arguments.generation}"
    expected_release = object_root / prefix / "release.json"
    signature = expected_release.with_name("release.sig")
    if release != expected_release:
        raise LifecycleError("candidate release path does not match the generation")
    _verify_release_signature(release, signature, public_key)
    document = _read_canonical_document(release, "candidate release object")
    if document.get("acceptance_only") is True:
        raise LifecycleError("evaluation release is candidate-only")
    if (
        document.get("schema_version") != 2
        or document.get("channel") != arguments.channel
        or document.get("generation") != arguments.generation
        or document.get("source_sha") != arguments.source_sha
        or document.get("version") != arguments.version
    ):
        raise LifecycleError("candidate release identity does not match the run")
    bootstraps = _object(document.get("bootstraps"), "candidate bootstraps")
    if not bootstraps:
        raise LifecycleError("candidate release bootstraps are missing")
    images = assert_fork_images(
        _object(document.get("images"), "candidate image graph"),
        arguments.source_sha,
    )
    assert_fork_overlay(overlay, images, arguments.source_sha)
    artifacts = _object(document.get("artifacts"), "candidate artifacts")
    expected_paths = {
        "agent-package-linux-arm64": f"{prefix}/spark/current/linux-arm64/vonk-forge-agent.deb",
        "agent-package-signature-linux-arm64": (
            f"{prefix}/spark/current/linux-arm64/vonk-forge-agent.deb.host.sig"
        ),
        "nas-payload": f"{prefix}/nas/current/payload.json",
        "nas-setup-linux-arm64": f"{prefix}/nas/current/linux-arm64/vonk-nas-setup",
        "spark-setup-linux-arm64": f"{prefix}/spark/current/linux-arm64/vonk-spark-setup",
        "spark-setup-signature-linux-arm64": (
            f"{prefix}/spark/current/linux-arm64/vonk-spark-setup.sig"
        ),
    }
    package_record = _artifact_record(
        artifacts,
        "agent-package-linux-arm64",
        expected_path=expected_paths["agent-package-linux-arm64"],
        extra_fields={
            "architecture",
            "host_signature",
            "package_version",
            "target_binary_digest",
            "target_build_digest",
        },
    )
    host_signature = package_record.get("host_signature")
    if (
        package_record.get("architecture") != "linux-arm64"
        or package_record.get("package_version") != arguments.version
        or not isinstance(host_signature, str)
        or re.fullmatch(r"[0-9a-f]{128}", host_signature) is None
        or not isinstance(package_record.get("target_binary_digest"), str)
        or SHA256.fullmatch(str(package_record["target_binary_digest"])) is None
        or not isinstance(package_record.get("target_build_digest"), str)
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(package_record["target_build_digest"])
        )
        is None
    ):
        raise LifecycleError("candidate agent package identity is invalid")
    limits = {
        "agent-package-linux-arm64": MAX_PACKAGE_BYTES,
        "agent-package-signature-linux-arm64": 1024,
        "nas-payload": MAX_PAYLOAD_BYTES,
        "nas-setup-linux-arm64": MAX_SETUP_BYTES,
        "spark-setup-linux-arm64": MAX_SETUP_BYTES,
        "spark-setup-signature-linux-arm64": MAX_SIGNATURE_BYTES,
    }
    resolved: dict[str, Path] = {}
    digests: dict[str, str] = {}
    for key in REQUIRED_ARTIFACTS:
        extra = (
            {
                "architecture",
                "host_signature",
                "package_version",
                "target_binary_digest",
                "target_build_digest",
            }
            if key == "agent-package-linux-arm64"
            else None
        )
        record = (
            package_record
            if key == "agent-package-linux-arm64"
            else _artifact_record(
                artifacts,
                key,
                expected_path=expected_paths[key],
                extra_fields=extra,
            )
        )
        path = object_root / str(record["path"])
        size, digest = _digest_regular_file(path, key, maximum=limits[key])
        if size != record["size"] or digest != record["sha256"]:
            raise LifecycleError(f"{key} digest does not match its release record")
        resolved[key] = path
        digests[key] = digest
    package_signature = resolved["agent-package-signature-linux-arm64"].read_bytes()
    if package_signature != f"{host_signature}\n".encode("ascii"):
        raise LifecycleError(
            "candidate package signature does not match its release record"
        )
    if not os.access(resolved["nas-setup-linux-arm64"], os.X_OK):
        raise LifecycleError("native NAS setup is not executable")
    if not os.access(resolved["spark-setup-linux-arm64"], os.X_OK):
        raise LifecycleError("native Spark setup is not executable")
    graph = {
        "baseline_version": "",
        "candidate_package_sha256": digests["agent-package-linux-arm64"],
        "candidate_version": arguments.version,
        "channel": arguments.channel,
        "generation": arguments.generation,
        "images_sha256": hashlib.sha256(_canonical(images)).hexdigest(),
        "platform": arguments.platform,
        "schema_version": 1,
        "source_sha": arguments.source_sha,
    }
    return LocalReleaseArtifacts(
        overlay=overlay,
        package=resolved["agent-package-linux-arm64"],
        nas_payload=resolved["nas-payload"],
        nas_setup=resolved["nas-setup-linux-arm64"],
        spark_setup=resolved["spark-setup-linux-arm64"],
        spark_setup_signature=resolved["spark-setup-signature-linux-arm64"],
        release=release,
        signature=signature,
        public_key=public_key,
        graph=graph,
        artifact_digests=digests,
    )


class EvaluationLocalLifecycle(SparkLifecycle):
    """Candidate synthetic lifecycle against local signed fork artifacts."""

    def __init__(
        self,
        arguments: argparse.Namespace,
        graph: dict[str, object],
        *,
        artifacts: LocalReleaseArtifacts,
    ) -> None:
        require_disposable_evaluation_context()
        _require_loopback_controller_boundary()
        if arguments.origin != EVALUATION_ORIGIN:
            raise LifecycleError("evaluation origin is identity-only and fork-specific")
        self.arguments = arguments
        self.graph = graph
        self.artifacts = artifacts
        self.project = _spark_project_identity(arguments.run_id, arguments.platform)
        self.workspace = self._required_workspace()
        self.temporary_root: Path | None = None
        self.bundle: Path | None = None
        self.control = None
        self.browser = None
        self.synthetic_paths: list[Path] = []
        self.synthetic_interfaces: list[str] = []
        self.synthetic_fabric_octet = os.getpid() % 200 + 20
        self.firewall_environment: dict[str, str] = {}
        self.agent_installed = False
        self.synthetic_fixture_sha256: str | None = None
        self.compose_overlay = artifacts.overlay
        self.tailnet_services = {
            "control": LOCAL_CONTROL_SERVICE,
            "hermes_api": LOCAL_HERMES_API_SERVICE,
            "hermes_dashboard": LOCAL_HERMES_DASHBOARD_SERVICE,
        }
        try:
            self.control_hostname = tailscale_service_hostname(
                self.tailnet_services["control"],
                LOCAL_DNS_SUFFIX,
            )
        except AcceptanceError as error:
            raise LifecycleError(
                "acceptance Tailscale Service name is invalid"
            ) from error
        self.origin = arguments.origin
        self.machine = platform.machine()
        if self.machine not in {"aarch64", "arm64"} or os.geteuid() == 0:
            raise LifecycleError(
                "evaluation lifecycle is not running natively as an ordinary user"
            )

    def _compose(self, *arguments: str) -> list[str]:
        return [
            "docker",
            "compose",
            "--project-name",
            self.project,
            "-f",
            "docker-compose.yaml",
            "-f",
            os.fspath(self.compose_overlay),
            *(
                [
                    "-f",
                    str(
                        Path(__file__).with_name(
                            "evaluation-observation-diagnostic.json"
                        )
                    ),
                ]
                if os.environ.get("VONK_EVALUATION_OBSERVATION_DIAGNOSTIC") == "1"
                else []
            ),
            *arguments,
        ]

    def _write_installer_answers(
        self, root: Path, responses: list[tuple[str, str]]
    ) -> Path:
        if any(
            "\n" in answer or "\r" in answer or "\0" in answer
            for _, answer in responses
        ):
            raise LifecycleError("installer answer is not a single line")
        answers = root / ".installer-answers"
        descriptor = os.open(answers, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write("".join(f"{answer}\n" for _, answer in responses))
        return answers

    def _generate_local_bundle(self, root: Path) -> Path:
        try:
            root.mkdir(mode=0o700)
        except FileExistsError as error:
            raise LifecycleError("NAS evaluation target is unsafe") from error
        responses = nas_responses(
            nas_ip="127.0.0.1",
            tailnet_suffix=LOCAL_DNS_SUFFIX,
            oauth_client_id=DISABLED_TAILSCALE_CREDENTIAL,
            oauth_client_secret=DISABLED_TAILSCALE_CREDENTIAL,
            upstream_key=self._required_environment(
                "VONK_ACCEPTANCE_LITELLM_UPSTREAM_KEY", secret=True
            ),
            hermes=False,
            control_service=self.tailnet_services["control"],
            hermes_dashboard_service=self.tailnet_services["hermes_dashboard"],
            enrollment_hostname=ENROLLMENT_HOST,
            agent_hostname=AGENT_HOST,
            registry_hostname=REGISTRY_HOST,
        )
        replacements = self._controller_response_replacements()
        responses = [
            (prompt, replacements.get(prompt, answer)) for prompt, answer in responses
        ]
        answers = self._write_installer_answers(root, responses)
        try:
            self._run_command(
                native_nas_setup_command(
                    nas_setup=self.artifacts.nas_setup,
                    payload=self.artifacts.nas_payload,
                    output=root,
                    answers=answers,
                ),
                cwd=root,
                timeout=300,
            )
        except LifecycleError as error:
            raise LifecycleError("local NAS setup failed") from error
        finally:
            answers.unlink(missing_ok=True)
        bundle = root / "vonk-forge"
        try:
            assert_bundle_contract(bundle)
        except AcceptanceError as error:
            raise LifecycleError("NAS bundle contract is invalid") from error
        return bundle

    def _start_controller(self) -> None:
        self.temporary_root = Path(
            tempfile.mkdtemp(prefix="vonk-evaluation-lifecycle-", dir=self.workspace)
        )
        self.bundle = self._generate_local_bundle(self.temporary_root / "controller")
        _configure_acceptance_renewal(
            self.bundle,
            lifetime_seconds=CERTIFICATE_LIFETIME_SECONDS,
            agent_source_address=f"172.31.{self.synthetic_fabric_octet}.1",
        )
        library_root = self._required_environment("VONK_RECIPE_LIBRARY_ROOT")
        self.synthetic_canary_fixture = _canonical_canary_fixture(Path(library_root))
        _configure_canonical_canary_library(self.bundle, self.synthetic_canary_fixture)
        self._assert_project_is_empty()
        self._assert_compose_image_graph()
        try:
            self._run_command(
                self._local_controller_up_command(),
                cwd=self.bundle,
                timeout=420,
            )
        except LifecycleError as error:
            diagnostics = self._controller_startup_diagnostics()
            raise LifecycleError(
                f"candidate controller startup failed; {diagnostics}"
            ) from error
        status = self._run_command(
            self._compose("ps", "--all", "--format", "json"), cwd=self.bundle
        )
        try:
            assert_compose_services_healthy(status.stdout, LOCAL_CONTROLLER_SERVICES)
        except AcceptanceError as error:
            raise LifecycleError(
                "candidate controller services are not healthy"
            ) from error
        self._assert_running_publication_images()
        self.synthetic_fixture_sha256 = self._materialize_synthetic_device()
        self._prepare_synthetic_firewall_environment()
        boundary = LocalBrowserController(
            hostname=self.control_hostname,
            port=self._local_browser_port(),
        )
        self.browser = boundary
        password = self._read_secret("admin-password")
        self.control = boundary.login(password, timeout=30)
        del password

    def _assert_compose_image_graph(self) -> None:
        assert self.bundle is not None
        candidate = _read_canonical_document(
            self.arguments.candidate_release, "candidate release object"
        )
        images = assert_fork_images(
            _object(candidate.get("images"), "candidate image graph"),
            self.arguments.source_sha,
        )
        if candidate.get("generation") != self.arguments.generation:
            raise LifecycleError("candidate controller generation is invalid")
        assert_fork_overlay(self.compose_overlay, images, self.arguments.source_sha)
        configured = self._run_command(
            self._compose("--profile", "hermes", "config", "--format", "json"),
            cwd=self.bundle,
        )
        try:
            services = json.loads(configured.stdout)["services"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise LifecycleError("Compose image graph is invalid") from error
        if not isinstance(services, dict):
            raise LifecycleError("Compose image graph is invalid")
        for role, service in COMPOSE_IMAGE_ROLES.items():
            configured_service = services.get(service)
            if (
                not isinstance(configured_service, dict)
                or configured_service.get("image") != images[role]
            ):
                raise LifecycleError("Compose image graph differs from the fork pin")
        provisioner = services.get("hermes-litellm-key-provisioner")
        if (
            not isinstance(provisioner, dict)
            or provisioner.get("image") != images["litellm"]
        ):
            raise LifecycleError("Compose image graph differs from the fork pin")

    def _native_spark_environment(self) -> dict[str, str]:
        assert self.temporary_root is not None
        environment = {
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TMPDIR": os.fspath(self.temporary_root),
            "VONK_CONTROLLER_ADDRESS": CONTROLLER_ADDRESS,
        }
        environment.update(self.firewall_environment)
        for name in (
            "DOCKER_CERT_PATH",
            "DOCKER_CONFIG",
            "DOCKER_CONTEXT",
            "DOCKER_HOST",
            "DOCKER_TLS_VERIFY",
        ):
            if value := os.environ.get(name):
                environment[name] = value
        return environment

    def _run_native_spark_setup(
        self,
        enrollment_url: str,
        ca_sha256: str,
        pairing_token: str,
        *,
        interactive=run_interactive,
    ) -> str:
        assert self.temporary_root is not None
        # The signed object graph uses a canonical generic name; native setup
        # requires the normal versioned DEB filename and verifies its contents.
        package = self.temporary_root / (
            f"vonk-forge-agent_{self.arguments.version}_arm64.deb"
        )
        with package.open("xb") as output:
            output.write(self.artifacts.package.read_bytes())
        package.chmod(0o600)
        return interactive(
            native_spark_setup_command(
                spark_setup=self.artifacts.spark_setup,
                package=package,
                release=self.artifacts.release,
                signature=self.artifacts.signature,
                setup_signature=self.artifacts.spark_setup_signature,
            ),
            cwd=self.temporary_root,
            environment=self._native_spark_environment(),
            responses=[
                ("Enrollment URL: ", enrollment_url),
                ("Controller CA SHA-256: ", ca_sha256),
                ("Pairing token: ", pairing_token),
            ],
            timeout=300,
            require_all_prompts=True,
            forbidden_values=[pairing_token],
        )

    def _installation_failure(self, stage: str, error: Exception) -> LifecycleError:
        failure = super()._installation_failure(stage, error)
        sections = [str(failure)]
        # Keep each service's validation error intact; the shared 2K tail can
        # retain only the final stack frames and hide the rejected field.
        if self.bundle is not None:
            for service in ("control-api", "control-worker"):
                logs = self._diagnostic_command(
                    self._compose("logs", "--no-color", "--tail", "160", service)
                )
                if logs is not None:
                    sections.append(
                        service
                        + " diagnostics:\n"
                        + self._redact_diagnostics(
                            logs.stdout or logs.stderr, limit=16000
                        )
                    )
        return LifecycleError("\n".join(sections))

    def observe(self) -> dict[str, object]:
        if self.control is None or self.bundle is None or self.temporary_root is None:
            raise LifecycleError("candidate controller is not ready")
        completed = ["signed-release-verified", "controller-ready"]
        if self.synthetic_fixture_sha256:
            completed.append("synthetic-device-ready")
        grant_id, enrollment_url, ca_sha256, pairing_token = self._create_grant()
        try:
            self._run_native_spark_setup(enrollment_url, ca_sha256, pairing_token)
        except AcceptanceError as error:
            raise self._installation_failure(
                "candidate Spark installation", error
            ) from error
        finally:
            del pairing_token
        self.agent_installed = True
        self._prepare_podman_apparmor_profile()
        candidate = self._wait_for_agent_identity(
            package_version=str(self.graph["candidate_version"]), timeout=180
        )
        completed.extend(("candidate-installed", "paired"))
        use_count = self._pairing_grant_use_count(grant_id)
        node_id = str(candidate["node_id"])
        canary = self._run_synthetic_canary(node_id)
        completed.append("canary-completed")
        return {
            "artifacts": self.artifacts.proof(),
            "canary": canary,
            "completed_phases": completed,
            "controller_generation": self.arguments.generation,
            "direct_agent_health": self._direct_agent_health(),
            "evaluation": {
                "boundary": "disposable-fork",
                "harness_source": os.environ.get("GITHUB_SHA", ""),
                "recipe_fixture_repository": "kelchm/vonk-forge-recipes",
                "recipe_fixture_source": os.environ.get(
                    "VONK_EVALUATION_RECIPE_LIBRARY_SOURCE", ""
                ),
                "origin": self.origin,
                "publication_acceptance": False,
                "observation_diagnostic": os.environ.get(
                    "VONK_EVALUATION_OBSERVATION_DIAGNOSTIC"
                )
                == "1",
            },
            "installation": {
                "architecture": "arm64",
                "identity": self._installation_identity(candidate),
            },
            "node_id": node_id,
            "pairing_grant_use_count": use_count,
            "platform": self.arguments.platform,
            "schema_version": 1,
            "source_sha": self.arguments.source_sha,
            "synthetic_device": {
                "architecture": self.arguments.platform,
                "cdi_name": "nvidia.com/gpu=all",
                "fixture_sha256": self.synthetic_fixture_sha256,
                "physical_gpu": False,
                "provenance": "ci-only-synthetic-cdi",
                "synthetic": True,
            },
            "version": self.arguments.version,
        }


def run_evaluation(arguments: argparse.Namespace) -> None:
    require_disposable_evaluation_context()
    if arguments.run_id <= 0 or arguments.platform not in PLATFORMS:
        raise LifecycleError("evaluation run identity is invalid")
    artifacts = verify_local_signed_release(arguments)
    with EvaluationLocalLifecycle(
        arguments, artifacts.graph, artifacts=artifacts
    ) as lifecycle_run:
        proof = lifecycle_run.observe()
    _atomic_write(arguments.output, proof)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--candidate-release", type=Path, required=True)
    run.add_argument("--object-root", type=Path, required=True)
    run.add_argument("--installer-public-key", type=Path, required=True)
    run.add_argument("--compose-overlay", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--channel", required=True)
    run.add_argument("--version", required=True)
    run.add_argument("--source-sha", required=True)
    run.add_argument("--generation", required=True)
    run.add_argument("--run-id", type=int, required=True)
    run.add_argument("--platform", required=True)
    run.add_argument("--origin", default=EVALUATION_ORIGIN)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        if arguments.command != "run":
            raise LifecycleError("evaluation command is invalid")
        run_evaluation(arguments)
    except LifecycleError as error:
        print(f"evaluation local release failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
