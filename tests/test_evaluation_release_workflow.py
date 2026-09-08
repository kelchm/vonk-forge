from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/evaluation-release.yml"
HELPER = ROOT / "scripts/evaluation-build-release"


def workflow_job(text: str, job_name: str) -> str:
    marker = f"\n  {job_name}:\n"
    body = text.split(marker, 1)[1]
    next_job = re.search(r"\n  [a-z0-9][a-z0-9-]*:\n", body)
    return body if next_job is None else body[: next_job.start()]


def test_evaluation_workflow_is_scoped_to_the_evaluation_fork() -> None:
    text = WORKFLOW.read_text()

    assert text.startswith("name: Fork evaluation native package\n")
    assert "  workflow_dispatch:\n" in text
    assert "  push:\n    branches: [patch/evaluation-current-release]\n" in text
    assert "pull_request:" not in text
    assert "workflow_call:" not in text
    assert "workflow_run:" not in text
    assert "permissions:\n  contents: read\n" in text
    assert "contents: write" not in text
    assert "id-token: write" not in text
    assert "kelchm/vonk-forge" in text
    assert "refs/heads/patch/evaluation-*" in text
    assert "GITHUB_REF_TYPE" in text
    assert "install/installer-release-public.pem" in text
    assert HELPER.is_file()
    assert "scripts/evaluation-build-release" in text


def test_evaluation_workflow_does_not_reuse_upstream_authority_gates() -> None:
    text = WORKFLOW.read_text()

    assert "agent-package-compile" not in text
    assert "agent-package-build" not in text
    assert "agent-package-metadata" not in text
    assert "refs/heads/main" not in text
    assert "GITHUB_RUN_NUMBER" not in text
    assert "agent-development" not in text
    assert "agent-release" not in text


def test_evaluation_workflow_keeps_signing_secret_in_the_sign_job() -> None:
    text = WORKFLOW.read_text()
    authority = workflow_job(text, "authority")
    compile_job = workflow_job(text, "compile")
    sign = workflow_job(text, "sign")

    assert "environment: evaluation-release" in sign
    assert "environment:" not in authority
    assert "environment:" not in compile_job
    assert "secrets.VONK_EVALUATION_AGENT_PRIVATE_KEY" in sign
    assert "vars.VONK_EVALUATION_AGENT_KEY_SHA256" in sign
    assert "secrets." not in authority
    assert "secrets." not in compile_job
    assert "VONK_EVALUATION_AGENT_PRIVATE_KEY" not in authority
    assert "VONK_EVALUATION_AGENT_PRIVATE_KEY" not in compile_job
    assert "install -m 0600 /dev/null" in sign
    assert "trap cleanup EXIT INT TERM" in sign
    assert "if: ${{ always() }}" in sign
    assert 'rm -f "$RUNNER_TEMP/vonk-evaluation-agent.pem"' in sign


def test_evaluation_workflow_compiles_native_arm64_with_pinned_toolchain() -> None:
    text = WORKFLOW.read_text()
    compile_job = workflow_job(text, "compile")
    sign = workflow_job(text, "sign")

    assert "runs-on: ubuntu-24.04-arm" in compile_job
    assert "runs-on: ubuntu-24.04-arm" in sign
    assert "rustup toolchain install 1.97.1" in compile_job
    assert "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6" in compile_job
    assert "shared-key: linux-arm64-evaluation" in compile_job
    assert 'add-job-id-key: "false"' in compile_job
    assert "vonk-agent-build-v2" in compile_job
    assert "SOURCE_DATE_EPOCH" in compile_job
    assert "VONK_AGENT_BUILD_DIGEST" in compile_job
    assert "VONK_AGENT_SEMANTIC_VERSION" in compile_job
    assert "--package vonk-agent --package vonk-agent-helper" in compile_job
    assert "-C target-feature=+crt-static" in compile_job
    assert "--package vonk-build-egress" in compile_job
    assert "--package vonk-spark-setup --package vonk-nas-setup" in compile_job
    assert "scripts/materialize-agent-tools --output-root target" in compile_job
    assert "scripts/verify-agent-binaries" in compile_job
    assert "compiled/binaries/vonk-runtime-probe" in compile_job
    assert "prebuilt/binaries/vonk-runtime-probe" in sign
    assert (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        in compile_job
    )
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in sign
    assert "needs.authority.outputs.compiled_artifact_name" in compile_job
    assert "needs.authority.outputs.compiled_artifact_name" in sign


def test_evaluation_workflow_builds_honest_fork_package_and_public_outputs() -> None:
    text = WORKFLOW.read_text()
    sign = workflow_job(text, "sign")

    assert "scripts/build-agent-deb" in sign
    assert "--architecture linux-arm64" in sign
    assert "--binaries-dir" in sign
    assert "VONK_SOURCE_REPOSITORY: https://github.com/kelchm/vonk-forge" in sign
    assert "scripts/verify-agent-deb --json" in sign
    assert "scripts/materialize-agent-tools --output-root target" in sign
    assert (
        "cmp --silent prebuilt/tools/oras target/aarch64-unknown-linux-gnu/release/oras"
        in sign
    )
    assert (
        "cmp --silent prebuilt/tools/oras.LICENSE target/aarch64-unknown-linux-gnu/release/oras.LICENSE"
        in sign
    )
    assert "scripts/evaluation-build-release verify-key" in sign
    assert "retention-days: 7" in sign
    assert "retention-days: 7" in workflow_job(text, "compile")
    assert "path: dist/*" not in text
    assert "current.manifest" not in text
    assert "R2_" not in text
    assert "gh release" not in text
    assert "apt-development" not in text
    assert "actions/attest@" not in text
    assert "cosign" not in text
    for name in (
        "vonk-forge-agent_${{ needs.authority.outputs.version }}_arm64.deb",
        "vonk-forge-agent_${{ needs.authority.outputs.version }}_arm64.deb.host.sig",
        "vonk-forge-agent_${{ needs.authority.outputs.version }}_arm64.sbom.spdx.json",
        "vonk-forge-agent_${{ needs.authority.outputs.version }}_arm64.provenance.json",
        "prebuilt/setup/vonk-nas-setup",
        "prebuilt/setup/vonk-spark-setup",
        "prebuilt/setup/SHA256SUMS",
    ):
        assert name in sign
    assert (
        "vonk-evaluation-agent.pem"
        not in sign.split("Upload exact public evaluation output set", 1)[1]
    )


def test_evaluation_workflow_external_actions_are_commit_pinned() -> None:
    text = WORKFLOW.read_text()
    invalid = [
        match.group(1)
        for match in re.finditer(r"^\s*uses:\s*(\S+)", text, re.MULTILINE)
        if not match.group(1).startswith("./")
        and re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", match.group(1)) is None
    ]

    assert invalid == []
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in text
