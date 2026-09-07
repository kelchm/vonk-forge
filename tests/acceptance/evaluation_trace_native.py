"""Fork-only diagnostic entrypoint; runs the unchanged official lifecycle.

Attach to the disposable host helper only during the synthetic canary and
record writes to stderr, which its command runner otherwise discards.
This is diagnostic execution, not an uninstrumented acceptance result.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import test_spark_lifecycle as lifecycle

original = lifecycle.SparkLifecycle._run_synthetic_canary


def traced_canary(self, node_id):
    if os.environ.get("GITHUB_REPOSITORY") != "kelchm/vonk-forge":
        raise lifecycle.LifecycleError("native trace is restricted to the evaluation fork")
    pid = subprocess.check_output(
        ["systemctl", "show", "vonk-forge-package-helper.service", "--property=MainPID", "--value"],
        text=True, timeout=10,
    ).strip()
    if not pid.isdecimal() or int(pid) <= 1:
        raise lifecycle.LifecycleError("native helper PID unavailable for trace")
    with tempfile.TemporaryDirectory(prefix="vonk-native-stderr-") as directory:
        trace_path = Path(directory) / "stderr.txt"
        with trace_path.open("w") as stream:
            process = subprocess.Popen(
                ["sudo", "-n", "strace", "--quiet", "--follow-forks", "--trace=write",
                 "--trace-fds=2", "--string-limit=2048", "--attach=" + pid],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stream,
                start_new_session=True,
            )
            error = None
            try:
                result = original(self, node_id)
            except lifecycle.LifecycleError as caught:
                error = caught
            finally:
                # The sudo/strace process group belongs only to this tracer.
                subprocess.run(["sudo", "-n", "kill", "-INT", "--", str(-process.pid)],
                               capture_output=True, timeout=10, check=False)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    subprocess.run(["sudo", "-n", "kill", "-KILL", "--", str(-process.pid)],
                                   capture_output=True, timeout=10, check=False)
                    process.wait(timeout=5)
        if error is not None:
            trace = self._redact_diagnostics(trace_path.read_text(errors="replace"))
            raise lifecycle.LifecycleError(f"{error}\nnative stderr trace (instrumented):\n{trace}") from error
        return result


if __name__ == "__main__":
    lifecycle.SparkLifecycle._run_synthetic_canary = traced_canary
    raise SystemExit(lifecycle.main())
