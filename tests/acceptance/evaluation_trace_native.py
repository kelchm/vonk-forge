"""Fork-only diagnostic entrypoint; runs the unchanged official lifecycle.

Attach to the disposable host helper only during the synthetic canary and
record writes to stderr, which its command runner otherwise discards.
This is diagnostic execution, not an uninstrumented acceptance result.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import threading
from pathlib import Path

import test_spark_lifecycle as lifecycle

original = lifecycle.SparkLifecycle._run_synthetic_canary


def traced_canary(self, node_id):
    if os.environ.get("GITHUB_REPOSITORY") != "kelchm/vonk-forge":
        raise lifecycle.LifecycleError("native trace is restricted to the evaluation fork")
    unit_override = Path("/etc/systemd/system/vonk-forge-package-helper.service")
    apply_unit_fix = os.environ.get("VONK_EVALUATION_CANONICAL_INSTALLATION_ACCESS") == "1"
    if apply_unit_fix:
        source = self.workspace / "packaging/systemd/vonk-forge-package-helper.service"
        addition = ("# Canonical installation projections need runtime-UID ACLs before launch.\n"
                    "ReadWritePaths=-/var/lib/vonk-forge-agent/installations\n")
        packaged = Path("/lib/systemd/system/vonk-forge-package-helper.service")
        if (unit_override.exists() or source.read_text().count(addition) != 1
                or source.read_text().replace(addition, "") != packaged.read_text()):
            raise lifecycle.LifecycleError("unit override is not the exact reviewed addition")
        self._run_command(["sudo", "-n", "install", "-m", "0644", str(source), str(unit_override)], cwd=self.workspace)
        self._run_command(["sudo", "-n", "systemctl", "daemon-reload"], cwd=self.workspace)
        self._run_command(["sudo", "-n", "systemctl", "try-restart", "vonk-forge-package-helper.service"], cwd=self.workspace)
        print("EVALUATION: official package plus reviewed canonical-installations unit allowance; instrumented", flush=True)

    # The helper is socket-activated: it may still have PID 0 before the
    # canary's image import. Follow activation while the ordinary flow runs.
    with tempfile.TemporaryDirectory(prefix="vonk-native-stderr-") as directory:
        trace_path = Path(directory) / "stderr.txt"
        with trace_path.open("w") as stream:
            processes = []
            stopped = threading.Event()

            def attach():
                while not stopped.is_set():
                    probe = subprocess.run(
                        ["systemctl", "show", "vonk-forge-package-helper.service", "--property=MainPID", "--value"],
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    pid = probe.stdout.strip()
                    if probe.returncode == 0 and pid.isdecimal() and int(pid) > 1:
                        processes.append(subprocess.Popen(
                            ["sudo", "-n", "strace", "--quiet", "--follow-forks", "--trace=write",
                             "--trace-fds=2", "--string-limit=2048", "--attach=" + pid],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stream,
                            start_new_session=True,
                        ))
                        return
                    stopped.wait(0.25)

            thread = threading.Thread(target=attach, daemon=True)
            thread.start()
            error = None
            try:
                result = original(self, node_id)
            except lifecycle.LifecycleError as caught:
                error = caught
            finally:
                stopped.set()
                thread.join(timeout=15)
                if apply_unit_fix:
                    self._run_command(["sudo", "-n", "rm", "--", str(unit_override)], cwd=self.workspace)
                    self._run_command(["sudo", "-n", "systemctl", "daemon-reload"], cwd=self.workspace)
                for process in processes:
                    # This group contains only our sudo/strace process.
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
            snapshot = subprocess.run(
                ["sudo", "-n", "env", "GITHUB_REPOSITORY=kelchm/vonk-forge", "/usr/bin/python3",
                 str(self.workspace / "tests/acceptance/evaluation_native_plan_snapshot.py")],
                capture_output=True, text=True, timeout=15, check=False,
            )
            plans = self._redact_diagnostics(snapshot.stdout or snapshot.stderr)
            raise lifecycle.LifecycleError(f"{error}\nnative stderr trace (instrumented):\n{trace}\nretained plan comparison:\n{plans}") from error
        return result


if __name__ == "__main__":
    lifecycle.SparkLifecycle._run_synthetic_canary = traced_canary
    raise SystemExit(lifecycle.main())
