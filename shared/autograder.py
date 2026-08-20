#!/usr/bin/env python3
"""
autograder.py -- automated black-box test suite for ENEE 4745's two-part
SGRP/1 SCADA client sequence (HW1: application-layer framing/handshake;
HW2: chaos resilience). See ../hw1/04_grading_rubric.md and
../hw2/04_grading_rubric.md for the design rationale and the full,
per-assignment scenario tables and point breakdowns.

This harness NEVER imports the student's client module. It grades purely
by parsing the client's stdout against the "Autograder Output Contract"
(see either grading rubric's Appendix A, or the TODO comments in the
corresponding client_starter.py).

TWO BACKEND MODES for where the server comes from:

  LOCAL mode (default; used for the entire HW1 suite, always): launches
  teacher_server.py as a subprocess on a scratch port with a specific
  combination of chaos flags for each scenario, tears it down when the
  scenario ends, and repeats for the next one.

  REMOTE mode (--remote-host; HW2 suite only): HW2's server is not
  distributed to students (see hw2/01_lab_handout.md Sec. 1 and 5) -- it
  runs as a small number of persistent, fixed-port instances on
  instructor-controlled hardware, one per chaos milestone. In this mode
  the harness spawns no server at all; it connects the student's client
  directly to the already-running instance for each scenario's flag
  combination, using the fixed REMOTE_PORTS mapping below (which mirrors
  the ports documented in the repo README's HW2 quickstart table). This
  lets students self-test against the actual server they'll be graded
  against, without ever having its source.

Usage:
    # HW1 grading (Scenarios A, G -- no chaos flags; always LOCAL, spawns
    # teacher_server.py itself):
    python3 autograder.py --suite hw1 --client /path/to/student/client.py \
        --student-id 123456 [--server-path teacher_server.py] [--report report.json]

    # HW2 grading, LOCAL mode (instructor/TA use only -- requires a local
    # copy of teacher_server.py, which students do not have):
    python3 autograder.py --suite hw2 --client /path/to/student/client.py \
        --student-id 123456 --server-path teacher_server.py [--report report.json]

    # HW2 self-testing, REMOTE mode (student use -- the supported HW2
    # workflow; connects to the instructor's live Pi instead of spawning
    # a local server):
    python3 autograder.py --suite hw2 --client /path/to/student/client.py \
        --student-id 123456 --remote-host sgrp-pi.class [--report report.json]

    # Run every scenario across both suites (e.g. for smoke-testing the
    # reference solution against the full harness, LOCAL mode only):
    python3 autograder.py --suite all --client /path/to/reference_client.py \
        --student-id 123456

    # Run one specific scenario by id regardless of suite:
    python3 autograder.py --scenario D --client ... --student-id ...

Exit code 0 if all requested scenarios pass, 1 otherwise.

IMPORTANT: this harness only ever produces the *automated* portion of
either assignment's grade (80/100 for HW1, 40/100 for HW2). The remaining
points -- HW1's written check-in, HW2's Wireshark trace analysis and quiz
-- are graded manually by the instructor/TA and merged in separately; see
the "Automated total" line in each grading_rubric.md.
"""

import argparse
import json
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# Autograder Output Contract regexes (must match both grading_rubric.md
# Appendix A sections exactly -- HW1 uses a subset of these; HW2 uses all)
# --------------------------------------------------------------------------

RE_AUTH_OK = re.compile(r"AUTH_OK\s+session_id=(\d+)")
RE_AUTH_FAIL = re.compile(r"AUTH_FAIL\s+reason=(\d+)")
RE_TELEMETRY = re.compile(
    r"TELEMETRY\s+seq=(\d+)\s+rtu=(\d+)\s+voltage=(-?\d+\.?\d*)\s+"
    r"current=(-?\d+\.?\d*)\s+freq=(-?\d+\.?\d*)\s+flags=(\d+)")
RE_CHECKSUM_NACK = re.compile(r"CHECKSUM_NACK\s+seq=(\d+)")
RE_SEQ_ANOMALY = re.compile(r"SEQ_ANOMALY\s+expected=(\d+)\s+got=(\d+)")
RE_DISCONNECT_OK = re.compile(r"DISCONNECT_OK")

# --------------------------------------------------------------------------
# REMOTE mode: fixed port-per-scenario convention on the instructor's
# persistent HW2 server. Mirrors the milestone ports in the repo README's
# HW2 quickstart table, plus one autograder-only port (D) that runs a
# boosted corruption rate so the scenario triggers reliably inside a
# bounded test window -- the same boost the LOCAL-mode Scenario D uses
# via --corrupt-rate 0.30. Only hw2 suite scenarios (B-F) are meaningful
# in remote mode; hw1 scenarios (A, G) always run LOCAL regardless of
# --remote-host, since HW1's server is fully given to students anyway.
# --------------------------------------------------------------------------

REMOTE_PORTS = {
    "B": 8081,  # --chaos-fragment
    "C": 8082,  # --chaos-coalesce
    "D": 8086,  # --chaos-corrupt --corrupt-rate 0.30 (autograder-only; the
                # student-facing milestone port for corrupt mode, 8083, runs
                # the realistic 5% rate instead and is not used here)
    "E": 8084,  # --chaos-jitter
    "F": 8085,  # all four flags combined
}


def find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class ServerProc:
    """Manages one teacher_server.py subprocess for the duration of a
    scenario. LOCAL mode only -- see start_backend()."""

    def __init__(self, python_exe, server_path, port, extra_args):
        cmd = [python_exe, str(server_path), "--port", str(port), "--no-color", *extra_args]
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if not wait_for_port("127.0.0.1", port, timeout=5.0):
            self.stop()
            raise RuntimeError(f"teacher_server.py did not open port {port} in time")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def start_backend(ctx, scenario_id, local_args):
    """Returns (server_or_none, host, port) for the given scenario.

    REMOTE mode (ctx.remote_host set): no subprocess is spawned. Connects
    directly to the instructor's already-running, fixed-port instance for
    this scenario (REMOTE_PORTS). `server` is None -- there is nothing for
    the caller to tear down.

    LOCAL mode (ctx.remote_host is None): spawns teacher_server.py on a
    scratch port with `local_args` as before. `server` is a ServerProc the
    caller MUST call .stop() on when the scenario ends.
    """
    if ctx.remote_host is not None:
        if scenario_id not in REMOTE_PORTS:
            raise RuntimeError(
                f"scenario {scenario_id} has no remote-mode port mapping -- "
                f"HW1 scenarios (A, G) are not supported in --remote-host mode, "
                f"since HW1's server is distributed to students directly.")
        return None, ctx.remote_host, REMOTE_PORTS[scenario_id]
    port = find_free_port()
    server = ServerProc(ctx.python, ctx.server_path, port, local_args)
    return server, "127.0.0.1", port


class ClientRun:
    """Spawns the student client and captures timestamped stdout lines from
    a background reader thread, so scenarios can assert both content and
    timing (e.g. "AUTH_OK within 5 seconds", "still emitting telemetry at
    t=120s")."""

    def __init__(self, python_exe, client_path, host, port, student_id, extra_args=None):
        cmd = [python_exe, str(client_path), "--host", host, "--port", str(port),
               "--student-id", str(student_id), *(extra_args or [])]
        self.start_time = time.monotonic()
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.lines = []          # list of (t_relative, line)
        self._lock = threading.Lock()
        self._stderr_chunks = []
        self._t_out = threading.Thread(target=self._read_stdout, daemon=True)
        self._t_err = threading.Thread(target=self._read_stderr, daemon=True)
        self._t_out.start()
        self._t_err.start()

    def _read_stdout(self):
        try:
            for line in self.proc.stdout:
                t = time.monotonic() - self.start_time
                with self._lock:
                    self.lines.append((t, line.rstrip("\n")))
        except Exception:
            pass

    def _read_stderr(self):
        try:
            for line in self.proc.stderr:
                with self._lock:
                    self._stderr_chunks.append(line)
        except Exception:
            pass

    def wait(self, timeout):
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass

    def alive(self):
        return self.proc.poll() is None

    def kill(self):
        if self.alive():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def snapshot(self):
        with self._lock:
            return list(self.lines), "".join(self._stderr_chunks), self.proc.returncode


def parse_events(lines):
    ev = {"AUTH_OK": [], "AUTH_FAIL": [], "TELEMETRY": [], "CHECKSUM_NACK": [],
          "SEQ_ANOMALY": [], "DISCONNECT_OK": []}
    for t, line in lines:
        m = RE_AUTH_OK.search(line)
        if m:
            ev["AUTH_OK"].append((t, int(m.group(1))))
            continue
        m = RE_AUTH_FAIL.search(line)
        if m:
            ev["AUTH_FAIL"].append((t, int(m.group(1))))
            continue
        m = RE_TELEMETRY.search(line)
        if m:
            seq, rtu, v, c, f, flags = m.groups()
            ev["TELEMETRY"].append((t, int(seq), int(rtu), float(v), float(c),
                                     float(f), int(flags)))
            continue
        m = RE_CHECKSUM_NACK.search(line)
        if m:
            ev["CHECKSUM_NACK"].append((t, int(m.group(1))))
            continue
        m = RE_SEQ_ANOMALY.search(line)
        if m:
            ev["SEQ_ANOMALY"].append((t, int(m.group(1)), int(m.group(2))))
            continue
        if RE_DISCONNECT_OK.search(line):
            ev["DISCONNECT_OK"].append((t,))
    return ev


def telemetry_plausible(ev):
    for _, seq, rtu, v, c, f, flags in ev["TELEMETRY"]:
        if not (100.0 <= v <= 140.0):
            return False, f"implausible voltage {v} (seq={seq})"
        if not (0.0 <= c <= 100.0):
            return False, f"implausible current {c} (seq={seq})"
        if not (59.5 <= f <= 60.5):
            return False, f"implausible frequency {f} (seq={seq})"
    return True, ""


def no_traceback(stderr):
    return "Traceback (most recent call last)" not in stderr


# --------------------------------------------------------------------------
# Scenario implementations
# --------------------------------------------------------------------------

def run_basic(ctx, scenario_id, server_args, min_telemetry=5, timeout=15.0, auth_deadline=5.0,
              duration=10.0):
    """Shared logic for a scenario that runs client-to-completion and checks
    handshake + telemetry + teardown. Returns (passed, detail).

    `duration` is passed to the client as `--duration <n>` per the
    Autograder Output Contract -- the client MUST stop streaming and
    disconnect on its own within that window, or `timeout` will be hit and
    the run graded as a hang.

    `scenario_id` selects the backend via start_backend() -- LOCAL spawn
    with `server_args`, or the fixed REMOTE_PORTS instance if
    ctx.remote_host is set."""
    server, host, port = start_backend(ctx, scenario_id, server_args)
    try:
        client = ClientRun(ctx.python, ctx.client_path, host, port,
                            ctx.student_id, extra_args=["--duration", str(duration)])
        client.wait(timeout=timeout)
        if client.alive():
            client.kill()
        lines, stderr, rc = client.snapshot()
        ev = parse_events(lines)

        if not ev["AUTH_OK"]:
            tail = stderr.strip()[-300:]
            return False, "never printed AUTH_OK" + (f" (stderr: {tail})" if tail else "")
        if ev["AUTH_OK"][0][0] > auth_deadline:
            return False, f"AUTH_OK took {ev['AUTH_OK'][0][0]:.2f}s (> {auth_deadline}s)"
        if len(ev["TELEMETRY"]) < min_telemetry:
            return False, f"only {len(ev['TELEMETRY'])} TELEMETRY lines (need >= {min_telemetry})"
        ok, why = telemetry_plausible(ev)
        if not ok:
            return False, why
        if not no_traceback(stderr):
            return False, f"unhandled traceback on stderr:\n{stderr[-800:]}"
        if not ev["DISCONNECT_OK"]:
            return False, "never printed DISCONNECT_OK (teardown not verified)"
        return True, f"AUTH_OK@{ev['AUTH_OK'][0][0]:.2f}s, {len(ev['TELEMETRY'])} telemetry samples"
    finally:
        if server is not None:
            server.stop()


def scenario_A(ctx):
    return run_basic(ctx, "A", [])


def scenario_B(ctx):
    """--chaos-fragment, must pass 10/10 consecutive runs."""
    failures = []
    for i in range(10):
        ok, detail = run_basic(ctx, "B", ["--chaos-fragment"], timeout=20.0, auth_deadline=8.0)
        if not ok:
            failures.append(f"run {i+1}: {detail}")
    if failures:
        return False, "; ".join(failures[:3]) + (" ..." if len(failures) > 3 else "")
    return True, "10/10 runs passed under --chaos-fragment"


def scenario_C(ctx):
    server, host, port = start_backend(ctx, "C", ["--chaos-coalesce"])
    try:
        client = ClientRun(ctx.python, ctx.client_path, host, port, ctx.student_id,
                            extra_args=["--duration", "10"])
        client.wait(timeout=15.0)
        if client.alive():
            client.kill()
        lines, stderr, rc = client.snapshot()
        ev = parse_events(lines)
        if not ev["AUTH_OK"]:
            tail = stderr.strip()[-300:]
            return False, "never printed AUTH_OK" + (f" (stderr: {tail})" if tail else "")
        if len(ev["TELEMETRY"]) < 15:
            return False, f"only {len(ev['TELEMETRY'])} TELEMETRY lines (need >= 15)"
        seqs = [row[1] for row in ev["TELEMETRY"]]
        if len(seqs) != len(set(seqs)):
            return False, "duplicate seq numbers decoded (coalesced burst mis-split)"
        if not no_traceback(stderr):
            return False, "unhandled traceback on stderr"
        return True, f"{len(ev['TELEMETRY'])} telemetry samples, no duplicate seqs"
    finally:
        if server is not None:
            server.stop()


def scenario_D(ctx):
    server, host, port = start_backend(ctx, "D", ["--chaos-corrupt", "--corrupt-rate", "0.30"])
    try:
        client = ClientRun(ctx.python, ctx.client_path, host, port, ctx.student_id,
                            extra_args=["--duration", "15"])
        client.wait(timeout=20.0)
        if client.alive():
            client.kill()
        lines, stderr, rc = client.snapshot()
        ev = parse_events(lines)
        if not ev["AUTH_OK"]:
            tail = stderr.strip()[-300:]
            return False, "never printed AUTH_OK" + (f" (stderr: {tail})" if tail else "")
        if not ev["CHECKSUM_NACK"]:
            return False, "never printed CHECKSUM_NACK despite 30% corruption rate"
        nack_seqs = {seq for _, seq in ev["CHECKSUM_NACK"]}
        recovered = False
        for t, seq, *_ in ev["TELEMETRY"]:
            if seq in nack_seqs:
                nack_t = min(tt for tt, s in ev["CHECKSUM_NACK"] if s == seq)
                if t > nack_t:
                    recovered = True
                    break
        if not recovered:
            return False, "sent CHECKSUM_NACK but no matching seq later decoded from TELEMETRY (retransmit round-trip incomplete)"
        if not no_traceback(stderr):
            return False, "unhandled traceback on stderr"
        return True, f"{len(ev['CHECKSUM_NACK'])} NACKs sent, at least one retransmit recovered"
    finally:
        if server is not None:
            server.stop()


def scenario_E(ctx):
    server, host, port = start_backend(ctx, "E", ["--chaos-jitter"])
    try:
        client = ClientRun(ctx.python, ctx.client_path, host, port, ctx.student_id,
                            extra_args=["--duration", "15"])
        client.wait(timeout=20.0)
        if client.alive():
            client.kill()
        lines, stderr, rc = client.snapshot()
        ev = parse_events(lines)
        if not ev["AUTH_OK"]:
            tail = stderr.strip()[-300:]
            return False, "never printed AUTH_OK" + (f" (stderr: {tail})" if tail else "")
        if len(ev["TELEMETRY"]) < 20:
            return False, f"only {len(ev['TELEMETRY'])} TELEMETRY lines (need >= 20)"
        if not ev["SEQ_ANOMALY"]:
            return False, "never printed SEQ_ANOMALY despite jitter mode"
        if not no_traceback(stderr):
            return False, "client crashed on non-monotonic sequence numbers"
        return True, f"{len(ev['TELEMETRY'])} telemetry, {len(ev['SEQ_ANOMALY'])} anomalies detected, no crash"
    finally:
        if server is not None:
            server.stop()


def scenario_F(ctx):
    server, host, port = start_backend(
        ctx, "F", ["--chaos-fragment", "--chaos-coalesce", "--chaos-corrupt", "--chaos-jitter"])
    try:
        client = ClientRun(ctx.python, ctx.client_path, host, port, ctx.student_id,
                            extra_args=["--duration", "150"])
        time.sleep(120.0)
        lines, stderr, rc = client.snapshot()
        still_alive = client.alive()
        client.kill()
        ev = parse_events(lines)
        if not ev["AUTH_OK"]:
            tail = stderr.strip()[-300:]
            return False, "never printed AUTH_OK" + (f" (stderr: {tail})" if tail else "")
        if not still_alive:
            return False, f"process exited before t=120s (returncode={rc})"
        if not ev["TELEMETRY"] or ev["TELEMETRY"][-1][0] < 100.0:
            return False, "no recent TELEMETRY activity near t=120s"
        if not no_traceback(stderr):
            return False, "unhandled traceback on stderr during sustained run"
        return True, f"alive at t=120s, {len(ev['TELEMETRY'])} total telemetry samples"
    finally:
        if server is not None:
            server.stop()


def scenario_G(ctx):
    return run_basic(ctx, "G", ["--inject-unknown-opcode"])


# (id, description, fn, points, suite)
SCENARIOS = [
    ("A", "Basic framing, handshake & math, no chaos", scenario_A, 55, "hw1"),
    ("G", "FSM enforcement: unknown opcode tolerance", scenario_G, 25, "hw1"),
    ("B", "Fragmentation resilience (10x)", scenario_B, 8, "hw2"),
    ("C", "Coalesced burst decoding", scenario_C, 8, "hw2"),
    ("D", "Checksum corruption + NACK recovery", scenario_D, 10, "hw2"),
    ("E", "Sequence jitter detection", scenario_E, 7, "hw2"),
    ("F", "All chaos modes, 120s sustained", scenario_F, 7, "hw2"),
]

MANUAL_POINTS = {
    "hw1": [("Written check-in (03_written_checkin.md)", 20)],
    "hw2": [("Wireshark trace analysis", 25), ("Quiz (oral defense + Layer 4 trace)", 35)],
}


class Ctx:
    def __init__(self, python, client_path, server_path, student_id, remote_host=None):
        self.python = python
        self.client_path = client_path
        self.server_path = server_path
        self.student_id = student_id
        self.remote_host = remote_host


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--client", required=True, help="path to student's client.py")
    p.add_argument("--student-id", type=int, required=True)
    p.add_argument("--server-path", default=str(HERE / "teacher_server.py"),
                    help="path to teacher_server.py for LOCAL-mode scenarios (HW1's "
                         "A/G always use this; HW2's B-F use it too unless "
                         "--remote-host is given)")
    p.add_argument("--remote-host", default=None,
                    help="HW2 self-testing: connect to the instructor's live, "
                         "fixed-port server instead of spawning teacher_server.py "
                         "locally. Only affects hw2 suite scenarios (B-F) -- hw1 "
                         "scenarios (A, G) always run LOCAL regardless, since HW1's "
                         "server is distributed to students directly. See the repo "
                         "README's HW2 quickstart for the actual host to use.")
    p.add_argument("--python", default=sys.executable)
    p.add_argument("--suite", choices=["hw1", "hw2", "all"], default="all",
                    help="which assignment's automated scenarios to run "
                         "(default: all scenarios from both)")
    p.add_argument("--scenario", default=None,
                    help="run only this scenario id (A-G) regardless of --suite; "
                         "default: every scenario in the selected suite")
    p.add_argument("--report", default=None, help="write JSON report to this path")
    args = p.parse_args()

    ctx = Ctx(args.python, args.client, args.server_path, args.student_id, args.remote_host)

    scenarios = [s for s in SCENARIOS if args.suite == "all" or s[4] == args.suite]
    if args.scenario is not None:
        scenarios = [s for s in scenarios if s[0] == args.scenario]
    if not scenarios:
        print(f"No scenarios match --suite {args.suite} --scenario {args.scenario}",
              file=sys.stderr)
        sys.exit(2)

    if args.remote_host is not None:
        hw1_ids = [s[0] for s in scenarios if s[4] == "hw1"]
        if hw1_ids:
            print(f"NOTE: --remote-host has no effect on HW1 scenario(s) "
                  f"{', '.join(hw1_ids)} -- these always spawn teacher_server.py "
                  f"locally, since HW1's server is distributed to students directly. "
                  f"Running them LOCAL as usual.")

    results = []
    total_points = sum(pts for _, _, _, pts, _ in scenarios)
    earned_points = 0

    mode_note = f"remote-host={args.remote_host}" if args.remote_host else "local"
    print(f"Grading {args.client} (student_id={args.student_id}) -- suite={args.suite} ({mode_note})")
    print("-" * 78)
    for sid, desc, fn, pts, suite in scenarios:
        print(f"[{sid}/{suite}] {desc} ({pts} pts) ... ", end="", flush=True)
        t0 = time.monotonic()
        try:
            passed, detail = fn(ctx)
        except Exception as e:
            passed, detail = False, f"harness exception: {e!r}"
        dt = time.monotonic() - t0
        status = "PASS" if passed else "FAIL"
        print(f"{status}  ({dt:.1f}s) -- {detail}")
        if passed:
            earned_points += pts
        results.append({"id": sid, "suite": suite, "description": desc, "points": pts,
                         "passed": passed, "detail": detail, "duration_s": round(dt, 2)})

    print("-" * 78)
    print(f"Automated score: {earned_points}/{total_points}")

    suites_touched = sorted({s[4] for s in scenarios})
    for suite in suites_touched:
        manual = MANUAL_POINTS.get(suite, [])
        if manual:
            manual_desc = ", ".join(f"{name} ({pts} pts)" for name, pts in manual)
            manual_total = sum(pts for _, pts in manual)
            print(f"  ({suite}: automated portion only -- remaining {manual_total} pts "
                  f"graded manually: {manual_desc})")

    if args.report:
        with open(args.report, "w") as f:
            json.dump({
                "client": str(args.client),
                "student_id": args.student_id,
                "suite": args.suite,
                "backend": mode_note,
                "results": results,
                "automated_points_earned": earned_points,
                "automated_points_possible": total_points,
            }, f, indent=2)
        print(f"Report written to {args.report}")

    sys.exit(0 if earned_points == total_points else 1)


if __name__ == "__main__":
    main()
