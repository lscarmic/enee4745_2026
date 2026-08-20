# HW2 — Grading Rubric & Automated Test Suite
## ENEE 4745 (SGRP/1 Chaos Resilience, Wireshark, and Quiz)

Total: 100 points, graded entirely independently of HW1 (its own 100-point
scale, its own gradebook entry). Automated scoring (`autograder.py --suite
hw2`) covers a meaningful minority of points objectively and
reproducibly; the majority of HW2's weight is intentionally in the parts
that can't be gamed by a black-box test alone — Wireshark evidence and the
live quiz.

**This is a deliberate shift from a single-assignment design:** now that
the oral/quiz component is scheduled and graded as its own explicit thing
(rather than an afterthought bolted onto a code rubric), it carries real
point weight — more than the automated chaos scenarios do. That's by
design: passing the autograder proves your code survives the chaos
harness; the quiz proves you understand why.

---

## 1. Point Breakdown

### 1.1 Chaos / Fragmentation Resilience — 40%

| Item | Points | How assessed |
|---|---:|---|
| Survives `--chaos-fragment` alone, full handshake + streaming, no crash, 10/10 runs | 8 | Automated (Scenario B) |
| Survives `--chaos-coalesce` alone, correctly decodes all 3 coalesced frames per burst | 8 | Automated (Scenario C) |
| Detects corrupted checksum and sends `C_CHECKSUM_NACK`; successfully receives and decodes the retransmit | 10 | Automated (Scenario D) |
| Detects and logs (does not silently ignore or crash on) non-monotonic sequence numbers | 7 | Automated (Scenario E) |
| Survives **all four chaos flags simultaneously** for a sustained 120-second run | 7 | Automated (Scenario F) |

### 1.2 Wireshark Trace Analysis — 25%

| Item | Points | How assessed |
|---|---:|---|
| `capture.pcapng` present, correct host+port filter, contains a full session | 4 | Manual |
| Annotation Table 1 — successful handshake, byte-accurate hex offsets | 8 | Manual |
| Annotation Table 2 — fragmented-segment reassembly, code trace correlated to pcap timestamps | 8 | Manual |
| Annotation Table 3 — corrupted-checksum NACK exchange, correct byte identified as flipped | 5 | Manual |

### 1.3 Quiz — 35%

| Item | Points | How assessed |
|---|---:|---|
| Part A: code/protocol oral defense (conceptual understanding + AI-hallucination diagnostics) | 20 | Manual, live — see `05_oral_quiz_bank.md` Sections A/B |
| Part B: TCP sequence/acknowledgment tracing from the student's own capture | 15 | Manual, live — see `05_oral_quiz_bank.md` Section C |

**Zero-`.pcapng` policy (handout §9):** a submission missing the capture or
any of the three annotation tables is capped at 50/100 regardless of code
score, because network evidence and code correctness are independently
graded competencies here — a client that "happens to work" without the
student being able to show *why*, byte by byte, has not met this
assignment's learning objectives.

**No-quiz policy:** a student who does not complete the quiz receives 0
for the Quiz category (35 points) regardless of automated and Wireshark
scores, and — consistent with the zero-`.pcapng` policy above — should be
flagged for a follow-up conversation rather than simply recorded as a
partial score, since the quiz is this course's primary defense against
work that isn't genuinely the student's own.

---

## 2. Automated Test Suite (`autograder.py --suite hw2`)

### 2.1 Design

The autograder is a **black-box harness**, not a unit-test importer of
student internals — it never imports the student's `client.py`. Instead
it:

1. Obtains a server to test against. There are two backend modes (see
   `../shared/autograder.py`'s module docstring for the full rationale):
   **LOCAL** (instructor/TA use — launches `teacher_server.py` as a
   subprocess on a scratch port with a specific combination of chaos
   flags for each scenario) or **REMOTE** (`--remote-host` — student
   self-testing, connects directly to the instructor's already-running,
   fixed-port instance instead of spawning anything; students don't have
   `teacher_server.py` for HW2, so this is the only self-test path
   available to them). Both modes exercise the identical scenario logic
   below.
2. Launches the student's `client.py` as a subprocess with a fixed
   argument set and a wall-clock timeout.
3. Captures the client's **stdout** and parses it against the **Autograder
   Output Contract** (Appendix A below) — the exact tagged print lines
   specified in the `TODO` comments of `02_client_starter.py`.
4. Applies scenario-specific pass/fail predicates against the parsed
   events (e.g., "at least 20 `TELEMETRY` lines with plausible voltage",
   "at least 1 `CHECKSUM_NACK` line when the corrupt-mode server is
   active", "no unhandled Python traceback on stderr", "process exits
   within timeout after `DISCONNECT_OK`").
5. In LOCAL mode, tears down the server subprocess and repeats for the
   next scenario; in REMOTE mode, there's nothing to tear down — the
   instructor's instance keeps running for the next student.

This design is deliberately robust to *internal* implementation choices
(threading vs. select vs. blocking sockets, exact buffer data structure,
etc.) — it only checks externally observable protocol behavior, which is
what actually matters for a network client.

### 2.2 Scenarios

| ID | Server flags | Pass criteria (summary) | Points |
|---|---|---|---:|
| B | `--chaos-fragment` | Same baseline as HW1's Scenario A, run 10× consecutively, all 10 must pass (framing accumulator must be deterministically correct, not "usually works") | 8 |
| C | `--chaos-coalesce` | `AUTH_OK`; ≥15 `TELEMETRY` lines (3 per burst × ≥5 bursts) with strictly no duplicate seq within a burst | 8 |
| D | `--chaos-corrupt --corrupt-rate 0.30` (boosted rate for faster, reliable triggering in a bounded test window — in REMOTE mode this is a dedicated autograder-only port, distinct from the realistic-5%-rate port students use for milestone practice and their Wireshark capture) | `AUTH_OK`; ≥1 `CHECKSUM_NACK` line; at least one seq number appears in a later `TELEMETRY` line **after** appearing in a `CHECKSUM_NACK` line (proves the retransmit round-trip actually completed, not just that the NACK was sent) | 10 |
| E | `--chaos-jitter` | `AUTH_OK`; ≥20 `TELEMETRY` lines; ≥1 `SEQ_ANOMALY` line; **no crash** (a client that hard-fails on out-of-order seq fails this scenario even if it "detects" the anomaly via an uncaught exception) | 7 |
| F | `--chaos-fragment --chaos-coalesce --chaos-corrupt --chaos-jitter` | Process must still be alive and producing `TELEMETRY` lines at t=120s; no traceback on stderr | 7 |

Instructor/TA grading (LOCAL mode, full source):
```
python3 autograder.py --suite hw2 --client path/to/student/client.py \
    --student-id 123456 --server-path teacher_server.py --report report.json
```

Student self-testing (REMOTE mode, no server source needed):
```
python3 autograder.py --suite hw2 --client path/to/student/client.py \
    --student-id 123456 --remote-host <instructor host> --report report.json
```

Both invocations run the identical scenario logic against the identical
protocol behavior — REMOTE mode is not a weaker approximation, it's the
same harness pointed at the same server the grading run will use.

Automated portion out of 40; Wireshark (25) and Quiz (35) are graded
separately and merged in by the instructor to produce the final 100-point
HW2 grade.

---

## Appendix A — Autograder Output Contract (full, HW2)

```
AUTH_OK session_id=<int>
AUTH_FAIL reason=<int>
TELEMETRY seq=<int> rtu=<int> voltage=<float> current=<float> freq=<float> flags=<int>
CHECKSUM_NACK seq=<int>
SEQ_ANOMALY expected=<int> got=<int>
DISCONNECT_OK
```

This is the full contract — HW1 only required the subset without
`CHECKSUM_NACK`/`SEQ_ANOMALY`. This contract is already embedded as
guidance in the `TODO` comments of `02_client_starter.py`; students
following the starter template's structure satisfy it without extra work.

The client must also accept a `--duration <seconds>` CLI flag (already
wired into `main()` and passed through to `streaming_loop()`) that bounds
how long it streams before initiating graceful disconnect; `0` means "run
until Ctrl-C." **The autograder always passes an explicit, finite
`--duration`** appropriate to each scenario (10–20s for Scenarios B–E,
150s for the sustained Scenario F) — a client whose `streaming_loop()`
ignores this argument and only ever stops on Ctrl-C will time out and fail
every automated scenario even if its framing and chaos-handling logic is
otherwise correct.
