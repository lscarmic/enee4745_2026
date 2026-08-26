# HW1 — Grading Rubric & Automated Test Suite
## ENEE 4745 (SGRP/1 Application-Layer Client)

Total: 100 points, graded entirely independently of HW2 (its own 100-point
scale, its own gradebook entry). Automated scoring (`autograder.py --suite
hw1`) covers the majority of points objectively and reproducibly; the
written check-in is graded by the instructor/TA.

---

## 1. Point Breakdown

### 1.1 Basic Framing, Handshake & Math — 55%

| Item | Points | How assessed |
|---|---:|---|
| Client connects and completes handshake | 10 | Automated (Scenario A) |
| Session-key rolling hash correctly implemented and matches server for **this student's own ID** | 10 | Automated (Scenario A — auth fails immediately if wrong) + manual spot-check of your handshake math writeup |
| All multi-byte integer fields parsed/packed with correct network byte order | 10 | Automated — a byte-order bug corrupts `payload_len`/`seq`/checksums and Scenario A fails outright |
| Fletcher-16 header and payload checksums bit-exact against the server | 10 | Automated (Scenario A — a wrong `fletcher16()` causes the client's own `ChecksumError` to fire on every real frame) |
| IEEE-754 float fields (`voltage`, `current`, `frequency`) decoded to physically plausible values (100–140V, 0–100A, 59.5–60.5Hz) | 10 | Automated (Scenario A telemetry-value sanity check) |
| Clean connection teardown (`C_DISCONNECT` / `S_DISCONNECT_ACK`) | 5 | Automated (Scenario A, teardown check) |

### 1.2 FSM Enforcement — 25%

| Item | Points | How assessed |
|---|---:|---|
| Client does not crash/hang on a well-formed frame carrying an opcode it has no specific handler for | 15 | Automated (Scenario G — server injects one unrecognized opcode after auth) |
| Client continues streaming normally after the unrecognized frame (doesn't silently stop, doesn't desync the byte stream) | 10 | Automated (Scenario G — telemetry count check after the injected frame) |

### 1.3 Written Check-In — 20%

| Item | Points | How assessed |
|---|---:|---|
| Written check-in score | 20 | Manual, instructor/TA-administered |

**Automated total: 80 of 100.** The remaining 20 points are the written
check-in, graded separately and merged in by the instructor. Expect
questions about your specific header layout and field offsets, how and
why the Fletcher-16 checksum is computed the way it is, the FSM state
transitions, and a worked example of your own handshake math — your
instructor will provide the exact format and timing.

---

## 2. Automated Test Suite (`autograder.py --suite hw1`)

### 2.1 Design

The autograder is a **black-box harness** — it never imports your
`client.py`. It launches `teacher_server.py` and your client as
subprocesses, and grades by parsing your client's stdout against the
Autograder Output Contract (Appendix A below).

### 2.2 Scenarios

| ID | Server flags | Pass criteria (summary) | Points |
|---|---|---|---:|
| A | *(none — HW1 never uses chaos flags)* | `AUTH_OK` within 5s; ≥5 `TELEMETRY` lines with voltage in [100,140]V, current in [0,100]A, freq in [59.5,60.5]Hz; `DISCONNECT_OK`; clean exit | 55 |
| G | `--inject-unknown-opcode` | Same baseline as A, plus: client does not crash after receiving one injected unrecognized-opcode frame, and continues producing `TELEMETRY` lines afterward | 25 |

```
python3 autograder.py --suite hw1 --client path/to/student/client.py \
    --student-id 123456 --server-path teacher_server.py --report report.json
```

Automated portion out of 80; written check-in (20) is merged in by the
instructor to produce the final 100-point HW1 grade.

---

## Appendix A — Autograder Output Contract (HW1 subset)

```
AUTH_OK session_id=<int>
AUTH_FAIL reason=<int>
TELEMETRY seq=<int> rtu=<int> voltage=<float> current=<float> freq=<float> flags=<int>
DISCONNECT_OK
```

This is a subset of the full contract used in HW2 (which adds
`CHECKSUM_NACK` and `SEQ_ANOMALY` lines, not required or checked in HW1).
The contract is already embedded as guidance in the `TODO` comments of
`02_client_starter.py`; students following the starter template's
structure satisfy it without extra work.

The client must also accept a `--duration <seconds>` CLI flag (already
wired into `main()` and passed through to `streaming_loop()`) that bounds
how long it streams before initiating graceful disconnect — the
autograder always passes an explicit, finite value, and a client that
ignores it and only stops on Ctrl-C will time out and fail Scenario A/G
even if its framing logic is otherwise correct.
