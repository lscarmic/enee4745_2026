# ENEE 4745 — Homework 1
## SGRP/1 Application-Layer Protocol Client: Framing, Handshake & Telemetry Decode

**Protocol:** SGRP/1 (Smart Grid RTU Protocol, version 1) — a fictional protocol designed for this course.
**Duration:** 2 weeks
**Individual assignment.** Every student receives a unique wire trace (see §5).
**Part 1 of 2.** This assignment is graded independently, on its own 100-point scale. HW2 (released separately, later in the course) picks up where this one leaves off and is graded independently as well.

---

## 1. Background & Scenario

You have been hired as a firmware/network engineer contractor for **Terrapin Power & Light (TP&L)**, a fictional regional utility modernizing its distribution substations. Each substation runs a **Remote Terminal Unit (RTU)** that reports voltage, current, and frequency telemetry to the utility's central SCADA (Supervisory Control and Data Acquisition) head-end.

TP&L's legacy RTUs speak a homegrown application-layer protocol over TCP called **SGRP** (Smart Grid RTU Protocol). In HW1, your job is to write the **head-end client** in Python that:

1. Opens a TCP connection to an RTU (simulated by the teacher-supplied `teacher_server.py`).
2. Performs a cryptographic-style handshake using your Student ID.
3. Subscribes to telemetry streaming for a given RTU.
4. Correctly decodes framed binary telemetry.
5. Enforces the protocol's session state machine — rejecting or ignoring anything that shows up out of place, without crashing.

This is a real protocol-engineering exercise, not a toy: TP&L's actual field deployment has to tolerate a genuinely hostile network, and you'll build that resilience in HW2. HW1 is scoped narrower on purpose — you're building and proving out the **application-layer protocol logic** first, against a well-behaved connection, before adding the transport-layer complications on top of it. Treat this as the foundation the rest of the project is built on: sloppy framing or handshake logic here will cost you twice, once on this grade and again when HW2 asks you to make that same logic survive a hostile network.

---

## 2. Learning Objectives

By the end of HW1 you will be able to:

1. Construct and parse fixed-and-variable-length binary frames using Python's `struct` module with explicit network byte order (`!`/`>`).
2. Implement and verify a **Fletcher-16 checksum** for corruption detection.
3. Implement a strict **finite state machine (FSM)** for an application-layer session and reject/ignore frames that violate the current state, without crashing.
4. Derive and apply a per-student cryptographic-style handshake key from a rolling-hash function.
5. Explain, in writing, the design decisions behind a binary wire protocol — why each field exists, why checksums are computed the way they are, and what a well-formed session looks like from first byte to last.

**Not covered in HW1 (deliberately deferred to HW2):** how TCP actually delivers bytes to your socket, why a single `recv()` call cannot be trusted to return one complete message, Wireshark packet capture and hex annotation, and be able to explain these things on a quiz. The course lecture sequence will not have reached TCP's transport-layer behavior yet and that's fine — HW1 doesn't require it. Keep that in mind, though: the fact that a simple `sock.recv(12)` "just works" against this assignment's server is a property of *this specific, well-behaved class server*, not a property of TCP in general. HW2 will make that distinction very concrete.

---

## 3. Wire Format Specification

### 3.1 Byte Order

All multi-byte integer fields are **network byte order (big-endian)**. Use `struct` format prefix `!` (or `>`) — never rely on host byte order. Conceptually this is the same operation `htons`/`htonl`/`ntohs`/`ntohl` perform in C; in Python, `struct.pack('!H', x)` and `struct.pack('!I', x)` do this for you. Floats are IEEE-754 single precision (`struct` code `f`), also big-endian on the wire.

### 3.2 Frame Layout

Every SGRP frame — client→server or server→client — has this shape:

```
+----------------+----------------------+------------------------+
|  Header (12B)  |  Payload (0..65535B) |  Payload Checksum (2B) |
+----------------+----------------------+------------------------+
```

Total frame length on the wire = `12 + PayloadLen + 2`. **`PayloadLen` (see below) counts only the payload — it does NOT include the 12-byte header or the 2-byte trailing checksum.** This is a deliberate trap: a naive client that reads `12 + PayloadLen` bytes and stops will be two bytes short of a full frame.

### 3.3 Header Diagram (12 bytes, offsets 0–11)

```
 Byte:      0        1        2        3
          +--------+--------+--------+--------+
          | 0xA5   | 0x5A   |Version | OpCode |
          | Magic0 | Magic1 | (0x01) |        |
          +--------+--------+--------+--------+
 Byte:      4        5        6        7
          +-----------------+-----------------+
          |   SeqNum (u16)  | SessionID (u16) |
          +-----------------+-----------------+
 Byte:      8        9        10       11
          +-----------------+-----------------+
          | PayloadLen(u16) | HdrChecksum(u16)|
          +-----------------+-----------------+
```

| Offset | Field | Type | Description |
|---|---|---|---|
| 0 | `magic0` | `uint8` | Always `0xA5`. First half of frame sync pattern. |
| 1 | `magic1` | `uint8` | Always `0x5A`. Second half of frame sync pattern. |
| 2 | `version` | `uint8` | Protocol version. Always `0x01` for SGRP/1. |
| 3 | `opcode` | `uint8` | Message type — see §3.6/§3.7. |
| 4–5 | `seq_num` | `uint16` | Monotonically increasing per-sender sequence counter, starts at 0 at handshake. |
| 6–7 | `session_id` | `uint16` | `0x0000` before authentication; server-assigned nonzero ID afterward. |
| 8–9 | `payload_len` | `uint16` | Length **in bytes of the payload only** (0–65535). |
| 10–11 | `hdr_checksum` | `uint16` | Fletcher-16 checksum computed over header bytes 0–9 (i.e., everything **except** this field). |

After the header: `payload_len` bytes of payload (structure depends on `opcode`, see §3.6/§3.7), followed by:

| Field | Type | Description |
|---|---|---|
| `payload_checksum` | `uint16` | Fletcher-16 checksum computed over the payload bytes only (zero-length payload ⇒ checksum of the empty sequence, which is `0x0000`). |

### 3.4 Fletcher-16 Checksum (reference algorithm)

```python
def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for b in data:
        sum1 = (sum1 + b) % 255
        sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1
```

You must implement this exact algorithm — the class server uses it for both the header and payload checksums, and grading depends on bit-exact agreement. **In HW1, the server never intentionally corrupts a frame** — but your client should still compute and check both checksums on every frame it receives. If your own `fletcher16()` has a bug, every real (uncorrupted) frame will appear to fail its checksum from your client's point of view. That's a sign to go fix your checksum function, not a case you need to build recovery logic for yet — checksum-mismatch *recovery* (asking the server to resend a frame) is an HW2 skill.

### 3.5 OpCode Table — Client → Server (`0x00`–`0x7F`)

| OpCode | Name | Payload | Valid FSM State(s) |
|---|---|---|---|
| `0x01` | `C_HELLO` | `student_id: uint32` (4B) | `UNCONNECTED` → sent immediately after `connect()` |
| `0x02` | `C_AUTH_RESPONSE` | `session_key: uint32` (4B) | `AWAITING_NONCE` (after receiving `S_NONCE_CHALLENGE`) |
| `0x10` | `C_SUBSCRIBE` | `rtu_id: uint16`, `sample_rate: uint8` (0=1Hz,1=5Hz,2=10Hz) (3B) | `AUTHENTICATED` |
| `0x11` | `C_UNSUBSCRIBE` | `rtu_id: uint16` (2B) | `STREAMING` |
| `0x20` | `C_GET_STATUS` | `rtu_id: uint16` (2B) | `AUTHENTICATED` or `STREAMING` |
| `0x30` | `C_PING` | *(empty)* | any post-auth state |
| `0x31` | `C_CHECKSUM_NACK` | `bad_seq: uint16` (2B) | `STREAMING` — this exists for HW2; you don't need to send it in HW1, but the opcode is part of the spec you should recognize. |
| `0x7F` | `C_DISCONNECT` | *(empty)* | any state — graceful teardown |

### 3.6 OpCode Table — Server → Client (`0x80`–`0xFF`)

| OpCode | Name | Payload | Meaning |
|---|---|---|---|
| `0x81` | `S_NONCE_CHALLENGE` | `nonce: uint32`, `poly_a: uint16`, `poly_b: uint16` (8B) | Sent in response to `C_HELLO`. See §4 for key derivation. |
| `0x82` | `S_AUTH_ACK` | `assigned_session_id: uint16` (2B) | Handshake succeeded; client is now `AUTHENTICATED`. |
| `0x83` | `S_AUTH_NACK` | `reason_code: uint8` (1B) | Handshake failed (bad key). Connection will be closed by server. |
| `0x90` | `S_TELEMETRY_DATA` | `rtu_id: uint16`, `timestamp: uint32` (unix epoch seconds), `voltage: float32`, `current: float32`, `frequency: float32`, `status_flags: uint8` (19B) | One telemetry sample. |
| `0x91` | `S_STATUS_RESPONSE` | `rtu_id: uint16`, `online: uint8`, `last_seen: uint32` (7B) | Response to `C_GET_STATUS`. |
| `0x92` | `S_PONG` | *(empty)* | Response to `C_PING`. |
| `0xE0` | `S_NACK_CHECKSUM` | `bad_seq: uint16` (2B) | Not used in HW1's default flow; part of the full spec for HW2. |
| `0xE1` | `S_NACK_SEQUENCE` | `expected_seq: uint16`, `got_seq: uint16` (4B) | Server-side sequence anomaly notice; relevant starting in HW2. |
| `0xE2` | `S_NACK_MALFORMED` | `reason_code: uint8` (1B) | Frame failed structural validation (bad magic, bad version, bad length). |
| `0xFF` | `S_DISCONNECT_ACK` | *(empty)* | Acknowledges `C_DISCONNECT`; server will close the socket. |

`status_flags` bitfield for `S_TELEMETRY_DATA`: bit 0 = breaker closed, bit 1 = over-voltage alarm, bit 2 = under-frequency alarm, bits 3–7 reserved (must be ignored, not treated as an error, if set — protocols evolve, and forward-compatible parsers don't choke on reserved bits).

---

## 4. Protocol Finite State Machine & Per-Student Handshake

### 4.1 States

```
UNCONNECTED
    │  TCP connect() succeeds
    ▼
HANDSHAKE_INIT ──(send C_HELLO)──► AWAITING_NONCE
    │
    │  recv S_NONCE_CHALLENGE
    ▼
AWAITING_AUTH_RESULT ──(send C_AUTH_RESPONSE)──┐
    │                                          │
    │ recv S_AUTH_ACK                          │ recv S_AUTH_NACK
    ▼                                          ▼
AUTHENTICATED                                CLOSED (auth failed)
    │  send C_SUBSCRIBE
    ▼
STREAMING ──(send C_DISCONNECT / recv S_DISCONNECT_ACK)──► CLOSED
```

Any frame that is structurally invalid for the *current* state (e.g., a `S_TELEMETRY_DATA` arriving before `AUTHENTICATED`), or that carries an opcode your client doesn't specifically handle, must be logged and discarded — **not** crash your client. A client that terminates on an unexpected opcode is a client that takes down the control room dashboard the moment the protocol gains one new message type.

### 4.2 Why Your Handshake Is Unique

Every student is assigned a **Student ID** (a `uint32` — your instructor will hand these out; do not reuse someone else's). During the handshake:

1. Client sends `C_HELLO{student_id}`.
2. Server derives two per-student polynomial coefficients:
   ```
   poly_a = (student_id % 251) + 2
   poly_b = (student_id * 7) % 65521
   ```
3. Server generates a fresh random `nonce: uint32` for this connection and sends `S_NONCE_CHALLENGE{nonce, poly_a, poly_b}`.
4. **Both sides** compute the session key with a rolling-hash function seeded by the student's own ID:
   ```python
   def derive_session_key(student_id: int, nonce: int, poly_a: int, poly_b: int) -> int:
       h = student_id & 0xFFFFFFFF
       for b in nonce.to_bytes(4, "big"):
           h = (h * poly_a + b + poly_b) & 0xFFFFFFFF
       return h
   ```
5. Client sends `C_AUTH_RESPONSE{session_key}`. Server compares against its own computation; match → `S_AUTH_ACK`, mismatch → `S_AUTH_NACK`.

Because `poly_a`/`poly_b`/`nonce` all depend on your Student ID (and the nonce is randomized per connection), **no two students will ever produce an identical byte-for-byte trace**, even running identical high-level logic. This is intentional: it defeats "copy a classmate's code and just run it" and forces genuine engagement with the math, not just the socket plumbing. Your written check-in (§6) will ask you to show this math worked out by hand for your own Student ID.

---

## 5. Milestones (1-Week Schedule)

- **Day 1:** Read this spec in full. Stand up `teacher_server.py --port 8080 --profile hw1` (no chaos flags — HW1 never uses them). Get `client_starter.py` to open a TCP connection and complete `C_HELLO` → `S_NONCE_CHALLENGE` → `C_AUTH_RESPONSE` → `S_AUTH_ACK`.
- **Day 2:** Implement Fletcher-16 for both header and payload checksums; verify bit-exact agreement against the server. Implement `C_SUBSCRIBE` and decode incoming `S_TELEMETRY_DATA`.
- **Day 3:** Implement FSM enforcement — reject/log frames with bad `magic`/`version`/checksum or an opcode that's invalid for the current state, without crashing. Implement graceful teardown (`C_DISCONNECT` / `S_DISCONNECT_ACK`).
- **Day 4:** Polish, re-run against the autograder locally, write up your handshake math (`handshake_math.md`).
- **Day 5 (or your instructor's designated check-in day):** Written check-in (see §6) and final submission.

**Checkpoint:** by the end of Day 3, your client should complete the handshake and print `AUTHENTICATED` reliably, and stream at least a few telemetry samples without crashing.

---

## 6. Written Check-In

Instead of a live oral defense (that begins in HW2), HW1 pairs its automated grading with a **short written check-in** — a handful of questions completed individually, in class or during a scheduled session, without your code or notes open. It's meant to confirm you understand what you built, not to catch you off guard: expect questions about your specific header layout and field offsets, how and why the Fletcher-16 checksum is computed the way it is, the FSM state transitions and why an unexpected opcode must be discarded rather than crash the client, and a worked example of your own handshake math (`poly_a`, `poly_b`, and a session key computed by hand for your Student ID). Your instructor will provide the exact question set and timing separately.

**One important thing this check-in exists to enforce:** everyone in the class needs a genuinely working HW1 client before HW2 begins, because HW2 builds directly on top of it. If your client isn't passing the automated checks by the time HW2 starts, talk to your instructor — don't just show up to HW2 with a broken foundation and hope to debug two layers of problems at once.

---

## 7. Submission Checklist

- [ ] `client.py` — your completed client implementation
- [ ] `handshake_math.md` or inline comments deriving your `poly_a`/`poly_b` for your specific Student ID, with a worked numeric example
- [ ] Written check-in completed (see §6 — scheduled separately by your instructor)

There is no Wireshark capture, no `.pcapng`, and no live oral defense in HW1 — those begin in HW2, once your working HW1 client is the thing you'll be asked to make resilient.

---

## 8. Looking Ahead to HW2

HW2 takes the client you build here and asks a harder question: what happens when the network stops being polite? You'll be introduced to a chaos-enabled version of this same server, learn why a single `recv()` call can never be trusted to return exactly one frame's worth of bytes, and rebuild your framing logic into something that survives fragmentation, coalescing, corruption, and out-of-order application-level sequence numbers — with a Wireshark capture and a live quiz to prove you understand *why* it works, not just that it happens to pass. Nothing about HW1's wire format changes; the protocol you're building today is the exact protocol you'll be defending under fire in HW2.
