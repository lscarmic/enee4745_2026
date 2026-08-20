# ENEE 4745 — Homework 2
## Robust Layer-7 SCADA Client for Substation RTU Telemetry over a Hostile TCP Link

**Protocol:** SGRP/1 (Smart Grid RTU Protocol, version 1) — unchanged from HW1.
**Duration:** 1.5 weeks (6–7 class days)
**Individual assignment.** Every student receives a unique wire trace (see §3, carried over from HW1). Two identical submissions are a Section 11 (Academic Integrity) referral regardless of who wrote the code.
**Part 2 of 2.** This assignment is graded independently, on its own 100-point scale, separate from HW1.

---

## 1. Recap & What's New

In HW1 you built a working SGRP/1 client: a per-student handshake, binary frame construction and parsing, Fletcher-16 checksums, and basic FSM discipline — all against a teacher server that was, deliberately, well-behaved, and that you ran yourself. HW2 keeps the exact same wire format and the exact same protocol logic you already built, and changes two things: the network stops being polite, and the server stops being something you can inspect.

You have been (still) hired as a firmware/network engineer contractor for **Terrapin Power & Light (TP&L)**. Their real field deployment doesn't run over a clean loopback connection — substation communication links are narrowband, congested, and unreliable, and you don't get to SSH into the RTU and read its firmware before you write a client for it. A SCADA client that misparses a byte stream under those conditions can report a fabricated voltage reading to a human operator. In the real world that has caused blackouts. HW2 is where you find out whether your HW1 client would have survived that.

**This is why HW2's server is different from HW1's in one more way, beyond chaos:** it runs on instructor-controlled hardware, not your laptop, and you will not have its source. `shared/teacher_server.py` — the file you ran yourself for HW1 — is not part of what you're given for HW2. You connect to a live, remote instance instead (see §5 and the repo README's HW2 quickstart for the connection details and fixed milestone ports). If you could read the exact corruption rate or fragmentation chunk size off disk, "make the client robust" quietly turns into "make the client handle exactly these parameters" — which is not the same skill, and not what a real RTU integration lets you do either.

**Bring your working HW1 client.py.** HW2 is an upgrade of it, not a replacement — you'll be adding new logic (a real framing accumulator, checksum-mismatch recovery, sequence-anomaly detection) on top of the handshake, FSM, and telemetry-decoding logic you already have working. If your HW1 client isn't working yet, talk to your instructor before you fall further behind — see HW1's written check-in policy.

---

## 2. Learning Objectives

By the end of HW2 you will be able to:

1. Explain, and demonstrate in code, why **TCP is a byte stream, not a message protocol** — and implement a framing accumulator (`read_exact`) that is correct regardless of how the OS chooses to segment `recv()` calls.
2. Detect corrupted data using a checksum you already trust, and drive a request/retransmit recovery cycle instead of crashing or silently accepting bad data.
3. Detect and reason about application-layer sequence anomalies, and articulate precisely why they are not the same thing as TCP-level reordering (which cannot happen on a single connection).
4. Read and annotate a **Wireshark** packet capture down to the individual byte, mapping hex offsets back to your protocol's field definitions.
5. Trace a live TCP stream's own sequence and acknowledgment numbers, and explain what they do and do not tell you about your application's message boundaries.
6. Articulate, under live oral questioning, *why* your code behaves the way it does — not just that it happens to pass the autograder.

---

## 3. The Stream vs. Packet Boundary Dilemma (read this before you write any code)

This is the single most common reason student submissions fail this assignment, and it is the single most common thing a generative AI assistant gets wrong when asked to "write a Python TCP client that reads a message." If your course lecture hasn't covered TCP's transport-layer behavior in detail yet, read this section slowly — it's the whole assignment in miniature.

**TCP guarantees an ordered, reliable, in-order byte stream between two endpoints. It does NOT guarantee that the bytes you `send()` in one call arrive together in one `recv()` call on the other end.**

Concretely, for this protocol:

* A single 12-byte SGRP header may arrive as 4 bytes in one `recv()`, then 8 bytes in the next `recv()`, arbitrarily far apart in time.
* A 19-byte telemetry payload may be split across three, four, or more `recv()` calls.
* Conversely, the OS/kernel may **coalesce** multiple frames that you sent as separate `send()` calls into a single `recv()` buffer full of bytes on the receiving end (this is legal and common — see Nagle's algorithm and kernel buffering).

Here's the part that should make you nervous: **your HW1 client almost certainly called `sock.recv(n)` and trusted it to return exactly `n` bytes.** That worked — not because it was correct, but because HW1's teacher server never fragmented or coalesced anything. The moment you point that same client at HW2's chaos-enabled server, it will **catastrophically fail**:

```python
# BROKEN -- this is exactly what HW1's given recv_frame() got away with,
# and exactly what our chaos server is built to expose.
header = sock.recv(12)          # <-- may return 1..12 bytes, not always 12!
opcode = header[3]
length = struct.unpack('!H', header[8:10])[0]
payload = sock.recv(length)     # <-- may also return fewer bytes than requested!
```

The fix is a **framing accumulator**: a function that keeps calling `recv()` into a buffer until it has *exactly* the number of bytes it asked for (or the connection closes), commonly named `read_exact(sock, n)`. You will implement this in `02_client_starter.py`, replacing HW1's simple `recv_frame()`. There is a `TODO` block marking exactly where it goes and why — read the comments there closely, because this course's autograder (and your quiz) will target this mechanism directly.

You must also handle the mirror-image case: a single `recv()` may return the tail of one frame *and* the head of the next. Your accumulator needs to be a persistent buffer across the life of the connection, not a fresh `recv()` per message.

---

## 4. Wire Format Specification (unchanged from HW1)

This is identical to HW1 handout §3–§4, reproduced here for convenience. If it's fresh in your memory, skim it.

### 4.1 Byte Order

All multi-byte integer fields are **network byte order (big-endian)**. Use `struct` format prefix `!` (or `>`). Floats are IEEE-754 single precision (`struct` code `f`), also big-endian on the wire.

### 4.2 Frame Layout

```
+----------------+----------------------+------------------------+
|  Header (12B)  |  Payload (0..65535B) |  Payload Checksum (2B) |
+----------------+----------------------+------------------------+
```

Total frame length on the wire = `12 + PayloadLen + 2`. `PayloadLen` counts only the payload — it does NOT include the header or the trailing checksum.

### 4.3 Header Diagram (12 bytes, offsets 0–11)

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

See HW1 handout §3.3 for the full offset/field/description table, and §3.5–§3.6 for the complete OpCode tables (`C_HELLO` through `S_DISCONNECT_ACK`) — none of it has changed. The two opcodes that were spec'd-but-unused in HW1 become active in HW2:

* `0x31` `C_CHECKSUM_NACK` (`bad_seq: uint16`) — **you will now send this** when you detect a corrupted incoming frame.
* `0xE1` `S_NACK_SEQUENCE` (`expected_seq: uint16`, `got_seq: uint16`) — server-side sequence anomaly notice; handle it defensively (log and continue) if you see it.

### 4.4 Fletcher-16 Checksum (reference algorithm — unchanged)

```python
def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for b in data:
        sum1 = (sum1 + b) % 255
        sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1
```

---

## 5. Chaos Modes (Fault Injection)

The instructor's server supports four independent chaos flags that transform how the server writes bytes to the socket — **the wire format itself never changes**, only the timing/grouping/integrity of the bytes as they hit the network. This is what makes "ask an AI for boilerplate socket code" insufficient: boilerplate assumes friendly framing, and none of these modes are friendly.

Unlike HW1, **you do not launch this server yourself and cannot pick your own flag combination.** The instructor runs one persistent instance per port, each with a fixed set of chaos flags active, matching the milestone schedule in §6. Connect to the port for the milestone you're working on — see the repo README's HW2 quickstart table for the exact host and ports.

| Flag (active on the port for that milestone) | Behavior | What it's testing |
|---|---|---|
| `--chaos-fragment` | Every outgoing frame is chopped into small (1–4 byte) chunks, each sent with its own `send()` call and a ~20ms delay between chunks. | Your `read_exact()` accumulator must correctly reassemble a frame that trickles in over dozens of `recv()` calls. |
| `--chaos-coalesce` | The server buffers up to 3 consecutive `S_TELEMETRY_DATA` frames and writes them to the socket in a **single** `send()` call. | Your client must not assume "one `recv()` = one frame" — it must keep parsing frames out of its buffer until the buffer is exhausted, then go back to reading more. |
| `--chaos-corrupt` | 5% of eligible outgoing frames have a single random bit flipped in their **payload checksum** trailer before transmission. Eligible frames are those exchanged **after authentication** — the handshake control frames and teardown frames are never corrupted, because this chaos mode's recovery mechanism (`C_CHECKSUM_NACK` + retransmit, keyed by `session_id`) only exists once a session is established. | Your client must actually verify Fletcher-16 on every received frame in your streaming loop (not just decode and trust it), detect the mismatch, and send `C_CHECKSUM_NACK{seq}` to request retransmission. |
| `--chaos-jitter` | For streamed telemetry, the server assigns **non-monotonic** `seq_num` values from a small shuffled window (e.g., sends seq 5, 7, 6, 8) before advancing. **Important:** TCP itself guarantees in-order, reliable delivery of bytes on a single connection — real network-layer packet reordering is invisible to a stream socket. This mode does *not* simulate that (it can't). It simulates an *application-layer* anomaly: the RTU's own telemetry buffer emitting samples out of logical order. Your client must detect the sequence anomaly using the `seq_num` field itself, not by relying on TCP to reorder anything for you. | Sequence-tracking logic, and your understanding of *where* ordering guarantees actually live in the stack. |

The Day 5 port runs all four flags combined, for your final sustained integration run.

---

## 6. Milestones (6–7 Class-Day Schedule)

- **Day 1:** Copy your working HW1 `client.py` into your HW2 workspace. Read §3 above closely. Implement `read_exact(sock, n)` — the framing accumulator — and rebuild `recv_frame()` on top of it (do not call `sock.recv()` directly anywhere else). Verify against the Day 1 port (fragment-only — see README quickstart).
- **Day 2:** Verify against the Day 2 port (coalesce-only) — confirm your loop keeps draining fully-buffered frames before requesting more bytes.
- **Day 3:** Implement checksum-corruption detection and the `C_CHECKSUM_NACK` retransmit request/response cycle. Verify against the Day 3 port (corrupt-only, 5%).
- **Day 4:** Implement sequence-anomaly detection. Verify against the Day 4 port (jitter-only). Decide and document your policy (e.g., log-and-continue vs. buffer-and-reorder) — either is acceptable if justified in your write-up.
- **Day 5:** Full integration run against the Day 5 port (all four chaos flags simultaneously), sustained for at least 2 minutes without a crash or hang. Capture Wireshark traces (see §7).
- **Day 6:** Finalize hex-annotation tables and design write-up.
- **Day 7 (or your instructor's designated day):** Quiz — live oral defense plus TCP sequence/acknowledgment tracing (see §8) — and final submission.

**Checkpoint (end of Day 2):** Client survives the Day 1 and Day 2 ports, individually, 10/10 runs each, with no crash and no misdecoded telemetry. Before your graded run, `shared/autograder.py --suite hw2 --remote-host <instructor host>` (see repo README §5) reproduces these checks against the real server, so you can self-verify without waiting for the quiz.

---

## 7. Wireshark & Hex-Dissection Deliverables

You must submit one `.pcapng` capture of your client talking to the chaos server, plus a written, byte-by-byte annotation table for **three** distinct captured frames, pulled from that capture:

**Capture on your real network interface (Wi-Fi/Ethernet), not loopback.** Unlike HW1, the server is a remote host now, so there is no `lo`/`lo0` traffic to capture — start Wireshark on the interface your machine actually uses to reach the instructor's server, and filter to isolate just this traffic, e.g. `ip.addr == <instructor host IP> && tcp.port == <milestone port>` (a plain `tcp.port` filter alone may also catch unrelated traffic on a shared network, so include the host filter).

1. **A successful handshake sequence** — annotate `C_HELLO`, `S_NONCE_CHALLENGE`, `C_AUTH_RESPONSE`, and `S_AUTH_ACK`. For each, produce a table mapping hex byte offset → field name → raw hex value → decoded value (e.g., offset `0x00-0x01: A5 5A -> magic sync`). Any milestone port works for this — the handshake happens before chaos-mode behavior kicks in.
2. **Recovery from a TCP-fragmented Layer-7 segment** — connect to the Day 1 (fragment) port, find a frame in Wireshark whose bytes arrived across multiple TCP segments (check the "TCP segment of a reassembled PDU" indicator, or correlate timestamps of consecutive small-length segments on the same stream), and show how your `read_exact` accumulator's internal buffer state evolved call-by-call to reassemble it. A code trace (print/log output alongside the pcap) is required here, not just the pcap.
3. **A corrupted-checksum NACK exchange** — connect to the Day 3 (corrupt) port, locate a frame your client rejected, and annotate both the corrupted frame's checksum field (showing the byte that was flipped versus what Fletcher-16 over the payload actually computes) and your client's `C_CHECKSUM_NACK` response plus the server's retransmission. At a 5% corruption rate this may take a few minutes of streaming to occur naturally — that's expected; do not stop early.

Screenshots must show the Wireshark **hex pane** (not just the decoded summary), with the relevant bytes highlighted/boxed. Cite the frame number and stream index from Wireshark in your write-up.

**Keep your `capture.pcapng` handy for the quiz (§8)** — you'll be asked to open it live and trace a TCP stream from it, so it needs to be a real capture from your own client, not a placeholder.

---

## 8. Quiz — Oral Defense & TCP Sequence/Acknowledgment Tracing

HW2's live check is a single combined sitting (10–20 minutes, format and exact scheduling set by your instructor) covering two things together:

**Part A — Code and protocol defense.** Your instructor verifies you understand your own socket state machine — not that the autograder passed. Expect questions about your framing accumulator, your checksum-recovery logic, your sequence-anomaly policy, and the boundary between what TCP guarantees and what SGRP has to enforce on top of it. A passing autograder score with an incoherent defense is treated as an academic-integrity flag, not just a low score.

**Part B — Layer 4 trace.** Using your own `capture.pcapng`, you'll be asked to trace the *actual TCP sequence and acknowledgment numbers* — not SGRP's own `seq_num` field, the real transport-layer numbers — across a short run of segments from one of your streams, and explain what they do and do not tell you (this is where the "TCP guarantees byte-stream order, not message boundaries" idea from §3 gets tested directly against a real capture, not a hypothetical). Some quick arithmetic warm-up questions (e.g., given a segment carrying a known byte range, what ACK comes back) may also be asked independent of your capture.

Your instructor will provide the exact question bank and scheduling separately. Come to the quiz with your `capture.pcapng` open and ready in Wireshark.

---

## 9. Submission Checklist

- [ ] `client.py` — your completed, HW2-upgraded client implementation
- [ ] `capture.pcapng`
- [ ] `hex_annotations.pdf` or `.md` — the three annotated tables from §7
- [ ] Brief design write-up (≤ 1 page): your buffering strategy, your sequence-anomaly policy, and one thing that broke during development and how you diagnosed it
- [ ] Quiz scheduled with instructor/TA (see §8)

**A submission with no `.pcapng` or no hex annotation table receives a maximum grade of 50%, regardless of code correctness — per the grading rubric's weighting, the network evidence is worth as much as the code.**
