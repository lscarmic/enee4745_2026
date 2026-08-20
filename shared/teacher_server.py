#!/usr/bin/env python3
"""
teacher_server.py -- SGRP/1 (Smart Grid RTU Protocol) reference server
ENEE 4745 -- shared server for HW1 and HW2

INSTRUCTOR / DISTRIBUTION NOTE: this file is part of the HW1 student
distribution (students run it themselves -- see the repo README's HW1
quickstart) but is NOT part of the HW2 distribution. For HW2, students
connect to instances of this same file running on instructor-controlled
hardware (a Raspberry Pi in past offerings) instead of running it
themselves. Handing a student the HW2 chaos parameters (exact corruption
rate, fragmentation chunk size, jitter window) via this source file would
let them special-case a client to those exact values instead of writing
one that's actually robust -- see hw2/01_lab_handout.md Sec. 1 and 5 for
the full rationale. Keep this file out of whatever archive/zip/branch you
hand out for HW2; HW1's distribution is unaffected.

This is the ONE teacher-supplied server used for both assignments in the
two-part SGRP/1 sequence:

    HW1 (Application-Layer Protocol: framing, handshake, telemetry decode)
        Run with NO chaos flags, by the student, on their own machine.
        The network is well-behaved: one recv() reliably returns one
        frame's worth of bytes. This is intentional -- HW1 is scoped to
        Layer 7 protocol design and should not require any assumption
        about how TCP segments a byte stream.

    HW2 (Transport-Layer Realities: fault injection, resilience, Wireshark)
        Run by the INSTRUCTOR, with one or more --chaos-* flags, as
        several persistent instances on fixed ports -- not launched ad
        hoc by students. The same wire format, the same opcodes, the same
        per-student handshake math -- but now the bytes arrive fragmented,
        coalesced, occasionally corrupted, and with non-monotonic
        application-level sequence numbers. A client that only worked
        because HW1's network was friendly will break here, which is the
        point: it's the live version of "here is what your socket calls
        were actually promising you all along." Because students no
        longer have this source file for HW2, they also can't read the
        exact chaos parameters off disk -- only the behavior documented
        in the handout (5% corruption, 1-4 byte fragments, etc.).

    --chaos-fragment   split every outgoing frame into tiny chunks with
                       inter-chunk delay (defeats "one recv() == one frame")
    --chaos-coalesce   glue up to 3 consecutive telemetry frames into a
                       single send() (defeats "one recv() == one frame",
                       the other direction)
    --chaos-corrupt    flip a bit in ~5% of outgoing payload checksums
                       (tests client-side Fletcher-16 validation + NACK/retry)
    --chaos-jitter     emit telemetry with non-monotonic L7 sequence numbers
                       (tests client sequence tracking -- NOT real TCP
                       reordering, which cannot happen on a single stream
                       socket; see the HW2 handout for why)

Run (instructor/local testing):
    # HW1 session -- no chaos, optionally pass --profile hw1 as a guard rail
    # so an instructor can't accidentally hand out a chaos-enabled server
    # during a "make sure everyone's client works" HW1 check-in:
    python3 teacher_server.py --port 8080 --profile hw1

    # HW2 session (ad hoc / local testing):
    python3 teacher_server.py --port 8080 --chaos-fragment --chaos-corrupt
    python3 teacher_server.py --port 8080 --chaos-fragment --chaos-coalesce \
        --chaos-corrupt --chaos-jitter

INSTRUCTOR OPS -- running the real HW2 deployment:

HW2 students never pick their own flag combination (see the note above);
instead, run one persistent instance per milestone port, matching the
table in the repo README's HW2 quickstart and hw2/01_lab_handout.md Sec.
5-6. Suggested convention (e.g. one instance per port, under systemd,
tmux, or `screen`, bound with --host 0.0.0.0 so it's reachable from the
class network -- firewall the box to campus/VPN ranges rather than the
open internet):

    python3 teacher_server.py --port 8081 --chaos-fragment                     # Day 1
    python3 teacher_server.py --port 8082 --chaos-coalesce                     # Day 2
    python3 teacher_server.py --port 8083 --chaos-corrupt                      # Day 3 (5%, realistic rate)
    python3 teacher_server.py --port 8084 --chaos-jitter                       # Day 4
    python3 teacher_server.py --port 8085 --chaos-fragment --chaos-coalesce \
        --chaos-corrupt --chaos-jitter                                         # Day 5 integration
    python3 teacher_server.py --port 8086 --chaos-corrupt --corrupt-rate 0.30  # autograder.py --remote-host
                                                                                 # self-test only (Scenario D
                                                                                 # needs a boosted rate to
                                                                                 # trigger reliably inside a
                                                                                 # bounded test window; this
                                                                                 # port is not a milestone port
                                                                                 # and isn't in the student
                                                                                 # quickstart table)

Each instance is single-process/multi-threaded (see handle_client below)
and handles one student connection per thread, so these six instances are
sufficient for a full class connecting concurrently -- no per-student
server needed. Read shared/autograder.py's REMOTE_PORTS mapping to keep
these port numbers in sync if you ever change them.

--profile is optional and purely a safety rail (see parse_args below) --
it does not change protocol behavior by itself. Nothing stops you from
running the server with chaos flags and no --profile at all; --profile hw1
specifically exists to make it hard to *accidentally* run a chaos-enabled
server during an HW1 session, since the whole point of HW1 is that it
doesn't require chaos-handling knowledge yet.

This file is intentionally verbose in its logging and comments: read it. It
is a second, complete reference implementation of everything students must
build themselves in client_starter.py -- studying *why* it is structured
this way (framing accumulator, send lock, cached retransmit buffer) is part
of the assignment (for HW1, where students still have this file).
"""

import argparse
import random
import socket
import struct
import sys
import threading
import time
from collections import deque

# --------------------------------------------------------------------------
# Protocol constants (must match hw1/01_lab_handout.md and hw2/01_lab_handout.md
# exactly -- the wire format is identical across both assignments)
# --------------------------------------------------------------------------

MAGIC0 = 0xA5
MAGIC1 = 0x5A
VERSION = 1

HEADER_LEN = 12          # bytes 0..11
TRAILER_LEN = 2          # payload checksum

# Client -> Server opcodes
C_HELLO = 0x01
C_AUTH_RESPONSE = 0x02
C_SUBSCRIBE = 0x10
C_UNSUBSCRIBE = 0x11
C_GET_STATUS = 0x20
C_PING = 0x30
C_CHECKSUM_NACK = 0x31
C_DISCONNECT = 0x7F

# Server -> Client opcodes
S_NONCE_CHALLENGE = 0x81
S_AUTH_ACK = 0x82
S_AUTH_NACK = 0x83
S_TELEMETRY_DATA = 0x90
S_STATUS_RESPONSE = 0x91
S_PONG = 0x92
S_NACK_CHECKSUM = 0xE0
S_NACK_SEQUENCE = 0xE1
S_NACK_MALFORMED = 0xE2
S_DISCONNECT_ACK = 0xFF

# Grading-utility-only opcode: not part of the student-facing spec surface
# in either handout's normal operation, but a legal, well-formed frame with
# an opcode the client has no specific handler for. Used by autograder.py's
# HW1 Scenario G to verify clients discard-and-continue on unrecognized
# opcodes ("any frame structurally invalid for the current state... must be
# logged and discarded -- not crash your client"), rather than to test
# anything students must implement beyond that general FSM-hygiene rule.
S_TEST_UNKNOWN = 0x93

OPCODE_NAMES = {
    C_HELLO: "C_HELLO", C_AUTH_RESPONSE: "C_AUTH_RESPONSE",
    C_SUBSCRIBE: "C_SUBSCRIBE", C_UNSUBSCRIBE: "C_UNSUBSCRIBE",
    C_GET_STATUS: "C_GET_STATUS", C_PING: "C_PING",
    C_CHECKSUM_NACK: "C_CHECKSUM_NACK", C_DISCONNECT: "C_DISCONNECT",
    S_NONCE_CHALLENGE: "S_NONCE_CHALLENGE", S_AUTH_ACK: "S_AUTH_ACK",
    S_AUTH_NACK: "S_AUTH_NACK", S_TELEMETRY_DATA: "S_TELEMETRY_DATA",
    S_STATUS_RESPONSE: "S_STATUS_RESPONSE", S_PONG: "S_PONG",
    S_NACK_CHECKSUM: "S_NACK_CHECKSUM", S_NACK_SEQUENCE: "S_NACK_SEQUENCE",
    S_NACK_MALFORMED: "S_NACK_MALFORMED", S_DISCONNECT_ACK: "S_DISCONNECT_ACK",
    S_TEST_UNKNOWN: "S_TEST_UNKNOWN(reserved)",
}

SAMPLE_RATE_HZ = {0: 1.0, 1: 5.0, 2: 10.0}

CHAOS_FLAG_NAMES = ["chaos_fragment", "chaos_coalesce", "chaos_corrupt", "chaos_jitter"]

# --------------------------------------------------------------------------
# Console logging -- color-codes L4 (TCP/socket) events vs L7 (SGRP FSM)
# events vs CHAOS fault injection, so students can visually separate "this
# is the network doing something weird" from "this is my protocol logic".
# --------------------------------------------------------------------------

class Color:
    RESET = "\033[0m"
    CYAN = "\033[36m"      # L4 TCP-level events
    GREEN = "\033[32m"     # L7 protocol / FSM events
    YELLOW = "\033[33m"    # CHAOS fault injection
    RED = "\033[31m"       # errors / NACKs
    MAGENTA = "\033[35m"   # handshake / crypto-ish math
    DIM = "\033[2m"


USE_COLOR = True


def _ts():
    return time.strftime("%H:%M:%S")


def log_l4(addr, msg):
    tag = f"{Color.CYAN}[L4  TCP ]{Color.RESET}" if USE_COLOR else "[L4  TCP ]"
    print(f"{_ts()} {tag} {addr!s:<21} {msg}")


def log_l7(addr, msg):
    tag = f"{Color.GREEN}[L7  FSM ]{Color.RESET}" if USE_COLOR else "[L7  FSM ]"
    print(f"{_ts()} {tag} {addr!s:<21} {msg}")


def log_chaos(addr, msg):
    tag = f"{Color.YELLOW}[CHAOS  ]{Color.RESET}" if USE_COLOR else "[CHAOS  ]"
    print(f"{_ts()} {tag} {addr!s:<21} {msg}")


def log_err(addr, msg):
    tag = f"{Color.RED}[ERROR  ]{Color.RESET}" if USE_COLOR else "[ERROR  ]"
    print(f"{_ts()} {tag} {addr!s:<21} {msg}")


def log_math(addr, msg):
    tag = f"{Color.MAGENTA}[HANDSHK]{Color.RESET}" if USE_COLOR else "[HANDSHK]"
    print(f"{_ts()} {tag} {addr!s:<21} {msg}")


# --------------------------------------------------------------------------
# Fletcher-16 checksum
# --------------------------------------------------------------------------

def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for b in data:
        sum1 = (sum1 + b) % 255
        sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1


# --------------------------------------------------------------------------
# Frame construction
# --------------------------------------------------------------------------

def build_frame(opcode: int, seq: int, session_id: int, payload: bytes) -> bytes:
    """Build one complete, well-formed SGRP frame: header + payload + trailer."""
    header_wo_checksum = struct.pack(
        "!BBBBHHH", MAGIC0, MAGIC1, VERSION, opcode, seq & 0xFFFF,
        session_id & 0xFFFF, len(payload)
    )
    hdr_checksum = fletcher16(header_wo_checksum)
    header = header_wo_checksum + struct.pack("!H", hdr_checksum)
    payload_checksum = fletcher16(payload)
    return header + payload + struct.pack("!H", payload_checksum)


def maybe_corrupt(frame: bytes, rate: float, addr, seq) -> bytes:
    """CHAOS: with probability `rate`, flip one random bit in the trailing
    payload-checksum field of an otherwise-valid frame. This never touches
    the cached "golden" copy used for retransmission -- only the bytes
    actually placed on the wire this one time."""
    if random.random() < rate:
        mutable = bytearray(frame)
        # last 2 bytes = payload checksum
        idx = len(mutable) - 1 - random.randint(0, 1)
        bit = 1 << random.randint(0, 7)
        mutable[idx] ^= bit
        log_chaos(addr, f"corrupt: flipped bit {bit:#04x} in payload checksum "
                         f"of seq={seq} (opcode={OPCODE_NAMES.get(frame[3], frame[3])})")
        return bytes(mutable)
    return frame


# --------------------------------------------------------------------------
# Low-level, chaos-aware transmission
# --------------------------------------------------------------------------

def transmit_bytes(conn, data: bytes, args, addr):
    """The ONLY function in this file allowed to call conn.send()/sendall().
    If --chaos-fragment is on, chops `data` into small pieces with a short
    delay between each send() call -- this is what forces a correctly
    written client to implement a real framing accumulator instead of
    trusting recv(n) to return exactly n bytes."""
    if not args.chaos_fragment:
        conn.sendall(data)
        return

    view = memoryview(data)
    offset = 0
    total = len(data)
    chunk_count = 0
    while offset < total:
        chunk_len = random.randint(1, 4)
        chunk = view[offset: offset + chunk_len]
        conn.sendall(chunk)
        offset += len(chunk)
        chunk_count += 1
        time.sleep(0.020)  # 20ms inter-chunk delay
    log_chaos(addr, f"fragment: sent {total}B as {chunk_count} chunks (1-4B each, 20ms apart)")


def read_exact(conn, n: int) -> bytes:
    """THE framing accumulator, server side. Keeps calling recv() into a
    buffer until exactly n bytes have been collected, or the peer closes
    the connection. This is the same pattern HW2 requires students to
    implement in client_starter.py -- see the TODO block there for the
    full rationale. Returns b"" if the connection closed before any bytes
    were read (clean EOF); raises ConnectionError on a partial read
    followed by EOF.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            if len(buf) == 0:
                return b""
            raise ConnectionError(
                f"peer closed mid-frame: wanted {n} bytes, got only {len(buf)}"
            )
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(conn):
    """Read one complete SGRP frame off the wire using read_exact(). Returns
    (opcode, seq, session_id, payload) or None on clean EOF. Raises
    ProtocolError on a structurally invalid frame (bad magic/version/
    checksum) -- the caller decides how to react (NACK + close, for this
    reference server, since chaos is server->client only; a client is never
    expected to send malformed bytes in this lab)."""
    header = read_exact(conn, HEADER_LEN)
    if header == b"":
        return None
    if len(header) < HEADER_LEN:
        raise ProtocolError("short header read")

    magic0, magic1, version, opcode, seq, session_id, payload_len, hdr_cksum = \
        struct.unpack("!BBBBHHHH", header)

    if magic0 != MAGIC0 or magic1 != MAGIC1:
        raise ProtocolError(f"bad magic bytes {magic0:#04x} {magic1:#04x}")
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    computed = fletcher16(header[:10])
    if computed != hdr_cksum:
        raise ProtocolError(f"header checksum mismatch: got {hdr_cksum:#06x}, "
                             f"computed {computed:#06x}")

    payload = read_exact(conn, payload_len)
    if len(payload) < payload_len:
        raise ProtocolError("short payload read (peer closed mid-frame)")

    trailer = read_exact(conn, TRAILER_LEN)
    if len(trailer) < TRAILER_LEN:
        raise ProtocolError("short trailer read (peer closed mid-frame)")
    (payload_cksum,) = struct.unpack("!H", trailer)
    computed_payload_cksum = fletcher16(payload)
    if computed_payload_cksum != payload_cksum:
        raise ProtocolError(f"payload checksum mismatch: got {payload_cksum:#06x}, "
                             f"computed {computed_payload_cksum:#06x}")

    return opcode, seq, session_id, payload


class ProtocolError(Exception):
    pass


# --------------------------------------------------------------------------
# Per-student handshake math (must match both handouts' Sec. 5.2 exactly)
# --------------------------------------------------------------------------

def derive_polynomials(student_id: int):
    poly_a = (student_id % 251) + 2
    poly_b = (student_id * 7) % 65521
    return poly_a, poly_b


def derive_session_key(student_id: int, nonce: int, poly_a: int, poly_b: int) -> int:
    h = student_id & 0xFFFFFFFF
    for b in nonce.to_bytes(4, "big"):
        h = (h * poly_a + b + poly_b) & 0xFFFFFFFF
    return h


# --------------------------------------------------------------------------
# Per-connection session state
# --------------------------------------------------------------------------

class Session:
    def __init__(self, conn, addr, args):
        self.conn = conn
        self.addr = addr
        self.args = args
        self.send_lock = threading.Lock()   # guards transmit_bytes so two
                                             # threads (reader replies +
                                             # telemetry streamer) never
                                             # interleave bytes of two
                                             # different frames on the wire
        self.state = "UNCONNECTED"
        self.student_id = None
        self.session_id = None
        self.expected_key = None
        self.out_seq = 0
        self.retransmit_cache = {}          # seq -> golden (uncorrupted) frame
        self.retransmit_order = deque(maxlen=64)
        self.subscribed_rtu = None
        self.sample_rate_code = 0
        self.streaming = threading.Event()
        self.stop = threading.Event()
        self.jitter_pool = deque()

    def next_seq(self):
        s = self.out_seq
        self.out_seq = (self.out_seq + 1) & 0xFFFF
        return s

    def next_telemetry_seq(self):
        """Sequence number for the next telemetry frame. Under
        --chaos-jitter, seq numbers are drawn from a shuffled 4-wide window
        instead of being strictly monotonic -- see the HW2 handout for why
        this simulates an *application-layer* anomaly rather than real TCP
        reordering."""
        if not self.args.chaos_jitter:
            return self.next_seq()
        if not self.jitter_pool:
            window = [self.next_seq() for _ in range(4)]
            random.shuffle(window)
            self.jitter_pool.extend(window)
            log_chaos(self.addr, f"jitter: shuffled seq window -> {list(self.jitter_pool)}")
        return self.jitter_pool.popleft()

    def cache_frame(self, seq, golden_frame):
        self.retransmit_cache[seq] = golden_frame
        self.retransmit_order.append(seq)
        while len(self.retransmit_order) > 64:
            old = self.retransmit_order.popleft()
            self.retransmit_cache.pop(old, None)

    def send_one(self, opcode, session_id, payload, seq=None, cache=True,
                 corruptible=True):
        """Build, (maybe corrupt,) cache, and transmit a single frame.

        `corruptible=False` is used for the three handshake-phase control
        frames (S_NONCE_CHALLENGE, S_AUTH_ACK, S_AUTH_NACK) and for
        S_NACK_MALFORMED. --chaos-corrupt's recovery story is the
        C_CHECKSUM_NACK / retransmit round-trip, which is only meaningful
        once a session_id exists and the client is in its main STREAMING
        receive loop -- the handshake phase is not specified to retry a
        corrupted handshake frame, so corrupting one would be an
        unrecoverable dead end rather than a fair test of the intended
        skill. Post-auth frames (S_TELEMETRY_DATA, S_STATUS_RESPONSE,
        S_PONG) remain corruptible, since they're all received inside the
        same generic recv_frame()-in-a-loop that HW2 requires students to
        wrap in a ChecksumError handler regardless of opcode."""
        if seq is None:
            seq = self.next_seq()
        golden = build_frame(opcode, seq, session_id, payload)
        if cache:
            self.cache_frame(seq, golden)
        apply_corrupt = self.args.chaos_corrupt and corruptible
        wire_copy = maybe_corrupt(golden, self.args.corrupt_rate, self.addr, seq) \
            if apply_corrupt else golden
        with self.send_lock:
            transmit_bytes(self.conn, wire_copy, self.args, self.addr)
        log_l7(self.addr, f"-> {OPCODE_NAMES.get(opcode, opcode)} seq={seq} "
                           f"len={len(payload)}")
        return seq


# --------------------------------------------------------------------------
# Telemetry generation (fake but plausible substation values)
# --------------------------------------------------------------------------

def fake_telemetry_payload(rtu_id: int) -> bytes:
    voltage = random.gauss(120.0, 1.5)          # nominal 120V RMS +/- noise
    current = max(0.0, random.gauss(42.0, 6.0))  # amps
    frequency = random.gauss(60.0, 0.03)         # nominal 60Hz grid
    status_flags = 0x01  # bit0 = breaker closed
    if voltage > 124.0:
        status_flags |= 0x02  # over-voltage alarm
    if frequency < 59.9:
        status_flags |= 0x04  # under-frequency alarm
    timestamp = int(time.time())
    return struct.pack("!HIfffB", rtu_id, timestamp, voltage, current,
                        frequency, status_flags)


# --------------------------------------------------------------------------
# Telemetry streamer thread (runs per connection once subscribed)
# --------------------------------------------------------------------------

def streamer_thread(session: Session):
    args = session.args
    coalesce_buf = []
    while not session.stop.is_set():
        if not session.streaming.is_set() or session.subscribed_rtu is None:
            time.sleep(0.05)
            continue

        interval = 1.0 / SAMPLE_RATE_HZ.get(session.sample_rate_code, 1.0)
        payload = fake_telemetry_payload(session.subscribed_rtu)
        seq = session.next_telemetry_seq()
        golden = build_frame(S_TELEMETRY_DATA, seq, session.session_id, payload)
        session.cache_frame(seq, golden)
        wire_copy = maybe_corrupt(golden, args.corrupt_rate, session.addr, seq) \
            if args.chaos_corrupt else golden

        if args.chaos_coalesce:
            coalesce_buf.append(wire_copy)
            log_chaos(session.addr, f"coalesce: buffered telemetry seq={seq} "
                                     f"({len(coalesce_buf)}/3)")
            if len(coalesce_buf) >= 3:
                blob = b"".join(coalesce_buf)
                with session.send_lock:
                    transmit_bytes(session.conn, blob, args, session.addr)
                log_chaos(session.addr, f"coalesce: flushed {len(coalesce_buf)} "
                                         f"frames in one send() ({len(blob)}B total)")
                coalesce_buf.clear()
        else:
            with session.send_lock:
                transmit_bytes(session.conn, wire_copy, args, session.addr)

        log_l7(session.addr, f"-> S_TELEMETRY_DATA seq={seq} rtu={session.subscribed_rtu}")
        time.sleep(interval)


# --------------------------------------------------------------------------
# Per-connection handler (runs in its own thread; reader loop)
# --------------------------------------------------------------------------

def handle_client(conn, addr, args):
    conn.settimeout(120.0)
    log_l4(addr, "TCP connection accepted")
    session = Session(conn, addr, args)
    session.state = "HANDSHAKE_INIT"
    streamer = threading.Thread(target=streamer_thread, args=(session,), daemon=True)
    streamer.start()

    try:
        # ---- Handshake: expect C_HELLO ----
        frame = recv_frame(conn)
        if frame is None:
            log_l4(addr, "peer closed before handshake")
            return
        opcode, seq, sid, payload = frame
        if opcode != C_HELLO or len(payload) != 4:
            log_err(addr, f"expected C_HELLO(4B), got opcode={opcode:#04x} len={len(payload)}")
            session.send_one(S_NACK_MALFORMED, 0, struct.pack("!B", 1), cache=False,
                              corruptible=False)
            return
        (student_id,) = struct.unpack("!I", payload)
        session.student_id = student_id
        log_l7(addr, f"<- C_HELLO student_id={student_id}")

        poly_a, poly_b = derive_polynomials(student_id)
        nonce = random.getrandbits(32)
        session.expected_key = derive_session_key(student_id, nonce, poly_a, poly_b)
        log_math(addr, f"student_id={student_id} -> poly_a={poly_a} poly_b={poly_b} "
                        f"nonce={nonce:#010x} expected_key={session.expected_key:#010x}")

        challenge_payload = struct.pack("!IHH", nonce, poly_a, poly_b)
        session.state = "AWAITING_AUTH_RESULT"
        session.send_one(S_NONCE_CHALLENGE, 0, challenge_payload, cache=False,
                          corruptible=False)

        # ---- Expect C_AUTH_RESPONSE ----
        frame = recv_frame(conn)
        if frame is None:
            log_l4(addr, "peer closed during handshake")
            return
        opcode, seq, sid, payload = frame
        if opcode != C_AUTH_RESPONSE or len(payload) != 4:
            log_err(addr, f"expected C_AUTH_RESPONSE(4B), got opcode={opcode:#04x}")
            session.send_one(S_NACK_MALFORMED, 0, struct.pack("!B", 2), cache=False,
                              corruptible=False)
            return
        (client_key,) = struct.unpack("!I", payload)
        log_l7(addr, f"<- C_AUTH_RESPONSE key={client_key:#010x}")

        if client_key != session.expected_key:
            log_err(addr, f"AUTH FAILED: expected {session.expected_key:#010x}, "
                           f"got {client_key:#010x}")
            session.send_one(S_AUTH_NACK, 0, struct.pack("!B", 1), cache=False,
                              corruptible=False)
            return

        session.session_id = random.randint(1, 65535)
        session.state = "AUTHENTICATED"
        session.send_one(S_AUTH_ACK, session.session_id,
                          struct.pack("!H", session.session_id), cache=False,
                          corruptible=False)
        log_l7(addr, f"AUTHENTICATED, assigned session_id={session.session_id}")

        if args.inject_unknown_opcode:
            session.send_one(S_TEST_UNKNOWN, session.session_id,
                              b"\x01\x02\x03", cache=False)
            log_chaos(addr, "injected one S_TEST_UNKNOWN(0x93) frame "
                             "(HW1 Scenario G: client must not crash on it)")

        # ---- Main command loop ----
        while not session.stop.is_set():
            frame = recv_frame(conn)
            if frame is None:
                log_l4(addr, "peer closed connection")
                break
            opcode, seq, sid, payload = frame
            name = OPCODE_NAMES.get(opcode, hex(opcode))
            log_l7(addr, f"<- {name} seq={seq} len={len(payload)}")

            if opcode == C_SUBSCRIBE and len(payload) == 3:
                rtu_id, rate = struct.unpack("!HB", payload)
                session.subscribed_rtu = rtu_id
                session.sample_rate_code = rate
                session.streaming.set()
                session.state = "STREAMING"
                log_l7(addr, f"subscribed rtu={rtu_id} rate_code={rate} "
                              f"({SAMPLE_RATE_HZ.get(rate, '?')}Hz) -> STREAMING")

            elif opcode == C_UNSUBSCRIBE and len(payload) == 2:
                session.streaming.clear()
                session.state = "AUTHENTICATED"
                log_l7(addr, "unsubscribed -> AUTHENTICATED")

            elif opcode == C_GET_STATUS and len(payload) == 2:
                (rtu_id,) = struct.unpack("!H", payload)
                resp = struct.pack("!HBI", rtu_id, 1, int(time.time()))
                session.send_one(S_STATUS_RESPONSE, session.session_id, resp)

            elif opcode == C_PING:
                session.send_one(S_PONG, session.session_id, b"")

            elif opcode == C_CHECKSUM_NACK and len(payload) == 2:
                (bad_seq,) = struct.unpack("!H", payload)
                golden = session.retransmit_cache.get(bad_seq)
                if golden is None:
                    log_err(addr, f"client requested retransmit of seq={bad_seq} "
                                   f"but it is no longer cached")
                else:
                    log_chaos(addr, f"retransmitting seq={bad_seq} on client request "
                                     f"(bypassing corruption chance this time)")
                    with session.send_lock:
                        transmit_bytes(conn, golden, args, addr)

            elif opcode == C_DISCONNECT:
                session.send_one(S_DISCONNECT_ACK, session.session_id, b"", cache=False,
                                  corruptible=False)
                log_l7(addr, "graceful disconnect requested -> CLOSED")
                break

            else:
                log_err(addr, f"unexpected opcode {name} in state {session.state}")
                session.send_one(S_NACK_MALFORMED, session.session_id,
                                  struct.pack("!B", 3), corruptible=False)

    except ProtocolError as e:
        log_err(addr, f"protocol error, closing connection: {e}")
    except (ConnectionError, socket.timeout, OSError) as e:
        log_l4(addr, f"connection ended: {e}")
    finally:
        session.stop.set()
        try:
            conn.close()
        except OSError:
            pass
        log_l4(addr, "TCP connection closed")


# --------------------------------------------------------------------------
# Accept loop
# --------------------------------------------------------------------------

def serve(args):
    global USE_COLOR
    USE_COLOR = not args.no_color

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(16)

    profile_note = f" [profile={args.profile}]" if args.profile else ""
    print(f"{Color.GREEN if USE_COLOR else ''}"
          f"SGRP/1 teacher_server.py listening on {args.host}:{args.port}{profile_note}"
          f"{Color.RESET if USE_COLOR else ''}")
    active_modes = [name for name, on in [
        ("fragment", args.chaos_fragment), ("coalesce", args.chaos_coalesce),
        ("corrupt", args.chaos_corrupt), ("jitter", args.chaos_jitter)] if on]
    print(f"Chaos modes active: {', '.join(active_modes) if active_modes else '(none)'}")
    print("-" * 78)

    try:
        while True:
            conn, addr = listener.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, args), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down (Ctrl-C).")
    finally:
        listener.close()


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="ENEE 4745 SGRP/1 teacher reference server, shared by HW1 and HW2, "
                     "with optional chaos fault injection for HW2.")
    p.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=8080, help="TCP port (default 8080)")
    p.add_argument("--profile", choices=["hw1", "hw2"], default=None,
                    help="Optional safety rail, not required. '--profile hw1' refuses "
                         "to start if any --chaos-* flag is also given, so an instructor "
                         "running an HW1 check-in session can't accidentally hand students "
                         "a chaos-enabled server before they've been taught what to do "
                         "with one. '--profile hw2' is accepted for symmetry/documentation "
                         "but does not enforce anything (HW2 sessions may reasonably run "
                         "with zero, some, or all chaos flags depending on the day's lesson).")
    p.add_argument("--chaos-fragment", action="store_true",
                    help="split every outgoing frame into 1-4 byte chunks, 20ms apart")
    p.add_argument("--chaos-coalesce", action="store_true",
                    help="glue up to 3 consecutive telemetry frames into one send()")
    p.add_argument("--chaos-corrupt", action="store_true",
                    help="flip a bit in ~5%% of outgoing payload checksums")
    p.add_argument("--corrupt-rate", type=float, default=0.05,
                    help="corruption probability per frame when --chaos-corrupt is set")
    p.add_argument("--chaos-jitter", action="store_true",
                    help="emit telemetry with non-monotonic L7 sequence numbers")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color logging")
    p.add_argument("--inject-unknown-opcode", action="store_true",
                    help="grading utility: send one frame with an unrecognized "
                         "opcode after auth (used by autograder.py HW1 Scenario G)")
    args = p.parse_args(argv)

    if args.profile == "hw1":
        active = [name for name in CHAOS_FLAG_NAMES if getattr(args, name)]
        if active:
            flags = ", ".join("--" + n.replace("_", "-") for n in active)
            p.error(f"--profile hw1 refuses to start with chaos flags active ({flags}). "
                    f"HW1 is scoped to run against a well-behaved network -- if you meant "
                    f"to run an HW2 session, drop --profile hw1 (or pass --profile hw2).")

    return args


if __name__ == "__main__":
    serve(parse_args())
