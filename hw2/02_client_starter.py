#!/usr/bin/env python3
"""
client_starter.py -- HW2 UPGRADE TEMPLATE for the SGRP/1 SCADA client
ENEE 4745

THIS IS NOT A FRESH START. Copy the working implementations of
handshake(), send_all(), and graceful_disconnect() over from your own HW1
client.py -- those functions do not change in HW2 (they're marked
"CARRIES OVER FROM HW1" below). What's new is everything to do with how
you read bytes off the socket and how you react to a corrupted or
out-of-order frame.

Read 01_lab_handout.md FIRST, especially Section 3 ("The Stream vs. Packet
Boundary Dilemma") before touching the new TODO blocks below.

WHAT IS ALREADY DONE FOR YOU:
  - Protocol constants / opcode numbers (unchanged from HW1)
  - fletcher16() checksum function
  - build_frame() -- constructs a complete, well-formed outgoing frame
  - derive_session_key() -- the per-student handshake math

WHAT CARRIES OVER FROM YOUR HW1 CLIENT (copy your own working code in):
  TODO 1: send_all(sock, data)      -- unchanged from HW1
  TODO 4: handshake(sock, ...)      -- unchanged from HW1
  TODO 6: graceful_disconnect(sock) -- unchanged from HW1

WHAT IS NEW IN HW2 (search for "TODO" -- there are 6 blocks total; 2, 3,
and the checksum/sequence-handling parts of 5 are the genuinely new work):
  TODO 2: read_exact(sock, n)       -- THE framing accumulator (NEW)
  TODO 3: recv_frame(sock)          -- rebuild this on read_exact(), NOT
                                        on HW1's simple recv() calls (NEW)
  TODO 5: streaming_loop(sock, ...) -- decode telemetry, detect checksum
                                        corruption and NACK it, detect
                                        sequence anomalies (checksum/seq
                                        handling is NEW; telemetry decoding
                                        itself carries over from HW1)

Unlike HW1, you do NOT run a copy of the server yourself for HW2 -- you
connect to the instructor-hosted chaos server, one fixed port per chaos
milestone (see 01_lab_handout.md Sec. 5-6 and the repo README's HW2
quickstart table for the actual host and ports). Example, Day 1
(fragment-only port):

    python3 client_starter.py --host <instructor-host> --port 8081 --student-id 123456

This file WILL run start-to-finish once you fill in the TODOs -- it is not
pseudocode. Everything outside the TODO blocks is real, working code you can
rely on.
"""

import argparse
import socket
import struct
import sys
import time

# --------------------------------------------------------------------------
# Protocol constants -- unchanged from HW1. Do not change these; the
# teacher server will reject anything that doesn't match.
# --------------------------------------------------------------------------

MAGIC0 = 0xA5
MAGIC1 = 0x5A
VERSION = 1

HEADER_LEN = 12
TRAILER_LEN = 2

C_HELLO = 0x01
C_AUTH_RESPONSE = 0x02
C_SUBSCRIBE = 0x10
C_UNSUBSCRIBE = 0x11
C_GET_STATUS = 0x20
C_PING = 0x30
C_CHECKSUM_NACK = 0x31
C_DISCONNECT = 0x7F

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
}


class ChecksumError(Exception):
    """Raised specifically when a frame's magic/version are fine but a
    Fletcher-16 checksum does not match. Distinguished from ProtocolError
    because the correct reaction is different: a checksum error means
    'this frame is corrupt, ask for it again' (C_CHECKSUM_NACK), not
    'give up on the connection'. This exception did essentially nothing in
    your HW1 client (it should never have fired against the clean HW1
    server); in HW2 it's load-bearing -- the corrupt-mode port exists
    specifically to make this fire and verify you handle it correctly."""
    pass


class ProtocolError(Exception):
    """Raised for structurally invalid frames (bad magic, bad version,
    impossible lengths) that a checksum retry cannot fix."""
    pass


# --------------------------------------------------------------------------
# Fletcher-16 checksum (given -- unchanged from HW1, must match the server
# bit-for-bit)
# --------------------------------------------------------------------------

def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for b in data:
        sum1 = (sum1 + b) % 255
        sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1


# --------------------------------------------------------------------------
# Outgoing frame construction (given -- unchanged from HW1)
# --------------------------------------------------------------------------

def build_frame(opcode: int, seq: int, session_id: int, payload: bytes) -> bytes:
    header_wo_checksum = struct.pack(
        "!BBBBHHH", MAGIC0, MAGIC1, VERSION, opcode, seq & 0xFFFF,
        session_id & 0xFFFF, len(payload)
    )
    hdr_checksum = fletcher16(header_wo_checksum)
    header = header_wo_checksum + struct.pack("!H", hdr_checksum)
    payload_checksum = fletcher16(payload)
    return header + payload + struct.pack("!H", payload_checksum)


# --------------------------------------------------------------------------
# Per-student handshake math (given -- unchanged from HW1)
# --------------------------------------------------------------------------

def derive_session_key(student_id: int, nonce: int, poly_a: int, poly_b: int) -> int:
    h = student_id & 0xFFFFFFFF
    for b in nonce.to_bytes(4, "big"):
        h = (h * poly_a + b + poly_b) & 0xFFFFFFFF
    return h


# ==========================================================================
# TODO 1: send_all(sock, data)  --  CARRIES OVER FROM HW1
# --------------------------------------------------------------------------
# Copy your working HW1 implementation here. Nothing about it changes in
# HW2: it still just needs to loop on sock.send() until every byte is
# transmitted, and raise ConnectionError if send() ever returns 0.
# ==========================================================================

def send_all(sock: socket.socket, data: bytes) -> None:
    raise NotImplementedError("TODO 1: copy send_all() over from your HW1 client")


# ==========================================================================
# TODO 2: read_exact(sock, n) -- THE FRAMING ACCUMULATOR (NEW IN HW2)
# --------------------------------------------------------------------------
# This is the single most important function in this file, and the one
# your HW1 client did not have. Re-read handout Section 3 before writing
# it.
#
# TCP is a byte stream. sock.recv(n) is ONLY a request for "up to n bytes,
# whatever is available right now" -- it can legally return anywhere from 1
# byte to n bytes (or 0 bytes, meaning the peer closed the connection). A
# 12-byte header can arrive as 1+1+1+9 bytes across four recv() calls if
# the fragment-mode port is in use. Your job is to hide that reality from
# the rest of your program by blocking (looping) until you truly have
# exactly `n` bytes, then returning them as one contiguous bytes object.
#
# Requirements:
#   - Keep calling sock.recv() into an accumulating buffer (e.g. a
#     bytearray) until len(buffer) == n.
#   - If sock.recv() returns b"" (empty bytes) before you have n bytes,
#     the peer closed the connection mid-frame -- raise ConnectionError
#     with a message that says how many bytes you got vs. wanted.
#   - If the VERY FIRST recv() call returns b"" (clean EOF with zero bytes
#     read so far), that's a normal "no more frames" condition -- return
#     b"" rather than raising, so callers can distinguish "stream ended
#     cleanly between frames" from "stream died mid-frame".
#   - Do NOT assume you'll get all n bytes in one call. Do NOT recurse
#     unboundedly. A simple while loop is correct and sufficient.
# ==========================================================================

def read_exact(sock: socket.socket, n: int) -> bytes:
    raise NotImplementedError("TODO 2: implement read_exact() -- the framing accumulator")


# ==========================================================================
# TODO 3: recv_frame(sock) -- full SGRP frame parser (REBUILD FOR HW2)
# --------------------------------------------------------------------------
# Build this ENTIRELY on top of read_exact() from TODO 2. Do not call
# sock.recv() directly anywhere in this function -- if your HW1 client had
# a recv_frame() that called sock.recv() directly (or you're starting from
# HW1's given simple version), replace its body, not just patch around it.
#
# Steps:
#   1. header = read_exact(sock, HEADER_LEN). If header == b"", return None
#      (clean EOF between frames -- the connection is simply over).
#   2. Unpack header with struct.unpack("!BBBBHHHH", header) to get
#      (magic0, magic1, version, opcode, seq, session_id, payload_len,
#      hdr_checksum).
#   3. Validate magic0/magic1/version. If wrong, raise ProtocolError.
#   4. Recompute fletcher16(header[:10]) and compare to hdr_checksum.
#      If it doesn't match, raise ProtocolError (a corrupted header means
#      you can't even trust payload_len, so there's no safe way to keep
#      reading this stream -- unlike a payload checksum mismatch, this is
#      not recoverable with a simple NACK).
#   5. payload = read_exact(sock, payload_len).
#   6. trailer = read_exact(sock, TRAILER_LEN); unpack the uint16 payload
#      checksum from it.
#   7. Recompute fletcher16(payload) and compare. If it does NOT match,
#      raise ChecksumError (NOT ProtocolError -- this is the recoverable
#      case your streaming loop will catch and respond to with
#      C_CHECKSUM_NACK). Make sure the exception carries the `seq` number
#      so the caller knows what to NACK.
#   8. On success, return (opcode, seq, session_id, payload).
#
# Tip: give ChecksumError a constructor that stores `seq` as an attribute,
# e.g. `raise ChecksumError(seq)` and `class ChecksumError(Exception): ...`
# with `self.seq = args[0]` -- or add your own attribute-carrying subclass.
# ==========================================================================

def recv_frame(sock: socket.socket):
    raise NotImplementedError("TODO 3: implement recv_frame() on top of read_exact()")


def send_frame(sock: socket.socket, opcode: int, seq: int, session_id: int,
                payload: bytes) -> None:
    """Given for you: builds a frame and reliably transmits it via
    send_all() (TODO 1). You should not need to modify this."""
    frame = build_frame(opcode, seq, session_id, payload)
    send_all(sock, frame)


# ==========================================================================
# TODO 4: handshake(sock, student_id) -> session_id  --  CARRIES OVER FROM HW1
# --------------------------------------------------------------------------
# Copy your working HW1 implementation here. The handshake FSM did not
# change: C_HELLO -> S_NONCE_CHALLENGE -> C_AUTH_RESPONSE -> S_AUTH_ACK/
# S_AUTH_NACK, using derive_session_key(). It now runs on top of the new
# recv_frame() (TODO 3) instead of HW1's simple version, but you shouldn't
# need to change the handshake logic itself -- recv_frame()'s signature
# and return value are unchanged.
#
# AUTOGRADER OUTPUT CONTRACT (see 04_grading_rubric.md, Appendix A) --
# unchanged from HW1:
#   On S_AUTH_ACK success:  print(f"AUTH_OK session_id={assigned_session_id}")
#   On S_AUTH_NACK:         print(f"AUTH_FAIL reason={reason_code}")
# ==========================================================================

def handshake(sock: socket.socket, student_id: int) -> int:
    raise NotImplementedError("TODO 4: copy handshake() over from your HW1 client")


# ==========================================================================
# TODO 5: streaming_loop(sock, session_id, rtu_id, sample_rate_code)
# --------------------------------------------------------------------------
# Telemetry decoding (unpacking "!HIfffB", printing TELEMETRY lines)
# carries over from HW1. What's NEW is how you react to the two failure
# modes chaos mode can now actually trigger:
#
# 1. Send C_SUBSCRIBE (opcode 0x10, payload = struct.pack("!HB", rtu_id,
#    sample_rate_code)).
# 2. Loop calling recv_frame():
#      - On S_TELEMETRY_DATA (0x90): unpack payload with
#        "!HIfffB" -> (rtu_id, timestamp, voltage, current, frequency,
#        status_flags). Print/record it. ALSO: track the `seq` field
#        (returned by recv_frame) across calls and detect anomalies --
#        [NEW] at minimum, detect and log when a seq is repeated or jumps
#        by more than expected. Document your policy in your design
#        write-up (handout Sec. 9) -- "log and continue" is an acceptable
#        policy, but you must be able to explain in your quiz *why* you
#        can't simply assume seq numbers arrive in increasing order (hint:
#        the jitter-mode port, and re-read handout Sec. 3's note about
#        what TCP does and does not guarantee).
#      - On S_PONG, S_STATUS_RESPONSE, S_NACK_*, etc.: handle or log as
#        appropriate; do not crash on an opcode you don't have specific
#        handling for (this carries over from HW1's FSM-discipline TODO).
#      - [NEW] On a ChecksumError raised by recv_frame(): this means a
#        corrupted frame arrived -- and unlike HW1, this can now actually
#        happen. Send C_CHECKSUM_NACK (opcode 0x31, payload =
#        struct.pack("!H", err.seq)) to request retransmission, then
#        continue the loop waiting for the server's resend. DO NOT crash
#        or exit the loop on a checksum error -- that is exactly the
#        failure mode the corrupt-mode port exists to catch.
#      - On ProtocolError or ConnectionError: this is unrecoverable; log
#        it clearly and exit the loop.
#   Stop after some condition of your choosing (e.g. a fixed duration, a
#   fixed sample count, or Ctrl-C via KeyboardInterrupt) and proceed to
#   graceful_disconnect().
#
# AUTOGRADER OUTPUT CONTRACT (see 04_grading_rubric.md, Appendix A) --
# TELEMETRY carries over from HW1; CHECKSUM_NACK and SEQ_ANOMALY are NEW
# in HW2 and are what the chaos scenarios actually check for:
#   Each decoded telemetry sample:
#     print(f"TELEMETRY seq={seq} rtu={rtu_id} voltage={voltage:.2f} "
#           f"current={current:.2f} freq={frequency:.3f} flags={status_flags}")
#   Each time you send a C_CHECKSUM_NACK:
#     print(f"CHECKSUM_NACK seq={err.seq}")
#   Each time you detect a sequence anomaly:
#     print(f"SEQ_ANOMALY expected={expected_seq} got={got_seq}")
# ==========================================================================

def streaming_loop(sock: socket.socket, session_id: int, rtu_id: int,
                    sample_rate_code: int, duration: float = 0.0) -> None:
    """`duration`: stop streaming and return after this many seconds have
    elapsed since subscribing (0 = run until Ctrl-C / KeyboardInterrupt).
    The autograder always passes an explicit, finite --duration -- your
    loop MUST check elapsed time (e.g. time.monotonic() - start_time) and
    return once it's exceeded, or automated scenarios that expect a
    DISCONNECT_OK within a bounded window will time out and fail even if
    your framing/chaos-handling logic is otherwise correct."""
    raise NotImplementedError("TODO 5: implement streaming_loop()")


# ==========================================================================
# TODO 6: graceful_disconnect(sock, session_id)  --  CARRIES OVER FROM HW1
# --------------------------------------------------------------------------
# Copy your working HW1 implementation here. Send C_DISCONNECT (opcode
# 0x7F, empty payload), wait for S_DISCONNECT_ACK via recv_frame() (with a
# reasonable timeout), then close the socket. Unchanged in HW2 other than
# now running on top of the new recv_frame().
#
# AUTOGRADER OUTPUT CONTRACT: on receiving S_DISCONNECT_ACK, print exactly:
#     print("DISCONNECT_OK")
# ==========================================================================

def graceful_disconnect(sock: socket.socket, session_id: int) -> None:
    raise NotImplementedError("TODO 6: copy graceful_disconnect() over from your HW1 client")


# --------------------------------------------------------------------------
# main() -- given. Wires your TODOs together into a runnable program.
# You should not need to modify this, but you're free to once your TODOs
# work, e.g. to add CLI flags for sample rate or run duration.
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="ENEE 4745 HW2 SGRP/1 student client")
    p.add_argument("--host", default="127.0.0.1",
                    help="server hostname. For HW2 this must be the instructor-hosted "
                         "server given to you in class (see 01_lab_handout.md Sec. 5-6 "
                         "and the repo README's HW2 quickstart) -- the default of "
                         "127.0.0.1 will not work, since you no longer run the server "
                         "yourself.")
    p.add_argument("--port", type=int, default=8080,
                    help="server port. For HW2, pick the port matching the chaos "
                         "milestone you're working on (see the README's HW2 quickstart "
                         "table), not the HW1 default of 8080.")
    p.add_argument("--student-id", type=int, required=True,
                    help="your assigned 32-bit Student ID")
    p.add_argument("--rtu-id", type=int, default=1)
    p.add_argument("--sample-rate", type=int, default=1, choices=[0, 1, 2],
                    help="0=1Hz 1=5Hz 2=10Hz")
    p.add_argument("--duration", type=float, default=0.0,
                    help="AUTOGRADER CONTRACT: seconds to stream before initiating "
                         "graceful disconnect. 0 (default) means run until Ctrl-C. "
                         "The autograder always passes an explicit --duration, so "
                         "streaming_loop() MUST honor this argument as a stopping "
                         "condition (see TODO 5) for automated scenarios to pass.")
    args = p.parse_args()

    sock = socket.create_connection((args.host, args.port), timeout=10.0)
    print(f"Connected to {args.host}:{args.port}")

    try:
        session_id = handshake(sock, args.student_id)
        print(f"AUTHENTICATED, session_id={session_id}")
        streaming_loop(sock, session_id, args.rtu_id, args.sample_rate, args.duration)
    except KeyboardInterrupt:
        print("\nInterrupted by user, disconnecting...")
    except (ProtocolError, ConnectionError) as e:
        print(f"Fatal protocol/connection error: {e}", file=sys.stderr)
    finally:
        try:
            graceful_disconnect(sock, 0)
        except Exception:
            pass
        sock.close()
        print("Connection closed.")


if __name__ == "__main__":
    main()
