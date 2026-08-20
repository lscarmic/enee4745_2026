#!/usr/bin/env python3
"""
client_starter.py -- STUDENT STARTER TEMPLATE for HW1 (SGRP/1, no chaos)
ENEE 4745

Read 01_lab_handout.md FIRST.

WHAT IS ALREADY DONE FOR YOU:
  - Protocol constants / opcode numbers (must match the spec exactly)
  - fletcher16() checksum function
  - build_frame() -- constructs a complete, well-formed outgoing frame
  - derive_session_key() -- the per-student handshake math
  - recv_frame(sock) -- a SIMPLE frame reader (read the big comment on it
    before you use this pattern anywhere else -- it is only correct
    because HW1's server is deliberately well-behaved)
  - CLI argument parsing (--host, --port, --student-id)

WHAT YOU MUST IMPLEMENT (search for "TODO" -- there are 4 blocks):
  TODO 1: send_all(sock, data)      -- correct handling of partial send()
  TODO 2: handshake(sock, ...)      -- wire the FSM handshake transitions together
  TODO 3: streaming_loop(sock, ...) -- decode telemetry, enforce the FSM,
                                        never crash on an unexpected opcode
  TODO 4: graceful_disconnect(sock) -- clean teardown

Run against the teacher server, e.g.:
    python3 teacher_server.py --port 8080 --profile hw1       (terminal 1)
    python3 client_starter.py --port 8080 --student-id 123456 (terminal 2)

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
# Protocol constants -- copied verbatim from 01_lab_handout.md. Do not
# change these; the teacher server will reject anything that doesn't match.
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
    """Raised when a frame's magic/version are fine but a Fletcher-16
    checksum does not match. In HW1 this should never actually be raised
    by the given recv_frame() below, because the HW1 server never
    intentionally corrupts a frame -- if you do see this, the far more
    likely explanation is a bug in your own fletcher16() usage or in how
    you're slicing header/payload bytes, not a real corrupted frame.
    Checksum-mismatch *recovery* (asking the server to resend) is an HW2
    skill; you don't need to implement it here."""
    def __init__(self, seq):
        super().__init__(f"checksum mismatch seq={seq}")
        self.seq = seq


class ProtocolError(Exception):
    """Raised for structurally invalid frames (bad magic, bad version,
    impossible lengths) or a short read from the socket."""
    pass


# --------------------------------------------------------------------------
# Fletcher-16 checksum (given -- must match the server bit-for-bit)
# --------------------------------------------------------------------------

def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for b in data:
        sum1 = (sum1 + b) % 255
        sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1


# --------------------------------------------------------------------------
# Outgoing frame construction (given)
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
# Per-student handshake math (given -- must match handout Sec. 4.2 exactly)
# --------------------------------------------------------------------------

def derive_session_key(student_id: int, nonce: int, poly_a: int, poly_b: int) -> int:
    h = student_id & 0xFFFFFFFF
    for b in nonce.to_bytes(4, "big"):
        h = (h * poly_a + b + poly_b) & 0xFFFFFFFF
    return h


# --------------------------------------------------------------------------
# GIVEN: recv_frame(sock) -- a SIMPLE, direct frame reader for HW1
# --------------------------------------------------------------------------
# READ THIS COMMENT BEFORE YOU REUSE THIS PATTERN ANYWHERE ELSE.
#
# This function calls sock.recv(n) exactly once per field-group (header,
# payload, trailer) and trusts the return value to be exactly n bytes. In
# general, that trust is misplaced: a TCP socket's recv(n) is only a
# request for "up to n bytes, whatever is available right now" -- it is
# legally allowed to return anywhere from 1 byte to n bytes. This function
# is only correct here because HW1's teacher server is deliberately
# well-behaved: it never fragments a frame across multiple send() calls
# and never coalesces multiple frames into one. That is a property of
# *this specific server configuration*, not a property of TCP sockets in
# general.
#
# HW2 introduces a chaos-enabled version of this same server and has you
# replace this exact function with a real accumulator (`read_exact`) that
# does not make this assumption. For now, this is given to you as a
# working building block so you can focus HW1 on the application-layer
# protocol logic (framing fields, checksums, handshake math, FSM). Don't
# walk away from HW1 thinking recv(n) always returns n bytes -- it does
# not, and you'll prove that to yourself directly in HW2.
# --------------------------------------------------------------------------

def recv_frame(sock: socket.socket):
    header = sock.recv(HEADER_LEN)
    if header == b"":
        return None
    if len(header) != HEADER_LEN:
        raise ProtocolError(
            f"short header read ({len(header)}/{HEADER_LEN} bytes) -- this should not "
            f"happen against the HW1 server; if you hit this, something unusual is "
            f"going on with your connection, not a case you're expected to recover "
            f"from yet (that's an HW2 skill)."
        )
    magic0, magic1, version, opcode, seq, session_id, payload_len, hdr_cksum = \
        struct.unpack("!BBBBHHHH", header)

    if magic0 != MAGIC0 or magic1 != MAGIC1:
        raise ProtocolError(f"bad magic bytes {magic0:#04x} {magic1:#04x}")
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    if fletcher16(header[:10]) != hdr_cksum:
        raise ProtocolError("header checksum mismatch")

    payload = sock.recv(payload_len) if payload_len else b""
    if len(payload) != payload_len:
        raise ProtocolError(f"short payload read ({len(payload)}/{payload_len} bytes)")

    trailer = sock.recv(TRAILER_LEN)
    if len(trailer) != TRAILER_LEN:
        raise ProtocolError(f"short trailer read ({len(trailer)}/{TRAILER_LEN} bytes)")
    (payload_cksum,) = struct.unpack("!H", trailer)
    if fletcher16(payload) != payload_cksum:
        raise ChecksumError(seq)

    return opcode, seq, session_id, payload


# ==========================================================================
# TODO 1: send_all(sock, data)
# --------------------------------------------------------------------------
# socket.send(data) is NOT guaranteed to send every byte you hand it in one
# call -- it returns the number of bytes actually accepted into the kernel
# send buffer, which can be less than len(data). Python's socket object has
# a built-in sock.sendall() that already loops correctly, and you MAY use
# it in your real client -- but for this assignment, implement the loop
# yourself here so you understand exactly what sendall() is doing and can
# explain it during your written check-in.
#
# Requirements:
#   - Loop calling sock.send() until every byte of `data` has been sent.
#   - If sock.send() ever returns 0, the connection is broken -- raise
#     ConnectionError.
# ==========================================================================

def send_all(sock: socket.socket, data: bytes) -> None:
    raise NotImplementedError("TODO 1: implement send_all()")


def send_frame(sock: socket.socket, opcode: int, seq: int, session_id: int,
                payload: bytes) -> None:
    """Given for you: builds a frame and reliably transmits it via
    send_all() (TODO 1). You should not need to modify this."""
    frame = build_frame(opcode, seq, session_id, payload)
    send_all(sock, frame)


# ==========================================================================
# TODO 2: handshake(sock, student_id) -> session_id
# --------------------------------------------------------------------------
# Wire together the FSM transitions from handout Sec. 4:
#   UNCONNECTED -> (send C_HELLO) -> AWAITING_NONCE
#   -> (recv S_NONCE_CHALLENGE, unpack nonce/poly_a/poly_b with "!IHH")
#   -> compute session_key = derive_session_key(student_id, nonce, poly_a, poly_b)
#   -> (send C_AUTH_RESPONSE with that key, packed "!I")
#   -> (recv S_AUTH_ACK or S_AUTH_NACK)
#      - S_AUTH_ACK payload is "!H" -> assigned_session_id. Success!
#      - S_AUTH_NACK payload is "!B" -> reason_code. Raise a clear error
#        and let the caller decide whether to exit.
#
# Use send_frame() and recv_frame() -- do not touch raw sockets here.
# seq numbers you send should start at 0 and increment by 1 each frame you
# send (session_id is 0x0000 for these two client->server frames, since you
# are not authenticated yet).
#
# AUTOGRADER OUTPUT CONTRACT (see 04_grading_rubric.md, Appendix A) -- the
# automated test suite parses your stdout for these EXACT tagged lines, so
# print them verbatim (extra logging around them is fine):
#   On S_AUTH_ACK success:  print(f"AUTH_OK session_id={assigned_session_id}")
#   On S_AUTH_NACK:         print(f"AUTH_FAIL reason={reason_code}")
# ==========================================================================

def handshake(sock: socket.socket, student_id: int) -> int:
    raise NotImplementedError("TODO 2: implement handshake()")


# ==========================================================================
# TODO 3: streaming_loop(sock, session_id, rtu_id, sample_rate_code)
# --------------------------------------------------------------------------
# 1. Send C_SUBSCRIBE (opcode 0x10, payload = struct.pack("!HB", rtu_id,
#    sample_rate_code)).
# 2. Loop calling recv_frame():
#      - On S_TELEMETRY_DATA (0x90): unpack payload with "!HIfffB" ->
#        (rtu_id, timestamp, voltage, current, frequency, status_flags).
#        Print/record it (see the output contract below).
#      - On any OTHER recognized opcode (S_PONG, S_STATUS_RESPONSE,
#        S_NACK_*, etc.): handle it if you want, or simply ignore it --
#        either is fine.
#      - On any opcode you do NOT have specific handling for, or one that
#        is not valid in your current FSM state: log it and CONTINUE the
#        loop. Do not crash, do not raise an unhandled exception. This is
#        the FSM-enforcement requirement from handout Sec. 4.1 -- a real
#        RTU client that terminates on an unfamiliar opcode is a client
#        that takes down the dashboard the moment the protocol adds one
#        new message type.
#      - A ChecksumError from recv_frame() should not happen in HW1 (see
#        the comment on ChecksumError above) -- but if it somehow does,
#        log it clearly and continue the loop rather than crashing.
#   Stop after some condition of your choosing (e.g. a fixed duration, a
#   fixed sample count, or Ctrl-C via KeyboardInterrupt) and proceed to
#   graceful_disconnect().
#
# AUTOGRADER OUTPUT CONTRACT (see 04_grading_rubric.md, Appendix A) --
# print this EXACT tagged line for every decoded telemetry sample so the
# automated test suite can verify your client's behavior from captured
# stdout:
#     print(f"TELEMETRY seq={seq} rtu={rtu_id} voltage={voltage:.2f} "
#           f"current={current:.2f} freq={frequency:.3f} flags={status_flags}")
# ==========================================================================

def streaming_loop(sock: socket.socket, session_id: int, rtu_id: int,
                    sample_rate_code: int, duration: float = 0.0) -> None:
    """`duration`: stop streaming and return after this many seconds have
    elapsed since subscribing (0 = run until Ctrl-C / KeyboardInterrupt).
    The autograder always passes an explicit, finite --duration -- your
    loop MUST check elapsed time (e.g. time.monotonic() - start_time) and
    return once it's exceeded, or automated scenarios that expect a
    DISCONNECT_OK within a bounded window will time out and fail even if
    your framing logic is otherwise correct."""
    raise NotImplementedError("TODO 3: implement streaming_loop()")


# ==========================================================================
# TODO 4: graceful_disconnect(sock, session_id)
# --------------------------------------------------------------------------
# Send C_DISCONNECT (opcode 0x7F, empty payload), then wait for
# S_DISCONNECT_ACK via recv_frame() (with a reasonable timeout -- don't
# block forever if the server has already gone away), then close the
# socket.
#
# AUTOGRADER OUTPUT CONTRACT: on receiving S_DISCONNECT_ACK, print exactly:
#     print("DISCONNECT_OK")
# ==========================================================================

def graceful_disconnect(sock: socket.socket, session_id: int) -> None:
    raise NotImplementedError("TODO 4: implement graceful_disconnect()")


# --------------------------------------------------------------------------
# main() -- given. Wires your TODOs together into a runnable program.
# You should not need to modify this, but you're free to once your TODOs
# work, e.g. to add CLI flags for sample rate or run duration.
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="ENEE 4745 HW1 SGRP/1 student client")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--student-id", type=int, required=True,
                    help="your assigned 32-bit Student ID")
    p.add_argument("--rtu-id", type=int, default=1)
    p.add_argument("--sample-rate", type=int, default=1, choices=[0, 1, 2],
                    help="0=1Hz 1=5Hz 2=10Hz")
    p.add_argument("--duration", type=float, default=0.0,
                    help="AUTOGRADER CONTRACT: seconds to stream before initiating "
                         "graceful disconnect. 0 (default) means run until Ctrl-C. "
                         "The autograder always passes an explicit --duration, so "
                         "streaming_loop() MUST honor this argument (see TODO 3) for "
                         "automated scenarios to pass.")
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
