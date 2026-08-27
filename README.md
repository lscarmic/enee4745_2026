# ENEE 4745 — SGRP/1 Smart Grid Client Lab

This repo is everything you need for the two-part networking assignment: you'll
write a Python TCP client that speaks **SGRP/1**, a fictional Layer-7
protocol for substation RTU (Remote Terminal Unit) telemetry, against a
teacher-supplied server.

**HW1** gets your client talking to a well-behaved server (handshake,
framing, checksums, telemetry decode), which you run yourself. **HW2**
takes the same client and makes it survive a server that fragments,
coalesces, corrupts, and reorders its own traffic — the point being that
real TCP sockets never guarantee "one `recv()` = one message," and HW1's
naive code will not survive HW2 unchanged. For HW2, the chaos server runs
centrally on instructor-controlled hardware, not on your machine — see §4.

## 1. Get the repo

```bash
git clone <this-repo-url>
cd <this-repo>
```

You need Python 3.8+ and nothing else — everything here uses only the
standard library (`socket`, `struct`, `threading`, `argparse`). No `pip
install` required.

## 2. What's in here

```
.
├── README.md                    (this file)
├── hw1/
│   ├── 01_lab_handout.md        HW1 protocol spec + milestones — read first
│   ├── 02_client_starter.py     Your starting point for HW1
│   └── 04_grading_rubric.md     How HW1 is scored
├── hw2/
│   ├── 01_lab_handout.md        HW2 protocol spec + milestones — read first
│   ├── 02_client_starter.py     Your starting point for HW2 (builds on HW1)
│   └── 04_grading_rubric.md     How HW2 is scored
└── shared/
    ├── teacher_server.py        The reference server — used for HW1 only
    │                            (see §4: HW2 does not ship this file)
    └── autograder.py            Run this yourself before submitting
```

Start with `hw1/01_lab_handout.md` — it has the full byte-level protocol
spec (headers, opcodes, checksums) that both assignments are built on.

## 3. HW1 quickstart

Open two terminals in the repo root.

**Terminal 1 — start the server** (no chaos flags for HW1):
```bash
python3 shared/teacher_server.py --port 8080 --profile hw1
```

**Terminal 2 — run your client:**
```bash
python3 hw1/02_client_starter.py --port 8080 --student-id <your-student-id>
```

Copy `hw1/02_client_starter.py` to your own `client.py` and fill in the
`TODO` blocks — the file will not run until you do. Read the comments
above each `TODO`; they explain exactly what's expected and why.

## 4. HW2 quickstart

HW2 does **not** run against a server on your own machine. Your
instructors host the chaos server centrally, and you connect to it
directly over the network the same way a real head-end client would
connect to a remote RTU it can't see inside of. `shared/teacher_server.py`
is **not part of the HW2 distribution** — if you happen to still have a
local copy from HW1, running it yourself for HW2 won't help: the chaos
parameters (exact corruption rate, fragmentation chunking, jitter window)
are only guaranteed to match what's actually running on the instructor's
server, and reading the source defeats the point of the exercise (see
HW2 handout §1 and §5).

Your instructor will give you the actual hostname/IP to use — the
examples below use the placeholder `sgrp-pi.class`. The instructor server
exposes one fixed port per chaos milestone, matching the day-by-day
schedule in `hw2/01_lab_handout.md` §6:

| Port | Chaos flags active | Use it for |
|---|---|---|
| 8081 | `--chaos-fragment` | Day 1 |
| 8082 | `--chaos-coalesce` | Day 2 |
| 8083 | `--chaos-corrupt` (5%, the rate described in the handout) | Day 3, and your Wireshark corrupted-checksum-NACK capture |
| 8084 | `--chaos-jitter` | Day 4 |
| 8085 | all four flags combined | Day 5 sustained integration run + final capture |

**Run your client against a milestone port**, e.g. Day 1:
```bash
python3 hw2/02_client_starter.py --host sgrp-pi.class --port 8081 --student-id <your-student-id>
```

Copy `hw2/02_client_starter.py` to your own `client.py` (starting from
your working HW1 client — see that file's docstring) and fill in the new
`TODO` blocks. See `hw2/01_lab_handout.md` for what each chaos mode does
to the wire traffic and what your client needs to do about it.

HW2 also requires a Wireshark capture (`capture.pcapng`) of your client
talking to the chaos server — captured on your real network interface,
not loopback, since you're now talking to a remote host — plus a
byte-level annotation writeup. See `hw2/01_lab_handout.md` §7 for the
exact deliverables.

## 5. Test your work before submitting

**HW1** self-testing is unchanged — the autograder spins up
`shared/teacher_server.py` as a local subprocess:
```bash
python3 shared/autograder.py --suite hw1 --client path/to/your/client.py \
    --student-id <your-student-id> --server-path shared/teacher_server.py --report report.json
```

**HW2** self-testing runs the same scenarios against the instructor's
live server instead of a local one — pass `--remote-host` in place of
`--server-path`:
```bash
python3 shared/autograder.py --suite hw2 --client path/to/your/client.py \
    --student-id <your-student-id> --remote-host sgrp-pi.class --report report.json
```

This hits the same fixed-port instances described in §4 above (the
autograder knows which port each scenario needs), so a clean run here is
a real signal, not a local approximation — you're testing against the
actual server you'll be graded against. It still isn't the whole grade:
see `hw2/04_grading_rubric.md` for the full point breakdown, including
the Wireshark trace analysis and oral quiz administered separately by
the instructor.

## 6. A note on using AI tools

You're welcome to use AI assistants while working through this. Be aware
that generic AI-generated socket code almost always assumes a single
`recv()` call returns one full message — that assumption is wrong for
real TCP, and it's exactly what HW2's chaos server is built to expose. If you can't
explain why your own framing code works, that's a problem you
want to find before the deadline, not during grading.

## 7. Questions

Office hours  / email — lee-carmichael@utc.edu

If we need dedicated one-on-one time, we can set up a Zoom call. Either way, don't 
debug alone for hours before asking; a five-minute conversation can save an evening.