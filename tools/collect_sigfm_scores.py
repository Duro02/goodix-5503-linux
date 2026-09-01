#!/usr/bin/env python3
"""Collect SIGFM verification scores for threshold calibration.

Each round runs one `fprintd-verify` for the given user (one press per round), then parses
the score lines that the goodix5503 SIGFM matcher wrote to the fprintd debug
log during that round. Positive samples come from pressing the enrolled
finger; negative samples from another finger or another person.

Usage (in a terminal with sudo access):

    sudo -v                                  # refresh sudo credentials once
    python3 tools/collect_sigfm_scores.py --note positive --count 30
    python3 tools/collect_sigfm_scores.py --note negative --count 20

No persistent writes, no hardware access; the script only reads the fprintd
debug log and prints one summary line per round.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

LOG_PATH = Path("/var/log/fprintd-debug.log")
CSV_DIR = Path(__file__).resolve().parents[1] / ".tools" / "logs"
VERIFY_COMMAND = ["fprintd-verify"]
NOTIFY_SEND = "notify-send"


def notify(title: str, message: str) -> None:
    """Best-effort desktop notification for the pressing session."""
    env = os.environ.copy()
    env.setdefault("DBUS_SESSION_BUS_ADDRESS",
                   f"unix:path=/run/user/{os.getuid()}/bus")
    try:
        subprocess.run([NOTIFY_SEND, "-a", "SIGFM", "-u", "normal",
                        title, message], env=env, capture_output=True,
                       timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass

FEATURES_RE = re.compile(r"SIGFM features frame=(\d+) enrolled=(\d+)")
SCORE_RE = re.compile(r"SIGFM score=(\d+) \(threshold driver-side\)")
ZERO_RE = re.compile(r"SIGFM score=0 \(insufficient (raw|mutual|geometric) matches\)")
RESULT_RE = re.compile(r"report_verify_status: result (verify-match|verify-no-match)")


def parse_round(chunk: str) -> dict[str, int | str]:
    """Extract one round's samples: max score per distinct frame feature set.

    The matcher logs two lines per comparison:
        SIGFM features frame=N enrolled=M
        SIGFM score=... (or a zero-reason line)
    so scoring lines attach to the most recent features line.
    """
    frames: dict[int, list[int]] = {}
    current_frame: int | None = None
    result = "unknown"
    for line in chunk.splitlines():
        result_match = RESULT_RE.search(line)
        if result_match:
            result = result_match.group(1)
        features_match = FEATURES_RE.search(line)
        if features_match:
            current_frame = int(features_match.group(1))
            frames.setdefault(current_frame, [])
            continue
        if current_frame is None:
            continue
        score_match = SCORE_RE.search(line)
        if score_match:
            frames[current_frame].append(int(score_match.group(1)))
        elif ZERO_RE.search(line):
            frames[current_frame].append(0)
    if not frames:
        return {}
    best_frame = max(frames, key=lambda key: max(frames[key] or [0]))
    return {
        "frame_features": best_frame,
        "max_score": max(frames[best_frame] or [0]),
        "score_count": sum(len(values) for values in frames.values()),
        "result": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", default=getpass.getuser(),
                        help="fprintd user to verify against")
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--note", default="sample", help="sample group label")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds per round")
    args = parser.parse_args()

    if not args.log.is_file():
        print(f"error: debug log not found: {args.log}", file=sys.stderr)
        return 2
    if args.count < 1:
        print("error: --count must be positive", file=sys.stderr)
        return 2

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path = CSV_DIR / f"sigfm-scores-{args.note}-{timestamp}.csv"
    try:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        probe = csv_path.parent / ".write-probe"
        probe.touch()
        probe.unlink()
    except OSError:
        csv_path = Path("/tmp") / csv_path.name
        print(f"note: {CSV_DIR} not writable, using {csv_path}",
              file=sys.stderr)

    collected: list[dict[str, object]] = []
    missed = 0
    round_number = 0
    offset = args.log.stat().st_size
    command = VERIFY_COMMAND + [args.user]

    print(f"group={args.note}: press the enrolled finger for positive samples, "
          f"another finger/person for negative samples")
    print("press count target:", args.count, flush=True)

    while len(collected) < args.count:
        round_number += 1
        remaining = args.count - len(collected)
        notify("SIGFM 采集",
               f"第 {len(collected) + 1}/{args.count} 轮:请按手指"
               f"(本轮后还剩 {remaining - 1} 次)")
        print(f"  >>> round {len(collected) + 1}/{args.count} "
              f"(remaining {remaining - 1} after this): press the finger now",
              flush=True)
        try:
            completed = subprocess.run(command, timeout=args.timeout,
                                       capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            print(f"  round {round_number}: timed out waiting for verify; "
                  f"press again", flush=True)
            missed += 1
            continue
        except FileNotFoundError:
            print("error: fprintd-verify not found (is fprintd installed?)",
                  file=sys.stderr)
            return 2

        with args.log.open("rb") as handle:
            handle.seek(offset)
            chunk = handle.read().decode("utf-8", errors="replace")
        sample = parse_round(chunk)

        if not sample:
            print(f"  round {round_number}: no score lines matched "
                  f"(press may have been rejected early)", file=sys.stderr)
            missed += 1
            continue

        row = {
            "round": len(collected) + 1,
            "note": args.note,
            "frame_features": sample["frame_features"],
            "max_score": sample["max_score"],
            "score_count": sample["score_count"],
            "result": sample["result"],
            "verify_rc": completed.returncode,
        }
        collected.append(row)
        notify("SIGFM 结果",
               f"第 {len(collected)}/{args.count} 轮: "
               f"max_score={row['max_score']} result={row['result']}")
        print(f"  round {len(collected):3d}/{args.count}: "
              f"frame={row['frame_features']} max_score={row['max_score']} "
              f"samples={row['score_count']} result={row['result']}",
              flush=True)
        offset = args.log.stat().st_size

    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(collected[0].keys()))
        writer.writeheader()
        writer.writerows(collected)

    scores = [int(row["max_score"]) for row in collected]
    above = sum(1 for value in scores if value >= 150)
    print(f"\ncollected {len(collected)} rounds "
          f"(missed {missed}) -> {csv_path}")
    print(f"max_score: min={min(scores)} median={sorted(scores)[len(scores)//2]} "
          f"max={max(scores)}; >=150 in {above}/{len(scores)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())