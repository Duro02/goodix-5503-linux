#!/usr/bin/env python3
"""Counterbalanced comparison of one-shot fprintd CLI and PAM verification.

Install the isolated one-attempt PAM profile before running, and remove it
when finished:

    pkexec install -o root -g root -m 0644 \\
        tools/goodix5503-ab-test.pam /etc/pam.d/goodix5503-ab-test
    pkexec rm -f /etc/pam.d/goodix5503-ab-test

Each process is started before the user is notified. The notification is sent
only after fprintd logs FP_FINGER_STATUS_NEEDED, so both paths receive one
fresh press after the reader is armed. Results and SIGFM scores are read from
the fprintd debug log and written under .tools/logs (or /tmp as a fallback).
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

REPO = Path(__file__).resolve().parents[1]
LOG_PATH = Path("/var/log/fprintd-debug.log")
PAM_HELPER = REPO / ".tools" / "goodix5503-pam-verify-once"
PAM_SOURCE = REPO / "tools" / "pam_verify_once.c"
PAM_CONFIG_SOURCE = REPO / "tools" / "goodix5503-ab-test.pam"
PAM_SERVICE = "goodix5503-ab-test"
PAM_CONFIG = Path("/etc/pam.d") / PAM_SERVICE
READY_TEXT = "FP_FINGER_STATUS_NONE -> FP_FINGER_STATUS_NEEDED"
RESULT_RE = re.compile(r"report_verify_status: result (verify-match|verify-no-match)")
FEATURE_RE = re.compile(r"SIGFM features frame=(\d+) enrolled=(\d+)")
SCORE_RE = re.compile(r"SIGFM score=(\d+)")


def notify(title: str, message: str) -> None:
    env = os.environ.copy()
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{os.getuid()}/bus")
    try:
        subprocess.run(
            ["notify-send", "-a", "SIGFM A/B", "-u", "normal", title, message],
            env=env,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def read_from(path: Path, offset: int) -> tuple[str, int]:
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read()
        return data.decode("utf-8", errors="replace"), handle.tell()


def build_helper() -> None:
    PAM_HELPER.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         str(PAM_SOURCE), "-lpam", "-o", str(PAM_HELPER)],
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "failed to build PAM helper")


def method_order(per_method: int) -> list[str]:
    order: list[str] = []
    for pair in range(per_method):
        order.extend(("cli", "pam") if pair % 2 == 0 else ("pam", "cli"))
    return order


def parse_log(chunk: str) -> tuple[str, int | None, int | None, int]:
    results = RESULT_RE.findall(chunk)
    features = FEATURE_RE.findall(chunk)
    scores = [int(value) for value in SCORE_RE.findall(chunk)]
    result = results[-1] if results else "unknown"
    frame_features = int(features[-1][0]) if features else None
    return result, frame_features, max(scores) if scores else None, len(scores)


def run_trial(
    command: list[str], log: Path, sequence: int, total: int, ready_timeout: float,
    verify_timeout: float,
) -> dict[str, object]:
    start_offset = log.stat().st_size
    cursor = start_offset
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + ready_timeout
    ready = False

    while time.monotonic() < deadline:
        chunk, cursor = read_from(log, cursor)
        if READY_TEXT in chunk:
            ready = True
            break
        if process.poll() is not None:
            break
        time.sleep(0.02)

    if not ready:
        process.kill()
        stdout, stderr = process.communicate()
        raise RuntimeError(
            f"verification did not become ready: rc={process.returncode} "
            f"stdout={stdout.strip()!r} stderr={stderr.strip()!r}"
        )

    print(f">>> {sequence}/{total}: reader armed; press right index finger", flush=True)
    notify("指纹 A/B 测试", f"第 {sequence}/{total} 次：现在按右手食指")
    try:
        stdout, stderr = process.communicate(timeout=verify_timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise RuntimeError(f"verification timed out: {stdout!r} {stderr!r}")

    # Allow fprintd's append log stream to flush the final score/result lines.
    time.sleep(0.1)
    log_chunk, _ = read_from(log, start_offset)
    result, frame_features, max_score, score_count = parse_log(log_chunk)
    if result == "unknown":
        raise RuntimeError(
            f"no fprintd result found: rc={process.returncode} "
            f"stdout={stdout.strip()!r} stderr={stderr.strip()!r}"
        )
    return {
        "result": result,
        "frame_features": frame_features,
        "max_score": max_score,
        "score_count": score_count,
        "returncode": process.returncode,
    }


def output_path() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = REPO / ".tools" / "logs"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".write-probe"
        probe.touch()
        probe.unlink()
    except OSError:
        directory = Path("/tmp")
    return directory / f"verify-path-ab-{stamp}.csv"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", default=getpass.getuser())
    parser.add_argument("--finger", default="right-index-finger")
    parser.add_argument("--per-method", type=int, default=20)
    parser.add_argument("--rest", type=float, default=2.0)
    parser.add_argument("--ready-timeout", type=float, default=10.0)
    parser.add_argument("--verify-timeout", type=float, default=45.0)
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    args = parser.parse_args()

    if args.per_method < 1 or args.rest < 0:
        parser.error("--per-method must be positive and --rest must be non-negative")
    if not args.log.is_file():
        parser.error(f"debug log not found: {args.log}")
    if not PAM_CONFIG.is_file():
        parser.error(
            "single-attempt PAM profile not installed; run: "
            f"pkexec install -o root -g root -m 0644 {PAM_CONFIG_SOURCE} {PAM_CONFIG}"
        )

    build_helper()
    methods = method_order(args.per_method)
    csv_path = output_path()
    rows: list[dict[str, object]] = []

    print(f"Counterbalanced A/B: {args.per_method} CLI + {args.per_method} PAM presses")
    print("A notification is sent only after fprintd reports that the reader is armed.", flush=True)

    try:
        for index, method in enumerate(methods, 1):
            if method == "cli":
                command = ["fprintd-verify", "-f", args.finger, args.user]
            else:
                command = [str(PAM_HELPER), args.user, PAM_SERVICE]
            sample = run_trial(command, args.log, index, len(methods),
                               args.ready_timeout, args.verify_timeout)
            row = {"sequence": index, "pair": (index + 1) // 2,
                   "method": method, **sample}
            rows.append(row)
            print(f"    method={method} result={sample['result']} "
                  f"score={sample['max_score']} features={sample['frame_features']}",
                  flush=True)
            if index != len(methods):
                notify("本轮已记录", f"请完全抬起手指，{args.rest:g} 秒后继续")
                time.sleep(args.rest)
    except (KeyboardInterrupt, RuntimeError) as error:
        print(f"\nstopped: {error}", file=sys.stderr)

    if rows:
        with csv_path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nresults: {csv_path}")
        for method in ("cli", "pam"):
            selected = [row for row in rows if row["method"] == method]
            passed = sum(row["result"] == "verify-match" for row in selected)
            print(f"{method}: {passed}/{len(selected)} single-attempt matches")
    return 0 if len(rows) == len(methods) else 1


if __name__ == "__main__":
    raise SystemExit(main())
