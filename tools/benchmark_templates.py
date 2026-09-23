#!/usr/bin/env python3
"""Compare fixed enrollment galleries on independent, single-frame live presses.

The original template remains active in fprintd. Its result must agree with
read-only replay. A second gallery comes from 8 to 24 explicitly supervised
reference images. Reference presses and evaluation presses must be disjoint.
Requires opt-in diagnostic logging/image dumps already enabled by the operator.
Never installs a driver or enrolls/updates a system print. Ambiguous captures
stop the run instead of selecting their best frame or dropping failures.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time

DUMP = re.compile(r"dumped fingerprint image to (.+\.pgm)$")
RESULT = re.compile(r"report_verify_status: result (verify-[\w-]+)")


def parse_capture(chunk: str) -> dict:
    """One physical press, one image, and the first terminal result only."""
    images = []
    result = None
    for line in chunk.splitlines():
        match = DUMP.search(line)
        if match:
            images.append(match[1])
        match = RESULT.search(line)
        if match and result is None:
            if not images:
                raise ValueError("Verification result preceded the captured image")
            result = match[1]
    if len(images) != 1:
        raise ValueError(f"Expected one image/press, got {len(images)}; run is not comparable")
    if result not in {"verify-match", "verify-no-match", "verify-retry-scan"}:
        raise ValueError("Capture did not complete verification")
    return {"image": images[0], "result": result}


def notify(message: str) -> None:
    subprocess.run(
        ["notify-send", "-a", "Goodix 实测", "-t", "8000",
         "-h", "string:x-canonical-private-synchronous:goodix-benchmark",
         "Goodix 指纹对照测试", message],
        capture_output=True, timeout=5, check=False)


def replay(args: argparse.Namespace, capture: dict, out: Path, number: int) -> dict:
    if Path(capture["image"]).resolve() in args.reference_images:
        raise ValueError("Evaluation image is also an enrollment reference")
    manifest = out / f"round-{number:02d}.tsv"
    manifest.write_text(f"{number}\t{capture['image']}\n")
    result = subprocess.run([str(args.replay), str(args.template), str(manifest),
                             str(args.references)],
                            capture_output=True, text=True, timeout=15, check=True)
    (out / f"round-{number:02d}-scores.tsv").write_text(result.stdout)
    rows = list(csv.DictReader(io.StringIO(result.stdout), delimiter="\t"))
    if len(rows) != 1:
        raise ValueError("Replay must return exactly one image")
    return rows[0]


def verify_once(args: argparse.Namespace, offset: int, message: str) -> tuple[str, str]:
    # Announce readiness only after the background/activation sequence. A
    # prompt before launching VerifyStart would itself encourage the user to
    # put a finger down while the driver is measuring its idle background.
    child = subprocess.Popen(["fprintd-verify", args.user], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + args.timeout
    try:
        ready = False
        while time.monotonic() < deadline and child.poll() is None:
            with args.log.open("rb") as log:
                log.seek(offset)
                chunk = log.read().decode("utf-8", errors="replace")
            if "FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON" in chunk:
                ready = True
                break
            time.sleep(0.05)
        if not ready:
            raise ValueError("Device did not become ready to capture")
        notify(message)
        return child.communicate(timeout=max(1, deadline - time.monotonic()))
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--references", type=Path, required=True)
    parser.add_argument("--replay", type=Path, default=Path(".tools/goodix5503-replay"))
    parser.add_argument("--log", type=Path, default=Path("/var/log/fprintd-debug.log"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--user", default=getpass.getuser())
    parser.add_argument("--label", choices=["positive", "negative"], required=True)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    if args.count < 1 or args.count > 100:
        parser.error("count must be between 1 and 100")
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Freeze the reference list before collecting any evaluation presses.
    reference_text = args.references.read_text()
    reference_lines = [line.split("\t") for line in reference_text.splitlines()]
    if not 8 <= len(reference_lines) <= 24 or any(len(line) != 2 for line in reference_lines):
        parser.error("references must contain 8 to 24 GROUP<TAB>IMAGE lines")
    args.reference_images = {Path(line[1]).resolve() for line in reference_lines}
    if len(args.reference_images) != len(reference_lines):
        parser.error("references must not repeat an image")
    args.references = args.output / "fixed-references.tsv"
    args.references.write_text(reference_text)
    rows = []
    finger = "已录入的右手食指" if args.label == "positive" else "未录入的另一根手指"
    for number in range(1, args.count + 1):
        offset = args.log.stat().st_size
        print(f"STARTING {args.label} {number}/{args.count}", flush=True)
        stdout, stderr = verify_once(
            args, offset,
            f"{args.label} 第 {number}/{args.count} 次：用{finger}按约一秒后抬起；等下一条通知再按。")
        (args.output / f"round-{number:02d}-verify.txt").write_text(stdout + stderr)
        with args.log.open("rb") as log:
            log.seek(offset)
            chunk = log.read().decode("utf-8", errors="replace")
        (args.output / f"round-{number:02d}.log").write_text(chunk)
        capture = parse_capture(chunk)
        scores = replay(args, capture, args.output, number)
        sufficient = int(scores["keypoints"]) >= 20
        baseline = sufficient and int(scores["max_score"]) >= 150
        candidate = sufficient and int(scores["reference_score"]) >= 150
        if baseline != (capture["result"] == "verify-match"):
            raise ValueError("Replay differs from the live result; do not count this run")
        row = {"round": number, "label": args.label,
               "baseline_pass": baseline, "candidate_pass": candidate,
               "baseline_score": int(scores["max_score"]),
               "candidate_score": int(scores["reference_score"]),
               "result": capture["result"]}
        rows.append(row)
        (args.output / "results.json").write_text(json.dumps(rows, indent=2))
        print(json.dumps(row), flush=True)
        # fprintd-verify may cancel its up-wait immediately after a result.
        # Give the one-second press time to finish before taking a new base.
        time.sleep(1.5)
    summary = {"label": args.label, "presses": len(rows),
               "baseline_pass": sum(row["baseline_pass"] for row in rows),
               "candidate_pass": sum(row["candidate_pass"] for row in rows),
               "recovered": sum(not row["baseline_pass"] and row["candidate_pass"] for row in rows),
               "lost": sum(row["baseline_pass"] and not row["candidate_pass"] for row in rows)}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
    print("SUMMARY " + json.dumps(summary), flush=True)
    notify(f"本组完成：原模板通过 {summary['baseline_pass']}/{len(rows)}，新参考通过 {summary['candidate_pass']}/{len(rows)}。请先停止按压。")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"BENCHMARK STOPPED: {error}", flush=True)
        raise SystemExit(1)
