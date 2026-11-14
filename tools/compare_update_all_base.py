#!/usr/bin/env python3
"""Offline CFG and ``context+0xb8`` evidence report for UpdateAllBase.

The program reads local PE files and uses local ``objdump`` only.  It does not
load a DLL, enumerate USB, or communicate with a fingerprint sensor.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from report_wbdi_initialization_pairs import EXPECTED_HASHES, PeImage, disassemble


@dataclass(frozen=True)
class Build:
    label: str
    update: int
    start_call: int
    final_begin: int
    final_end: int


BUILDS = (
    Build("10062", 0x18008BCD0, 0x1800888AE, 0x18008CD90, 0x18008CDBE),
    Build("10063", 0x18008BDC0, 0x18008899E, 0x18008CE97, 0x18008CF71),
)


def direct_branch_target(assembly: str) -> int | None:
    match = re.match(r"j[a-z]+\s+0x([0-9a-f]+)", assembly)
    return int(match.group(1), 16) if match else None


def cfg_metrics(instructions, start: int, end: int) -> tuple[int, int, int, int]:
    """Return syntactic basic-block, edge, conditional-branch and call counts."""
    addresses = {address for address, _bytes, _assembly in instructions}
    starts = {start}
    conditional_count = call_count = 0
    for address, code, assembly in instructions:
        target = direct_branch_target(assembly)
        if target in addresses:
            starts.add(target)
            if assembly.startswith("jmp"):
                starts.add(address + len(code))
            else:
                conditional_count += 1
                starts.add(address + len(code))
        if assembly.startswith("call "):
            call_count += 1
    block_starts = sorted(address for address in starts if address in addresses)
    edges = 0
    for index, block_start in enumerate(block_starts):
        block_end = block_starts[index + 1] if index + 1 < len(block_starts) else end
        last = next(
            instruction
            for instruction in reversed(instructions)
            if block_start <= instruction[0] < block_end
        )
        address, code, assembly = last
        target = direct_branch_target(assembly)
        if target in addresses:
            edges += 1
        if assembly.startswith("j") and not assembly.startswith("jmp"):
            if address + len(code) in addresses:
                edges += 1
        elif not assembly.startswith(("jmp", "ret")) and address + len(code) in addresses:
            edges += 1
    return len(block_starts), edges, conditional_count, call_count


def print_block(objdump: str, image: PeImage, begin: int, end: int) -> None:
    for address, _code, assembly in disassemble(objdump, image, begin, end):
        print(f"  0x{address:x}: {assembly}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll_10062", type=Path)
    parser.add_argument("dll_10063", type=Path)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--verbose", action="store_true",
                        help="print the final context+0xb8 decision blocks")
    args = parser.parse_args()
    if shutil.which(args.objdump) is None:
        parser.error(f"objdump not found: {args.objdump}")
    images = {
        "10062": PeImage(args.dll_10062),
        "10063": PeImage(args.dll_10063),
    }
    for label, image in images.items():
        digest = hashlib.sha256(image.data).hexdigest()
        print(f"{label} sha256={digest}; expected-input={digest == EXPECTED_HASHES[label]}")
        if digest != EXPECTED_HASHES[label]:
            return 2
    for build in BUILDS:
        image = images[build.label]
        start, end = image.function_span(build.update)
        instructions = disassemble(args.objdump, image, start, end)
        blocks, edges, conditionals, calls = cfg_metrics(instructions, start, end)
        print(
            f"{build.label} UpdateAllBase: 0x{start:x}..0x{end:x}; "
            f"bytes={end - start}; instructions={len(instructions)}; "
            f"syntactic-basic-blocks={blocks}; edges={edges}; "
            f"conditional-branches={conditionals}; calls={calls}; "
            f"Start-call=0x{build.start_call:x}"
        )
        if args.verbose:
            print(f"{build.label} final decision block:")
            print_block(args.objdump, image, build.final_begin, build.final_end)
    print("10062 final rule: ctx+0xb8 = (local_status_a == 2 && local_status_b == 2)")
    print(
        "10063 final rule: ctx+0xb8 = output byte from 0x18004ca20 when "
        "global 0x18026e0a8 is non-null, otherwise from 0x180040400"
    )
    print(
        "10063 fallback: 0x180040400 -> 0x180060080 -> 0x18005f030; "
        "it accepts aggregate state 2 only while global 0x180256da0 is 0, 2, or 3"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
