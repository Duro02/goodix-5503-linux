#!/usr/bin/env python3
"""Offline, reproducible comparison of the two official Goodix Wbdi.dll files.

The program reads PE metadata and runs objdump locally.  It never opens USB,
loads either DLL, or sends a command to a fingerprint sensor.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


IMAGE_BASE = 0x180000000


@dataclass(frozen=True)
class FunctionPair:
    name: str
    old: int
    new: int


# The addresses are DN2-related code paths matched by the two package layouts.
# ``otp selector container`` is deliberately named after its .pdata boundary:
# the documented selection logic begins inside that container at +0xf0.
FUNCTIONS = (
    # These loader entries are identified by their McuDevLoader.c/SpiDevLoader.c
    # ``Load`` logging arguments and their dispatcher table, not by a guessed
    # similarity match.  Keeping the sibling SPI entry in the report prevents
    # confusing the two adjacent loader implementations.
    FunctionPair("McuDevLoader::Load", 0x180053690, 0x1800536B0),
    FunctionPair("SpiDevLoader::Load", 0x1800541B0, 0x1800541D0),
    FunctionPair("GetFdtInitParam", 0x18006BE60, 0x18006BF50),
    FunctionPair("GetChipConfig", 0x18006BF30, 0x18006C020),
    FunctionPair("FDT template-field helper", 0x180064CB0, 0x180064DA0),
    FunctionPair("GetChipConfig child A", 0x18006E0D0, 0x18006E1C0),
    FunctionPair("GetChipConfig child B", 0x1800648E0, 0x1800649D0),
    FunctionPair("GetChipConfig child C", 0x180065290, 0x180065380),
    FunctionPair("GetChipConfig child D", 0x180064EC0, 0x180064FB0),
    FunctionPair("GetChipConfig child E", 0x180064FD0, 0x1800650C0),
    FunctionPair("GetChipConfig leaf", 0x180055470, 0x180055490),
    FunctionPair("OTP selector container", 0x18006EE40, 0x18006EF30),
    FunctionPair("OTP to DAC helper", 0x18006F0D0, 0x18006F1C0),
)


class PeImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe : pe + 4] != b"PE\0\0":
            raise ValueError(f"{path}: not a PE file")
        self.number_of_sections = struct.unpack_from("<H", self.data, pe + 6)[0]
        optional = pe + 24
        optional_size = struct.unpack_from("<H", self.data, pe + 20)[0]
        if struct.unpack_from("<H", self.data, optional)[0] != 0x20B:
            raise ValueError(f"{path}: expected PE32+")
        self.image_base = struct.unpack_from("<Q", self.data, optional + 24)[0]
        exception_rva, exception_size = struct.unpack_from("<II", self.data, optional + 112 + 24)
        self.sections = []
        for index in range(self.number_of_sections):
            offset = optional + optional_size + index * 40
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                "<IIII", self.data, offset + 8
            )
            self.sections.append((rva, max(virtual_size, raw_size), raw_size, raw_offset))
        pdata_offset = self.rva_to_offset(exception_rva)
        self.pdata = []
        for offset in range(pdata_offset, pdata_offset + exception_size, 12):
            start, end, unwind = struct.unpack_from("<III", self.data, offset)
            if start or end or unwind:
                self.pdata.append((start, end))

    def rva_to_offset(self, rva: int) -> int:
        for section_rva, _span, raw_size, raw_offset in self.sections:
            if section_rva <= rva < section_rva + raw_size:
                return raw_offset + rva - section_rva
        raise ValueError(f"{self.path}: RVA 0x{rva:x} is outside raw sections")

    def read_va(self, va: int, length: int) -> bytes:
        rva = va - self.image_base
        start = self.rva_to_offset(rva)
        return self.data[start : start + length]

    def function_span(self, va: int) -> tuple[int, int]:
        rva = va - self.image_base
        matches = [(start, end) for start, end in self.pdata if start <= rva < end]
        if len(matches) != 1:
            raise ValueError(f"{self.path}: expected one .pdata range for 0x{va:x}, got {matches}")
        start, end = matches[0]
        return start + self.image_base, end + self.image_base


def disassemble(objdump: str, image: PeImage, start: int, end: int):
    output = subprocess.check_output(
        [objdump, "-d", "-M", "intel", "-w", f"--start-address=0x{start:x}", f"--stop-address=0x{end:x}", str(image.path)],
        text=True,
    )
    instructions = []
    for line in output.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(.*)$", line)
        if match:
            instructions.append((int(match.group(1), 16), bytes.fromhex(match.group(2)), match.group(3)))
    if not instructions:
        raise ValueError(f"objdump produced no instructions for 0x{start:x}")
    return instructions


def classify_instruction(assembly: str) -> str:
    if assembly.startswith("call "):
        return "direct-call target"
    if "[rip+" in assembly:
        return "RIP-relative data target"
    return "non-address operand"


def compare_function(objdump: str, old: PeImage, new: PeImage, pair: FunctionPair, verbose: bool) -> bool:
    old_start, old_end = old.function_span(pair.old)
    new_start, new_end = new.function_span(pair.new)
    old_bytes = old.read_va(old_start, old_end - old_start)
    new_bytes = new.read_va(new_start, new_end - new_start)
    old_instructions = disassemble(objdump, old, old_start, old_end)
    new_instructions = disassemble(objdump, new, new_start, new_end)
    raw_differences = [i for i, (left, right) in enumerate(zip(old_bytes, new_bytes)) if left != right]
    valid_shape = (
        len(old_bytes) == len(new_bytes)
        and len(old_instructions) == len(new_instructions)
        and all(
            old_address - old_start == new_address - new_start and len(old_code) == len(new_code)
            for (old_address, old_code, _), (new_address, new_code, _) in zip(old_instructions, new_instructions)
        )
    )
    changed = []
    if valid_shape:
        for (old_address, old_code, old_assembly), (_new_address, new_code, new_assembly) in zip(
            old_instructions, new_instructions
        ):
            if old_code != new_code:
                changed.append(
                    (old_address - old_start, classify_instruction(old_assembly), old_assembly, new_assembly)
                )
    classes = {kind: sum(kind == changed_kind for _, changed_kind, _, _ in changed) for kind in (
        "direct-call target", "RIP-relative data target", "non-address operand"
    )}
    normalized = valid_shape and classes["non-address operand"] == 0
    print(
        f"{pair.name}: .pdata 0x{old_start:x}-0x{old_end:x} / 0x{new_start:x}-0x{new_end:x}; "
        f"size={len(old_bytes)}; instructions={len(old_instructions)}; raw-different-bytes={len(raw_differences)}; "
        f"address-only-instruction-deltas={classes['direct-call target'] + classes['RIP-relative data target']}; "
        f"non-address-deltas={classes['non-address operand']}; normalized-equivalent={normalized}"
    )
    if verbose:
        for offset, kind, old_assembly, new_assembly in changed:
            print(f"  +0x{offset:x} {kind}: {old_assembly} || {new_assembly}")
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll_10062", type=Path)
    parser.add_argument("dll_10063", type=Path)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if shutil.which(args.objdump) is None:
        parser.error(f"objdump executable not found: {args.objdump}")
    old, new = PeImage(args.dll_10062), PeImage(args.dll_10063)
    if old.image_base != IMAGE_BASE or new.image_base != IMAGE_BASE:
        parser.error("unexpected image base; update the reviewed addresses before comparing")
    print(f"10062 sha256={hashlib.sha256(old.data).hexdigest()}")
    print(f"10063 sha256={hashlib.sha256(new.data).hexdigest()}")
    prefix_and_template_old = old.read_va(0x180207D40, 0x110)
    prefix_and_template_new = new.read_va(0x180257D60, 0x110)
    data_equal = prefix_and_template_old == prefix_and_template_new
    print(
        "FDT-prefix-plus-config-identical="
        f"{data_equal}; "
        f"config-sha256={hashlib.sha256(prefix_and_template_old[0x10:]).hexdigest()}"
    )
    equivalent = data_equal
    for pair in FUNCTIONS:
        # Do not short-circuit: a failed pair should not hide the remaining
        # comparison evidence from an offline investigation.
        equivalent = compare_function(args.objdump, old, new, pair, args.verbose) and equivalent
    return 0 if equivalent else 1


if __name__ == "__main__":
    raise SystemExit(main())
