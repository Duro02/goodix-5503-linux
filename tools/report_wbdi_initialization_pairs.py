#!/usr/bin/env python3
"""Offline structural report for the Goodix 10062/10063 initialization paths.

The script reads only the two supplied PE files and invokes local ``objdump``.
It does not load the DLLs, enumerate USB, or send a device command.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


IMAGE_BASE = 0x180000000
EXPECTED_HASHES = {
    "10062": "35891ece58fecc5f97d5b76bf7a56292e1a845692e218a98754ae505b229fdf1",
    "10063": "1f0b55106e637bb39485f29bf85740518a7f3ab21a621967d282ae7e9ea5dffd",
}


@dataclass(frozen=True)
class Pair:
    name: str
    old: int
    new: int


PAIRS = (
    # Identified by their respective source-file and ``Load`` log arguments,
    # and by the adjacent Mcu/SPI dispatch table entries.
    Pair("McuDevLoader::Load", 0x180053690, 0x1800536B0),
    Pair("SpiDevLoader::Load", 0x1800541B0, 0x1800541D0),
    Pair("Start", 0x1800877A0, 0x180087890),
    Pair("McuGetFirmwareVersion", 0x1800A5EA0, 0x1800A6060),
    Pair("ProcessPsk", 0x18009A410, 0x18009A5D0),
    Pair("SetIap", 0x1800A5740, 0x1800A5900),
    Pair("McuReqTlsConnection", 0x1800ABEA0, 0x1800AC060),
    Pair("McuGetTlsStatus", 0x1800AF050, 0x1800AF210),
    Pair("PresetPskIsValidR", 0x1800426C0, 0x1800426C0),
    Pair("PresetPskReadSpecDataR", 0x180043130, 0x180043130),
    Pair("McuParseFdt", 0x1800A6490, 0x1800A6650),
    Pair("GetChipConfig", 0x18006BF30, 0x18006C020),
    Pair("GetFdtInitParam", 0x18006BE60, 0x18006BF50),
    Pair("OTP selector container", 0x18006EE40, 0x18006EF30),
    Pair("OTP to DAC", 0x18006F0D0, 0x18006F1C0),
)


class PeImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe : pe + 4] != b"PE\0\0":
            raise ValueError(f"{path}: not a PE image")
        optional = pe + 24
        if struct.unpack_from("<H", self.data, optional)[0] != 0x20B:
            raise ValueError(f"{path}: expected PE32+")
        self.image_base = struct.unpack_from("<Q", self.data, optional + 24)[0]
        optional_size = struct.unpack_from("<H", self.data, pe + 20)[0]
        section_count = struct.unpack_from("<H", self.data, pe + 6)[0]
        self.sections = []
        for index in range(section_count):
            offset = optional + optional_size + index * 40
            _virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                "<IIII", self.data, offset + 8
            )
            self.sections.append((rva, raw_size, raw_offset))
        exception_rva, exception_size = struct.unpack_from("<II", self.data, optional + 136)
        pdata_offset = self.rva_to_offset(exception_rva)
        self.pdata = [
            struct.unpack_from("<II", self.data, offset)
            for offset in range(pdata_offset, pdata_offset + exception_size, 12)
            if self.data[offset : offset + 8] != b"\0" * 8
        ]

    def rva_to_offset(self, rva: int) -> int:
        for section_rva, raw_size, raw_offset in self.sections:
            if section_rva <= rva < section_rva + raw_size:
                return raw_offset + rva - section_rva
        raise ValueError(f"{self.path}: RVA 0x{rva:x} is outside raw sections")

    def read_va(self, va: int, length: int) -> bytes:
        return self.data[self.rva_to_offset(va - self.image_base) : self.rva_to_offset(va - self.image_base) + length]

    def function_span(self, va: int) -> tuple[int, int]:
        rva = va - self.image_base
        matches = [(start, end) for start, end in self.pdata if start <= rva < end]
        if len(matches) != 1:
            raise ValueError(f"{self.path}: no unique .pdata span for 0x{va:x}")
        return tuple(value + self.image_base for value in matches[0])


def disassemble(objdump: str, image: PeImage, start: int, end: int):
    output = subprocess.check_output(
        [objdump, "-d", "-M", "intel", "-w", f"--start-address=0x{start:x}",
         f"--stop-address=0x{end:x}", str(image.path)],
        text=True,
    )
    result = []
    for line in output.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)$", line)
        if match:
            result.append((int(match.group(1), 16), bytes.fromhex(match.group(2)), match.group(3)))
    if not result:
        raise ValueError(f"objdump produced no instructions for 0x{start:x}")
    return result


def delta_kind(assembly: str) -> str:
    if re.match(r"(?:call|j[a-z]+)\s+0x", assembly):
        return "direct code target"
    if "[rip+" in assembly:
        return "RIP-relative reference"
    if re.match(r"mov\s+DWORD PTR \[rsp\+0x20\],0x[0-9a-f]+$", assembly):
        return "diagnostic line immediate"
    return "other operand"


def compare_pair(objdump: str, old: PeImage, new: PeImage, pair: Pair) -> bool:
    old_start, old_end = old.function_span(pair.old)
    new_start, new_end = new.function_span(pair.new)
    old_code = old.read_va(old_start, old_end - old_start)
    new_code = new.read_va(new_start, new_end - new_start)
    old_insns = disassemble(objdump, old, old_start, old_end)
    new_insns = disassemble(objdump, new, new_start, new_end)
    same_shape = (
        len(old_code) == len(new_code)
        and len(old_insns) == len(new_insns)
        and all(
            old_address - old_start == new_address - new_start
            and len(old_bytes) == len(new_bytes)
            for (old_address, old_bytes, _), (new_address, new_bytes, _) in zip(old_insns, new_insns)
        )
    )
    counts: dict[str, int] = {}
    if same_shape:
        for (_old_address, old_bytes, old_asm), (_new_address, new_bytes, _new_asm) in zip(old_insns, new_insns):
            if old_bytes != new_bytes:
                kind = delta_kind(old_asm)
                counts[kind] = counts.get(kind, 0) + 1
    equivalent = same_shape and counts.get("other operand", 0) == 0
    detail = ", ".join(f"{kind}={count}" for kind, count in sorted(counts.items())) or "none"
    print(
        f"{pair.name}: 10062=0x{old_start:x}..0x{old_end:x} ({len(old_code)} B), "
        f"10063=0x{new_start:x}..0x{new_end:x} ({len(new_code)} B); "
        f"same-shape={same_shape}; deltas={detail}; normalized-equivalent={equivalent}"
    )
    return equivalent


def profile_report(image: PeImage, label: str, profile: int) -> None:
    chip_id = struct.unpack("<I", image.read_va(profile + 0x3C, 4))[0]
    ops = profile + 0x50
    print(f"{label} DN2: profile=0x{profile:x}; chip-id@+0x3c=0x{chip_id:04x}; ops=0x{ops:x}")
    for offset in (0x30, 0x50, 0x58, 0x60, 0x78, 0x80, 0x88):
        target = struct.unpack("<Q", image.read_va(ops + offset, 8))[0]
        print(f"  ops+0x{offset:02x}=0x{target:x}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll_10062", type=Path)
    parser.add_argument("dll_10063", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    if shutil.which(args.objdump) is None:
        parser.error(f"objdump not found: {args.objdump}")
    old, new = PeImage(args.dll_10062), PeImage(args.dll_10063)
    if old.image_base != IMAGE_BASE or new.image_base != IMAGE_BASE:
        parser.error("unexpected image base")
    for label, image in (("10062", old), ("10063", new)):
        digest = hashlib.sha256(image.data).hexdigest()
        print(f"{label} sha256={digest}; expected-input={digest == EXPECTED_HASHES[label]}")
        if digest != EXPECTED_HASHES[label]:
            return 2
    profile_report(old, "10062", 0x180207A50)
    profile_report(new, "10063", 0x180257A70)
    all_equivalent = all(compare_pair(args.objdump, old, new, pair) for pair in PAIRS)
    old_span = old.function_span(0x18008BCD0)
    new_span = new.function_span(0x18008BDC0)
    print(
        "UpdateAllBase: "
        f"10062=0x{old_span[0]:x}..0x{old_span[1]:x} ({old_span[1] - old_span[0]} B); "
        f"10063=0x{new_span[0]:x}..0x{new_span[1]:x} ({new_span[1] - new_span[0]} B); "
        "requires separate analysis"
    )
    return 0 if all_equivalent else 1


if __name__ == "__main__":
    raise SystemExit(main())
