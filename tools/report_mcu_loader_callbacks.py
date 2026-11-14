#!/usr/bin/env python3
"""Report statically bound callbacks used by the Goodix MCU device loader.

This is an offline PE reader.  It reads the two supplied Wbdi.dll files and
uses local ``objdump`` to compare functions.  It does not load a DLL, enumerate
USB, or communicate with a fingerprint device.
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
class ImageLayout:
    label: str
    root_cell: int
    expected_root: int
    expected_callbacks: int


@dataclass(frozen=True)
class Callback:
    offset: int
    name: str
    old: int
    new: int


LAYOUTS = (
    ImageLayout("10062", 0x180206840, 0x180209DE0, 0x180209D00),
    ImageLayout("10063", 0x180256840, 0x180259E00, 0x180259D20),
)

CALLBACKS = (
    Callback(0x30, "McuResetFingerPrint", 0x1800A7B00, 0x1800A7CC0),
    Callback(0x40, "McuGetChipId wrapper", 0x1800A5B30, 0x1800A5CF0),
    Callback(0x78, "Realtek UpdateFirmware", 0x1800AE520, 0x1800AE6E0),
    Callback(0x80, "Realtek ProcessPsk", 0x1800AD900, 0x1800ADAC0),
    Callback(0xC0, "wake trampoline", 0x1800A9730, 0x1800A98F0),
)

EXTRA_PAIRS = (
    ("descriptor CreateContext factory", 0x1800AC300, 0x1800AC4C0),
    ("wake successor McuSendNop", 0x1800A8090, 0x1800A8250),
    ("chip-ID transport helper", 0x1800ABCB0, 0x1800ABE70),
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
        section_count = struct.unpack_from("<H", self.data, pe + 6)[0]
        optional_size = struct.unpack_from("<H", self.data, pe + 20)[0]
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
        raise ValueError(f"{self.path}: RVA 0x{rva:x} outside raw sections")

    def read_qword(self, va: int) -> int:
        offset = self.rva_to_offset(va - self.image_base)
        return struct.unpack_from("<Q", self.data, offset)[0]

    def function_span(self, va: int) -> tuple[int, int]:
        rva = va - self.image_base
        matches = [(start, end) for start, end in self.pdata if start <= rva < end]
        if len(matches) != 1:
            raise ValueError(f"{self.path}: no unique .pdata span for 0x{va:x}")
        start, end = matches[0]
        return start + self.image_base, end + self.image_base


def disassemble(objdump: str, path: Path, start: int, end: int):
    output = subprocess.check_output(
        [
            objdump,
            "-d",
            "-M",
            "intel",
            "-w",
            f"--start-address=0x{start:x}",
            f"--stop-address=0x{end:x}",
            str(path),
        ],
        text=True,
    )
    instructions = []
    for line in output.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)$", line)
        if match:
            instructions.append(
                (int(match.group(1), 16), bytes.fromhex(match.group(2)), match.group(3))
            )
    if not instructions:
        raise ValueError(f"objdump produced no instructions for 0x{start:x}")
    return instructions


def normalized_equivalent(objdump: str, old: PeImage, new: PeImage, old_va: int, new_va: int):
    old_start, old_end = old.function_span(old_va)
    new_start, new_end = new.function_span(new_va)
    left = disassemble(objdump, old.path, old_start, old_end)
    right = disassemble(objdump, new.path, new_start, new_end)
    same_shape = len(left) == len(right) and all(
        old_address - old_start == new_address - new_start
        and len(old_bytes) == len(new_bytes)
        for (old_address, old_bytes, _), (new_address, new_bytes, _) in zip(left, right)
    )
    non_address = 0
    address_only = 0
    if same_shape:
        for (_, old_bytes, old_assembly), (_, new_bytes, _) in zip(left, right):
            if old_bytes == new_bytes:
                continue
            if old_assembly.startswith("call ") or "[rip+" in old_assembly:
                address_only += 1
            else:
                non_address += 1
    return old_start, old_end, new_start, new_end, len(left), address_only, non_address, (
        same_shape and non_address == 0
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll_10062", type=Path)
    parser.add_argument("dll_10063", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    if shutil.which(args.objdump) is None:
        parser.error(f"objdump not found: {args.objdump}")

    images = (PeImage(args.dll_10062), PeImage(args.dll_10063))
    if any(image.image_base != IMAGE_BASE for image in images):
        parser.error("unexpected image base")
    for layout, image in zip(LAYOUTS, images):
        digest = hashlib.sha256(image.data).hexdigest()
        if digest != EXPECTED_HASHES[layout.label]:
            print(f"{layout.label}: unexpected SHA-256 {digest}")
            return 2
        root = image.read_qword(layout.root_cell)
        callbacks = image.read_qword(root + 0x38)
        print(
            f"{layout.label}: root-cell=0x{layout.root_cell:x} -> 0x{root:x}; "
            f"root[0]=0x{image.read_qword(root):x}; root+0x38=0x{callbacks:x}"
        )
        if root != layout.expected_root or callbacks != layout.expected_callbacks:
            print("  unexpected static descriptor binding")
            return 2

    old, new = images
    all_equivalent = True
    for callback in CALLBACKS:
        old_target = old.read_qword(LAYOUTS[0].expected_callbacks + callback.offset)
        new_target = new.read_qword(LAYOUTS[1].expected_callbacks + callback.offset)
        if (old_target, new_target) != (callback.old, callback.new):
            print(f"+0x{callback.offset:x} {callback.name}: unexpected table target")
            return 2
        result = normalized_equivalent(args.objdump, old, new, old_target, new_target)
        old_start, old_end, new_start, new_end, instructions, address_only, other, equivalent = result
        print(
            f"+0x{callback.offset:02x} {callback.name}: "
            f"0x{old_target:x} ({old_start:#x}..{old_end:#x}) / "
            f"0x{new_target:x} ({new_start:#x}..{new_end:#x}); "
            f"instructions={instructions}; address-only={address_only}; "
            f"other={other}; normalized-equivalent={equivalent}"
        )
        all_equivalent = all_equivalent and equivalent
    for name, old_target, new_target in EXTRA_PAIRS:
        result = normalized_equivalent(args.objdump, old, new, old_target, new_target)
        old_start, old_end, new_start, new_end, instructions, address_only, other, equivalent = result
        print(
            f"{name}: 0x{old_target:x} ({old_start:#x}..{old_end:#x}) / "
            f"0x{new_target:x} ({new_start:#x}..{new_end:#x}); "
            f"instructions={instructions}; address-only={address_only}; "
            f"other={other}; normalized-equivalent={equivalent}"
        )
        all_equivalent = all_equivalent and equivalent
    return 0 if all_equivalent else 1


if __name__ == "__main__":
    raise SystemExit(main())
