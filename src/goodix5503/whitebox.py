"""Pinned local emulation of the official Goodix white-box encoder.

The proprietary Wbdi.dll is never distributed by this project. This module
requires the user-supplied Lenovo artifact with an exact SHA-256 and executes
only the pinned SecWhiteEncrypt function in Unicorn.
"""

from __future__ import annotations

import ctypes
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .security import disable_core_dumps

EXPECTED_WBDI_SHA256: Final = (
    "567b5af3f2c51eca058172aaa0d0403d82680c75e77d2d073cfd403b1180fb8a"
)
IMAGE_BASE: Final = 0x180000000
SEC_WHITE_ENCRYPT: Final = 0x180001090
CALLOC: Final = 0x180136FD4
FREE: Final = 0x1801321E0
LOG: Final = 0x180002810
CHECK_COOKIE: Final = 0x1800CC900
KNOWN_ZERO_WHITEBOX: Final = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5"
)


class WhiteboxError(RuntimeError):
    """The pinned official white-box encoder could not be emulated safely."""


@dataclass(frozen=True)
class EmulationTrace:
    instruction_count: int
    address_sha256: str
    helper_calls: tuple[int, ...]


def find_pinned_wbdi(project_root: Path) -> Path:
    matches = list(
        (project_root / "artifacts" / "windows-driver" / "extracted" / "win11").glob(
            "**/Goodix_3.1.581.610/Wbdi.dll"
        )
    )
    if len(matches) != 1:
        raise WhiteboxError("expected exactly one local Goodix 3.1.581.610 Wbdi.dll")
    digest = hashlib.sha256(matches[0].read_bytes()).hexdigest()
    if digest != EXPECTED_WBDI_SHA256:
        raise WhiteboxError("local Wbdi.dll does not match the pinned SHA-256")
    return matches[0]


def _load_pe_image(uc, binary: bytes) -> None:
    pe_offset = struct.unpack_from("<I", binary, 0x3C)[0]
    section_count = struct.unpack_from("<H", binary, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", binary, pe_offset + 20)[0]
    optional = pe_offset + 24
    image_size = struct.unpack_from("<I", binary, optional + 56)[0]
    header_size = struct.unpack_from("<I", binary, optional + 60)[0]
    mapped_size = (image_size + 0xFFF) & ~0xFFF
    uc.mem_map(IMAGE_BASE, mapped_size)
    uc.mem_write(IMAGE_BASE, binary[:header_size])

    section_table = optional + optional_size
    for index in range(section_count):
        entry = section_table + index * 40
        virtual_address = struct.unpack_from("<I", binary, entry + 12)[0]
        raw_size, raw_offset = struct.unpack_from("<II", binary, entry + 16)
        if raw_size:
            uc.mem_write(
                IMAGE_BASE + virtual_address,
                binary[raw_offset : raw_offset + raw_size],
            )


def _wipe_and_unmap(uc, address: int, size: int) -> None:
    zeros = b"\x00" * 0x100000
    try:
        for offset in range(0, size, len(zeros)):
            length = min(len(zeros), size - offset)
            uc.mem_write(address + offset, zeros[:length])
    finally:
        uc.mem_unmap(address, size)


def _wipe_secret_regions(uc, regions: tuple[tuple[int, int], ...]) -> None:
    errors = []
    for address, size in regions:
        try:
            _wipe_and_unmap(uc, address, size)
        except Exception as error:
            errors.append(error)
    if errors:
        raise WhiteboxError("failed to clear all emulated secret memory") from errors[0]


def _clear_emulated_secrets(
    uc, registers: tuple[int, ...], regions: tuple[tuple[int, int], ...]
) -> None:
    errors = []
    for register in registers:
        try:
            uc.reg_write(register, 0)
        except Exception as error:
            errors.append(error)
    try:
        _wipe_secret_regions(uc, regions)
    except Exception as error:
        errors.append(error)
    if errors:
        raise WhiteboxError("failed to clear all emulated secret state") from errors[0]


def _emulate_whitebox(
    psk: bytearray, wbdi_path: Path, *, collect_trace: bool
) -> tuple[bytearray, EmulationTrace | None]:
    if not isinstance(psk, bytearray):
        raise TypeError("PSK must be a mutable bytearray so its caller can wipe it")
    if len(psk) != 32:
        raise ValueError("PSK must be exactly 32 bytes")

    # This process-wide hardening is permanent and must precede every secret copy.
    disable_core_dumps()
    binary = wbdi_path.read_bytes()
    if hashlib.sha256(binary).hexdigest() != EXPECTED_WBDI_SHA256:
        raise WhiteboxError("refusing to emulate an unpinned Wbdi.dll")

    try:
        from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64
        from unicorn.x86_const import (
            UC_X86_REG_R8,
            UC_X86_REG_R9,
            UC_X86_REG_R10,
            UC_X86_REG_R11,
            UC_X86_REG_R12,
            UC_X86_REG_R13,
            UC_X86_REG_R14,
            UC_X86_REG_R15,
            UC_X86_REG_RAX,
            UC_X86_REG_RBP,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDI,
            UC_X86_REG_RDX,
            UC_X86_REG_RIP,
            UC_X86_REG_RSI,
            UC_X86_REG_RSP,
            UC_X86_REG_XMM0,
            UC_X86_REG_XMM1,
            UC_X86_REG_XMM2,
            UC_X86_REG_XMM3,
            UC_X86_REG_XMM4,
            UC_X86_REG_XMM5,
            UC_X86_REG_XMM6,
            UC_X86_REG_XMM7,
            UC_X86_REG_XMM8,
            UC_X86_REG_XMM9,
            UC_X86_REG_XMM10,
            UC_X86_REG_XMM11,
            UC_X86_REG_XMM12,
            UC_X86_REG_XMM13,
            UC_X86_REG_XMM14,
            UC_X86_REG_XMM15,
        )
    except ImportError as error:
        raise WhiteboxError("install the whitebox extra: pip install -e '.[whitebox]'") from error

    stack_base, stack_size = 0x200000000, 0x200000
    heap_base, heap_size = 0x300000000, 0x2000000
    sentinel = 0x400000000
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    _load_pe_image(uc, binary)
    uc.mem_map(stack_base, stack_size)
    uc.mem_map(heap_base, heap_size)
    uc.mem_map(sentinel, 0x1000)
    heap_next = heap_base + 0x30000
    trace_hash = hashlib.sha256()
    instruction_count = 0
    helper_calls: list[int] = []

    def emulate_return(value: int = 0) -> None:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RAX, value)
        uc.reg_write(UC_X86_REG_RIP, target)

    def code_hook(_uc, address: int, _size: int, _data) -> None:
        nonlocal heap_next, instruction_count
        if collect_trace:
            instruction_count += 1
            trace_hash.update(struct.pack("<Q", address))
        if address == CALLOC:
            if collect_trace:
                helper_calls.append(address)
            count = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
            item_size = uc.reg_read(UC_X86_REG_RDX) & 0xFFFFFFFF
            total = max(1, count * item_size)
            result = (heap_next + 15) & ~15
            heap_next = result + total
            if heap_next >= heap_base + heap_size:
                raise WhiteboxError("emulated heap exhausted")
            uc.mem_write(result, b"\x00" * total)
            emulate_return(result)
        elif address in (FREE, LOG, CHECK_COOKIE):
            if collect_trace:
                helper_calls.append(address)
            emulate_return(0)

    uc.hook_add(UC_HOOK_CODE, code_hook)
    input_address = heap_base + 0x100
    output_address = heap_base + 0x10000
    length_address = heap_base + 0x20000
    output: bytearray | None = None
    trace: EmulationTrace | None = None

    try:
        # A ctypes view lets Unicorn copy from the caller's mutable storage
        # without creating an immutable bytes(psk) secret.
        psk_view = (ctypes.c_char * len(psk)).from_buffer(psk)
        uc.mem_write(input_address, psk_view)
        uc.mem_write(output_address, b"\x00" * 0x800)
        uc.mem_write(length_address, struct.pack("<I", 0x800))

        rsp = ((stack_base + stack_size - 0x1000) & ~0xF) - 8
        uc.mem_write(rsp, struct.pack("<Q", sentinel))
        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.reg_write(UC_X86_REG_RCX, input_address)
        uc.reg_write(UC_X86_REG_RDX, 32)
        uc.reg_write(UC_X86_REG_R8, output_address)
        uc.reg_write(UC_X86_REG_R9, length_address)

        try:
            uc.emu_start(SEC_WHITE_ENCRYPT, sentinel, count=20_000_000)
        except Exception as error:
            rip = uc.reg_read(UC_X86_REG_RIP)
            raise WhiteboxError(f"official encoder emulation failed at 0x{rip:x}") from error

        result = uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        output_length = struct.unpack("<I", uc.mem_read(length_address, 4))[0]
        if result != 0 or output_length != 96:
            raise WhiteboxError(
                f"official encoder returned status 0x{result:08x}, length {output_length}"
            )
        output = bytearray(uc.mem_read(output_address, output_length))
        if collect_trace:
            trace = EmulationTrace(
                instruction_count, trace_hash.hexdigest(), tuple(helper_calls)
            )
    finally:
        # Input, output, cipher contexts, registers and stack temporaries may all
        # contain PSK material. Clear every guest location on success or failure.
        _clear_emulated_secrets(
            uc,
            (
                UC_X86_REG_RAX,
                UC_X86_REG_RBX,
                UC_X86_REG_RCX,
                UC_X86_REG_RDX,
                UC_X86_REG_RSI,
                UC_X86_REG_RDI,
                UC_X86_REG_RBP,
                UC_X86_REG_RSP,
                UC_X86_REG_R8,
                UC_X86_REG_R9,
                UC_X86_REG_R10,
                UC_X86_REG_R11,
                UC_X86_REG_R12,
                UC_X86_REG_R13,
                UC_X86_REG_R14,
                UC_X86_REG_R15,
                UC_X86_REG_XMM0,
                UC_X86_REG_XMM1,
                UC_X86_REG_XMM2,
                UC_X86_REG_XMM3,
                UC_X86_REG_XMM4,
                UC_X86_REG_XMM5,
                UC_X86_REG_XMM6,
                UC_X86_REG_XMM7,
                UC_X86_REG_XMM8,
                UC_X86_REG_XMM9,
                UC_X86_REG_XMM10,
                UC_X86_REG_XMM11,
                UC_X86_REG_XMM12,
                UC_X86_REG_XMM13,
                UC_X86_REG_XMM14,
                UC_X86_REG_XMM15,
            ),
            ((heap_base, heap_size), (stack_base, stack_size)),
        )

    if output is None:
        raise WhiteboxError("official encoder produced no output")
    return output, trace


def emulate_whitebox(psk: bytearray, wbdi_path: Path) -> bytearray:
    """Encode one PSK; the caller must wipe both mutable buffers after use."""
    return _emulate_whitebox(psk, wbdi_path, collect_trace=False)[0]


def trace_whitebox(psk: bytearray, wbdi_path: Path) -> tuple[bytearray, EmulationTrace]:
    """Test-only encoder entry point that records the exact guest instruction path."""
    output, trace = _emulate_whitebox(psk, wbdi_path, collect_trace=True)
    if trace is None:
        raise AssertionError("trace collection unexpectedly disabled")
    return output, trace


def verify_known_vector(wbdi_path: Path) -> None:
    psk = bytearray(32)
    output = emulate_whitebox(psk, wbdi_path)
    try:
        if output != KNOWN_ZERO_WHITEBOX:
            raise WhiteboxError("official encoder failed the pinned zero-PSK vector")
    finally:
        psk[:] = b"\x00" * len(psk)
        output[:] = b"\x00" * len(output)
