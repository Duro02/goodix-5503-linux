"""Official OTP-dependent 5503 runtime configuration derivation."""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct
from pathlib import Path
from typing import Final

from .security import disable_core_dumps
from .whitebox import (
    CHECK_COOKIE,
    EXPECTED_WBDI_SHA256,
    WhiteboxError,
    _clear_emulated_secrets,
    _load_pe_image,
)

GET_CHIP_CONFIG: Final = 0x18006C020
CONFIG_ALLOC: Final = 0x1800C9320
DRIVER_LOG: Final = 0x1800C8520
PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
RUNTIME_CONFIG_PATH: Final = (
    PROJECT_ROOT / "artifacts" / "device-backup" / "runtime-config-5503.bin"
)
EXPECTED_ZERO_OTP_CONFIG: Final = bytes.fromhex(
    "581160712c9d2cc91ce518fd00fd00fd03ba000180ca0004008400c0b38600bb"
    "c48800baba8a00b2b28c00aaaa8e00c1c19000bbbb9200b1b1940000a8960000"
    "b6980000009a000000d2000000d4000000d6000000d800000050000105d00000"
    "00700000007200785674003412200010402a0102042200012024003200800001"
    "005c008000560024205800030032000c02660000027c000058820080152a0182"
    "032200012024001400800001005c000001560004205800030032000c02660000"
    "027c000058820080152a0108005c000001540000016200080464001000660000"
    "027c0000582a0108005c0000015200080054000001660000027c00005800a574"
)


class ChipConfigError(RuntimeError):
    """The pinned official GetChipConfig routine failed."""


def _config_checksum(config_without_checksum: bytes | bytearray) -> int:
    if len(config_without_checksum) != 254:
        raise ValueError("configuration checksum input must be exactly 254 bytes")
    words = struct.unpack("<127H", config_without_checksum)
    return (-(0xA5A5 + sum(words))) & 0xFFFF


def _validate_config_checksum(config: bytes | bytearray) -> None:
    if len(config) != 256:
        raise ChipConfigError("configuration must be exactly 256 bytes")
    expected = _config_checksum(config[:254])
    received = struct.unpack("<H", config[254:256])[0]
    if received != expected:
        raise ChipConfigError(
            f"invalid official configuration checksum 0x{received:04x}"
        )


def emulate_chip_config(otp: bytearray, wbdi_path: Path) -> bytearray:
    if not isinstance(otp, bytearray):
        raise TypeError("OTP must be a mutable bytearray")
    if len(otp) != 64:
        raise ValueError("5503 OTP must be exactly 64 bytes")
    disable_core_dumps()
    binary = wbdi_path.read_bytes()
    if hashlib.sha256(binary).hexdigest() != EXPECTED_WBDI_SHA256:
        raise ChipConfigError("refusing to emulate an unpinned Wbdi.dll")

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
        raise ChipConfigError("install the whitebox optional dependency") from error

    stack_base, stack_size = 0x200000000, 0x200000
    heap_base, heap_size = 0x300000000, 0x2000000
    sentinel = 0x400000000
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    _load_pe_image(uc, binary)
    uc.mem_map(stack_base, stack_size)
    uc.mem_map(heap_base, heap_size)
    uc.mem_map(sentinel, 0x1000)
    heap_next = heap_base + 0x100000
    allocations: list[tuple[int, int]] = []

    def emulate_return(value: int = 0) -> None:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RAX, value)
        uc.reg_write(UC_X86_REG_RIP, target)

    def code_hook(_uc, address: int, _size: int, _data) -> None:
        nonlocal heap_next
        if address == CONFIG_ALLOC:
            length = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
            result = (heap_next + 15) & ~15
            heap_next = result + max(1, length)
            if heap_next >= heap_base + heap_size:
                raise ChipConfigError("emulated configuration heap exhausted")
            allocated_length = max(1, length)
            allocations.append((result, allocated_length))
            uc.mem_write(result, b"\x00" * allocated_length)
            emulate_return(result)
        elif address in (DRIVER_LOG, CHECK_COOKIE):
            emulate_return(0)

    uc.hook_add(UC_HOOK_CODE, code_hook)
    context_address = heap_base + 0x1000
    otp_address = heap_base + 0x3000
    output_pointer_address = heap_base + 0x4000
    output_length_address = heap_base + 0x4010
    output: bytearray | None = None
    try:
        uc.mem_write(context_address, b"\x00" * 0x200)
        otp_view = (ctypes.c_char * len(otp)).from_buffer(otp)
        uc.mem_write(otp_address, otp_view)
        uc.mem_write(output_pointer_address, b"\x00" * 8)
        uc.mem_write(output_length_address, b"\x00" * 4)
        rsp = ((stack_base + stack_size - 0x1000) & ~0xF) - 8
        uc.mem_write(rsp, struct.pack("<Q", sentinel))
        uc.mem_write(rsp + 0x28, struct.pack("<Q", output_length_address))
        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.reg_write(UC_X86_REG_RCX, context_address)
        uc.reg_write(UC_X86_REG_RDX, otp_address)
        uc.reg_write(UC_X86_REG_R8, len(otp))
        uc.reg_write(UC_X86_REG_R9, output_pointer_address)
        try:
            uc.emu_start(GET_CHIP_CONFIG, sentinel, count=5_000_000)
        except Exception as error:
            rip = uc.reg_read(UC_X86_REG_RIP)
            raise ChipConfigError(f"GetChipConfig emulation failed at 0x{rip:x}") from error
        status = uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        output_pointer = struct.unpack(
            "<Q", uc.mem_read(output_pointer_address, 8)
        )[0]
        output_length = struct.unpack(
            "<I", uc.mem_read(output_length_address, 4)
        )[0]
        if status != 1 or output_length != 256:
            raise ChipConfigError(
                f"GetChipConfig returned status {status}, length {output_length}"
            )
        if not any(
            output_pointer == address and output_length <= allocated_length
            for address, allocated_length in allocations
        ):
            raise ChipConfigError(
                "GetChipConfig output did not originate from the hooked allocator"
            )
        output = bytearray(uc.mem_read(output_pointer, output_length))
        _validate_config_checksum(output)
    finally:
        _clear_emulated_secrets(
            uc,
            (
                UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
                UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
                UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2,
                UC_X86_REG_XMM3, UC_X86_REG_XMM4, UC_X86_REG_XMM5,
                UC_X86_REG_XMM6, UC_X86_REG_XMM7, UC_X86_REG_XMM8,
                UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11,
                UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14,
                UC_X86_REG_XMM15,
            ),
            ((heap_base, heap_size), (stack_base, stack_size)),
        )
    if output is None:
        raise ChipConfigError("GetChipConfig produced no output")
    return output


def derive_live_chip_config(timeout_seconds: float = 5.0) -> dict[str, int | str]:
    """Read fixed OTP once and save its official derived config; never print OTP."""
    from .probe import (
        COMMAND_FIRMWARE_VERSION,
        COMMAND_GET_IAP_VERSION,
        COMMAND_NOP,
        ReadOnlyUsbSession,
        _decode_c_string,
        _drop_sudo_privileges,
        _write_or_verify_secure_backup,
    )
    from .whitebox import find_pinned_wbdi

    disable_core_dumps()
    session: ReadOnlyUsbSession | None = None
    otp = bytearray()
    config = bytearray()
    try:
        session = ReadOnlyUsbSession(timeout_seconds)
        session.request(COMMAND_NOP, checksum=False)
        firmware = _decode_c_string(session.request(COMMAND_FIRMWARE_VERSION))
        iap = _decode_c_string(session.request(COMMAND_GET_IAP_VERSION, b"\x19\x00"))
        if firmware != "GF3258_RTSEC_APP_10063" or iap != "MILAN_RTSEC_IAP_10027":
            raise ChipConfigError("unexpected firmware or IAP for config derivation")
        otp = session.read_otp()
        session.close()
        session = None

        _drop_sudo_privileges()
        disable_core_dumps()
        if os.geteuid() == 0:
            raise ChipConfigError("refusing local driver/config access as root")
        wbdi = find_pinned_wbdi(PROJECT_ROOT)
        verify_zero_otp_vector(wbdi)
        config = emulate_chip_config(otp, wbdi)
        status = _write_or_verify_secure_backup(RUNTIME_CONFIG_PATH, config)
        return {
            "operation": "read-only-otp-official-config-derivation",
            "firmware": firmware,
            "iap": iap,
            "otp_length": len(otp),
            "config_length": len(config),
            "config_sha256": hashlib.sha256(config).hexdigest(),
            "fdt_delta": config[0xC8],
            "status": status,
        }
    finally:
        close_error: BaseException | None = None
        if session is not None:
            try:
                session.close()
            except BaseException as error:
                close_error = error
        otp[:] = b"\x00" * len(otp)
        config[:] = b"\x00" * len(config)
        if close_error is not None:
            raise ChipConfigError("failed to close OTP USB session") from close_error


def verify_zero_otp_vector(wbdi_path: Path) -> None:
    otp = bytearray(64)
    output = emulate_chip_config(otp, wbdi_path)
    try:
        if output != EXPECTED_ZERO_OTP_CONFIG:
            raise ChipConfigError("GetChipConfig failed the zero-OTP vector")
    finally:
        otp[:] = b"\x00" * len(otp)
        output[:] = b"\x00" * len(output)
