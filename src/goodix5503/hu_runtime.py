"""Free GF3258 DN2/HU runtime parameter derivation.

These helpers reproduce fixed host-side transformations from the pinned 10063
Windows driver. They perform no I/O and expose no generic command interface.
"""

from __future__ import annotations

import struct
from enum import IntEnum


class HuRuntimeError(ValueError):
    """The local HU runtime parameters could not be derived safely."""


class RightInfoClass(IntEnum):
    INVALID = 0
    OTP_32 = 1
    OTP_2E = 2
    REPAIRED = 3


def goodix_crc8(data: bytes | bytearray) -> int:
    """Return the Goodix complemented CRC-8/poly-0x07 used for HU OTP."""
    crc = 0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc ^ 0xFF


def gf3258_dn2_otp_integrity(otp: bytes | bytearray) -> bool:
    """Apply the pinned MilanHUCheckSensorOTP three-region integrity gate."""
    if len(otp) != 64:
        return False
    mt = bytes(otp[0x16:0x1C]) + bytes(otp[0x1D:0x24]) + bytes(otp[0x28:0x32])
    if goodix_crc8(mt) != otp[0x3F]:
        return False
    ft = (
        bytes(otp[0x0B:0x16])
        + bytes(otp[0x1C:0x1D])
        + bytes(otp[0x32:0x3C])
        + bytes(otp[0x3E:0x3F])
    )
    if goodix_crc8(ft) != otp[0x3D]:
        return False
    whole = bytes(otp[0x00:0x0B]) + bytes(otp[0x24:0x28])
    return goodix_crc8(whole) == otp[0x3C]


def classify_hu_right_info(otp: bytearray) -> RightInfoClass:
    """Classify, and when required repair, an exact mutable 64-byte OTP copy."""
    if not isinstance(otp, bytearray):
        raise TypeError("OTP must be a mutable bytearray")
    if len(otp) != 64:
        raise HuRuntimeError("GF3258 OTP must be exactly 64 bytes")

    left_crc_input = otp[0x0B:0x16] + otp[0x1C:0x1D] + otp[0x32:0x3C]
    predicate_a = goodix_crc8(left_crc_input) == otp[0x3D]
    selected_32 = otp[0x32:0x36]
    predicate_b = all(selected_32) and goodix_crc8(selected_32) == otp[0x3E]
    if predicate_a or predicate_b:
        return RightInfoClass.OTP_32

    right_crc_input = otp[0x16:0x1C] + otp[0x1D:0x24] + otp[0x28:0x32]
    predicate_c = goodix_crc8(right_crc_input) == otp[0x3F]
    selected_2e = otp[0x2E:0x32]
    predicate_d = all(selected_2e) and goodix_crc8(selected_2e) == otp[0x16]
    if predicate_c or predicate_d:
        return RightInfoClass.OTP_2E

    equal = [otp[0x2E + index] == otp[0x32 + index] for index in range(4)]
    if sum(equal) < 3:
        return RightInfoClass.INVALID
    if all(equal):
        return RightInfoClass.REPAIRED

    mismatch = equal.index(False)
    replacement = sum(
        otp[0x2E + ((mismatch + offset) & 3)] for offset in (1, 3, 2)
    ) // 3
    otp[0x2E + mismatch] = replacement
    otp[0x32 + mismatch] = replacement
    return RightInfoClass.REPAIRED


def derive_hu_dac_field(otp: bytearray) -> bytearray:
    """Derive the four zero-extended LE16 DAC values consumed by HU commands."""
    classification = classify_hu_right_info(otp)
    if classification in (RightInfoClass.OTP_32, RightInfoClass.REPAIRED):
        selected = otp[0x32:0x36]
    elif classification is RightInfoClass.OTP_2E:
        selected = otp[0x2E:0x32]
    else:
        raise HuRuntimeError("GF3258 HU right-info classification failed")

    field = bytearray(8)
    for index, value in enumerate(selected):
        struct.pack_into("<H", field, index * 2, value)
    return field


def build_hu_nav_base(decoded_image: bytes | bytearray) -> bytearray:
    """Crop the official 80x12 navigation base from an 80x64 LE16 image."""
    if len(decoded_image) != 80 * 64 * 2:
        raise HuRuntimeError("decoded GF3258 image must be exactly 10240 bytes")
    nav = bytearray(80 * 12 * 2)
    for output_row in range(12):
        source_row = 8 + 4 * output_row
        source_offset = source_row * 80 * 2
        output_offset = output_row * 80 * 2
        nav[output_offset : output_offset + 160] = decoded_image[
            source_offset : source_offset + 160
        ]
    return nav


def build_hu_image_request(dac_field: bytes | bytearray) -> bytes:
    """Build the fixed-purpose local command-20 request payload."""
    if len(dac_field) != 8:
        raise HuRuntimeError("HU DAC field must be exactly 8 bytes")
    return b"\x01\x00" + bytes(dac_field)


def parse_hu_manual_fdt_response(
    response: bytes | bytearray,
) -> tuple[bytearray, bytearray]:
    """Parse the HU FDT header and return its six-word base forms."""
    # McuParseFdt consumes two LE16 header fields before copying the
    # profile-sized base. The protocol checksum was already removed by the
    # packet decoder, so the normal HU body is exactly 4 + 12 bytes.
    if len(response) != 16:
        raise HuRuntimeError(
            f"HU manual FDT response must be exactly 16 bytes, got {len(response)}"
        )
    raw = bytearray(response[4:])
    transformed = bytearray(12)
    try:
        for offset in range(0, 12, 2):
            word = struct.unpack_from("<H", raw, offset)[0]
            struct.pack_into(
                "<H", transformed, offset, (((word >> 1) << 8) | 0x0080) & 0xFFFF
            )
        return raw, transformed
    except BaseException:
        raw[:] = b"\x00" * len(raw)
        transformed[:] = b"\x00" * len(transformed)
        raise


def hu_fdt_bases_within_delta(
    first: bytes | bytearray,
    second: bytes | bytearray,
    delta: int,
) -> bool:
    """Apply the official inclusive six-word FDT consistency comparison."""
    if len(first) != 12 or len(second) != 12:
        raise HuRuntimeError("HU FDT bases must each be exactly 12 bytes")
    if not 0 <= delta <= 0xFFFF:
        raise HuRuntimeError("HU FDT delta must be in range 0..65535")
    return all(
        abs(
            struct.unpack_from("<H", first, offset)[0]
            - struct.unpack_from("<H", second, offset)[0]
        )
        <= delta
        for offset in range(0, 12, 2)
    )


def build_hu_manual_fdt_request(
    dac_field: bytes | bytearray,
    base: bytes | bytearray,
    *,
    mode_nibble: int = 0,
) -> bytes:
    """Build the fixed-purpose local command-36 manual-base request payload."""
    if len(dac_field) != 8:
        raise HuRuntimeError("HU DAC field must be exactly 8 bytes")
    if len(base) != 12:
        raise HuRuntimeError("HU FDT base must be exactly 12 bytes")
    if not 0 <= mode_nibble <= 0x0F:
        raise HuRuntimeError("HU mode nibble must be in range 0..15")

    transformed = bytearray(12)
    try:
        for offset in range(0, 12, 2):
            word = struct.unpack_from("<H", base, offset)[0]
            struct.pack_into("<H", transformed, offset, (word & 0xFF00) | 0x0080)
        return bytes(((mode_nibble << 4) | 0x0D, 1)) + bytes(dac_field) + bytes(transformed)
    finally:
        transformed[:] = b"\x00" * len(transformed)
