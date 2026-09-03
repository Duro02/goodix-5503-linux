"""Single-purpose, review-gated PSK provisioning path.

There is deliberately no standalone mutator CLI. The public setup orchestrator
can reach only this fixed operation after explicit confirmation. It accepts one
fixed 96-byte white-box value and emits the official 0xbb010003 TLV with opcode
0xe0. Firmware, registers and configuration are not writable here.
"""

from __future__ import annotations

import hmac
import os
import struct
from pathlib import Path
from typing import Final

from .pairing import (
    PROJECT_ROOT,
    PSK_PATH,
    VERIFICATION_PATH,
    WHITEBOX_PATH,
    _read_secure_secret,
    calculate_r_verification_record,
)
from .probe import (
    COMMAND_FIRMWARE_VERSION,
    COMMAND_GET_IAP_VERSION,
    COMMAND_NOP,
    COMMAND_PRESET_PSK_READ,
    OFFICIAL_R_PSK_HASH_SELECTOR,
    OFFICIAL_WHITEBOX_PSK_SELECTOR,
    VERIFICATION_RECORD_BACKUP,
    ProtocolError,
    ReadOnlyUsbSession,
    _decode_c_string,
    _decode_r_read_response,
    _disable_core_dumps,
    _drop_sudo_privileges,
)
from .whitebox import emulate_whitebox, find_pinned_wbdi, verify_known_vector

COMMAND_PRESET_PSK_WRITE_R: Final = 0xE0
EXPECTED_FIRMWARE: Final = "GF3258_RTSEC_APP_10063"
EXPECTED_IAP: Final = "MILAN_RTSEC_IAP_10027"
WRITE_CONFIRMATION: Final = "replace-unrecoverable-old-psk-with-prepared-key"


class ProvisioningError(RuntimeError):
    """A fixed provisioning precondition or postcondition failed."""


def _write_prepared_whitebox(
    session: ReadOnlyUsbSession, whitebox: bytearray
) -> None:
    """Internal fixed mutation reachable only from the validated orchestrator."""
    if not isinstance(whitebox, bytearray):
        raise TypeError("white-box record must be a mutable bytearray")
    if len(whitebox) != 96:
        raise ValueError("white-box record must be exactly 96 bytes")
    _disable_core_dumps()
    payload = bytearray(struct.pack("<II", OFFICIAL_WHITEBOX_PSK_SELECTOR, 96))
    payload.extend(whitebox)
    try:
        # No public session mutator is exposed. The existing transport remains
        # name-mangled and this helper has no command/selector parameters.
        response = session._ReadOnlyUsbSession__exchange(  # type: ignore[attr-defined]
            COMMAND_PRESET_PSK_WRITE_R, payload
        )
        if not response:
            raise ProtocolError("device returned an empty PSK write response")
        if response[0] != 0:
            raise ProtocolError(
                f"device rejected PSK write with status 0x{response[0]:02x}"
            )
    finally:
        payload[:] = b"\x00" * len(payload)


def _read_live_verification(session: ReadOnlyUsbSession) -> bytearray:
    payload = struct.pack("<II", OFFICIAL_R_PSK_HASH_SELECTOR, 0)
    record = _decode_r_read_response(
        session.request(COMMAND_PRESET_PSK_READ, payload),
        OFFICIAL_R_PSK_HASH_SELECTOR,
    )
    if len(record) != 32:
        record[:] = b"\x00" * len(record)
        raise ProtocolError("live R verification record is not exactly 32 bytes")
    return record


def _load_and_validate_material() -> tuple[bytearray, bytearray, bytearray]:
    psk = bytearray()
    whitebox = bytearray()
    verification = bytearray()
    derived_whitebox = bytearray()
    derived_verification = bytearray()
    try:
        psk = _read_secure_secret(PSK_PATH, 32)
        whitebox = _read_secure_secret(WHITEBOX_PATH, 96)
        verification = _read_secure_secret(VERIFICATION_PATH, 32)
        wbdi = find_pinned_wbdi(PROJECT_ROOT)
        verify_known_vector(wbdi)
        derived_whitebox = emulate_whitebox(psk, wbdi)
        derived_verification = calculate_r_verification_record(psk)
        if not hmac.compare_digest(whitebox, derived_whitebox):
            raise ProvisioningError("saved white-box record does not match saved PSK")
        if not hmac.compare_digest(verification, derived_verification):
            raise ProvisioningError("saved verification record does not match saved PSK")
        result = (psk, whitebox, verification)
        psk = bytearray()
        whitebox = bytearray()
        verification = bytearray()
        return result
    finally:
        psk[:] = b"\x00" * len(psk)
        whitebox[:] = b"\x00" * len(whitebox)
        verification[:] = b"\x00" * len(verification)
        derived_whitebox[:] = b"\x00" * len(derived_whitebox)
        derived_verification[:] = b"\x00" * len(derived_verification)


def provision_prepared_pairing(
    *, confirmation: str, timeout_seconds: float = 5.0
) -> dict[str, str]:
    """Perform one confirmed, fixed write followed by exact readback."""
    if confirmation != WRITE_CONFIRMATION:
        raise ProvisioningError("exact hardware-write confirmation was not supplied")
    _disable_core_dumps()

    live_before = bytearray()
    old_expected = bytearray()
    psk = bytearray()
    whitebox = bytearray()
    expected_after = bytearray()
    live_after = bytearray()
    session: ReadOnlyUsbSession | None = None
    pending_error: BaseException | None = None
    try:
        # Open and identify the already-confirmed hardware before dropping sudo.
        session = ReadOnlyUsbSession(timeout_seconds)
        session.request(COMMAND_NOP, checksum=False)
        firmware = _decode_c_string(session.request(COMMAND_FIRMWARE_VERSION))
        iap = _decode_c_string(session.request(COMMAND_GET_IAP_VERSION, b"\x19\x00"))
        if firmware != EXPECTED_FIRMWARE or iap != EXPECTED_IAP:
            raise ProvisioningError(
                f"unexpected target firmware/IAP: {firmware!r} / {iap!r}"
            )
        live_before = _read_live_verification(session)

        # Keep the claimed USB handle, but permanently become the invoking user
        # before touching any local secret file.
        _drop_sudo_privileges()
        _disable_core_dumps()
        if os.geteuid() == 0:
            raise ProvisioningError("refusing local pairing-secret access as root")

        old_expected = _read_secure_secret(Path(VERIFICATION_RECORD_BACKUP), 32)
        psk, whitebox, expected_after = _load_and_validate_material()

        # A rerun after an ambiguous USB response must recognize that the exact
        # prepared key was already committed, rather than trying another write.
        if hmac.compare_digest(live_before, expected_after):
            return {
                "operation": "already-provisioned-no-write",
                "firmware": firmware,
                "iap": iap,
                "verification": "matched-prepared-record",
            }
        if not hmac.compare_digest(live_before, old_expected):
            raise ProvisioningError(
                "live PSK state matches neither the old backup nor the prepared key"
            )

        try:
            _write_prepared_whitebox(session, whitebox)
            live_after = _read_live_verification(session)
        except BaseException as error:
            raise ProvisioningError(
                "write outcome is ambiguous; retain files and rerun only this prepared key"
            ) from error
        if not hmac.compare_digest(live_after, expected_after):
            raise ProvisioningError(
                "post-write verification mismatch; retain files and rerun only this prepared key"
            )
        return {
            "operation": "fixed-psk-write-and-readback",
            "firmware": firmware,
            "iap": iap,
            "verification": "matched-prepared-record",
        }
    except BaseException as error:
        pending_error = error
        raise
    finally:
        close_error: BaseException | None = None
        if session is not None:
            try:
                session.close()
            except BaseException as error:
                close_error = error
        live_before[:] = b"\x00" * len(live_before)
        old_expected[:] = b"\x00" * len(old_expected)
        psk[:] = b"\x00" * len(psk)
        whitebox[:] = b"\x00" * len(whitebox)
        expected_after[:] = b"\x00" * len(expected_after)
        live_after[:] = b"\x00" * len(live_after)
        if close_error is not None:
            if pending_error is None:
                raise ProvisioningError(
                    "failed to close provisioning USB session"
                ) from close_error
            pending_error.add_note(
                f"also failed to close provisioning USB session: {close_error}"
            )
