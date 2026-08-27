"""Offline preparation of a fresh Goodix pairing secret.

This module has no USB transport and cannot write the fingerprint device.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
from typing import Final

from .probe import _write_or_verify_secure_backup
from .security import disable_core_dumps
from .whitebox import emulate_whitebox, find_pinned_wbdi, verify_known_vector

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
PAIRING_DIRECTORY: Final = PROJECT_ROOT / "artifacts" / "device-backup"
PSK_PATH: Final = PAIRING_DIRECTORY / "new-pairing-psk.bin"
WHITEBOX_PATH: Final = PAIRING_DIRECTORY / "new-pairing-whitebox-bb010003.bin"
VERIFICATION_PATH: Final = PAIRING_DIRECTORY / "new-pairing-verification-bb020007.bin"
KNOWN_ZERO_R_VERIFICATION: Final = bytes.fromhex(
    "81b8ff490612022a121a9449ee3aad2792f32b9f3141182cd01019945ee50361"
)


class PairingPreparationError(RuntimeError):
    """Offline pairing material could not be prepared safely."""


def calculate_r_verification_record(psk: bytearray) -> bytearray:
    """Reproduce the official R-family PMK-HMAC calculation."""
    if not isinstance(psk, bytearray):
        raise TypeError("PSK must be a mutable bytearray")
    if len(psk) != 32:
        raise ValueError("PSK must be exactly 32 bytes")
    disable_core_dumps()

    # CalculatePmk hashes: BE16(32), 32 zero bytes, BE16(32), PSK.
    raw_pmk = bytearray(68)
    pmk = bytearray(64)
    message = bytearray(range(64, 0, -1))
    try:
        raw_pmk[1] = 32
        raw_pmk[35] = 32
        raw_pmk[36:] = psk
        pmk[:32] = hashlib.sha256(raw_pmk).digest()
        return bytearray(hmac.digest(pmk, message, "sha256"))
    finally:
        raw_pmk[:] = b"\x00" * len(raw_pmk)
        pmk[:] = b"\x00" * len(pmk)
        message[:] = b"\x00" * len(message)


def _fill_random_secret(secret: bytearray) -> None:
    descriptor = os.open("/dev/urandom", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        view = memoryview(secret)
        filled = 0
        while filled < len(view):
            count = os.readv(descriptor, [view[filled:]])
            if count <= 0:
                raise OSError("short read from /dev/urandom")
            filled += count
    finally:
        os.close(descriptor)


def _read_secure_secret(path: Path, expected_length: int) -> bytearray:
    if os.geteuid() == 0:
        raise PairingPreparationError("refusing pairing-secret filesystem access as root")
    directory_descriptor = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    descriptor = -1
    secret = bytearray(expected_length)
    extra = bytearray(1)
    try:
        directory_info = os.fstat(directory_descriptor)
        if (
            directory_info.st_uid != os.geteuid()
            or stat.S_IMODE(directory_info.st_mode) != 0o700
        ):
            raise PairingPreparationError("pairing-secret directory ownership/mode is unsafe")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_descriptor,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PairingPreparationError("pairing secret is not a regular file")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise PairingPreparationError("pairing secret ownership/mode is unsafe")
        if info.st_size != expected_length:
            raise PairingPreparationError("pairing secret has an unexpected length")

        view = memoryview(secret)
        read_count = 0
        while read_count < len(view):
            count = os.readv(descriptor, [view[read_count:]])
            if count == 0:
                break
            read_count += count
        if read_count != expected_length or os.readv(descriptor, [extra]) != 0:
            raise PairingPreparationError("pairing secret read was incomplete")
    except Exception:
        secret[:] = b"\x00" * len(secret)
        raise
    finally:
        extra[:] = b"\x00"
        close_errors = []
        for open_descriptor in (descriptor, directory_descriptor):
            if open_descriptor >= 0:
                try:
                    os.close(open_descriptor)
                except Exception as error:
                    close_errors.append(error)
        if close_errors:
            secret[:] = b"\x00" * len(secret)
            raise PairingPreparationError("failed to close pairing-secret file") from close_errors[0]
    return secret


def prepare_pairing() -> dict[str, object]:
    """Create or idempotently verify local files; never access USB hardware."""
    disable_core_dumps()
    if os.geteuid() == 0:
        raise PairingPreparationError("run pairing preparation as the desktop user, not sudo")

    psk = bytearray()
    whitebox = bytearray()
    verification = bytearray()
    try:
        try:
            psk = _read_secure_secret(PSK_PATH, 32)
            key_source = "existing"
        except FileNotFoundError:
            psk = bytearray(32)
            _fill_random_secret(psk)
            key_source = "generated"

        wbdi_path = find_pinned_wbdi(PROJECT_ROOT)
        verify_known_vector(wbdi_path)
        whitebox = emulate_whitebox(psk, wbdi_path)
        verification = calculate_r_verification_record(psk)

        statuses = {
            "psk": _write_or_verify_secure_backup(PSK_PATH, psk),
            "whitebox_bb010003": _write_or_verify_secure_backup(
                WHITEBOX_PATH, whitebox
            ),
            "verification_bb020007": _write_or_verify_secure_backup(
                VERIFICATION_PATH, verification
            ),
        }
        return {
            "operation": "offline-only-no-usb",
            "key_source": key_source,
            "statuses": statuses,
            "lengths": {"psk": 32, "whitebox_bb010003": 96, "verification_bb020007": 32},
        }
    finally:
        psk[:] = b"\x00" * len(psk)
        whitebox[:] = b"\x00" * len(whitebox)
        verification[:] = b"\x00" * len(verification)


def main() -> None:
    print(json.dumps(prepare_pairing(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
