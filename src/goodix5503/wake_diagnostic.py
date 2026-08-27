"""Fixed, gated observation of USB IN completions around Geneva WakeUp."""

from __future__ import annotations

import math
import time
from typing import Final

import usb.core

from .probe import (
    COMMAND_FIRMWARE_VERSION,
    ProtocolError,
    ReadOnlyUsbSession,
    _drop_sudo_privileges,
    _encode_packet,
)
from .security import disable_core_dumps

WAKE_DIAGNOSTIC_CONFIRMATION: Final = "OBSERVE-ONE-GENEVA-WAKE-IN-MEMORY"
WAKE_DIAGNOSTIC_REVIEW_COMPLETE: Final = False
WAKE_A8_DIAGNOSTIC_CONFIRMATION: Final = "OBSERVE-ONE-GENEVA-WAKE-A8-IN-MEMORY"
WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE: Final = False
_MAX_TRANSFERS: Final = 8
_OBSERVATION_SECONDS: Final = 0.5


class WakeDiagnosticError(RuntimeError):
    """Raised when a fixed wake observation cannot finish safely."""


def _observe_fixed_wake(
    usb_timeout_seconds: float,
    *,
    send_firmware_request: bool,
) -> dict[str, object]:
    disable_core_dumps()
    session: ReadOnlyUsbSession | None = None
    captured: list[bytearray] = []
    try:
        session = ReadOnlyUsbSession(usb_timeout_seconds)
        _drop_sudo_privileges()
        disable_core_dumps()
        session.wake_up(timeout_ms=max(1, int(usb_timeout_seconds * 1000)))
        time.sleep(0.050)
        if send_firmware_request:
            session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
                _encode_packet(COMMAND_FIRMWARE_VERSION)
            )
        deadline = time.monotonic() + _OBSERVATION_SECONDS
        while True:
            remaining_ms = math.ceil((deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                break
            try:
                usb_buffer = session.endpoint_in.read(
                    session._max_packet_size,
                    timeout=remaining_ms,
                )
            except usb.core.USBTimeoutError:
                break
            try:
                transfer = bytearray(usb_buffer)
            finally:
                memoryview(usb_buffer).cast("B")[:] = b"\x00" * len(usb_buffer)
            if not transfer:
                raise WakeDiagnosticError("bulk-IN completed with zero bytes")
            if len(captured) == _MAX_TRANSFERS:
                transfer[:] = b"\x00" * len(transfer)
                raise WakeDiagnosticError("wake observation transfer capacity reached")
            captured.append(transfer)
        return {
            "operation": (
                "runtime-only-memory-geneva-wake-a8-observation"
                if send_firmware_request
                else "runtime-only-memory-geneva-wake-observation"
            ),
            "transfer_count": len(captured),
            "transfers": [
                {"length": len(transfer), "hex": bytes(transfer).hex()}
                for transfer in captured
            ],
        }
    except ProtocolError as error:
        raise WakeDiagnosticError("fixed Geneva observation failed") from error
    finally:
        try:
            if session is not None:
                session.close()
        finally:
            for transfer in captured:
                transfer[:] = b"\x00" * len(transfer)


def observe_one_wake(
    confirmation: str | None = None,
    *,
    usb_timeout_seconds: float = 1.0,
) -> dict[str, object]:
    """Observe complete post-wake bulk-IN transfers without sending a command."""
    if confirmation != WAKE_DIAGNOSTIC_CONFIRMATION:
        raise WakeDiagnosticError("exact wake diagnostic confirmation is required")
    if not WAKE_DIAGNOSTIC_REVIEW_COMPLETE:
        raise WakeDiagnosticError("wake diagnostic review is not complete")
    return _observe_fixed_wake(usb_timeout_seconds, send_firmware_request=False)


def observe_one_wake_a8(
    confirmation: str | None = None,
    *,
    usb_timeout_seconds: float = 1.0,
) -> dict[str, object]:
    """Observe raw completions after exact WakeUp and one read-only A8 request."""
    if confirmation != WAKE_A8_DIAGNOSTIC_CONFIRMATION:
        raise WakeDiagnosticError("exact wake A8 diagnostic confirmation is required")
    if not WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE:
        raise WakeDiagnosticError("wake A8 diagnostic review is not complete")
    return _observe_fixed_wake(usb_timeout_seconds, send_firmware_request=True)
