"""Fixed, gated observation of USB IN completions caused by Geneva WakeUp."""

from __future__ import annotations

import math
import time
from typing import Final

import usb.core

from .probe import ProtocolError, ReadOnlyUsbSession, _drop_sudo_privileges
from .security import disable_core_dumps

WAKE_DIAGNOSTIC_CONFIRMATION: Final = "OBSERVE-ONE-GENEVA-WAKE-IN-MEMORY"
WAKE_DIAGNOSTIC_REVIEW_COMPLETE: Final = False
_MAX_TRANSFERS: Final = 8
_OBSERVATION_SECONDS: Final = 0.5


class WakeDiagnosticError(RuntimeError):
    """Raised when the fixed wake observation cannot finish safely."""


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
    disable_core_dumps()
    session: ReadOnlyUsbSession | None = None
    captured: list[bytearray] = []
    try:
        session = ReadOnlyUsbSession(usb_timeout_seconds)
        _drop_sudo_privileges()
        disable_core_dumps()
        session.wake_up(timeout_ms=max(1, int(usb_timeout_seconds * 1000)))
        time.sleep(0.050)
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
            "operation": "runtime-only-memory-geneva-wake-observation",
            "transfer_count": len(captured),
            "transfers": [
                {"length": len(transfer), "hex": bytes(transfer).hex()}
                for transfer in captured
            ],
        }
    except ProtocolError as error:
        raise WakeDiagnosticError("fixed Geneva wake failed") from error
    finally:
        try:
            if session is not None:
                session.close()
        finally:
            for transfer in captured:
                transfer[:] = b"\x00" * len(transfer)
