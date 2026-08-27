"""Fixed, gated observation of USB IN completions around Geneva WakeUp."""

from __future__ import annotations

import math
import threading
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
QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION: Final = (
    "OBSERVE-ONE-QUEUED-GENEVA-WAKE-A8-IN-MEMORY"
)
QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE: Final = False
OFFICIAL_GENEVA_A8_DIAGNOSTIC_CONFIRMATION: Final = (
    "OBSERVE-ONE-OFFICIAL-GENEVA-WAKE-A8-IN-MEMORY"
)
OFFICIAL_GENEVA_A8_DIAGNOSTIC_REVIEW_COMPLETE: Final = False
OFFICIAL_GENEVA_A8_REQUEST: Final = bytes.fromhex(
    "0a0a0a0aa80300000001" + "00" * 54
)
_MAX_TRANSFERS: Final = 8
_OBSERVATION_SECONDS: Final = 0.5
_QUEUED_OBSERVATION_SECONDS: Final = 3.250


class WakeDiagnosticError(RuntimeError):
    """Raised when a fixed wake observation cannot finish safely."""


def _write_official_geneva_a8(
    session: ReadOnlyUsbSession,
    timeout_ms: int,
) -> None:
    if timeout_ms <= 0:
        raise WakeDiagnosticError("official Geneva A8 timeout must be positive")
    written = session.endpoint_out.write(OFFICIAL_GENEVA_A8_REQUEST, timeout_ms)
    if written != len(OFFICIAL_GENEVA_A8_REQUEST):
        raise WakeDiagnosticError("official Geneva A8 was not fully written")


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


def _observe_one_queued_wake_a8(
    usb_timeout_seconds: float,
    *,
    official_transport: bool,
) -> dict[str, object]:
    """Queue one 32 KiB IN read before WakeUp and one fixed A8 transport."""
    disable_core_dumps()
    session: ReadOnlyUsbSession | None = None
    captured: list[bytearray] = []
    worker_errors: list[BaseException] = []
    worker_completed_at: list[float] = []
    captured_elapsed_ms: list[int] = []
    worker: threading.Thread | None = None
    try:
        session = ReadOnlyUsbSession(usb_timeout_seconds)
        _drop_sudo_privileges()
        disable_core_dumps()
        sequence_started = time.monotonic()
        deadline = sequence_started + _QUEUED_OBSERVATION_SECONDS
        wake_completed = sequence_started
        a8_started = sequence_started
        a8_completed = sequence_started
        entered_read = threading.Event()

        def receive_worker() -> None:
            try:
                while True:
                    remaining_ms = math.ceil((deadline - time.monotonic()) * 1000)
                    if remaining_ms <= 0:
                        return
                    entered_read.set()
                    try:
                        usb_buffer = session.endpoint_in.read(0x8000, timeout=remaining_ms)
                    except usb.core.USBTimeoutError:
                        return
                    try:
                        transfer = bytearray(usb_buffer)
                    finally:
                        memoryview(usb_buffer).cast("B")[:] = b"\x00" * len(usb_buffer)
                    if not transfer:
                        raise WakeDiagnosticError("bulk-IN completed with zero bytes")
                    if len(captured) == _MAX_TRANSFERS:
                        transfer[:] = b"\x00" * len(transfer)
                        raise WakeDiagnosticError("queued observation transfer capacity reached")
                    captured.append(transfer)
                    captured_elapsed_ms.append(
                        round((time.monotonic() - sequence_started) * 1000)
                    )
            except BaseException as error:
                worker_errors.append(error)
            finally:
                worker_completed_at.append(time.monotonic())

        worker = threading.Thread(
            target=receive_worker,
            name="goodix5503-one-queued-read",
            daemon=False,
        )
        worker.start()
        if not entered_read.wait(timeout=0.100):
            raise WakeDiagnosticError("queued USB reader did not reach its read call")
        # PyUSB has no submitted-URB acknowledgement; this bounded host-only
        # barrier reduces, but cannot eliminate, the call-site/submission race.
        time.sleep(0.025)
        if not worker.is_alive() or worker_errors:
            raise WakeDiagnosticError("queued USB reader stopped before wake")
        remaining_ms = math.ceil((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            raise WakeDiagnosticError("queued observation deadline expired before wake")
        session.wake_up(timeout_ms=remaining_ms)
        wake_completed = time.monotonic()
        if not worker.is_alive() or worker_errors:
            raise WakeDiagnosticError("queued USB reader stopped during wake")
        if deadline - wake_completed <= 0.050:
            raise WakeDiagnosticError("queued observation deadline cannot cover settle")
        time.sleep(0.050)
        if not worker.is_alive() or worker_errors:
            raise WakeDiagnosticError("queued USB reader stopped before A8")
        remaining_ms = math.ceil((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            raise WakeDiagnosticError("queued observation deadline expired before A8")
        a8_started = time.monotonic()
        if official_transport:
            _write_official_geneva_a8(session, remaining_ms)
        else:
            session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
                _encode_packet(COMMAND_FIRMWARE_VERSION),
                timeout_ms=remaining_ms,
            )
        a8_completed = time.monotonic()
        if a8_completed > deadline:
            raise WakeDiagnosticError("A8 write exceeded queued observation deadline")
        worker.join(timeout=max(0.0, deadline - time.monotonic()) + 0.250)
        if worker.is_alive():
            raise WakeDiagnosticError("queued USB reader did not stop after its deadline")
        if worker_errors:
            raise WakeDiagnosticError("queued USB reader failed") from worker_errors[0]
        if len(worker_completed_at) != 1:
            raise WakeDiagnosticError("queued USB reader completion was not recorded")
        if worker_completed_at[0] < deadline:
            raise WakeDiagnosticError("queued USB reader stopped before its deadline")
        return {
            "operation": (
                "runtime-only-memory-official-geneva-wake-a8-observation"
                if official_transport
                else "runtime-only-memory-geneva-queued-wake-a8-observation"
            ),
            "transfer_count": len(captured),
            "timing_ms": {
                "wake_completed": round((wake_completed - sequence_started) * 1000),
                "a8_started": round((a8_started - sequence_started) * 1000),
                "a8_completed": round((a8_completed - sequence_started) * 1000),
                "deadline": round(_QUEUED_OBSERVATION_SECONDS * 1000),
            },
            "transfers": [
                {
                    "elapsed": elapsed,
                    "length": len(transfer),
                    "hex": bytes(transfer).hex(),
                }
                for transfer, elapsed in zip(captured, captured_elapsed_ms, strict=True)
            ],
        }
    except ProtocolError as error:
        raise WakeDiagnosticError("fixed queued Geneva observation failed") from error
    finally:
        if worker is not None and worker.is_alive():
            worker.join()
        try:
            if session is not None:
                session.close()
        finally:
            for transfer in captured:
                transfer[:] = b"\x00" * len(transfer)


def observe_one_queued_wake_a8(
    confirmation: str | None = None,
    *,
    usb_timeout_seconds: float = 1.0,
) -> dict[str, object]:
    """Queue one 32 KiB IN read before WakeUp and one free outer A8."""
    if confirmation != QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION:
        raise WakeDiagnosticError("exact queued wake A8 confirmation is required")
    if not QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE:
        raise WakeDiagnosticError("queued wake A8 diagnostic review is not complete")
    return _observe_one_queued_wake_a8(
        usb_timeout_seconds,
        official_transport=False,
    )


def observe_one_official_geneva_a8(
    confirmation: str | None = None,
    *,
    usb_timeout_seconds: float = 1.0,
) -> dict[str, object]:
    """Observe the exact pinned Geneva-wrapped firmware A8 transaction once."""
    if confirmation != OFFICIAL_GENEVA_A8_DIAGNOSTIC_CONFIRMATION:
        raise WakeDiagnosticError("exact official Geneva A8 confirmation is required")
    if not OFFICIAL_GENEVA_A8_DIAGNOSTIC_REVIEW_COMPLETE:
        raise WakeDiagnosticError("official Geneva A8 diagnostic review is not complete")
    return _observe_one_queued_wake_a8(
        usb_timeout_seconds,
        official_transport=True,
    )


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
