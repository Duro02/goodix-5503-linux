"""Fixed experimental clear-frame acquisition path for the Goodix 5503."""

from __future__ import annotations

__test__ = False

import hmac
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from typing import Final

from .chip_config import _validate_config_checksum, build_runtime_config
from .hu_runtime import (
    build_hu_image_request,
    build_hu_manual_fdt_request,
    build_hu_nav_base,
    derive_hu_dac_field,
    gf3258_dn2_otp_integrity,
    hu_fdt_bases_within_delta,
    parse_hu_manual_fdt_response,
)
from .pairing import (
    PSK_PATH,
    VERIFICATION_PATH,
    _read_secure_secret,
    calculate_r_verification_record,
)
from .probe import (
    COMMAND_ACK,
    COMMAND_FIRMWARE_VERSION,
    FLAGS_MESSAGE_PROTOCOL,
    ProtocolError,
    ReadOnlyUsbSession,
    _check_ack,
    _decode_chip_id_register,
    _decode_c_string,
    _decode_packet,
    _disable_core_dumps,
    _drop_sudo_privileges,
    _encode_packet,
)
from .provision import EXPECTED_FIRMWARE, _read_live_verification
from .tls_check import (
    FLAGS_TLS,
    TlsTestError,
    _build_tls_context,
    _decode_outer,
    _preflight_tls_runtime,
    COMMAND_REQUEST_TLS,
    COMMAND_RESET,
    _receive_tls,
    _request_tls_client_hello,
    _reset_sensor,
    _send_tls,
)

COMMAND_COLD_PRECHECK: Final = 0x00
COMMAND_UPLOAD_CONFIG: Final = 0x90
COMMAND_SET_DRIVER_STATE: Final = 0xC4
COMMAND_POV_IMAGE_CHECK: Final = 0xD6
COMMAND_SWITCH_FDT_MODE: Final = 0x36
COMMAND_SWITCH_IDLE: Final = 0x70
COMMAND_READ_REGISTER: Final = 0x82
COMMAND_GET_IMAGE: Final = 0x20
FLAGS_TLS_IMAGE: Final = 0xB2

UPLOAD_CONFIG_LENGTH: Final = 256
PACKED_IMAGE_LENGTH: Final = 7680
PLAINTEXT_IMAGE_LENGTH: Final = 7684
PIXEL_COUNT: Final = 5120
IMAGE_WIDTH: Final = 80
IMAGE_HEIGHT: Final = 64
MAX_FRESH_BASE_ATTEMPTS: Final = 3
EXPECTED_CHIP_ID: Final = 0x220F


class ImageCaptureError(RuntimeError):
    """The fixed clear-frame path failed or returned malformed data."""


def _remaining_timeout_ms(operation_deadline: float | None) -> int | None:
    if operation_deadline is None:
        return None
    remaining = int((operation_deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise ImageCaptureError("capture operation deadline expired")
    return remaining


def _queued_frame_bounded(
    session: ReadOnlyUsbSession,
    operation_deadline: float | None,
    *,
    packet: bytes | None = None,
) -> bytes:
    """Queue one 32 KiB IN read before an optional fixed OUT, then parse it."""
    timeout_ms = _remaining_timeout_ms(operation_deadline)
    if timeout_ms is None:
        timeout_ms = getattr(session, "timeout_ms", 5000)
    timeout_ms = min(1500, timeout_ms)
    # Protocol-unit fakes intentionally have no USB endpoint. Real sessions
    # always take the queued path below.
    if not hasattr(session, "endpoint_in"):
        if packet is not None:
            session._ReadOnlyUsbSession__write_packet(packet)  # type: ignore[attr-defined]
        try:
            return session._read_frame(timeout_ms=timeout_ms)
        except TypeError as error:
            if "unexpected keyword argument" not in str(error):
                raise
            return session._read_frame()
    entered = threading.Event()
    captured: list[bytearray] = []
    errors: list[BaseException] = []

    def receive() -> None:
        entered.set()
        try:
            usb_buffer = session.endpoint_in.read(0x8000, timeout=timeout_ms)
            try:
                captured.append(bytearray(usb_buffer))
            finally:
                memoryview(usb_buffer).cast("B")[:] = b"\x00" * len(usb_buffer)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=receive, name="goodix5503-queued-in")
    worker.start()
    if not entered.wait(0.100):
        raise ImageCaptureError("queued USB reader did not start")
    write_error: BaseException | None = None
    if packet is not None:
        # PyUSB has no submit acknowledgement. The command-00 experiment proved
        # that this short barrier is sufficient to put the read ahead of OUT on
        # this host; it is transport ordering, not a protocol delay.
        time.sleep(0.025)
        try:
            session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
                packet
            )
        except BaseException as error:
            write_error = error
    join_seconds = timeout_ms / 1000 + 0.100
    worker.join(join_seconds)
    if worker.is_alive():
        raise ImageCaptureError("queued USB reader exceeded its bounded timeout")
    if write_error is not None:
        raise ImageCaptureError("queued USB write failed") from write_error
    if errors:
        raise ImageCaptureError("queued USB read failed") from errors[0]
    if len(captured) != 1 or not captured[0]:
        raise ImageCaptureError("queued USB read returned no transfer")
    transfer = captured[0]
    try:
        session._rx_buffer.extend(transfer)
    finally:
        transfer[:] = b"\x00" * len(transfer)
    return session._read_frame(timeout_ms=1)


def _read_frame_bounded(
    session: ReadOnlyUsbSession, operation_deadline: float | None
) -> bytes:
    return _queued_frame_bounded(session, operation_deadline)


def _write_and_read_frame_bounded(
    session: ReadOnlyUsbSession,
    packet: bytes,
    operation_deadline: float | None,
) -> bytes:
    return _queued_frame_bounded(session, operation_deadline, packet=packet)


def _ack_only(
    session: ReadOnlyUsbSession,
    command: int,
    payload: bytes,
    operation_deadline: float | None = None,
) -> None:
    ack = _decode_packet(
        _write_and_read_frame_bounded(
            session, _encode_packet(command, payload), operation_deadline
        ),
        COMMAND_ACK,
    )
    _check_ack(ack, command)


def _read_firmware_identity(
    session: ReadOnlyUsbSession,
    operation_deadline: float | None = None,
) -> str:
    _ack_only(
        session,
        COMMAND_COLD_PRECHECK,
        b"\x00\x00\x00\x00",
        operation_deadline,
    )
    return _decode_c_string(
        _fixed_exchange(
            session,
            COMMAND_FIRMWARE_VERSION,
            b"\x00\x00",
            operation_deadline,
        )
    )


def _milan_parse_other_body(body: bytes) -> bytes:
    """Return payload already stripped of the checksum by ``_decode_packet``."""
    # The DLL parser subtracts the trailing protocol checksum from its packet
    # length and copies from the unchanged payload pointer. Our decoder has
    # already validated and removed that checksum, so no payload byte is lost.
    return body


def _exchange_raw_command_body(
    session: ReadOnlyUsbSession,
    command: int,
    payload: bytes,
    operation_deadline: float | None = None,
) -> bytes:
    ack = _decode_packet(
        _write_and_read_frame_bounded(
            session, _encode_packet(command, payload), operation_deadline
        ),
        COMMAND_ACK,
    )
    _check_ack(ack, command)
    return _decode_packet(
        _read_frame_bounded(session, operation_deadline), command
    )


def _fixed_exchange(
    session: ReadOnlyUsbSession,
    command: int,
    payload: bytes,
    operation_deadline: float | None = None,
) -> bytes:
    body = _exchange_raw_command_body(
        session, command, payload, operation_deadline
    )
    return _milan_parse_other_body(body)


def _chip_config_exchange(
    session: ReadOnlyUsbSession,
    payload: bytes,
    operation_deadline: float,
) -> bytes:
    body = _exchange_raw_command_body(
        session, COMMAND_UPLOAD_CONFIG, payload, operation_deadline
    )
    # McuParseChipConfig removes the packet checksum at a lower layer. The
    # checksum-free payload returned by our decoder must remain intact.
    return body


def _read_chip_id_bounded(
    session: ReadOnlyUsbSession,
    operation_deadline: float,
) -> int:
    body = _exchange_raw_command_body(
        session,
        COMMAND_READ_REGISTER,
        b"\x00\x00\x00\x04\x00",
        operation_deadline,
    )
    return _decode_chip_id_register(body)


def _read_otp_bounded(
    session: ReadOnlyUsbSession,
    operation_deadline: float,
) -> bytearray:
    command = 0xA6
    ack = _decode_packet(
        _write_and_read_frame_bounded(
            session, _encode_packet(command, b"\x00\x00"), operation_deadline
        ),
        COMMAND_ACK,
    )
    _check_ack(ack, command)
    body = _decode_packet(
        _read_frame_bounded(session, operation_deadline), command
    )
    if len(body) != 64:
        raise ImageCaptureError("post-reset OTP response must be exactly 64 bytes")
    return bytearray(body)


def _read_register_exchange(
    session: ReadOnlyUsbSession,
    payload: bytes,
    operation_deadline: float,
) -> bytes:
    body = _exchange_raw_command_body(
        session, COMMAND_READ_REGISTER, payload, operation_deadline
    )
    # McuParseRegRw derives read/write from the separate command header (0x82),
    # which _decode_packet has already checked. Its payload is the register data.
    if len(body) != 2:
        raise ImageCaptureError("register-read response must be exactly 2 bytes")
    return body


def _validate_tls_records(ciphertext: bytes | bytearray) -> None:
    if not ciphertext:
        raise ImageCaptureError("image TLS ciphertext is empty")
    offset = 0
    while offset < len(ciphertext):
        if len(ciphertext) - offset < 5:
            raise ImageCaptureError("truncated image TLS record header")
        content_type = ciphertext[offset]
        version = ciphertext[offset + 1 : offset + 3]
        length = struct.unpack(">H", ciphertext[offset + 3 : offset + 5])[0]
        if content_type != 23 or version != b"\x03\x03":
            raise ImageCaptureError("unexpected image TLS record type or version")
        if length == 0 or length > 0x4000 + 2048:
            raise ImageCaptureError("invalid image TLS record length")
        offset += 5 + length
        if offset > len(ciphertext):
            raise ImageCaptureError("truncated image TLS record")
    if offset != len(ciphertext):
        raise ImageCaptureError("invalid image TLS record boundary")


def _request_encrypted_clear_image(
    session: ReadOnlyUsbSession,
    request_payload: bytes,
    operation_deadline: float | None = None,
) -> tuple[bytearray, bytearray]:
    if len(request_payload) != 10:
        raise ImageCaptureError("GF3258 HU image request must be exactly 10 bytes")
    ack = _decode_packet(
        _write_and_read_frame_bounded(
            session,
            _encode_packet(COMMAND_GET_IMAGE, request_payload),
            operation_deadline,
        ),
        COMMAND_ACK,
    )
    _check_ack(ack, COMMAND_GET_IMAGE)
    frame = _read_frame_bounded(session, operation_deadline)
    seen_tls_completion = False
    seen_image_prelude = False
    for _index in range(2):
        if frame[0] != FLAGS_MESSAGE_PROTOCOL:
            break
        if len(frame) < 5:
            raise ImageCaptureError("truncated image prelude")
        command = frame[4]
        if (
            command == COMMAND_REQUEST_TLS
            and not seen_tls_completion
            and not seen_image_prelude
        ):
            seen_tls_completion = True
            completion = _decode_packet(frame, command)
            # Official McuReqTlsConnection supplies no output buffer and waits
            # only for ACK. Its later A0 data is therefore an opaque completion,
            # not a command status byte. Bound and discard it after validation.
            if len(completion) > 16:
                raise ImageCaptureError("delayed TLS completion is too large")
        elif command == COMMAND_GET_IMAGE and not seen_image_prelude:
            seen_image_prelude = True
            prelude = _decode_packet(frame, command)
            if prelude != b"\x01":
                raise ImageCaptureError("image prelude did not report exact success")
        else:
            raise ImageCaptureError("unexpected or duplicate image prelude command")
        frame = _read_frame_bounded(session, operation_deadline)
    payload = _decode_outer(frame, FLAGS_TLS_IMAGE)
    if len(payload) <= 9:
        raise ImageCaptureError("encrypted image envelope is too short")
    opaque_prefix = bytearray(payload[:9])
    ciphertext = bytearray(payload[9:])
    try:
        _validate_tls_records(ciphertext)
        return opaque_prefix, ciphertext
    except BaseException:
        opaque_prefix[:] = b"\x00" * len(opaque_prefix)
        ciphertext[:] = b"\x00" * len(ciphertext)
        raise


def _validate_cold_pov_result(result: bytes) -> int:
    if len(result) > 1:
        raise ImageCaptureError("cold POV response exceeds one byte")
    discriminator = result[0] if result else 0
    # AA/DA/DF call McuStopTls in the pinned Start path and then rejoin the
    # common D0/config path. At this point the free path has no active host TLS
    # session, socket, thread or server, so it is already in that stopped state.
    return discriminator


def _validate_dn2_chip_id(chip_id: int) -> None:
    if chip_id != EXPECTED_CHIP_ID:
        raise ImageCaptureError(
            f"unexpected MCU chip ID 0x{chip_id:04x}; refusing DN2 sequence"
        )


def _validate_config_result(result: bytes) -> None:
    if not 1 <= len(result) <= 2 or result[0] != 1:
        raise ImageCaptureError("runtime configuration upload was rejected")


def _validate_prepared_config(config: bytes | bytearray) -> None:
    _validate_config_checksum(config)


def decode_packed_image(packed: bytes | bytearray | memoryview) -> bytearray:
    """Decode exactly 80x64 packed 12-bit pixels into little-endian uint16."""
    if len(packed) != PACKED_IMAGE_LENGTH:
        raise ValueError("packed image must be exactly 7680 bytes")
    pixels = bytearray(PIXEL_COUNT * 2)
    output = 0
    for offset in range(0, len(packed), 6):
        b0, b1, b2, b3, b4, b5 = packed[offset : offset + 6]
        values = (
            ((b0 & 0x0F) << 8) | b1,
            (b3 << 4) | (b0 >> 4),
            ((b5 & 0x0F) << 8) | b2,
            (b4 << 4) | (b5 >> 4),
        )
        for value in values:
            struct.pack_into("<H", pixels, output, value)
            output += 2
    return pixels




class _ResetGuard:
    """Remember a reset before transmission so ambiguous commits are cleaned up."""

    def __init__(self, session: ReadOnlyUsbSession):
        self.session = session
        self.attempted = False

    def start(self, operation_deadline: float | None = None) -> None:
        self.attempted = True
        if operation_deadline is None:
            _reset_sensor(self.session)
            return
        response = _exchange_raw_command_body(
            self.session,
            COMMAND_RESET,
            b"\x05\x14",
            operation_deadline,
        )
        if len(response) > 4:
            raise ProtocolError("sensor reset response exceeds four bytes")

    def cleanup(self) -> None:
        if self.attempted:
            _reset_sensor(self.session)


class _TlsImageServer:
    """Keep the reviewed local TLS socket alive for one application record set."""

    def __init__(self, context: ssl.SSLContext, operation_deadline: float):
        self.context = context
        self.operation_deadline = operation_deadline
        self.server_transport: socket.socket | None = None
        self.bridge: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.handshake_done = threading.Event()
        self.release = threading.Event()
        self.image_condition = threading.Condition()
        self.image_requests = 0
        self.handshake_result: list[str | BaseException] = []
        self.image_results: list[bytearray | BaseException] = []

    def _run(self) -> None:
        try:
            assert self.server_transport is not None
            with self.context.wrap_socket(
                self.server_transport, server_side=True
            ) as tls_socket:
                cipher = tls_socket.cipher()
                if cipher is None:
                    raise TlsTestError("TLS server negotiated no cipher")
                self.handshake_result.append(cipher[0])
                self.handshake_done.set()
                image_index = 0
                while not self.release.is_set():
                    with self.image_condition:
                        image_wait = max(
                            0.0, self.operation_deadline - time.monotonic()
                        )
                        ready = self.image_condition.wait_for(
                            lambda: self.release.is_set()
                            or self.image_requests > image_index,
                            image_wait,
                        )
                        if not ready or self.release.is_set():
                            return
                    plaintext = bytearray(PLAINTEXT_IMAGE_LENGTH)
                    surplus = bytearray(1)
                    received = 0
                    result: bytearray | BaseException
                    try:
                        view = memoryview(plaintext)
                        while received < len(plaintext):
                            remaining = self.operation_deadline - time.monotonic()
                            if remaining <= 0:
                                raise ImageCaptureError(
                                    "TLS image operation deadline expired"
                                )
                            tls_socket.settimeout(remaining)
                            count = tls_socket.recv_into(view[received:])
                            if not count:
                                raise ImageCaptureError(
                                    "TLS server closed during image transfer"
                                )
                            received += count
                        tls_socket.setblocking(False)
                        try:
                            extra = tls_socket.recv_into(surplus)
                        except (ssl.SSLWantReadError, BlockingIOError):
                            extra = 0
                        if extra:
                            raise ImageCaptureError(
                                "TLS image plaintext has surplus data"
                            )
                        result = plaintext
                        plaintext = bytearray()
                    except BaseException as error:
                        result = error
                    finally:
                        surplus[:] = b"\x00" * len(surplus)
                        plaintext[:] = b"\x00" * len(plaintext)
                    with self.image_condition:
                        if self.release.is_set():
                            if isinstance(result, bytearray):
                                result[:] = b"\x00" * len(result)
                            self.image_condition.notify_all()
                            return
                        self.image_results.append(result)
                        image_index += 1
                        self.image_condition.notify_all()
                    if isinstance(result, BaseException):
                        return
        except BaseException as error:
            if not self.handshake_done.is_set():
                self.handshake_result.append(error)
                self.handshake_done.set()
            else:
                with self.image_condition:
                    self.image_results.append(error)
                    self.image_condition.notify_all()

    def _set_bridge_deadline(self) -> None:
        if self.bridge is None:
            raise ImageCaptureError("TLS bridge is not established")
        remaining = self.operation_deadline - time.monotonic()
        if remaining <= 0:
            raise ImageCaptureError("TLS bridge operation deadline expired")
        self.bridge.settimeout(remaining)

    def establish(self, session: ReadOnlyUsbSession) -> str:
        self.server_transport, self.bridge = socket.socketpair()
        remaining = self.operation_deadline - time.monotonic()
        if remaining <= 0:
            raise ImageCaptureError("TLS handshake operation deadline expired")
        self.server_transport.settimeout(remaining)
        self.bridge.settimeout(remaining)
        self.thread = threading.Thread(
            target=self._run, name="goodix-clear-frame-tls", daemon=True
        )
        self.thread.start()
        self._set_bridge_deadline()
        self.bridge.sendall(
            _request_tls_client_hello(session, self.operation_deadline)
        )
        from .tls_check import _recv_server_flight

        _send_tls(
            session,
            _recv_server_flight(
                self.bridge,
                final=False,
                operation_deadline=self.operation_deadline,
            ),
        )
        for _index in range(3):
            self._set_bridge_deadline()
            self.bridge.sendall(_receive_tls(session, self.operation_deadline))
        _send_tls(
            session,
            _recv_server_flight(
                self.bridge,
                final=True,
                operation_deadline=self.operation_deadline,
            ),
        )
        handshake_wait = max(0.0, self.operation_deadline - time.monotonic())
        if not self.handshake_done.wait(handshake_wait) or not self.handshake_result:
            raise ImageCaptureError("TLS image server handshake timed out")
        result = self.handshake_result[0]
        if isinstance(result, BaseException):
            raise ImageCaptureError("TLS image server rejected device") from result
        return result

    def decrypt(self, ciphertext: bytearray) -> bytearray:
        if self.bridge is None:
            raise ImageCaptureError("TLS image server is not established")
        with self.image_condition:
            image_index = self.image_requests
            self.image_requests += 1
            self.image_condition.notify_all()
        self._set_bridge_deadline()
        self.bridge.sendall(ciphertext)
        with self.image_condition:
            image_wait = max(0.0, self.operation_deadline - time.monotonic())
            ready = self.image_condition.wait_for(
                lambda: len(self.image_results) > image_index,
                image_wait,
            )
            if not ready:
                raise ImageCaptureError("TLS image plaintext timed out")
            result = self.image_results[image_index]
        if isinstance(result, BaseException):
            raise ImageCaptureError("TLS image decryption failed") from result
        return result

    def close(self) -> None:
        self.release.set()
        with self.image_condition:
            self.image_condition.notify_all()
        if self.bridge is not None:
            self.bridge.close()
        if self.server_transport is not None:
            self.server_transport.close()
        if self.thread is not None and self.thread.ident is not None:
            # Socket closure interrupts any in-flight TLS read. Keep cleanup
            # bounded even when the operation deadline has already expired.
            self.thread.join(1.0)
        with self.image_condition:
            for result in self.image_results:
                if isinstance(result, bytearray):
                    result[:] = b"\x00" * len(result)
            self.image_results.clear()
        if self.thread is not None and self.thread.is_alive():
            raise ImageCaptureError("TLS image server thread did not stop")


def _receive_hu_plaintext_image(
    session: ReadOnlyUsbSession,
    tls_server: _TlsImageServer,
    image_request: bytes,
    operation_deadline: float,
) -> tuple[bytearray, bytearray]:
    prefix = bytearray()
    ciphertext = bytearray()
    plaintext = bytearray()
    try:
        prefix, ciphertext = _request_encrypted_clear_image(
            session, image_request, operation_deadline
        )
        plaintext = tls_server.decrypt(ciphertext)
        if len(plaintext) != PLAINTEXT_IMAGE_LENGTH:
            raise ImageCaptureError("decrypted HU image has an invalid length")
        result_prefix, result_plaintext = prefix, plaintext
        prefix = bytearray()
        plaintext = bytearray()
        return result_prefix, result_plaintext
    finally:
        prefix[:] = b"\x00" * len(prefix)
        ciphertext[:] = b"\x00" * len(ciphertext)
        plaintext[:] = b"\x00" * len(plaintext)


def _parse_hu_fdt_body(response: bytes) -> tuple[bytearray, bytearray]:
    try:
        return parse_hu_manual_fdt_response(response)
    except ValueError as error:
        raise ImageCaptureError(str(error)) from error


def _acquire_hu_fresh_base_frame(
    session: ReadOnlyUsbSession,
    tls_server: _TlsImageServer,
    dac_field: bytearray,
    image_request: bytes,
    operation_deadline: float,
) -> tuple[bytearray, bytearray]:
    zero_base = bytearray(12)
    try:
        fdt_request = build_hu_manual_fdt_request(dac_field, zero_base)
        for _attempt in range(MAX_FRESH_BASE_ATTEMPTS):
            _remaining_timeout_ms(operation_deadline)
            raw0 = transformed0 = raw1 = transformed1 = bytearray()
            raw2 = transformed2 = bytearray()
            nav_prefix = nav_plaintext = bytearray()
            nav_decoded = nav_base = bytearray()
            candidate_prefix = candidate_plaintext = bytearray()
            keep_candidate = False
            try:
                response0 = _fixed_exchange(
                    session,
                    COMMAND_SWITCH_FDT_MODE,
                    fdt_request,
                    operation_deadline,
                )
                raw0, transformed0 = _parse_hu_fdt_body(response0)
                nav_prefix, nav_plaintext = _receive_hu_plaintext_image(
                    session, tls_server, image_request, operation_deadline
                )
                nav_decoded = decode_packed_image(
                    memoryview(nav_plaintext)[:PACKED_IMAGE_LENGTH]
                )
                nav_base = build_hu_nav_base(nav_decoded)
                response1 = _fixed_exchange(
                    session,
                    COMMAND_SWITCH_FDT_MODE,
                    fdt_request,
                    operation_deadline,
                )
                raw1, transformed1 = _parse_hu_fdt_body(response1)
                _ack_only(
                    session,
                    COMMAND_SWITCH_IDLE,
                    b"\x14\x00",
                    operation_deadline,
                )
                delta_body = _read_register_exchange(
                    session,
                    b"\x00\x82\x00\x02\x00",
                    operation_deadline,
                )
                if len(delta_body) != 2:
                    raise ImageCaptureError(
                        "FDT delta register response must be exactly 2 bytes"
                    )
                delta = struct.unpack("<H", delta_body)[0] >> 8
                if not hu_fdt_bases_within_delta(raw0, raw1, delta):
                    continue

                candidate_prefix, candidate_plaintext = (
                    _receive_hu_plaintext_image(
                        session, tls_server, image_request, operation_deadline
                    )
                )
                response2 = _fixed_exchange(
                    session,
                    COMMAND_SWITCH_FDT_MODE,
                    fdt_request,
                    operation_deadline,
                )
                raw2, transformed2 = _parse_hu_fdt_body(response2)
                if not hu_fdt_bases_within_delta(raw1, raw2, delta):
                    continue
                keep_candidate = True
                return candidate_prefix, candidate_plaintext
            finally:
                for buffer in (
                    raw0,
                    transformed0,
                    raw1,
                    transformed1,
                    raw2,
                    transformed2,
                    nav_prefix,
                    nav_plaintext,
                    nav_decoded,
                    nav_base,
                ):
                    buffer[:] = b"\x00" * len(buffer)
                if not keep_candidate:
                    candidate_prefix[:] = b"\x00" * len(candidate_prefix)
                    candidate_plaintext[:] = b"\x00" * len(candidate_plaintext)
        raise ImageCaptureError("fresh FDT base did not stabilize")
    finally:
        zero_base[:] = b"\x00" * len(zero_base)


def run_prepared_clear_frame_capture(
    timeout_seconds: float = 5.0,
) -> dict[str, int | str]:
    """Capture one experimental memory-only frame using fixed commands."""
    _disable_core_dumps()
    _preflight_tls_runtime()
    session: ReadOnlyUsbSession | None = None
    tls_server: _TlsImageServer | None = None
    live = bytearray()
    expected = bytearray()
    derived = bytearray()
    psk = bytearray()
    config = bytearray()
    otp = bytearray()
    dac_field = bytearray()
    image_request = b""
    opaque_prefix = bytearray()
    plaintext = bytearray()
    opaque_trailer = bytearray()
    pixels = bytearray()
    reset_guard: _ResetGuard | None = None
    try:
        session = ReadOnlyUsbSession(timeout_seconds)
        reset_guard = _ResetGuard(session)
        operation_deadline = time.monotonic() + min(
            120.0, max(30.0, timeout_seconds * 8)
        )
        # The pinned Windows USB trace starts directly with command 00. Although
        # Geneva exposes a raw-wake method, no e5 OUT precedes this runtime path.
        firmware = _read_firmware_identity(session, operation_deadline)
        if firmware != EXPECTED_FIRMWARE:
            raise ImageCaptureError("unexpected firmware")
        live = _read_live_verification(session)

        _drop_sudo_privileges()
        _disable_core_dumps()
        if os.geteuid() == 0:
            raise ImageCaptureError("refusing local pairing/config access as root")
        expected = _read_secure_secret(VERIFICATION_PATH, 32)
        psk = _read_secure_secret(PSK_PATH, 32)
        derived = calculate_r_verification_record(psk)
        if not hmac.compare_digest(expected, derived):
            raise ImageCaptureError("saved PSK verification record is inconsistent")
        if not hmac.compare_digest(live, derived):
            raise ImageCaptureError("device PSK does not match prepared PSK")
        context = _build_tls_context(psk)

        reset_guard.start(operation_deadline)
        time.sleep(0.010)
        chip_id = _read_chip_id_bounded(session, operation_deadline)
        _validate_dn2_chip_id(chip_id)
        _ack_only(
            session,
            COMMAND_COLD_PRECHECK,
            b"\x00\x00\x00\x00",
            operation_deadline,
        )
        otp = _read_otp_bounded(session, operation_deadline)
        if not gf3258_dn2_otp_integrity(otp):
            raise ImageCaptureError("post-reset OTP failed DN2 integrity checks")
        dac_field = derive_hu_dac_field(otp)
        image_request = build_hu_image_request(dac_field)
        config = build_runtime_config(otp)
        _validate_prepared_config(config)
        otp[:] = b"\x00" * len(otp)
        pov_result = _fixed_exchange(
            session,
            COMMAND_POV_IMAGE_CHECK,
            b"\x00\x00",
            operation_deadline,
        )
        _validate_cold_pov_result(pov_result)

        tls_server = _TlsImageServer(context, operation_deadline)
        cipher = tls_server.establish(session)
        config_result = _chip_config_exchange(
            session,
            bytes(config),
            operation_deadline,
        )
        _validate_config_result(config_result)
        _ack_only(
            session,
            COMMAND_SET_DRIVER_STATE,
            b"\x01\x00",
            operation_deadline,
        )

        opaque_prefix, plaintext = _acquire_hu_fresh_base_frame(
            session,
            tls_server,
            dac_field,
            image_request,
            operation_deadline,
        )
        opaque_trailer = bytearray(memoryview(plaintext)[PACKED_IMAGE_LENGTH:])
        if len(opaque_prefix) != 9 or len(opaque_trailer) != 4:
            raise ImageCaptureError("image opaque metadata has an invalid length")
        pixels = decode_packed_image(memoryview(plaintext)[:PACKED_IMAGE_LENGTH])
        return {
            "operation": "runtime-only-memory-clear-frame",
            "firmware": firmware,
            "tls": "established",
            "cipher": cipher,
            "width": IMAGE_WIDTH,
            "height": IMAGE_HEIGHT,
            "packed_length": PACKED_IMAGE_LENGTH,
            "opaque_prefix_length": len(opaque_prefix),
            "opaque_trailer_length": len(opaque_trailer),
        }
    finally:
        had_primary_error = sys.exc_info()[0] is not None
        primary_cleanup_error: BaseException | None = None
        if tls_server is not None:
            try:
                tls_server.close()
            except BaseException as error:
                primary_cleanup_error = error
        if reset_guard is not None and reset_guard.attempted:
            try:
                reset_guard.cleanup()
            except BaseException as error:
                if primary_cleanup_error is None:
                    primary_cleanup_error = error
        if session is not None:
            try:
                session.close()
            except BaseException as error:
                if primary_cleanup_error is None:
                    primary_cleanup_error = error
        for buffer in (
            live,
            expected,
            derived,
            psk,
            config,
            otp,
            dac_field,
            opaque_prefix,
            plaintext,
            opaque_trailer,
            pixels,
        ):
            buffer[:] = b"\x00" * len(buffer)
        if primary_cleanup_error is not None and not had_primary_error:
            raise ImageCaptureError("clear-frame cleanup failed") from primary_cleanup_error


def main() -> int:
    print(json.dumps(run_prepared_clear_frame_capture(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
