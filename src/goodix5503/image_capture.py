"""Review-gated, fixed clear-frame acquisition path for the Goodix 5503."""

from __future__ import annotations

__test__ = False

import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Final

from .chip_config import (
    LOCAL_RUNTIME_CONFIG_SHA256,
    RUNTIME_CONFIG_PATH,
    _validate_config_checksum,
)
from .hu_runtime import (
    build_hu_image_request,
    build_hu_manual_fdt_request,
    build_hu_nav_base,
    derive_hu_dac_field,
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
    COMMAND_GET_IAP_VERSION,
    COMMAND_NOP,
    FLAGS_MESSAGE_PROTOCOL,
    ProtocolError,
    ReadOnlyUsbSession,
    _check_ack,
    _decode_c_string,
    _decode_packet,
    _disable_core_dumps,
    _drop_sudo_privileges,
    _encode_packet,
)
from .provision import EXPECTED_FIRMWARE, EXPECTED_IAP, _read_live_verification
from .tls_check import (
    FLAGS_TLS,
    TlsTestError,
    _build_tls_context,
    _decode_outer,
    _preflight_tls_runtime,
    COMMAND_REQUEST_TLS,
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
EXPECTED_RUNTIME_CONFIG_SHA256: Final = LOCAL_RUNTIME_CONFIG_SHA256
CLEAR_CAPTURE_CONFIRMATION: Final = (
    "I AUTHORIZE ONE RUNTIME-ONLY MEMORY CLEAR FRAME"
)
# The pinned GF3258 cold/base call graph is still being reconstructed. Keep the
# former community-derived candidate unreachable even with confirmation.
OFFICIAL_SEQUENCE_RECONSTRUCTION_COMPLETE: Final = False

class ImageCaptureError(RuntimeError):
    """The fixed clear-frame path failed or returned malformed data."""


def _remaining_timeout_ms(operation_deadline: float | None) -> int | None:
    if operation_deadline is None:
        return None
    remaining = int((operation_deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise ImageCaptureError("capture operation deadline expired")
    return remaining


def _read_frame_bounded(
    session: ReadOnlyUsbSession, operation_deadline: float | None
) -> bytes:
    timeout_ms = _remaining_timeout_ms(operation_deadline)
    if timeout_ms is None:
        return session._read_frame()
    return session._read_frame(timeout_ms=timeout_ms)


def _ack_only(
    session: ReadOnlyUsbSession,
    command: int,
    payload: bytes,
    operation_deadline: float | None = None,
) -> None:
    session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
        _encode_packet(command, payload)
    )
    ack = _decode_packet(
        _read_frame_bounded(session, operation_deadline), COMMAND_ACK
    )
    _check_ack(ack, command)


def _milan_parse_other_body(body: bytes) -> bytes:
    """Reproduce Milan McuParseOther's one-byte result-prefix removal."""
    if len(body) < 1:
        raise ImageCaptureError("Milan command response has no result prefix")
    return body[1:]


def _fixed_exchange(
    session: ReadOnlyUsbSession,
    command: int,
    payload: bytes,
    operation_deadline: float | None = None,
) -> bytes:
    session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
        _encode_packet(command, payload)
    )
    ack = _decode_packet(
        _read_frame_bounded(session, operation_deadline), COMMAND_ACK
    )
    _check_ack(ack, command)
    body = _decode_packet(
        _read_frame_bounded(session, operation_deadline), command
    )
    return _milan_parse_other_body(body)


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
    session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
        _encode_packet(COMMAND_GET_IMAGE, request_payload)
    )
    ack = _decode_packet(
        _read_frame_bounded(session, operation_deadline), COMMAND_ACK
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
            if not prelude or prelude[0] != 1:
                raise ImageCaptureError("image prelude did not report success")
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


def _validate_cold_pov_result(result: bytes) -> None:
    if len(result) != 1:
        raise ImageCaptureError("cold POV response must be exactly one byte")
    if result[0] in (0xAA, 0xDA, 0xDF):
        raise ImageCaptureError("unsupported resume/reconnect POV state")


def _validate_config_result(result: bytes) -> None:
    if not 1 <= len(result) <= 2 or result[0] != 1:
        raise ImageCaptureError("runtime configuration upload was rejected")


def _validate_prepared_config(config: bytes | bytearray) -> None:
    _validate_config_checksum(config)
    if not hmac.compare_digest(
        hashlib.sha256(config).hexdigest(), EXPECTED_RUNTIME_CONFIG_SHA256
    ):
        raise ImageCaptureError("runtime configuration is not the prepared OTP-derived value")


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


def _pixel_metrics(pixels: bytearray) -> dict[str, int]:
    if len(pixels) != PIXEL_COUNT * 2:
        raise ValueError("decoded image has an invalid length")
    minimum = 0xFFFF
    maximum = 0
    total = 0
    for offset in range(0, len(pixels), 2):
        value = pixels[offset] | (pixels[offset + 1] << 8)
        minimum = min(minimum, value)
        maximum = max(maximum, value)
        total += value
    return {"pixel_min": minimum, "pixel_max": maximum, "pixel_sum": total}


class _ResetGuard:
    """Remember a reset before transmission so ambiguous commits are cleaned up."""

    def __init__(self, session: ReadOnlyUsbSession):
        self.session = session
        self.attempted = False

    def start(self) -> None:
        self.attempted = True
        _reset_sensor(self.session)

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
) -> tuple[bytearray, bytearray, tuple[int, ...]]:
    zero_base = bytearray(12)
    fdt_response_lengths: list[int] = []
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
                fdt_response_lengths.append(len(response0))
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
                fdt_response_lengths.append(len(response1))
                raw1, transformed1 = _parse_hu_fdt_body(response1)
                _ack_only(
                    session,
                    COMMAND_SWITCH_IDLE,
                    b"\x14\x00",
                    operation_deadline,
                )
                delta_body = _fixed_exchange(
                    session,
                    COMMAND_READ_REGISTER,
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
                fdt_response_lengths.append(len(response2))
                raw2, transformed2 = _parse_hu_fdt_body(response2)
                if not hu_fdt_bases_within_delta(raw1, raw2, delta):
                    continue
                keep_candidate = True
                return (
                    candidate_prefix,
                    candidate_plaintext,
                    tuple(fdt_response_lengths),
                )
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
    confirmation: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, int | str]:
    """Capture one memory-only clear frame using only reviewed fixed commands."""
    if confirmation != CLEAR_CAPTURE_CONFIRMATION:
        raise ImageCaptureError("exact clear-frame hardware confirmation is required")
    if not OFFICIAL_SEQUENCE_RECONSTRUCTION_COMPLETE:
        raise ImageCaptureError("official GF3258 capture sequence is not complete")
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
        session.request(COMMAND_NOP, checksum=False)
        firmware = _decode_c_string(session.request(COMMAND_FIRMWARE_VERSION))
        iap = _decode_c_string(session.request(COMMAND_GET_IAP_VERSION, b"\x19\x00"))
        if firmware != EXPECTED_FIRMWARE or iap != EXPECTED_IAP:
            raise ImageCaptureError("unexpected firmware or IAP")
        live = _read_live_verification(session)
        otp = session.read_otp()
        dac_field = derive_hu_dac_field(otp)
        image_request = build_hu_image_request(dac_field)
        otp[:] = b"\x00" * len(otp)

        _drop_sudo_privileges()
        _disable_core_dumps()
        if os.geteuid() == 0:
            raise ImageCaptureError("refusing local pairing/config access as root")
        expected = _read_secure_secret(VERIFICATION_PATH, 32)
        psk = _read_secure_secret(PSK_PATH, 32)
        config = _read_secure_secret(Path(RUNTIME_CONFIG_PATH), UPLOAD_CONFIG_LENGTH)
        _validate_prepared_config(config)
        derived = calculate_r_verification_record(psk)
        if not hmac.compare_digest(expected, derived):
            raise ImageCaptureError("saved PSK verification record is inconsistent")
        if not hmac.compare_digest(live, derived):
            raise ImageCaptureError("device PSK does not match prepared PSK")
        context = _build_tls_context(psk)
        operation_deadline = time.monotonic() + min(
            120.0, max(30.0, timeout_seconds * 8)
        )

        reset_guard.start()
        _ack_only(
            session,
            COMMAND_COLD_PRECHECK,
            b"\x00\x00\x00\x00",
            operation_deadline,
        )
        pov_result = _fixed_exchange(
            session,
            COMMAND_POV_IMAGE_CHECK,
            b"\x00\x00",
            operation_deadline,
        )
        _validate_cold_pov_result(pov_result)

        tls_server = _TlsImageServer(context, operation_deadline)
        cipher = tls_server.establish(session)
        config_result = _fixed_exchange(
            session,
            COMMAND_UPLOAD_CONFIG,
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

        opaque_prefix, plaintext, fdt_response_lengths = _acquire_hu_fresh_base_frame(
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
        metrics = _pixel_metrics(pixels)
        return {
            "operation": "runtime-only-memory-clear-frame",
            "firmware": firmware,
            "iap": iap,
            "tls": "established",
            "cipher": cipher,
            "width": IMAGE_WIDTH,
            "height": IMAGE_HEIGHT,
            "packed_length": PACKED_IMAGE_LENGTH,
            "opaque_prefix_length": len(opaque_prefix),
            "opaque_trailer_length": len(opaque_trailer),
            "fdt_response_lengths": ",".join(
                str(length) for length in fdt_response_lengths
            ),
            **metrics,
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
