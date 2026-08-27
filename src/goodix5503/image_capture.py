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
from pathlib import Path
from typing import Final

from .chip_config import (
    LOCAL_RUNTIME_CONFIG_SHA256,
    RUNTIME_CONFIG_PATH,
    _validate_config_checksum,
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

COMMAND_UPLOAD_CONFIG: Final = 0x90
COMMAND_SET_DRIVER_STATE: Final = 0xC4
COMMAND_GET_POV_IMAGE: Final = 0xD2
COMMAND_POV_IMAGE_CHECK: Final = 0xD6
COMMAND_SWITCH_FDT_MODE: Final = 0x36
COMMAND_GET_IMAGE: Final = 0x20
FLAGS_TLS_IMAGE: Final = 0xB2

UPLOAD_CONFIG_LENGTH: Final = 256
PACKED_IMAGE_LENGTH: Final = 7680
PLAINTEXT_IMAGE_LENGTH: Final = 7684
PIXEL_COUNT: Final = 5120
IMAGE_WIDTH: Final = 80
IMAGE_HEIGHT: Final = 64
EXPECTED_RUNTIME_CONFIG_SHA256: Final = LOCAL_RUNTIME_CONFIG_SHA256
CLEAR_CAPTURE_CONFIRMATION: Final = (
    "I AUTHORIZE ONE RUNTIME-ONLY MEMORY CLEAR FRAME"
)

FDT_CLEAR_MODE: Final = bytes.fromhex(
    "0d018b0084008c0088008096809180928085808c8086"
)
GET_IMAGE_CLEAR: Final = bytes.fromhex("01008b0084008c008800")


class ImageCaptureError(RuntimeError):
    """The fixed clear-frame path failed or returned malformed data."""


def _ack_only(session: ReadOnlyUsbSession, command: int, payload: bytes) -> None:
    session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
        _encode_packet(command, payload)
    )
    ack = _decode_packet(session._read_frame(), COMMAND_ACK)
    _check_ack(ack, command)


def _fixed_exchange(
    session: ReadOnlyUsbSession, command: int, payload: bytes
) -> bytes:
    return session._ReadOnlyUsbSession__exchange(  # type: ignore[attr-defined]
        command, payload
    )


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
) -> tuple[bytearray, bytearray]:
    session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
        _encode_packet(COMMAND_GET_IMAGE, GET_IMAGE_CLEAR)
    )
    ack = _decode_packet(session._read_frame(), COMMAND_ACK)
    _check_ack(ack, COMMAND_GET_IMAGE)
    frame = session._read_frame()
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
        frame = session._read_frame()
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

    def __init__(self, context: ssl.SSLContext):
        self.context = context
        self.server_transport: socket.socket | None = None
        self.bridge: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.handshake_done = threading.Event()
        self.image_requested = threading.Event()
        self.image_done = threading.Event()
        self.release = threading.Event()
        self.handshake_result: list[str | BaseException] = []
        self.image_result: list[bytearray | BaseException] = []

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
                if not self.image_requested.wait(10):
                    return
                plaintext = bytearray(PLAINTEXT_IMAGE_LENGTH)
                surplus = bytearray(1)
                received = 0
                try:
                    view = memoryview(plaintext)
                    while received < len(plaintext):
                        count = tls_socket.recv_into(view[received:])
                        if not count:
                            raise ImageCaptureError(
                                "TLS server closed during image transfer"
                            )
                        received += count
                    # The caller has sent the complete validated ciphertext
                    # envelope. A nonblocking read therefore establishes the
                    # application-data boundary without waiting for more USB.
                    tls_socket.setblocking(False)
                    try:
                        extra = tls_socket.recv_into(surplus)
                    except (ssl.SSLWantReadError, BlockingIOError):
                        extra = 0
                    if extra:
                        raise ImageCaptureError("TLS image plaintext has surplus data")
                    self.image_result.append(plaintext)
                    plaintext = bytearray()
                finally:
                    surplus[:] = b"\x00" * len(surplus)
                    plaintext[:] = b"\x00" * len(plaintext)
                    self.image_done.set()
                self.release.wait(5)
        except BaseException as error:
            if not self.handshake_done.is_set():
                self.handshake_result.append(error)
                self.handshake_done.set()
            else:
                self.image_result.append(error)
                self.image_done.set()

    def establish(self, session: ReadOnlyUsbSession) -> str:
        self.server_transport, self.bridge = socket.socketpair()
        self.server_transport.settimeout(5)
        self.bridge.settimeout(5)
        self.thread = threading.Thread(
            target=self._run, name="goodix-clear-frame-tls", daemon=True
        )
        self.thread.start()
        self.bridge.sendall(_request_tls_client_hello(session))
        from .tls_check import _recv_server_flight

        _send_tls(session, _recv_server_flight(self.bridge, final=False))
        for _index in range(3):
            self.bridge.sendall(_receive_tls(session))
        _send_tls(session, _recv_server_flight(self.bridge, final=True))
        if not self.handshake_done.wait(5) or not self.handshake_result:
            raise ImageCaptureError("TLS image server handshake timed out")
        result = self.handshake_result[0]
        if isinstance(result, BaseException):
            raise ImageCaptureError("TLS image server rejected device") from result
        return result

    def decrypt(self, ciphertext: bytearray) -> bytearray:
        if self.bridge is None:
            raise ImageCaptureError("TLS image server is not established")
        self.image_requested.set()
        self.bridge.sendall(ciphertext)
        if not self.image_done.wait(10) or not self.image_result:
            raise ImageCaptureError("TLS image plaintext timed out")
        result = self.image_result[0]
        if isinstance(result, BaseException):
            raise ImageCaptureError("TLS image decryption failed") from result
        return result

    def close(self) -> None:
        self.release.set()
        # Wake a server that completed TLS but whose caller failed before the
        # image request; closing the bridge then makes its bounded recv exit.
        self.image_requested.set()
        if self.bridge is not None:
            self.bridge.close()
        if self.server_transport is not None and (
            self.thread is None or not self.thread.is_alive()
        ):
            self.server_transport.close()
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(6)
        if self.thread is not None and self.thread.is_alive():
            raise ImageCaptureError("TLS image server thread did not stop")


def run_prepared_clear_frame_capture(
    confirmation: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, int | str]:
    """Capture one memory-only clear frame using only reviewed fixed commands."""
    if confirmation != CLEAR_CAPTURE_CONFIRMATION:
        raise ImageCaptureError("exact clear-frame hardware confirmation is required")
    _disable_core_dumps()
    _preflight_tls_runtime()
    session: ReadOnlyUsbSession | None = None
    tls_server: _TlsImageServer | None = None
    live = bytearray()
    expected = bytearray()
    derived = bytearray()
    psk = bytearray()
    config = bytearray()
    opaque_prefix = bytearray()
    ciphertext = bytearray()
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

        reset_guard.start()
        pov = _fixed_exchange(session, COMMAND_POV_IMAGE_CHECK, b"\x00\x00")
        if not pov:
            raise ImageCaptureError("POV check returned an empty response")

        tls_server = _TlsImageServer(context)
        cipher = tls_server.establish(session)
        uploaded = _fixed_exchange(session, COMMAND_UPLOAD_CONFIG, bytes(config))
        if not uploaded or uploaded[0] != 1:
            raise ImageCaptureError("runtime configuration upload was rejected")
        _ack_only(session, COMMAND_SET_DRIVER_STATE, b"\x01\x00")
        _ack_only(session, COMMAND_SET_DRIVER_STATE, b"\x01\x00")
        pov_image = _fixed_exchange(session, COMMAND_GET_POV_IMAGE, b"\x00\x00")
        if not pov_image:
            raise ImageCaptureError("MCU POV-image initialization returned empty data")
        _fixed_exchange(session, COMMAND_SWITCH_FDT_MODE, FDT_CLEAR_MODE)

        opaque_prefix, ciphertext = _request_encrypted_clear_image(session)
        plaintext = tls_server.decrypt(ciphertext)
        if len(plaintext) != PLAINTEXT_IMAGE_LENGTH:
            raise ImageCaptureError("decrypted clear image has an invalid length")
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
            opaque_prefix,
            ciphertext,
            plaintext,
            opaque_trailer,
            pixels,
        ):
            buffer[:] = b"\x00" * len(buffer)
        if primary_cleanup_error is not None and not had_primary_error:
            raise ImageCaptureError("clear-frame cleanup failed") from primary_cleanup_error
