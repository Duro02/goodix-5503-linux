"""Fixed, non-persistent TLS-PSK handshake test for the confirmed 5503."""

from __future__ import annotations

# Defense in depth for test runners with non-default collection patterns.
__test__ = False

import hmac
import os
import socket
import ssl
import struct
import threading
import time
from typing import Final

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

FLAGS_TLS: Final = 0xB0
COMMAND_RESET: Final = 0xA2
COMMAND_REQUEST_TLS: Final = 0xD0


class TlsTestError(RuntimeError):
    """The fixed local TLS handshake did not complete."""


def _encode_outer(flags: int, payload: bytes) -> bytes:
    header = struct.pack("<BH", flags, len(payload))
    return header + bytes((sum(header) & 0xFF,)) + payload


def _decode_outer(frame: bytes, expected_flags: int) -> bytes:
    if len(frame) < 4:
        raise ProtocolError("TLS frame is too short")
    flags, length = struct.unpack("<BH", frame[:3])
    if flags != expected_flags:
        raise ProtocolError(f"unexpected TLS frame flags 0x{flags:02x}")
    if (sum(frame[:3]) & 0xFF) != frame[3]:
        raise ProtocolError("invalid TLS frame header checksum")
    if len(frame) != 4 + length:
        raise ProtocolError("invalid TLS frame length")
    return frame[4:]


def _reset_sensor(session: ReadOnlyUsbSession) -> None:
    response = session._ReadOnlyUsbSession__exchange(  # type: ignore[attr-defined]
        COMMAND_RESET, b"\x05\x14"
    )
    if not response or response[0] != 1:
        raise ProtocolError("sensor reset was not acknowledged")


def _request_tls_client_hello(session: ReadOnlyUsbSession) -> bytes:
    session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
        _encode_packet(COMMAND_REQUEST_TLS, b"\x00\x00")
    )
    ack = _decode_packet(session._read_frame(), COMMAND_ACK)
    _check_ack(ack, COMMAND_REQUEST_TLS)
    return _decode_outer(session._read_frame(), FLAGS_TLS)


def _send_tls(session: ReadOnlyUsbSession, record: bytes) -> None:
    session._ReadOnlyUsbSession__write_packet(  # type: ignore[attr-defined]
        _encode_outer(FLAGS_TLS, record)
    )


def _receive_tls(session: ReadOnlyUsbSession) -> bytes:
    return _decode_outer(session._read_frame(), FLAGS_TLS)


def _recv_exact(sock: socket.socket, length: int, deadline: float) -> bytes:
    result = bytearray(length)
    received = 0
    while received < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TlsTestError("TLS server flight timed out")
        sock.settimeout(remaining)
        chunk = sock.recv(length - received)
        if not chunk:
            raise TlsTestError("TLS server closed during a flight")
        result[received : received + len(chunk)] = chunk
        received += len(chunk)
    return bytes(result)


def _recv_server_flight(sock: socket.socket, *, final: bool) -> bytes:
    """Collect records until a protocol-defined TLS 1.2 flight boundary."""
    deadline = time.monotonic() + 5
    records = bytearray()
    handshake = bytearray()
    saw_change_cipher_spec = False
    while True:
        header = _recv_exact(sock, 5, deadline)
        record_length = struct.unpack(">H", header[3:5])[0]
        if record_length > 0x4000 + 2048:
            raise TlsTestError("TLS server record is unreasonably large")
        payload = _recv_exact(sock, record_length, deadline)
        records.extend(header)
        records.extend(payload)
        content_type = header[0]
        if content_type == 21:
            raise TlsTestError("TLS server returned an alert")
        if final:
            if content_type == 20:
                saw_change_cipher_spec = True
            elif content_type == 22 and saw_change_cipher_spec:
                return bytes(records)
            continue

        if content_type != 22:
            continue
        handshake.extend(payload)
        offset = 0
        while len(handshake) - offset >= 4:
            message_length = int.from_bytes(handshake[offset + 1 : offset + 4], "big")
            total = 4 + message_length
            if len(handshake) - offset < total:
                break
            message_type = handshake[offset]
            offset += total
            if message_type == 14:  # ServerHelloDone
                return bytes(records)
        if offset:
            del handshake[:offset]


def _build_tls_context(psk: bytearray) -> ssl.SSLContext:
    """Fail before reset unless this runtime can serve the exact PSK suite."""
    if len(psk) != 32:
        raise ValueError("PSK must be exactly 32 bytes")
    if not hasattr(ssl.SSLContext, "set_psk_server_callback"):
        raise TlsTestError("Python/OpenSSL runtime does not support PSK callbacks")
    # Python's ssl callback requires immutable bytes. Core dumping is disabled;
    # this short-lived closure copy is the remaining interpreter/API limitation.
    psk_for_ssl = bytes(psk)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("PSK-AES128-CBC-SHA256")
        context.options |= ssl.OP_NO_TICKET
        context.set_psk_server_callback(lambda _identity: psk_for_ssl)
        if "PSK-AES128-CBC-SHA256" not in {
            cipher["name"] for cipher in context.get_ciphers()
        }:
            raise TlsTestError("exact Goodix PSK cipher is unavailable")
        return context
    except Exception as error:
        if isinstance(error, TlsTestError):
            raise
        raise TlsTestError("failed to initialize exact TLS-PSK server") from error


def _preflight_tls_runtime() -> None:
    dummy = bytearray(32)
    try:
        _build_tls_context(dummy)
    finally:
        dummy[:] = b"\x00" * len(dummy)


def _bridge_handshake(
    session: ReadOnlyUsbSession, context: ssl.SSLContext
) -> str:
    """Bridge the device's fixed TLS 1.2 flight to a preflighted PSK server."""
    _disable_core_dumps()
    server_transport: socket.socket | None = None
    bridge: socket.socket | None = None
    handshake_done = threading.Event()
    release_server = threading.Event()
    result: list[str | BaseException] = []

    def run_server() -> None:
        try:
            with context.wrap_socket(server_transport, server_side=True) as tls_socket:
                cipher = tls_socket.cipher()
                if cipher is None:
                    raise TlsTestError("TLS server negotiated no cipher")
                result.append(cipher[0])
                handshake_done.set()
                release_server.wait(5)
        except BaseException as error:
            result.append(error)
            handshake_done.set()

    thread = threading.Thread(target=run_server, name="goodix-tls-test", daemon=True)
    try:
        server_transport, bridge = socket.socketpair()
        server_transport.settimeout(5)
        bridge.settimeout(5)
        thread.start()
        bridge.sendall(_request_tls_client_hello(session))
        _send_tls(session, _recv_server_flight(bridge, final=False))
        for _index in range(3):
            bridge.sendall(_receive_tls(session))
        _send_tls(session, _recv_server_flight(bridge, final=True))
        if not handshake_done.wait(5):
            raise TlsTestError("TLS server handshake timed out")
        if not result:
            raise TlsTestError("TLS server produced no handshake result")
        if isinstance(result[0], BaseException):
            raise TlsTestError("TLS server rejected the device PSK") from result[0]
        return result[0]
    finally:
        release_server.set()
        if bridge is not None:
            bridge.close()
        if server_transport is not None and not thread.is_alive():
            server_transport.close()
        if thread.ident is not None:
            thread.join(6)
        if thread.is_alive():
            raise TlsTestError("TLS server thread did not stop")


def run_prepared_tls_check(timeout_seconds: float = 5.0) -> dict[str, str]:
    """Reset runtime state and test TLS; performs no persistent write."""
    _disable_core_dumps()
    _preflight_tls_runtime()
    session: ReadOnlyUsbSession | None = None
    live = bytearray()
    expected = bytearray()
    psk = bytearray()
    derived = bytearray()
    try:
        session = ReadOnlyUsbSession(timeout_seconds)
        session.request(COMMAND_NOP, checksum=False)
        firmware = _decode_c_string(session.request(COMMAND_FIRMWARE_VERSION))
        iap = _decode_c_string(session.request(COMMAND_GET_IAP_VERSION, b"\x19\x00"))
        if firmware != EXPECTED_FIRMWARE or iap != EXPECTED_IAP:
            raise TlsTestError("unexpected firmware or IAP")
        live = _read_live_verification(session)

        _drop_sudo_privileges()
        _disable_core_dumps()
        if os.geteuid() == 0:
            raise TlsTestError("refusing local PSK access as root")
        expected = _read_secure_secret(VERIFICATION_PATH, 32)
        psk = _read_secure_secret(PSK_PATH, 32)
        derived = calculate_r_verification_record(psk)
        if not hmac.compare_digest(expected, derived):
            raise TlsTestError("saved PSK does not match its verification record")
        if not hmac.compare_digest(live, derived):
            raise TlsTestError("live verification record does not match prepared PSK")
        context = _build_tls_context(psk)

        _reset_sensor(session)
        cipher = _bridge_handshake(session, context)
        return {
            "operation": "non-persistent-tls-handshake",
            "firmware": firmware,
            "iap": iap,
            "tls": "established",
            "cipher": cipher,
        }
    finally:
        close_error: BaseException | None = None
        if session is not None:
            try:
                session.close()
            except BaseException as error:
                close_error = error
        live[:] = b"\x00" * len(live)
        expected[:] = b"\x00" * len(expected)
        psk[:] = b"\x00" * len(psk)
        derived[:] = b"\x00" * len(derived)
        if close_error is not None:
            raise TlsTestError("failed to close TLS test USB session") from close_error
