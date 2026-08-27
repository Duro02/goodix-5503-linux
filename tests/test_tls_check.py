import socket
import ssl
import struct
import threading
import time
import unittest
from unittest.mock import patch

from goodix5503 import tls_check
from goodix5503.probe import (
    COMMAND_ACK,
    ProtocolError,
    ReadOnlyUsbSession,
    _decode_packet,
    _encode_packet,
)


class TlsTests(unittest.TestCase):
    def test_runtime_feature_gate_or_exact_goodix_psk_suite(self):
        if not hasattr(ssl.SSLContext, "set_psk_server_callback"):
            with self.assertRaisesRegex(tls_check.TlsTestError, "does not support"):
                tls_check._build_tls_context(bytearray(32))
            return
        try:
            context = tls_check._build_tls_context(bytearray(32))
        except tls_check.TlsTestError as error:
            self.assertRegex(str(error), "TLS-PSK|cipher")
            return
        self.assertIn(
            "PSK-AES128-CBC-SHA256",
            {cipher["name"] for cipher in context.get_ciphers()},
        )

    def test_unsupported_runtime_fails_before_usb_open(self):
        with (
            patch.object(
                tls_check,
                "_preflight_tls_runtime",
                side_effect=tls_check.TlsTestError("unsupported"),
            ),
            patch.object(
                tls_check.ReadOnlyUsbSession,
                "__init__",
                side_effect=AssertionError("USB must not open"),
            ),
            self.assertRaisesRegex(tls_check.TlsTestError, "unsupported"),
        ):
            tls_check.run_prepared_tls_check()

    def test_outer_tls_frame_round_trip(self):
        frame = tls_check._encode_outer(tls_check.FLAGS_TLS, b"tls-record")
        self.assertEqual(
            tls_check._decode_outer(frame, tls_check.FLAGS_TLS), b"tls-record"
        )
        with self.assertRaises(Exception):
            tls_check._decode_outer(frame + b"trailing", tls_check.FLAGS_TLS)

    def test_reset_uses_only_fixed_payload(self):
        session = object.__new__(ReadOnlyUsbSession)
        captured = []

        def exchange(command, payload):
            captured.append((command, payload))
            return b"\x08\x00\x01\x00"

        session._ReadOnlyUsbSession__exchange = exchange
        tls_check._reset_sensor(session)
        self.assertEqual(captured, [(tls_check.COMMAND_RESET, b"\x05\x14")])

        session._ReadOnlyUsbSession__exchange = lambda *_args: b"\x00" * 5
        with self.assertRaisesRegex(ProtocolError, "exceeds four"):
            tls_check._reset_sensor(session)

    def test_tls_request_uses_fixed_command_and_decodes_tls_outer_frame(self):
        session = object.__new__(ReadOnlyUsbSession)
        writes = []
        frames = iter(
            [
                _encode_packet(COMMAND_ACK, bytes((tls_check.COMMAND_REQUEST_TLS, 1))),
                tls_check._encode_outer(tls_check.FLAGS_TLS, b"client-hello"),
            ]
        )
        session._ReadOnlyUsbSession__write_packet = writes.append
        session._read_frame = lambda: next(frames)
        self.assertEqual(
            tls_check._request_tls_client_hello(session), b"client-hello"
        )
        self.assertEqual(
            _decode_packet(writes[0], tls_check.COMMAND_REQUEST_TLS), b"\x00\x00"
        )

    def test_fragmented_first_flight_ends_at_server_hello_done(self):
        first, second = socket.socketpair()
        handshake = b"\x02\x00\x00\x00" + b"\x0e\x00\x00\x00"
        records = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake

        def send_fragments():
            for offset in range(0, len(records), 2):
                first.sendall(records[offset : offset + 2])
                time.sleep(0.01)

        thread = threading.Thread(target=send_fragments)
        thread.start()
        try:
            self.assertEqual(
                tls_check._recv_server_flight(second, final=False), records
            )
        finally:
            thread.join()
            first.close()
            second.close()

    def test_final_flight_requires_ccs_then_finished_record(self):
        first, second = socket.socketpair()
        records = (
            b"\x14\x03\x03\x00\x01\x01"
            b"\x16\x03\x03\x00\x03xyz"
        )
        try:
            first.sendall(records)
            self.assertEqual(
                tls_check._recv_server_flight(second, final=True), records
            )
        finally:
            first.close()
            second.close()

    def test_orchestration_checks_live_key_before_tls(self):
        verification = bytearray(b"\x44" * 32)
        psk = bytearray(b"\x22" * 32)

        class FakeSession:
            def request(self, command, payload=b"", *, checksum=True):
                if command == tls_check.COMMAND_NOP:
                    return b""
                if command == tls_check.COMMAND_FIRMWARE_VERSION:
                    return tls_check.EXPECTED_FIRMWARE.encode() + b"\x00"
                if command == tls_check.COMMAND_GET_IAP_VERSION:
                    return tls_check.EXPECTED_IAP.encode() + b"\x00"
                raise AssertionError(f"unexpected command {command:#x}")

            def close(self):
                pass

        with (
            patch.object(tls_check, "_preflight_tls_runtime") as preflight,
            patch.object(tls_check, "ReadOnlyUsbSession", return_value=FakeSession()),
            patch.object(tls_check, "_disable_core_dumps"),
            patch.object(tls_check, "_drop_sudo_privileges"),
            patch.object(tls_check.os, "geteuid", return_value=1000),
            patch.object(
                tls_check,
                "_read_live_verification",
                return_value=bytearray(verification),
            ),
            patch.object(
                tls_check,
                "_read_secure_secret",
                side_effect=[bytearray(verification), psk],
            ),
            patch.object(
                tls_check,
                "calculate_r_verification_record",
                return_value=bytearray(verification),
            ),
            patch.object(tls_check, "_build_tls_context", return_value="context") as build,
            patch.object(tls_check, "_reset_sensor") as reset,
            patch.object(
                tls_check, "_bridge_handshake", return_value="PSK-AES128-CBC-SHA256"
            ) as handshake,
        ):
            result = tls_check.run_prepared_tls_check()

        self.assertEqual(result["tls"], "established")
        preflight.assert_called_once()
        build.assert_called_once()
        reset.assert_called_once()
        handshake.assert_called_once_with(unittest.mock.ANY, "context")
        self.assertEqual(psk, bytearray(32))


if __name__ == "__main__":
    unittest.main()
