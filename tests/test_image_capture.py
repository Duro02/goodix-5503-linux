import struct
import unittest
from unittest.mock import patch

from goodix5503.image_capture import (
    CLEAR_CAPTURE_CONFIRMATION,
    COMMAND_GET_IMAGE,
    GET_IMAGE_CLEAR,
    IMAGE_HEIGHT,
    IMAGE_WIDTH,
    PACKED_IMAGE_LENGTH,
    PIXEL_COUNT,
    FDT_CLEAR_MODE,
    ImageCaptureError,
    _ResetGuard,
    _TlsImageServer,
    _request_encrypted_clear_image,
    _validate_prepared_config,
    _validate_tls_records,
    decode_packed_image,
    run_prepared_clear_frame_capture,
)
from goodix5503.chip_config import EXPECTED_ZERO_OTP_CONFIG, RUNTIME_CONFIG_PATH
from goodix5503.image_capture import (
    COMMAND_GET_POV_IMAGE,
    COMMAND_POV_IMAGE_CHECK,
    COMMAND_SET_DRIVER_STATE,
    COMMAND_SWITCH_FDT_MODE,
    COMMAND_TLS_ESTABLISHED,
    COMMAND_UPLOAD_CONFIG,
)
from goodix5503.pairing import PSK_PATH, VERIFICATION_PATH
from goodix5503.probe import COMMAND_ACK, ProtocolError, ReadOnlyUsbSession, _encode_packet
from goodix5503.tls_check import COMMAND_REQUEST_TLS, _encode_outer


class ImageDecodeTests(unittest.TestCase):
    def test_zero_otp_config_is_not_the_prepared_device_config(self):
        with self.assertRaisesRegex(ImageCaptureError, "OTP-derived"):
            _validate_prepared_config(EXPECTED_ZERO_OTP_CONFIG)

    def test_local_prepared_config_has_pinned_identity_when_present(self):
        if not RUNTIME_CONFIG_PATH.exists():
            self.skipTest("local Git-ignored prepared config is absent")
        config = bytearray(RUNTIME_CONFIG_PATH.read_bytes())
        try:
            _validate_prepared_config(config)
        finally:
            config[:] = b"\x00" * len(config)

    def test_decoder_uses_confirmed_four_pixel_packing(self):
        group = bytes((0xA5, 0x34, 0x67, 0x89, 0xBC, 0xD2))
        packed = group * (PACKED_IMAGE_LENGTH // len(group))
        pixels = decode_packed_image(packed)
        try:
            self.assertEqual(len(pixels), PIXEL_COUNT * 2)
            self.assertEqual(
                struct.unpack("<4H", pixels[:8]),
                (0x534, 0x89A, 0x267, 0xBCD),
            )
            self.assertEqual(IMAGE_WIDTH * IMAGE_HEIGHT, PIXEL_COUNT)
        finally:
            pixels[:] = b"\x00" * len(pixels)

    def test_decoder_rejects_every_non_exact_length(self):
        for length in (0, PACKED_IMAGE_LENGTH - 1, PACKED_IMAGE_LENGTH + 1):
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "exactly 7680"):
                    decode_packed_image(b"\x00" * length)


class ImageEnvelopeTests(unittest.TestCase):
    @staticmethod
    def tls_record(payload: bytes = b"encrypted") -> bytes:
        return b"\x17\x03\x03" + struct.pack(">H", len(payload)) + payload

    def test_tls_record_validator_accepts_only_complete_application_records(self):
        record = self.tls_record() + self.tls_record(b"second")
        _validate_tls_records(record)
        malformed = (
            b"",
            b"\x17\x03",
            b"\x16\x03\x03\x00\x01x",
            b"\x17\x03\x01\x00\x01x",
            b"\x17\x03\x03\x00\x00",
            b"\x17\x03\x03\x00\x02x",
        )
        for value in malformed:
            with self.subTest(value=value):
                with self.assertRaises(ImageCaptureError):
                    _validate_tls_records(value)

    def test_image_request_has_fixed_command_payload_and_nine_byte_envelope(self):
        self.assertEqual(GET_IMAGE_CLEAR, b"\x01\x00")
        session = object.__new__(ReadOnlyUsbSession)
        writes = []
        ciphertext = self.tls_record(b"ciphertext")
        frames = iter(
            (
                _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                _encode_outer(0xB2, b"123456789" + ciphertext),
            )
        )
        session._ReadOnlyUsbSession__write_packet = writes.append
        session._read_frame = lambda: next(frames)

        prefix, result = _request_encrypted_clear_image(session)
        try:
            self.assertEqual(prefix, bytearray(b"123456789"))
            self.assertEqual(result, bytearray(ciphertext))
            self.assertEqual(writes, [_encode_packet(COMMAND_GET_IMAGE, GET_IMAGE_CLEAR)])
        finally:
            prefix[:] = b"\x00" * len(prefix)
            result[:] = b"\x00" * len(result)

    def test_image_request_accepts_only_exact_success_prelude_before_b2(self):
        session = object.__new__(ReadOnlyUsbSession)
        ciphertext = self.tls_record(b"ciphertext")
        frames = iter(
            (
                _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                _encode_packet(COMMAND_GET_IMAGE, b"\x01"),
                _encode_outer(0xB2, b"123456789" + ciphertext),
            )
        )
        session._ReadOnlyUsbSession__write_packet = lambda _packet: None
        session._read_frame = lambda: next(frames)
        prefix, result = _request_encrypted_clear_image(session)
        try:
            self.assertEqual(prefix, bytearray(b"123456789"))
            self.assertEqual(result, bytearray(ciphertext))
        finally:
            prefix[:] = b"\x00" * len(prefix)
            result[:] = b"\x00" * len(result)

        for command, status in ((COMMAND_GET_IMAGE, 0), (0x36, 1)):
            with self.subTest(command=command, status=status):
                bad_session = object.__new__(ReadOnlyUsbSession)
                bad_frames = iter(
                    (
                        _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                        _encode_packet(command, bytes((status,))),
                    )
                )
                bad_session._ReadOnlyUsbSession__write_packet = lambda _packet: None
                bad_session._read_frame = lambda: next(bad_frames)
                with self.assertRaises((ImageCaptureError, ProtocolError)):
                    _request_encrypted_clear_image(bad_session)

    def test_image_request_accepts_delayed_tls_completion_before_b2(self):
        ciphertext = self.tls_record(b"ciphertext")
        for preludes in (
            ((COMMAND_REQUEST_TLS, b""),),
            ((COMMAND_REQUEST_TLS, b"\x00"),),
            ((COMMAND_REQUEST_TLS, b"opaque"), (COMMAND_GET_IMAGE, b"\x01")),
        ):
            with self.subTest(preludes=preludes):
                session = object.__new__(ReadOnlyUsbSession)
                frames = [
                    _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                    *(_encode_packet(command, body) for command, body in preludes),
                    _encode_outer(0xB2, b"123456789" + ciphertext),
                ]
                iterator = iter(frames)
                session._ReadOnlyUsbSession__write_packet = lambda _packet: None
                session._read_frame = lambda: next(iterator)
                prefix, result = _request_encrypted_clear_image(session)
                try:
                    self.assertEqual(prefix, bytearray(b"123456789"))
                    self.assertEqual(result, bytearray(ciphertext))
                finally:
                    prefix[:] = b"\x00" * len(prefix)
                    result[:] = b"\x00" * len(result)

        oversized = object.__new__(ReadOnlyUsbSession)
        oversized_frames = iter(
            (
                _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                _encode_packet(COMMAND_REQUEST_TLS, b"x" * 17),
            )
        )
        oversized._ReadOnlyUsbSession__write_packet = lambda _packet: None
        oversized._read_frame = lambda: next(oversized_frames)
        with self.assertRaisesRegex(ImageCaptureError, "too large"):
            _request_encrypted_clear_image(oversized)

        session = object.__new__(ReadOnlyUsbSession)
        bad_order = iter(
            (
                _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                _encode_packet(COMMAND_GET_IMAGE, b"\x01"),
                _encode_packet(COMMAND_REQUEST_TLS, b"\x01"),
            )
        )
        session._ReadOnlyUsbSession__write_packet = lambda _packet: None
        session._read_frame = lambda: next(bad_order)
        with self.assertRaisesRegex(ImageCaptureError, "unexpected or duplicate"):
            _request_encrypted_clear_image(session)

        for command in (COMMAND_REQUEST_TLS, COMMAND_GET_IMAGE):
            with self.subTest(duplicate=command):
                duplicate = object.__new__(ReadOnlyUsbSession)
                duplicate_frames = iter(
                    (
                        _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                        _encode_packet(command, b"\x01"),
                        _encode_packet(command, b"\x01"),
                    )
                )
                duplicate._ReadOnlyUsbSession__write_packet = lambda _packet: None
                duplicate._read_frame = lambda: next(duplicate_frames)
                with self.assertRaisesRegex(ImageCaptureError, "unexpected or duplicate"):
                    _request_encrypted_clear_image(duplicate)

    def test_image_request_rejects_short_or_malformed_envelope(self):
        for payload in (b"123456789", b"123456789not-tls"):
            with self.subTest(payload=payload):
                session = object.__new__(ReadOnlyUsbSession)
                frames = iter(
                    (
                        _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                        _encode_outer(0xB2, payload),
                    )
                )
                session._ReadOnlyUsbSession__write_packet = lambda _packet: None
                session._read_frame = lambda: next(frames)
                with self.assertRaises(ImageCaptureError):
                    _request_encrypted_clear_image(session)


class ResetGuardTests(unittest.TestCase):
    def test_ambiguous_initial_reset_still_triggers_cleanup_reset(self):
        guard = _ResetGuard(object())
        with patch(
            "goodix5503.image_capture._reset_sensor",
            side_effect=(ProtocolError("lost response"), None),
        ) as reset:
            with self.assertRaises(ProtocolError):
                guard.start()
            self.assertTrue(guard.attempted)
            guard.cleanup()
        self.assertEqual(reset.call_count, 2)


class TlsPlaintextBoundaryTests(unittest.TestCase):
    def test_server_rejects_a_7685th_plaintext_byte(self):
        class FakeTlsSocket:
            def __init__(self):
                self.calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def cipher(self):
                return ("PSK-AES128-CBC-SHA256", "TLSv1.2", 128)

            def recv_into(self, target):
                self.calls += 1
                target[0] = 1
                return len(target) if self.calls == 1 else 1

            def setblocking(self, value):
                self.blocking = value

        fake_socket = FakeTlsSocket()

        class FakeContext:
            def wrap_socket(self, _transport, *, server_side):
                self.server_side = server_side
                return fake_socket

        server = _TlsImageServer(FakeContext())
        server.server_transport = object()
        server.image_requested.set()
        server._run()
        self.assertTrue(server.image_done.is_set())
        self.assertIsInstance(server.image_result[0], ImageCaptureError)
        self.assertIn("surplus", str(server.image_result[0]))


class CaptureOrchestratorTests(unittest.TestCase):
    def test_orchestrator_refuses_before_usb_without_exact_confirmation(self):
        for confirmation in (None, "", CLEAR_CAPTURE_CONFIRMATION + " "):
            with self.subTest(confirmation=confirmation):
                with patch("goodix5503.image_capture.ReadOnlyUsbSession") as session:
                    with self.assertRaisesRegex(ImageCaptureError, "confirmation"):
                        run_prepared_clear_frame_capture(confirmation)
                session.assert_not_called()

    def test_orchestrator_uses_only_fixed_runtime_sequence_and_resets_cleanup(self):
        events = []

        class FakeSession:
            def __init__(self, timeout):
                events.append(("open", timeout))

            def request(self, command, payload=b"", *, checksum=True):
                events.append(("request", command, payload, checksum))
                if command == 0xA8:
                    return b"GF3258_RTSEC_APP_10063\x00"
                if command == 0xF6:
                    return b"MILAN_RTSEC_IAP_10027\x00"
                return b""

            def close(self):
                events.append(("close",))

        class FakeTlsServer:
            def __init__(self, _context):
                events.append(("tls-init",))

            def establish(self, _session):
                events.append(("tls-establish",))
                return "PSK-AES128-CBC-SHA256"

            def decrypt(self, _ciphertext):
                events.append(("tls-decrypt",))
                return bytearray(7684)

            def close(self):
                events.append(("tls-close",))

        def read_secret(path, length):
            self.assertEqual(length, 256 if path == RUNTIME_CONFIG_PATH else 32)
            if path == RUNTIME_CONFIG_PATH:
                return bytearray(EXPECTED_ZERO_OTP_CONFIG)
            return bytearray(b"K" * 32)

        def fixed_exchange(_session, command, payload):
            events.append(("exchange", command, payload))
            if command in (COMMAND_POV_IMAGE_CHECK, COMMAND_UPLOAD_CONFIG):
                return b"\x01"
            if command == COMMAND_GET_POV_IMAGE:
                return b"\x00"
            return b""

        def ack_only(_session, command, payload):
            events.append(("ack-only", command, payload))

        with (
            patch("goodix5503.image_capture.ReadOnlyUsbSession", FakeSession),
            patch("goodix5503.image_capture._disable_core_dumps"),
            patch("goodix5503.image_capture._preflight_tls_runtime"),
            patch("goodix5503.image_capture._read_live_verification", return_value=bytearray(b"K" * 32)),
            patch("goodix5503.image_capture._drop_sudo_privileges"),
            patch("goodix5503.image_capture.os.geteuid", return_value=1000),
            patch("goodix5503.image_capture._read_secure_secret", side_effect=read_secret),
            patch("goodix5503.image_capture._validate_prepared_config"),
            patch("goodix5503.image_capture.calculate_r_verification_record", return_value=bytearray(b"K" * 32)),
            patch("goodix5503.image_capture._build_tls_context", return_value=object()),
            patch("goodix5503.image_capture._reset_sensor", side_effect=lambda _s: events.append(("reset",))),
            patch("goodix5503.image_capture._fixed_exchange", side_effect=fixed_exchange),
            patch("goodix5503.image_capture._ack_only", side_effect=ack_only),
            patch("goodix5503.image_capture._TlsImageServer", FakeTlsServer),
            patch(
                "goodix5503.image_capture._request_encrypted_clear_image",
                return_value=(bytearray(9), bytearray(b"cipher")),
            ),
        ):
            result = run_prepared_clear_frame_capture(CLEAR_CAPTURE_CONFIRMATION)

        self.assertEqual(result["pixel_min"], 0)
        self.assertEqual(result["pixel_max"], 0)
        self.assertEqual(result["pixel_sum"], 0)
        self.assertEqual(events.count(("reset",)), 2)
        runtime = [event for event in events if event[0] in ("exchange", "ack-only")]
        self.assertEqual(runtime[0], ("exchange", COMMAND_POV_IMAGE_CHECK, b"\x00\x00"))
        self.assertEqual(
            runtime[1], ("ack-only", COMMAND_TLS_ESTABLISHED, b"\x00\x00")
        )
        self.assertEqual(runtime[2][0:2], ("exchange", COMMAND_UPLOAD_CONFIG))
        self.assertEqual(len(runtime[2][2]), 256)
        self.assertEqual(
            runtime[3:5],
            [
                ("ack-only", COMMAND_SET_DRIVER_STATE, b"\x01\x00"),
                ("ack-only", COMMAND_SET_DRIVER_STATE, b"\x01\x00"),
            ],
        )
        self.assertEqual(runtime[5], ("exchange", COMMAND_GET_POV_IMAGE, b"\x00\x00"))
        self.assertEqual(runtime[6], ("exchange", COMMAND_SWITCH_FDT_MODE, FDT_CLEAR_MODE))
        self.assertIn(("tls-close",), events)
        self.assertEqual(events[-1], ("close",))


if __name__ == "__main__":
    unittest.main()
