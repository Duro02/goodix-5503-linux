import struct
import time
import unittest
from unittest.mock import ANY, call, patch

import usb.core

from goodix5503.image_capture import (
    COMMAND_GET_IMAGE,
    IMAGE_HEIGHT,
    IMAGE_WIDTH,
    PACKED_IMAGE_LENGTH,
    PIXEL_COUNT,
    ImageCaptureError,
    _ResetGuard,
    _TlsImageServer,
    _acquire_hu_fresh_base_frame,
    _chip_config_exchange,
    _fixed_exchange,
    _milan_parse_other_body,
    _read_chip_id_bounded,
    _read_firmware_identity,
    _read_otp_bounded,
    _read_register_exchange,
    _request_encrypted_clear_image,
    _validate_cold_pov_result,
    _validate_config_result,
    _validate_dn2_chip_id,
    _validate_prepared_config,
    _validate_tls_records,
    _wait_hu_fdt_down_event,
    build_hu_difference_image,
    decode_packed_image,
    run_prepared_clear_frame_capture,
)
from goodix5503.chip_config import (
    EXPECTED_ZERO_OTP_CONFIG,
    RUNTIME_CONFIG_PATH,
    ChipConfigError,
)
from goodix5503.hu_runtime import goodix_crc8
from goodix5503.image_capture import (
    COMMAND_COLD_PRECHECK,
    COMMAND_POV_IMAGE_CHECK,
    COMMAND_READ_REGISTER,
    COMMAND_SET_DRIVER_STATE,
    COMMAND_SWITCH_FDT_DOWN,
    COMMAND_SWITCH_FDT_MODE,
    COMMAND_SWITCH_IDLE,
    COMMAND_UPLOAD_CONFIG,
)
from goodix5503.pairing import PSK_PATH, VERIFICATION_PATH
from goodix5503.probe import COMMAND_ACK, ProtocolError, ReadOnlyUsbSession, _encode_packet
from goodix5503.tls_check import COMMAND_REQUEST_TLS, _encode_outer

TEST_DEADLINE = 1_000_000_000.0
HU_DAC_FIELD = bytes.fromhex("8b0084008c008800")
HU_IMAGE_REQUEST = b"\x01\x00" + HU_DAC_FIELD
HU_FRESH_FDT_REQUEST = bytes.fromhex(
    "0d018b0084008c008800800080008000800080008000"
)


def seal_dn2_otp_integrity(otp: bytearray) -> bytearray:
    otp[0x3E] = goodix_crc8(otp[0x32:0x36])
    otp[0x3F] = goodix_crc8(
        otp[0x16:0x1C] + otp[0x1D:0x24] + otp[0x28:0x32]
    )
    otp[0x3D] = goodix_crc8(
        otp[0x0B:0x16]
        + otp[0x1C:0x1D]
        + otp[0x32:0x3C]
        + otp[0x3E:0x3F]
    )
    otp[0x3C] = goodix_crc8(otp[0x00:0x0B] + otp[0x24:0x28])
    return otp


class ImageDecodeTests(unittest.TestCase):
    def test_cold_pov_accepts_all_bounded_official_discriminators(self):
        self.assertEqual(_validate_cold_pov_result(b""), 0)
        for value in (0x00, 0x01, 0xAA, 0xDA, 0xDF):
            with self.subTest(value=value):
                self.assertEqual(_validate_cold_pov_result(bytes((value,))), value)
        with self.assertRaises(ImageCaptureError):
            _validate_cold_pov_result(b"\x00\x00")

    def test_dn2_profile_refuses_zero_and_wn2_chip_ids(self):
        _validate_dn2_chip_id(0x220F)
        for chip_id in (0, 0x2503):
            with self.subTest(chip_id=chip_id):
                with self.assertRaisesRegex(ImageCaptureError, "refusing DN2"):
                    _validate_dn2_chip_id(chip_id)

    def test_config_completion_requires_status_one_in_decoded_payload(self):
        _validate_config_result(b"\x01")
        _validate_config_result(b"\x01\x00")
        for result in (b"", b"\x00", b"\x02", b"\x01\x00\x00"):
            with self.subTest(result=result):
                with self.assertRaisesRegex(ImageCaptureError, "rejected"):
                    _validate_config_result(result)

    def test_runtime_config_requires_a_valid_checksum(self):
        config = bytearray(EXPECTED_ZERO_OTP_CONFIG)
        config[0] ^= 1
        with self.assertRaises(ChipConfigError):
            _validate_prepared_config(config)

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

    def test_background_difference_is_normalized_without_retaining_inputs(self):
        background = bytes(PACKED_IMAGE_LENGTH)
        group = bytes((0xA5, 0x34, 0x67, 0x89, 0xBC, 0xD2))
        finger = group * (PACKED_IMAGE_LENGTH // len(group))
        image = build_hu_difference_image(background, finger)
        try:
            self.assertEqual(len(image), PIXEL_COUNT)
            self.assertEqual(min(image), 0)
            self.assertEqual(max(image), 255)
        finally:
            image[:] = b"\x00" * len(image)

    def test_background_difference_rejects_no_contrast(self):
        with self.assertRaisesRegex(ImageCaptureError, "no background-relative contrast"):
            build_hu_difference_image(
                bytes(PACKED_IMAGE_LENGTH), bytes(PACKED_IMAGE_LENGTH)
            )

    def test_decoder_rejects_every_non_exact_length(self):
        for length in (0, PACKED_IMAGE_LENGTH - 1, PACKED_IMAGE_LENGTH + 1):
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "exactly 7680"):
                    decode_packed_image(b"\x00" * length)


class ImageEnvelopeTests(unittest.TestCase):
    def test_firmware_identity_uses_command00_then_one_a8_read(self):
        session = object.__new__(ReadOnlyUsbSession)
        writes = []
        frames = iter(
            (
                _encode_packet(COMMAND_ACK, b"\x00\x01"),
                _encode_packet(COMMAND_ACK, b"\xa8\x01"),
                _encode_packet(0xA8, b"GF3258_RTSEC_APP_10063\x00"),
            )
        )
        session._ReadOnlyUsbSession__write_packet = writes.append
        session._read_frame = lambda: next(frames)
        self.assertEqual(_read_firmware_identity(session), "GF3258_RTSEC_APP_10063")
        self.assertEqual(
            writes,
            [
                _encode_packet(COMMAND_COLD_PRECHECK, b"\x00\x00\x00\x00"),
                _encode_packet(0xA8, b"\x00\x00"),
            ],
        )

    def test_fdt_down_wait_retries_only_usb_timeouts(self):
        timeout = ImageCaptureError("queued USB read failed")
        timeout.__cause__ = usb.core.USBTimeoutError("timed out")
        expected = bytes(range(16))
        with patch(
            "goodix5503.image_capture._read_frame_bounded",
            side_effect=(timeout, _encode_packet(COMMAND_SWITCH_FDT_DOWN, expected)),
        ) as read_frame:
            self.assertEqual(
                _wait_hu_fdt_down_event(object(), TEST_DEADLINE), expected
            )
        self.assertEqual(read_frame.call_count, 2)

    def test_fixed_exchange_preserves_checksum_free_milan_payload(self):
        for command, result in (
            (COMMAND_POV_IMAGE_CHECK, b"\x00"),
            (COMMAND_SWITCH_FDT_MODE, bytes(range(12))),
            (COMMAND_SWITCH_FDT_MODE, b""),
        ):
            with self.subTest(command=command, result=result):
                session = object.__new__(ReadOnlyUsbSession)
                writes = []
                frames = iter(
                    (
                        _encode_packet(COMMAND_ACK, bytes((command, 1))),
                        _encode_packet(command, result),
                    )
                )
                session._ReadOnlyUsbSession__write_packet = writes.append
                session._read_frame = lambda: next(frames)
                self.assertEqual(_fixed_exchange(session, command, b"request"), result)
                self.assertEqual(writes, [_encode_packet(command, b"request")])

    def test_chip_config_exchange_preserves_checksum_free_payload(self):
        for body in (b"", b"\x01", b"\x01\x7f"):
            with self.subTest(body=body):
                session = object.__new__(ReadOnlyUsbSession)
                frames = iter(
                    (
                        _encode_packet(COMMAND_ACK, bytes((COMMAND_UPLOAD_CONFIG, 1))),
                        _encode_packet(COMMAND_UPLOAD_CONFIG, body),
                    )
                )
                session._ReadOnlyUsbSession__write_packet = lambda _packet: None
                session._read_frame = lambda **_kwargs: next(frames)
                self.assertEqual(
                    _chip_config_exchange(session, b"config", TEST_DEADLINE),
                    body,
                )

    def test_bounded_chip_id_exchange_preserves_deadline_and_normalizes_words(self):
        session = object.__new__(ReadOnlyUsbSession)
        frames = iter(
            (
                _encode_packet(COMMAND_ACK, bytes((COMMAND_READ_REGISTER, 1))),
                _encode_packet(COMMAND_READ_REGISTER, bytes.fromhex("0f000022")),
            )
        )
        writes = []
        timeouts = []
        session._ReadOnlyUsbSession__write_packet = writes.append

        def read_frame(**kwargs):
            timeouts.append(kwargs["timeout_ms"])
            return next(frames)

        session._read_frame = read_frame
        self.assertEqual(_read_chip_id_bounded(session, TEST_DEADLINE), 0x220F)
        self.assertEqual(
            writes,
            [_encode_packet(COMMAND_READ_REGISTER, b"\x00\x00\x00\x04\x00")],
        )
        self.assertEqual(len(timeouts), 2)
        self.assertTrue(all(timeout > 0 for timeout in timeouts))

    def test_bounded_post_reset_otp_exchange_uses_exact_request(self):
        session = object.__new__(ReadOnlyUsbSession)
        frames = iter(
            (
                _encode_packet(COMMAND_ACK, b"\xa6\x01"),
                _encode_packet(0xA6, bytes(range(64))),
            )
        )
        writes = []
        timeouts = []
        session._ReadOnlyUsbSession__write_packet = writes.append

        def read_frame(**kwargs):
            timeouts.append(kwargs["timeout_ms"])
            return next(frames)

        session._read_frame = read_frame
        otp = _read_otp_bounded(session, TEST_DEADLINE)
        try:
            self.assertEqual(otp, bytearray(range(64)))
            self.assertEqual(writes, [_encode_packet(0xA6, b"\x00\x00")])
            self.assertEqual(timeouts, [1500, 1500])
        finally:
            otp[:] = b"\x00" * len(otp)

        reducing = object.__new__(ReadOnlyUsbSession)
        reducing_frames = iter(
            (
                _encode_packet(COMMAND_ACK, b"\xa6\x01"),
                _encode_packet(0xA6, bytes(64)),
            )
        )
        reducing_timeouts = []
        reducing._ReadOnlyUsbSession__write_packet = lambda _packet: None

        def reducing_read(**kwargs):
            reducing_timeouts.append(kwargs["timeout_ms"])
            return next(reducing_frames)

        reducing._read_frame = reducing_read
        with patch(
            "goodix5503.image_capture.time.monotonic",
            side_effect=(9.0, 9.5),
        ):
            reduced_otp = _read_otp_bounded(reducing, 10.0)
        try:
            self.assertEqual(reducing_timeouts, [1000, 500])
        finally:
            reduced_otp[:] = b"\x00" * len(reduced_otp)

        short = object.__new__(ReadOnlyUsbSession)
        short_frames = iter(
            (
                _encode_packet(COMMAND_ACK, b"\xa6\x01"),
                _encode_packet(0xA6, b"short"),
            )
        )
        short._ReadOnlyUsbSession__write_packet = lambda _packet: None
        short._read_frame = lambda **_kwargs: next(short_frames)
        with self.assertRaisesRegex(ImageCaptureError, "exactly 64"):
            _read_otp_bounded(short, TEST_DEADLINE)

    def test_register_exchange_uses_exact_milan_read_parser(self):
        session = object.__new__(ReadOnlyUsbSession)
        frames = iter(
            (
                _encode_packet(COMMAND_ACK, bytes((COMMAND_READ_REGISTER, 1))),
                _encode_packet(COMMAND_READ_REGISTER, b"\x34\x12"),
            )
        )
        writes = []
        session._ReadOnlyUsbSession__write_packet = writes.append
        session._read_frame = lambda **_kwargs: next(frames)
        self.assertEqual(
            _read_register_exchange(session, b"request", TEST_DEADLINE),
            b"\x34\x12",
        )
        self.assertEqual(writes, [_encode_packet(COMMAND_READ_REGISTER, b"request")])

        for body in (b"", b"\x34", b"\x34\x12\x00"):
            with self.subTest(body=body):
                bad = object.__new__(ReadOnlyUsbSession)
                bad_frames = iter(
                    (
                        _encode_packet(COMMAND_ACK, bytes((COMMAND_READ_REGISTER, 1))),
                        _encode_packet(COMMAND_READ_REGISTER, body),
                    )
                )
                bad._ReadOnlyUsbSession__write_packet = lambda _packet: None
                bad._read_frame = lambda **_kwargs: next(bad_frames)
                with self.assertRaises(ImageCaptureError):
                    _read_register_exchange(bad, b"request", TEST_DEADLINE)

    def test_milan_parse_other_preserves_decoded_payload(self):
        self.assertEqual(_milan_parse_other_body(b""), b"")
        self.assertEqual(_milan_parse_other_body(b"\x01"), b"\x01")
        self.assertEqual(
            _milan_parse_other_body(bytes(range(12))),
            bytes(range(12)),
        )

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

        prefix, result = _request_encrypted_clear_image(session, HU_IMAGE_REQUEST)
        try:
            self.assertEqual(prefix, bytearray(b"123456789"))
            self.assertEqual(result, bytearray(ciphertext))
            self.assertEqual(writes, [_encode_packet(COMMAND_GET_IMAGE, HU_IMAGE_REQUEST)])
        finally:
            prefix[:] = b"\x00" * len(prefix)
            result[:] = b"\x00" * len(result)

    def test_image_request_rejects_non_hu_payload_before_writing(self):
        session = object.__new__(ReadOnlyUsbSession)
        session._ReadOnlyUsbSession__write_packet = lambda _packet: self.fail(
            "invalid payload was written"
        )
        with self.assertRaisesRegex(ImageCaptureError, "exactly 10"):
            _request_encrypted_clear_image(session, b"\x01\x00")

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
        prefix, result = _request_encrypted_clear_image(session, HU_IMAGE_REQUEST)
        try:
            self.assertEqual(prefix, bytearray(b"123456789"))
            self.assertEqual(result, bytearray(ciphertext))
        finally:
            prefix[:] = b"\x00" * len(prefix)
            result[:] = b"\x00" * len(result)

        for command, body in (
            (COMMAND_GET_IMAGE, b"\x00"),
            (COMMAND_GET_IMAGE, b"\x01\x00"),
            (0x36, b"\x01"),
        ):
            with self.subTest(command=command, body=body):
                bad_session = object.__new__(ReadOnlyUsbSession)
                bad_frames = iter(
                    (
                        _encode_packet(COMMAND_ACK, bytes((COMMAND_GET_IMAGE, 1))),
                        _encode_packet(command, body),
                    )
                )
                bad_session._ReadOnlyUsbSession__write_packet = lambda _packet: None
                bad_session._read_frame = lambda: next(bad_frames)
                with self.assertRaises((ImageCaptureError, ProtocolError)):
                    _request_encrypted_clear_image(bad_session, HU_IMAGE_REQUEST)

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
                prefix, result = _request_encrypted_clear_image(session, HU_IMAGE_REQUEST)
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
            _request_encrypted_clear_image(oversized, HU_IMAGE_REQUEST)

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
            _request_encrypted_clear_image(session, HU_IMAGE_REQUEST)

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
                    _request_encrypted_clear_image(duplicate, HU_IMAGE_REQUEST)

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
                    _request_encrypted_clear_image(session, HU_IMAGE_REQUEST)


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

            def settimeout(self, _value):
                self.blocking = True

        fake_socket = FakeTlsSocket()

        class FakeContext:
            def wrap_socket(self, _transport, *, server_side):
                self.server_side = server_side
                return fake_socket

        server = _TlsImageServer(FakeContext(), TEST_DEADLINE)
        server.server_transport = object()
        server.image_requests = 1
        server._run()
        self.assertIsInstance(server.image_results[0], ImageCaptureError)
        self.assertIn("surplus", str(server.image_results[0]))


class FreshBaseCoordinatorTests(unittest.TestCase):
    @staticmethod
    def base(value):
        return b"\x82\x01\x3f\x00" + struct.pack(
            "<6H", *(value for _index in range(6))
        )

    def test_runs_proven_fresh_base_sequence_and_returns_image_base(self):
        responses = iter((self.base(1000), self.base(1002), self.base(1004)))
        commands = []
        image_count = 0

        def exchange(_session, command, payload, _deadline):
            commands.append((command, payload))
            self.assertEqual(command, COMMAND_SWITCH_FDT_MODE)
            return next(responses)

        def read_register(_session, payload, _deadline):
            commands.append((COMMAND_READ_REGISTER, payload))
            self.assertEqual(payload, b"\x00\x82\x00\x02\x00")
            return b"\x00\x05"

        def receive(_session, _tls, payload, _deadline):
            nonlocal image_count
            self.assertEqual(payload, HU_IMAGE_REQUEST)
            image_count += 1
            return bytearray(9), bytearray([image_count]) * 7684

        with (
            patch("goodix5503.image_capture._fixed_exchange", side_effect=exchange),
            patch(
                "goodix5503.image_capture._read_register_exchange",
                side_effect=read_register,
            ),
            patch("goodix5503.image_capture._ack_only") as ack,
            patch(
                "goodix5503.image_capture._receive_hu_plaintext_image",
                side_effect=receive,
            ),
        ):
            prefix, plaintext, base = _acquire_hu_fresh_base_frame(
                object(), object(), bytearray(HU_DAC_FIELD), HU_IMAGE_REQUEST, TEST_DEADLINE
            )
        try:
            self.assertEqual(prefix, bytearray(9))
            self.assertEqual(plaintext, bytearray([2]) * 7684)
            self.assertEqual(base, bytearray.fromhex("80f680f680f680f680f680f6"))
            self.assertEqual(image_count, 2)
            self.assertEqual(
                [command for command, _payload in commands],
                [
                    COMMAND_SWITCH_FDT_MODE,
                    COMMAND_SWITCH_FDT_MODE,
                    COMMAND_READ_REGISTER,
                    COMMAND_SWITCH_FDT_MODE,
                ],
            )
            ack.assert_called_once_with(
                ANY,
                COMMAND_SWITCH_IDLE,
                b"\x14\x00",
                TEST_DEADLINE,
            )
        finally:
            prefix[:] = b"\x00" * len(prefix)
            plaintext[:] = b"\x00" * len(plaintext)
            base[:] = b"\x00" * len(base)

    def test_rejects_malformed_command36_body_before_image(self):
        with (
            patch(
                "goodix5503.image_capture._fixed_exchange",
                return_value=bytes(17),
            ),
            patch(
                "goodix5503.image_capture._receive_hu_plaintext_image"
            ) as receive,
        ):
            with self.assertRaisesRegex(ImageCaptureError, "exactly 16"):
                _acquire_hu_fresh_base_frame(
                    object(),
                    object(),
                    bytearray(HU_DAC_FIELD),
                    HU_IMAGE_REQUEST,
                    TEST_DEADLINE,
                )
        receive.assert_not_called()

    def test_retries_an_inconsistent_first_pair_then_succeeds(self):
        responses = iter(
            (
                self.base(1000),
                self.base(2000),
                self.base(1000),
                self.base(1001),
                self.base(1002),
            )
        )
        image_count = 0

        def exchange(_session, _command, _payload, _deadline):
            return next(responses)

        def receive(_session, _tls, _payload, _deadline):
            nonlocal image_count
            image_count += 1
            return bytearray(9), bytearray(7684)

        with (
            patch("goodix5503.image_capture._fixed_exchange", side_effect=exchange),
            patch(
                "goodix5503.image_capture._read_register_exchange",
                return_value=b"\x00\x05",
            ),
            patch("goodix5503.image_capture._ack_only"),
            patch(
                "goodix5503.image_capture._receive_hu_plaintext_image",
                side_effect=receive,
            ),
        ):
            prefix, plaintext, base = _acquire_hu_fresh_base_frame(
                object(), object(), bytearray(HU_DAC_FIELD), HU_IMAGE_REQUEST, TEST_DEADLINE
            )
        try:
            self.assertEqual(image_count, 3)
        finally:
            prefix[:] = b"\x00" * len(prefix)
            plaintext[:] = b"\x00" * len(plaintext)
            base[:] = b"\x00" * len(base)


    def test_stops_after_three_inconsistent_fresh_base_attempts(self):
        exchange_count = 0
        image_count = 0

        def exchange(_session, command, _payload, _deadline):
            nonlocal exchange_count
            self.assertEqual(command, COMMAND_SWITCH_FDT_MODE)
            exchange_count += 1
            # Alternate far-apart base0/base1 values on every attempt.
            return self.base(1000 if exchange_count % 2 == 1 else 2000)

        def receive(_session, _tls, _payload, _deadline):
            nonlocal image_count
            image_count += 1
            return bytearray(9), bytearray(7684)

        with (
            patch("goodix5503.image_capture._fixed_exchange", side_effect=exchange),
            patch(
                "goodix5503.image_capture._read_register_exchange",
                return_value=b"\x00\x01",
            ),
            patch("goodix5503.image_capture._ack_only"),
            patch(
                "goodix5503.image_capture._receive_hu_plaintext_image",
                side_effect=receive,
            ),
        ):
            with self.assertRaisesRegex(ImageCaptureError, "did not stabilize"):
                _acquire_hu_fresh_base_frame(
                    object(),
                    object(),
                    bytearray(HU_DAC_FIELD),
                    HU_IMAGE_REQUEST,
                    TEST_DEADLINE,
                )
        self.assertEqual(image_count, 3)
        self.assertEqual(exchange_count, 6)

    def test_deadline_reset_uses_exact_payload_and_rejects_oversized_result(self):
        guard = _ResetGuard(object())
        with patch(
            "goodix5503.image_capture._exchange_raw_command_body",
            return_value=b"\x08\x00\x01\x00",
        ) as exchange:
            guard.start(TEST_DEADLINE)
        self.assertTrue(guard.attempted)
        exchange.assert_called_once_with(
            guard.session,
            0xA2,
            b"\x05\x14",
            TEST_DEADLINE,
        )

        oversized = _ResetGuard(object())
        with patch(
            "goodix5503.image_capture._exchange_raw_command_body",
            return_value=b"\x00" * 5,
        ):
            with self.assertRaisesRegex(ProtocolError, "exceeds four"):
                oversized.start(TEST_DEADLINE)
        self.assertTrue(oversized.attempted)

    def test_timeout_cleanup_wipes_an_unclaimed_late_plaintext_result(self):
        class FakeBridge:
            def settimeout(self, _value):
                pass

            def sendall(self, _data):
                pass

            def close(self):
                pass

        class FakeTransport:
            def close(self):
                pass

        server = _TlsImageServer(object(), time.monotonic() + 0.02)
        server.bridge = FakeBridge()
        server.server_transport = FakeTransport()
        with self.assertRaisesRegex(ImageCaptureError, "timed out"):
            server.decrypt(bytearray(b"ciphertext"))
        late = bytearray(b"biometric plaintext")
        server.image_results.append(late)
        server.close()
        self.assertEqual(late, bytearray(len(late)))
        self.assertEqual(server.image_results, [])

    def test_server_decrypts_two_sequential_hu_images_on_one_tls_session(self):
        class FakeTlsSocket:
            def __init__(self):
                self.image = 1
                self.remaining = 7684
                self.blocking = True
                self.timeouts = []

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def cipher(self):
                return ("PSK-AES128-CBC-SHA256", "TLSv1.2", 128)

            def setblocking(self, value):
                self.blocking = value

            def settimeout(self, value):
                self.blocking = True
                self.timeouts.append(value)

            def recv_into(self, target):
                if not self.blocking:
                    raise BlockingIOError
                count = min(len(target), self.remaining, 1024)
                target[:count] = bytes((self.image,)) * count
                self.remaining -= count
                if self.remaining == 0:
                    self.image += 1
                    self.remaining = 7684
                return count

        class FakeContext:
            def __init__(self):
                self.socket = FakeTlsSocket()

            def wrap_socket(self, _transport, *, server_side):
                self.server_side = server_side
                return self.socket

        class FakeBridge:
            def sendall(self, _data):
                pass

            def settimeout(self, _value):
                pass

            def close(self):
                pass

        class FakeTransport:
            def close(self):
                pass

        context = FakeContext()
        server = _TlsImageServer(context, TEST_DEADLINE)
        server.server_transport = FakeTransport()
        server.bridge = FakeBridge()
        server.thread = __import__("threading").Thread(target=server._run)
        server.thread.start()
        self.assertTrue(server.handshake_done.wait(1))
        first = server.decrypt(bytearray(b"one"))
        second = server.decrypt(bytearray(b"two"))
        try:
            self.assertEqual(first, bytearray(b"\x01" * 7684))
            self.assertEqual(second, bytearray(b"\x02" * 7684))
            self.assertGreaterEqual(len(context.socket.timeouts), 16)
            self.assertTrue(
                all(
                    later <= earlier
                    for earlier, later in zip(
                        context.socket.timeouts, context.socket.timeouts[1:]
                    )
                )
            )
        finally:
            first[:] = b"\x00" * len(first)
            second[:] = b"\x00" * len(second)
            server.close()


class CaptureOrchestratorTests(unittest.TestCase):
    def test_otp_is_wiped_when_runtime_derivation_fails(self):
        issued = bytearray(b"S" * 64)
        issued[0x32:0x36] = bytes.fromhex("8b848c88")
        issued[42], issued[43] = 0xD7, 0x28
        seal_dn2_otp_integrity(issued)

        class FakeSession:
            def __init__(self, _timeout):
                pass

            def wake_up(self, *, timeout_ms):
                self.timeout_ms = timeout_ms

            def request(self, command, payload=b"", *, checksum=True):
                if command == 0xA8:
                    return b"GF3258_RTSEC_APP_10063\x00"
                return b""

            def close(self):
                pass

        with (
            patch("goodix5503.image_capture.ReadOnlyUsbSession", FakeSession),
            patch("goodix5503.image_capture._disable_core_dumps"),
            patch("goodix5503.image_capture._preflight_tls_runtime"),
            patch(
                "goodix5503.image_capture._read_firmware_identity",
                return_value="GF3258_RTSEC_APP_10063",
            ),
            patch(
                "goodix5503.image_capture._read_live_verification",
                return_value=bytearray(32),
            ),
            patch("goodix5503.image_capture._drop_sudo_privileges"),
            patch("goodix5503.image_capture.os.geteuid", return_value=1000),
            patch("goodix5503.image_capture._read_secure_secret", return_value=bytearray(32)),
            patch("goodix5503.image_capture.calculate_r_verification_record", return_value=bytearray(32)),
            patch("goodix5503.image_capture._build_tls_context", return_value=object()),
            patch("goodix5503.image_capture._ResetGuard.start"),
            patch("goodix5503.image_capture._read_chip_id_bounded", return_value=0x220F),
            patch("goodix5503.image_capture._ack_only"),
            patch("goodix5503.image_capture._read_otp_bounded", return_value=issued),
            patch(
                "goodix5503.image_capture.derive_hu_dac_field",
                side_effect=ValueError("derivation stopped"),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "derivation stopped"):
                run_prepared_clear_frame_capture()
        self.assertEqual(issued, bytearray(64))

    def test_orchestrator_uses_only_fixed_runtime_sequence_and_resets_cleanup(self):
        events = []
        issued_otps = []

        class FakeSession:
            def __init__(self, timeout):
                events.append(("open", timeout))

            def wake_up(self, *, timeout_ms):
                events.append(("wake", timeout_ms))

            def request(self, command, payload=b"", *, checksum=True):
                events.append(("request", command, payload, checksum))
                if command == 0xA8:
                    return b"GF3258_RTSEC_APP_10063\x00"
                return b""

            def close(self):
                events.append(("close",))

        class FakeTlsServer:
            def __init__(self, _context, _operation_deadline):
                events.append(("tls-init",))

            def establish(self, _session):
                events.append(("tls-establish",))
                return "PSK-AES128-CBC-SHA256"

            def decrypt(self, _ciphertext):
                events.append(("tls-decrypt",))
                return bytearray(7684)

            def close(self):
                events.append(("tls-close",))

        def drop_privileges():
            self.assertFalse(issued_otps)
            events.append(("drop-privileges",))

        def read_secret(_path, length):
            self.assertEqual(length, 32)
            return bytearray(b"K" * 32)

        def read_otp(_session, _deadline):
            events.append(("read-otp",))
            otp = bytearray(64)
            otp[0x32:0x36] = bytes.fromhex("8b848c88")
            otp[42], otp[43] = 0xD7, 0x28
            seal_dn2_otp_integrity(otp)
            issued_otps.append(otp)
            return otp

        def fixed_exchange(_session, command, payload, _deadline=None):
            events.append(("exchange", command, payload))
            if command == 0xA8:
                return b"GF3258_RTSEC_APP_10063\x00"
            if command == COMMAND_POV_IMAGE_CHECK:
                return b"\x00"
            return b""

        def chip_config_exchange(_session, payload, _deadline):
            events.append(("exchange", COMMAND_UPLOAD_CONFIG, payload))
            return b"\x01"

        def ack_only(_session, command, payload, _deadline=None):
            events.append(("ack-only", command, payload))

        def acquire_fresh(_session, _tls, dac, payload, _deadline):
            self.assertEqual(dac, HU_DAC_FIELD)
            self.assertEqual(payload, HU_IMAGE_REQUEST)
            return bytearray(9), bytearray(7684), bytearray(12)

        with (
            patch("goodix5503.image_capture.ReadOnlyUsbSession", FakeSession),
            patch("goodix5503.image_capture._disable_core_dumps"),
            patch("goodix5503.image_capture._preflight_tls_runtime"),
            patch(
                "goodix5503.image_capture._read_live_verification",
                side_effect=lambda _session: events.append(("verification-read",)) or bytearray(b"K" * 32),
            ),
            patch(
                "goodix5503.image_capture._drop_sudo_privileges",
                side_effect=drop_privileges,
            ),
            patch("goodix5503.image_capture.os.geteuid", return_value=1000),
            patch("goodix5503.image_capture._read_secure_secret", side_effect=read_secret),
            patch("goodix5503.image_capture._read_otp_bounded", side_effect=read_otp),
            patch("goodix5503.image_capture.calculate_r_verification_record", return_value=bytearray(b"K" * 32)),
            patch("goodix5503.image_capture._build_tls_context", return_value=object()),
            patch(
                "goodix5503.image_capture._exchange_raw_command_body",
                side_effect=lambda _s, command, payload, _deadline: (
                    events.append(("reset",)) or b""
                    if command == 0xA2
                    else self.fail(f"unexpected raw command 0x{command:02x}")
                ),
            ),
            patch(
                "goodix5503.image_capture._read_chip_id_bounded",
                side_effect=lambda _s, _d: events.append(("read-chip-id",)) or 0x220F,
            ),
            patch("goodix5503.image_capture._reset_sensor", side_effect=lambda _s: events.append(("reset",))),
            patch(
                "goodix5503.image_capture.time.sleep",
                side_effect=lambda duration: events.append(("sleep", duration)),
            ) as sleep,
            patch("goodix5503.image_capture._fixed_exchange", side_effect=fixed_exchange),
            patch(
                "goodix5503.image_capture._chip_config_exchange",
                side_effect=chip_config_exchange,
            ),
            patch("goodix5503.image_capture._ack_only", side_effect=ack_only),
            patch("goodix5503.image_capture._TlsImageServer", FakeTlsServer),
            patch(
                "goodix5503.image_capture._acquire_hu_fresh_base_frame",
                side_effect=acquire_fresh,
            ),
        ):
            result = run_prepared_clear_frame_capture()

        self.assertNotIn("pixel_min", result)
        self.assertNotIn("pixel_max", result)
        self.assertNotIn("pixel_sum", result)
        self.assertNotIn("fdt_response_lengths", result)
        requests = [event for event in events if event[0] == "request"]
        self.assertEqual(requests, [])
        self.assertEqual(events.count(("verification-read",)), 1)
        self.assertEqual(events.count(("reset",)), 2)
        self.assertEqual(events.count(("read-chip-id",)), 1)
        update_firmware_event = ("exchange", 0xA8, b"\x00\x00")
        self.assertEqual(events.count(update_firmware_event), 1)
        self.assertLess(events.index(update_firmware_event), events.index(("reset",)))
        self.assertLess(events.index(("reset",)), events.index(("sleep", 0.010)))
        self.assertLess(events.index(("sleep", 0.010)), events.index(("read-chip-id",)))
        cold_ack_indices = [
            index for index, event in enumerate(events)
            if event == ("ack-only", COMMAND_COLD_PRECHECK, b"\x00\x00\x00\x00")
        ]
        self.assertEqual(len(cold_ack_indices), 2)
        self.assertLess(cold_ack_indices[0], events.index(("verification-read",)))
        self.assertLess(events.index(("read-chip-id",)), cold_ack_indices[1])
        self.assertLess(cold_ack_indices[1], events.index(("read-otp",)))
        sleep.assert_called_once_with(0.010)
        runtime = [
            event for event in events if event[0] in ("exchange", "ack-only")
        ]
        self.assertEqual(
            runtime[0],
            ("ack-only", COMMAND_COLD_PRECHECK, b"\x00\x00\x00\x00"),
        )
        self.assertEqual(runtime[1], ("exchange", 0xA8, b"\x00\x00"))
        self.assertEqual(
            runtime[2],
            ("ack-only", COMMAND_COLD_PRECHECK, b"\x00\x00\x00\x00"),
        )
        self.assertEqual(
            runtime[3],
            ("exchange", COMMAND_POV_IMAGE_CHECK, b"\x00\x00"),
        )
        self.assertEqual(runtime[4][0:2], ("exchange", COMMAND_UPLOAD_CONFIG))
        self.assertEqual(len(runtime[4][2]), 256)
        self.assertEqual(
            runtime[5],
            ("ack-only", COMMAND_SET_DRIVER_STATE, b"\x01\x00"),
        )
        self.assertEqual(len(runtime), 6)
        self.assertIn(("tls-close",), events)
        self.assertEqual(events[-1], ("close",))
        self.assertTrue(all(not any(otp) for otp in issued_otps))


if __name__ == "__main__":
    unittest.main()
