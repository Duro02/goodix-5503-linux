import array
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from goodix5503.probe import (
    COMMAND_ACK,
    COMMAND_FIRMWARE_VERSION,
    COMMAND_PRESET_PSK_READ,
    OFFICIAL_PROTECTED_PSK_SELECTOR,
    OFFICIAL_R_PSK_HASH_SELECTOR,
    ProtocolError,
    ReadOnlyUsbSession,
    UnsafeCommandError,
    _decode_r_read_response,
    _decode_packet,
    _encode_packet,
    _write_secure_backup,
)


class FakeInEndpoint:
    wMaxPacketSize = 64

    def __init__(self, chunks):
        self.chunks = list(chunks)

    def read(self, _size, timeout):
        del timeout
        if not self.chunks:
            raise AssertionError("unexpected USB read")
        return array.array("B", self.chunks.pop(0))


def reader_session(*chunks):
    session = object.__new__(ReadOnlyUsbSession)
    session.timeout_ms = 5000
    session._max_packet_size = 64
    session._rx_buffer = bytearray()
    session.endpoint_in = FakeInEndpoint(chunks)
    return session


class PacketTests(unittest.TestCase):
    def test_packet_round_trip(self):
        packet = _encode_packet(COMMAND_FIRMWARE_VERSION, b"\x00\x00")
        self.assertEqual(
            _decode_packet(packet, COMMAND_FIRMWARE_VERSION), b"\x00\x00"
        )

    def test_inconsistent_inner_outer_lengths_are_rejected(self):
        packet = bytearray(_encode_packet(COMMAND_FIRMWARE_VERSION))
        packet[1] += 1
        packet[3] = sum(packet[:3]) & 0xFF
        packet.append(0)
        with self.assertRaises(ProtocolError):
            _decode_packet(bytes(packet), COMMAND_FIRMWARE_VERSION)

    def test_mutating_command_is_blocked_before_usb_write(self):
        session = object.__new__(ReadOnlyUsbSession)
        session._ReadOnlyUsbSession__write_packet = lambda _packet: self.fail(
            "USB write must not occur"
        )

        # 0xa4 is MCU_ERASE_APP in the reverse-engineered protocol.
        with self.assertRaises(UnsafeCommandError):
            session.request(0xA4)

    def test_unexpected_payload_is_blocked_before_usb_write(self):
        session = object.__new__(ReadOnlyUsbSession)
        session._ReadOnlyUsbSession__write_packet = lambda _packet: self.fail(
            "USB write must not occur"
        )
        with self.assertRaises(UnsafeCommandError):
            session.request(COMMAND_FIRMWARE_VERSION, b"unexpected")

    def test_only_exact_official_r_hash_read_is_allowed(self):
        allowed = struct.pack("<II", OFFICIAL_R_PSK_HASH_SELECTOR, 0)
        ReadOnlyUsbSession._validate_request(
            COMMAND_PRESET_PSK_READ, allowed, True
        )

        for payload in (
            struct.pack("<II", OFFICIAL_R_PSK_HASH_SELECTOR, 1),
            struct.pack("<IIII", 32, 0, 0xBB020001, 0),
            struct.pack("<II", OFFICIAL_PROTECTED_PSK_SELECTOR, 0),
            struct.pack("<II", OFFICIAL_PROTECTED_PSK_SELECTOR, 1),
            struct.pack("<II", 0xBB010003, 0),
        ):
            with self.subTest(payload=payload), self.assertRaises(
                UnsafeCommandError
            ):
                ReadOnlyUsbSession._validate_request(
                    COMMAND_PRESET_PSK_READ, payload, True
                )

    def test_r_read_response_requires_exact_selector_and_length(self):
        value = b"x" * 32
        reply = (
            b"\x00"
            + struct.pack("<II", OFFICIAL_R_PSK_HASH_SELECTOR, len(value))
            + value
        )
        self.assertEqual(
            _decode_r_read_response(reply, OFFICIAL_R_PSK_HASH_SELECTOR), value
        )
        with self.assertRaises(ProtocolError):
            _decode_r_read_response(reply + b"trailing", OFFICIAL_R_PSK_HASH_SELECTOR)
        with self.assertRaises(ProtocolError):
            _decode_r_read_response(reply, 0xBB020001)
        with self.assertRaisesRegex(ProtocolError, "status 0x01"):
            _decode_r_read_response(
                b"\x01" + reply[1:], OFFICIAL_R_PSK_HASH_SELECTOR
            )

    def test_protected_record_metadata_reports_only_length_and_digest(self):
        value = b"opaque-protected-record"
        reply = (
            b"\x00"
            + struct.pack("<II", OFFICIAL_PROTECTED_PSK_SELECTOR, len(value))
            + value
        )

        session = object.__new__(ReadOnlyUsbSession)
        calls = []

        def exchange(command, payload, *, checksum=True):
            calls.append((command, payload, checksum))
            return reply

        session._ReadOnlyUsbSession__exchange = exchange
        with patch("goodix5503.probe._disable_core_dumps") as disable_dumps:
            length, digest = session.protected_record_metadata()
        disable_dumps.assert_called_once_with()
        self.assertEqual(length, len(value))
        self.assertEqual(
            digest,
            "c32b89b774b73f6f575c3581648adc0a8ca07769782ae601d69a3675c4e96567",
        )
        self.assertEqual(
            calls,
            [
                (
                    COMMAND_PRESET_PSK_READ,
                    struct.pack("<II", OFFICIAL_PROTECTED_PSK_SELECTOR, 0),
                    True,
                )
            ],
        )

    def test_backup_drops_privileges_before_filesystem_access(self):
        value = b"opaque-protected-record"
        reply = (
            b"\x00"
            + struct.pack("<II", OFFICIAL_PROTECTED_PSK_SELECTOR, len(value))
            + value
        )
        session = object.__new__(ReadOnlyUsbSession)
        session._ReadOnlyUsbSession__exchange = (
            lambda _command, _payload, checksum=True: reply
        )
        order = []
        session.close = lambda: order.append("close")

        with (
            patch(
                "goodix5503.probe._disable_core_dumps",
                side_effect=lambda: order.append("harden"),
            ),
            patch(
                "goodix5503.probe._drop_sudo_privileges",
                side_effect=lambda: order.append("drop"),
            ),
            patch(
                "goodix5503.probe._write_secure_backup",
                side_effect=lambda _path, _data: order.append("write"),
            ),
        ):
            length, _digest, _path = session.backup_protected_record()
        self.assertEqual(length, len(value))
        self.assertEqual(
            order, ["harden", "close", "drop", "harden", "write"]
        )

    def test_secure_backup_refuses_root_filesystem_access(self):
        with patch("goodix5503.probe.os.geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "filesystem access as root"):
                _write_secure_backup(Path("unused"), bytearray(b"protected"))

    def test_secure_backup_is_exclusive_and_mode_600(self):
        protected = bytearray(b"opaque-protected-record")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "artifacts" / "device-backup"
            path = directory / "backup.bin"
            with patch("goodix5503.probe.PROJECT_ROOT", root):
                _write_secure_backup(path, protected)
                self.assertEqual(path.read_bytes(), bytes(protected))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

                with self.assertRaises(FileExistsError):
                    _write_secure_backup(path, bytearray(b"replacement"))
            self.assertEqual(path.read_bytes(), bytes(protected))
            self.assertEqual(list(directory.glob(".psk-record-*")), [])

    def test_padded_64_byte_response_returns_one_frame(self):
        frame = _encode_packet(COMMAND_ACK, bytes((COMMAND_FIRMWARE_VERSION, 1)))
        session = reader_session(frame + b"\x00" * (64 - len(frame)))
        self.assertEqual(session._read_frame(), frame)
        self.assertEqual(session._rx_buffer, b"")

    def test_split_response_is_reassembled(self):
        frame = _encode_packet(COMMAND_FIRMWARE_VERSION, b"x" * 100)
        session = reader_session(frame[:64], frame[64:])
        self.assertEqual(session._read_frame(), frame)

    def test_coalesced_frames_are_preserved(self):
        ack = _encode_packet(COMMAND_ACK, bytes((COMMAND_FIRMWARE_VERSION, 1)))
        reply = _encode_packet(COMMAND_FIRMWARE_VERSION, b"firmware\x00")
        session = reader_session(ack + reply)
        self.assertEqual(session._read_frame(), ack)
        self.assertEqual(session._read_frame(), reply)

    def test_timeout_must_be_positive_and_bounded(self):
        for timeout in (0, 0.0001, -1, float("inf"), float("nan"), 31):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                ReadOnlyUsbSession(timeout)


if __name__ == "__main__":
    unittest.main()
