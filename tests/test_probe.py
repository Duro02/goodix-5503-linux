import array
import unittest

from goodix5503.probe import (
    COMMAND_ACK,
    COMMAND_FIRMWARE_VERSION,
    ProtocolError,
    ReadOnlyUsbSession,
    UnsafeCommandError,
    _decode_packet,
    _encode_packet,
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
