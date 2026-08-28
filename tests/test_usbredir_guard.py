import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from goodix5503.usbredir_guard import (
    AuditLog, BULK_PACKET, CAP_32BIT_BULK_LENGTH, CAP_64BIT_IDS,
    CONTROL_PACKET, DEVICE_CONNECT, FILTER_FILTER, GOODIX_A8, GuardState, GuardViolation,
    HELLO, MAX_FRAME, Packet, UsbRedirGuard, authorize_guest,
    authorize_upstream, read_packet,
)


def frame(kind, body=b"", ident=0, wide=False):
    header = struct.pack("<IIQ" if wide else "<III", kind, len(body), ident)
    return header + body


def hello(caps=(1 << CAP_64BIT_IDS) | (1 << CAP_32BIT_BULK_LENGTH)):
    version = b"test-usbredir\0".ljust(64, b"\0")
    return frame(HELLO, version + struct.pack("<I", caps))


def packet(kind, body=b"", ident=7, wide=True):
    raw = frame(kind, body, ident, wide)
    return Packet(kind, ident, body, raw)


def bulk(endpoint, data=b"", requested=None, status=0):
    length = len(data) if requested is None else requested
    body = struct.pack("<BBHIH", endpoint, status, length & 0xffff, 0, length >> 16) + data
    return packet(BULK_PACKET, body)


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            break
        result.extend(part)
    return bytes(result)


class FramingTests(unittest.TestCase):
    def test_initial_header_every_split(self):
        raw = hello(0)
        for split in range(1, 12):
            left, right = socket.socketpair()
            state = GuardState()
            sender = threading.Thread(target=lambda: (right.sendall(raw[:split]), right.sendall(raw[split:])))
            sender.start()
            parsed = read_packet(left, state, initial=True)
            sender.join()
            self.assertEqual(parsed.raw, raw)
            left.close(); right.close()

    def test_wide_header_every_split_and_opaque_id(self):
        raw = frame(7, b"abc", 0xfedcba9876543210, True)
        for split in range(1, 16):
            left, right = socket.socketpair()
            state = GuardState(); state.header_size = 16
            right.sendall(raw[:split]); right.sendall(raw[split:])
            parsed = read_packet(left, state, initial=False)
            self.assertEqual(parsed.packet_id, 0xfedcba9876543210)
            self.assertEqual(parsed.raw, raw)
            left.close(); right.close()

    def test_coalesced_frames_remain_distinct(self):
        state = GuardState(); state.header_size = 16
        first, second = frame(7, b"", 1, True), frame(10, b"\0", 2, True)
        left, right = socket.socketpair(); right.sendall(first + second)
        self.assertEqual(read_packet(left, state, False).raw, first)
        self.assertEqual(read_packet(left, state, False).raw, second)
        left.close(); right.close()

    def test_frame_bound_and_partial_eof_fail_closed(self):
        left, right = socket.socketpair()
        right.sendall(struct.pack("<III", HELLO, MAX_FRAME, 0)); right.close()
        with self.assertRaises(GuardViolation): read_packet(left, GuardState(), True)
        left.close()
        left, right = socket.socketpair()
        right.sendall(struct.pack("<III", HELLO, 64, 0) + b"short"); right.close()
        with self.assertRaisesRegex(GuardViolation, "EOF"): read_packet(left, GuardState(), True)
        left.close()

    def test_timeout_and_global_buffer_bound(self):
        left, right = socket.socketpair(); left.settimeout(0.01)
        with self.assertRaises(TimeoutError): read_packet(left, GuardState(), True)
        left.close(); right.close()
        state = GuardState(); state.reserve(2 * MAX_FRAME)
        with self.assertRaisesRegex(GuardViolation, "global buffer"):
            state.reserve(1)
        state.release(2 * MAX_FRAME)

    def test_negotiation_requires_both_capabilities(self):
        state = GuardState()
        state.register_hello("guest", hello()[12:])
        state.register_hello("upstream", hello(0)[12:])
        self.assertEqual(state.header_size, 12)
        self.assertEqual(state.bulk_header_size, 8)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.state = GuardState(); self.state.header_size = 16; self.state.bulk_header_size = 10
        self.state.device_connected = True

    def test_device_identity_exact_and_duplicate_denied(self):
        good = struct.pack("<BBBBHHH", 2, 0, 0, 0, 0x27c6, 0x5503, 0x0100)
        state = GuardState()
        self.assertEqual(authorize_upstream(packet(DEVICE_CONNECT, good), state), "goodix-27c6-5503")
        with self.assertRaises(GuardViolation): authorize_upstream(packet(DEVICE_CONNECT, good), state)
        bad_state = GuardState()
        bad = struct.pack("<BBBBHHH", 2, 0, 0, 0, 0x27c6, 0x5504, 0x0100)
        with self.assertRaisesRegex(GuardViolation, "identity"): authorize_upstream(packet(DEVICE_CONNECT, bad), bad_state)

    def test_exact_bulk_prefix_order_replay_and_mutation(self):
        self.assertEqual(authorize_guest(bulk(1, b"\xe5"), self.state), "goodix-wake-e5")
        self.assertEqual(authorize_guest(bulk(1, GOODIX_A8), self.state), "goodix-usb-a8-64")
        with self.assertRaises(GuardViolation): authorize_guest(bulk(1, GOODIX_A8), self.state)
        for first in (GOODIX_A8, b"\xe4", b"\xe5\0"):
            state = GuardState(); state.bulk_header_size = 10; state.device_connected = True
            with self.assertRaises(GuardViolation): authorize_guest(bulk(1, first), state)
        state = GuardState(); state.bulk_header_size = 10; state.device_connected = True
        authorize_guest(bulk(1, b"\xe5"), state)
        changed = bytearray(GOODIX_A8); changed[-1] = 1
        with self.assertRaises(GuardViolation): authorize_guest(bulk(1, bytes(changed)), state)

    def test_endpoint_stream_and_length_matrix(self):
        with self.assertRaises(GuardViolation): authorize_guest(bulk(2, b"\xe5"), self.state)
        malformed = packet(BULK_PACKET, struct.pack("<BBHIH", 1, 0, 2, 0, 0) + b"\xe5")
        with self.assertRaises(GuardViolation): authorize_guest(malformed, self.state)
        streamed = packet(BULK_PACKET, struct.pack("<BBHIH", 1, 0, 1, 1, 0) + b"\xe5")
        with self.assertRaisesRegex(GuardViolation, "stream"): authorize_guest(streamed, self.state)
        self.assertEqual(authorize_guest(bulk(0x82, requested=0x8000), self.state), "bulk-in-request")
        with self.assertRaises(GuardViolation): authorize_guest(bulk(0x82, requested=0x8001), self.state)

    def test_standard_control_matrix_denies_class_vendor_and_out(self):
        allowed_in = struct.pack("<BBBBHHH", 0x80, 6, 0x80, 0, 0x100, 0, 18)
        self.assertEqual(authorize_guest(packet(CONTROL_PACKET, allowed_in), self.state), "standard-enumeration-control")
        set_address = struct.pack("<BBBBHHH", 0, 5, 0, 0, 3, 0, 0)
        self.assertEqual(authorize_guest(packet(CONTROL_PACKET, set_address), self.state), "standard-enumeration-control")
        for request_type, request in ((0x40, 1), (0xc0, 1), (0x20, 1), (0, 3), (0, 9)):
            body = struct.pack("<BBBBHHH", request_type & 0x80, request, request_type, 0, 0, 0, 0)
            with self.assertRaises(GuardViolation): authorize_guest(packet(CONTROL_PACKET, body), self.state)

    def test_exact_device_filter_only_once(self):
        body = struct.pack("<iiiii", -1, 0x27c6, 0x5503, -1, 1)
        self.assertEqual(authorize_guest(packet(FILTER_FILTER, body), self.state), "exact-goodix-device-filter")
        with self.assertRaises(GuardViolation): authorize_guest(packet(FILTER_FILTER, body), self.state)
        other = GuardState()
        with self.assertRaises(GuardViolation): authorize_guest(packet(FILTER_FILTER, bytes([body[0] ^ 1]) + body[1:]), other)

    def test_stream_control_and_unknown_denied(self):
        for kind in (12, 17, 18, 102, 999):
            with self.assertRaises(GuardViolation): authorize_guest(packet(kind), self.state)


class IntegrationTests(unittest.TestCase):
    def test_denied_packet_forwards_zero_bytes_upstream(self):
        guest_guard, guest_peer = socket.socketpair()
        upstream_guard, upstream_peer = socket.socketpair()
        upstream_peer.settimeout(1)
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            audit = AuditLog(audit_path)
            guard = UsbRedirGuard(guest_guard, upstream_guard, audit, 1)
            thread = threading.Thread(target=guard.run); thread.start()
            guest_peer.sendall(hello()); upstream_peer.sendall(hello())
            self.assertEqual(recv_exact(upstream_peer, len(hello())), hello())
            self.assertEqual(recv_exact(guest_peer, len(hello())), hello())
            connect = frame(DEVICE_CONNECT, struct.pack("<BBBBHHH", 2, 0, 0, 0, 0x27c6, 0x5503, 0x100), 1, True)
            upstream_peer.sendall(connect)
            self.assertEqual(recv_exact(guest_peer, len(connect)), connect)
            wake = bulk(1, b"\xe5").raw
            guest_peer.sendall(wake); self.assertEqual(recv_exact(upstream_peer, len(wake)), wake)
            denied = bulk(1, b"\xe0persistent").raw
            guest_peer.sendall(denied)
            # Guard closes without forwarding any byte of the denied frame.
            self.assertEqual(upstream_peer.recv(1), b"")
            thread.join(2); self.assertFalse(thread.is_alive())
            audit.close()
            self.assertEqual(os.stat(audit_path).st_mode & 0o777, 0o600)
            text = audit_path.read_text()
            self.assertIn('"decision":"deny"', text)
            self.assertNotIn("persistent", text)
        guest_peer.close(); upstream_peer.close()


if __name__ == "__main__": unittest.main()
