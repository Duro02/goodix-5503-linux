import hashlib
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from goodix5503.usbredir_guard import (
    ALT_SETTING_STATUS, AuditLog, BULK_PACKET, CAP_32BIT_BULK_LENGTH,
    CAP_64BIT_IDS, CONFIGURATION_STATUS, CONTROL_PACKET, DEVICE_CONNECT,
    SET_CONFIGURATION,
    EP_INFO, FILTER_FILTER, GOODIX_COMMAND00, GOODIX_COMMAND00_ACK,
    GOODIX_FIRMWARE_A8, GuardState, GuardViolation, HELLO, RESET,
    INTERFACE_INFO, MAX_FRAME, Packet, UsbRedirGuard, _expected_ep_info,
    _expected_interface_info, authorize_guest, authorize_upstream, read_packet,
)


def frame(kind, body=b"", ident=0, wide=False):
    header = struct.pack("<IIQ" if wide else "<III", kind, len(body), ident)
    return header + body


DEFAULT_CAPS = sum(1 << bit for bit in (1, 2, 4, 5, 6, 7))


def hello(caps=DEFAULT_CAPS):
    version = b"test-usbredir\0".ljust(64, b"\0")
    return frame(HELLO, version + struct.pack("<I", caps))


def packet(kind, body=b"", ident=7, wide=True):
    raw = frame(kind, body, ident, wide)
    return Packet(kind, ident, body, raw)


def bulk(endpoint, data=b"", requested=None, status=0, ident=7, wide=True):
    length = len(data) if requested is None else requested
    body = struct.pack("<BBHIH", endpoint, status, length & 0xffff, 0, length >> 16) + data
    raw = frame(BULK_PACKET, body, ident, wide)
    return Packet(BULK_PACKET, ident, body, raw)


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

    def test_audit_parent_must_be_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaises(PermissionError): AuditLog(Path(directory) / "audit.jsonl")

    def test_timeout_and_global_buffer_bound(self):
        left, right = socket.socketpair(); left.settimeout(0.01)
        with self.assertRaisesRegex(GuardViolation, "timeout"): read_packet(left, GuardState(), True)
        left.close(); right.close()
        state = GuardState(); state.reserve(2 * MAX_FRAME)
        with self.assertRaisesRegex(GuardViolation, "global buffer"):
            state.reserve(1)
        state.release(2 * MAX_FRAME)

    def test_hello_rejects_extra_or_unknown_capability_words(self):
        version = b"test\0".ljust(64, b"\0")
        for body in (version + struct.pack("<II", DEFAULT_CAPS, 0),
                     version + struct.pack("<I", DEFAULT_CAPS | (1 << 8))):
            state = GuardState(); raw = frame(HELLO, body)
            with self.assertRaises(GuardViolation):
                state.register_hello("guest", Packet(HELLO, 0, body, raw))

    def test_negotiation_requires_both_capabilities(self):
        state = GuardState()
        state.register_hello("guest", Packet(HELLO, 0, hello()[12:], hello()))
        state.register_hello("upstream", Packet(HELLO, 0, hello(0)[12:], hello(0)))
        self.assertEqual(state.header_size, 12)
        self.assertEqual(state.bulk_header_size, 8)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.state = GuardState(); self.state.header_size = 16; self.state.bulk_header_size = 10
        self.state.negotiated_caps = DEFAULT_CAPS
        self.state.device_connected = self.state.identity_pinned = True
        self.state.interface_valid = self.state.endpoints_valid = True

    def test_device_identity_exact_and_duplicate_denied(self):
        good = struct.pack("<BBBBHHH", 2, 0xef, 2, 1, 0x27c6, 0x5503, 0x0100)
        state = GuardState(); state.negotiated_caps = (1 << 1) | (1 << 4)
        authorize_upstream(packet(INTERFACE_INFO, _expected_interface_info()), state)
        authorize_upstream(packet(EP_INFO, _expected_ep_info()), state)
        self.assertEqual(authorize_upstream(packet(DEVICE_CONNECT, good), state), "goodix-27c6-5503")
        with self.assertRaises(GuardViolation): authorize_upstream(packet(DEVICE_CONNECT, good), state)
        bad_state = GuardState(); bad_state.negotiated_caps = (1 << 1) | (1 << 4)
        authorize_upstream(packet(INTERFACE_INFO, _expected_interface_info()), bad_state)
        authorize_upstream(packet(EP_INFO, _expected_ep_info()), bad_state)
        bad = struct.pack("<BBBBHHH", 2, 0xef, 2, 1, 0x27c6, 0x5504, 0x0100)
        with self.assertRaisesRegex(GuardViolation, "identity"): authorize_upstream(packet(DEVICE_CONNECT, bad), bad_state)

    def test_device_connect_length_follows_negotiated_cap1(self):
        body8 = struct.pack("<BBBBHH", 2, 0xef, 2, 1, 0x27c6, 0x5503)
        state = GuardState(); state.interface_valid = state.endpoints_valid = state.awaiting_connect = True
        self.assertEqual(authorize_upstream(packet(DEVICE_CONNECT, body8), state), "goodix-27c6-5503")
        for caps, body in ((0, body8 + b"\0\1"), (1 << 1, body8)):
            variant = GuardState(); variant.negotiated_caps = caps
            variant.interface_valid = variant.endpoints_valid = variant.awaiting_connect = True
            with self.assertRaises(GuardViolation): authorize_upstream(packet(DEVICE_CONNECT, body), variant)

    def test_exact_bulk_prefix_order_replay_and_mutation(self):
        self.assertEqual(GOODIX_COMMAND00[:12].hex(), "a00800a800050000000000a5")
        self.assertEqual(GOODIX_COMMAND00[12:], bytes(52))
        self.assertEqual(hashlib.sha256(GOODIX_COMMAND00).hexdigest(), "e8a1b5c35d31da88a3f96ff1995e7aee4c3d30aa9d0c31de3c5c6bdc8fe8e5aa")
        self.assertEqual(authorize_guest(bulk(1, GOODIX_COMMAND00, ident=1), self.state), "goodix-usb-outer-a0-command00-64")
        get_status = struct.pack("<BBBBHHH", 0x80, 0, 0x80, 0, 0, 0, 2)
        self.assertEqual(authorize_guest(packet(CONTROL_PACKET, get_status, ident=3), self.state), "standard-enumeration-control")
        self.assertEqual(authorize_guest(bulk(0x82, requested=0x8000, ident=4), self.state), "bounded-bulk-in-request")
        with self.assertRaises(GuardViolation): authorize_guest(packet(RESET), self.state)
        with self.assertRaises(GuardViolation): authorize_guest(packet(SET_CONFIGURATION, b"\x01", ident=5), self.state)
        exact_filter = b"-1,0x27c6,0x5503,-1,1\x00"
        with self.assertRaises(GuardViolation): authorize_guest(packet(FILTER_FILTER, exact_filter, ident=5), self.state)
        set_address = struct.pack("<BBBBHHH", 0, 5, 0, 0, 3, 0, 0)
        with self.assertRaises(GuardViolation): authorize_guest(packet(CONTROL_PACKET, set_address, ident=6), self.state)
        vendor = struct.pack("<BBBBHHH", 0, 1, 0x40, 0, 0, 0, 0)
        with self.assertRaises(GuardViolation): authorize_guest(packet(CONTROL_PACKET, vendor, ident=6), self.state)
        with self.assertRaises(GuardViolation): authorize_guest(bulk(1, GOODIX_COMMAND00, ident=2), self.state)
        with self.assertRaises(GuardViolation): authorize_upstream(bulk(1, ident=1), self.state)
        self.assertEqual(authorize_upstream(bulk(1, requested=len(GOODIX_COMMAND00), ident=1), self.state), "command00-out-completion-observe")
        self.assertEqual(authorize_upstream(bulk(0x82, GOODIX_COMMAND00_ACK, ident=4), self.state), "exact-command00-success-ack")
        self.assertEqual(authorize_guest(bulk(1, GOODIX_FIRMWARE_A8, ident=7), self.state), "goodix-usb-outer-a0-firmware-a8-64")
        with self.assertRaises(GuardViolation): authorize_guest(bulk(1, GOODIX_FIRMWARE_A8, ident=8), self.state)
        self.assertEqual(authorize_upstream(bulk(1, requested=len(GOODIX_FIRMWARE_A8), ident=7), self.state), "firmware-a8-out-completion-observe")
        for first in (b"\xe5", b"\xe4", bytes.fromhex("0a0a0a0aa80300000001") + bytes(54)):
            state = GuardState(); state.bulk_header_size = 10
            state.device_connected = state.interface_valid = state.endpoints_valid = True
            with self.assertRaises(GuardViolation): authorize_guest(bulk(1, first), state)
        state = GuardState(); state.bulk_header_size = 10
        state.device_connected = state.interface_valid = state.endpoints_valid = True
        changed = bytearray(GOODIX_COMMAND00); changed[-1] = 1
        with self.assertRaises(GuardViolation): authorize_guest(bulk(1, bytes(changed), ident=2), state)

    def test_firmware_a8_requires_exact_command00_ack(self):
        self.assertEqual(authorize_guest(bulk(1, GOODIX_COMMAND00, ident=1), self.state), "goodix-usb-outer-a0-command00-64")
        self.assertEqual(authorize_upstream(bulk(1, requested=64, ident=1), self.state), "command00-out-completion-observe")
        self.assertEqual(authorize_guest(bulk(0x82, requested=0x8000, ident=2), self.state), "bounded-bulk-in-request")
        wrong = bytearray(GOODIX_COMMAND00_ACK); wrong[-1] ^= 1
        with self.assertRaisesRegex(GuardViolation, "exact command-00 ACK"):
            authorize_upstream(bulk(0x82, bytes(wrong), ident=2), self.state)
        with self.assertRaises(GuardViolation):
            authorize_guest(bulk(1, GOODIX_FIRMWARE_A8, ident=3), self.state)

    def test_endpoint_stream_and_length_matrix(self):
        with self.assertRaises(GuardViolation): authorize_guest(bulk(2, b"\xe5"), self.state)
        malformed = packet(BULK_PACKET, struct.pack("<BBHIH", 1, 0, 2, 0, 0) + b"\xe5")
        with self.assertRaises(GuardViolation): authorize_guest(malformed, self.state)
        streamed = packet(BULK_PACKET, struct.pack("<BBHIH", 1, 0, 1, 1, 0) + b"\xe5")
        with self.assertRaisesRegex(GuardViolation, "stream"): authorize_guest(streamed, self.state)
        request = bulk(0x82, requested=0x8000, ident=50)
        self.assertEqual(authorize_guest(request, self.state), "bounded-bulk-in-request")
        with self.assertRaises(GuardViolation): authorize_guest(request, self.state)
        response = bulk(0x82, b"abc", ident=50)
        self.assertEqual(authorize_upstream(response, self.state), "matched-bulk-in-response")
        with self.assertRaises(GuardViolation): authorize_guest(bulk(0x82, requested=0x8001), self.state)

    def test_bounded_enumeration_resets_allow_exact_topology_refresh(self):
        connect = struct.pack("<BBBBHHH", 2, 0xef, 2, 1, 0x27c6, 0x5503, 0x100)
        for reset_index in range(3):
            self.assertEqual(authorize_guest(packet(RESET), self.state), "bounded-enumeration-usb-reset")
            get_status = struct.pack("<BBBBHHH", 0x80, 0, 0x80, 0, 0, 0, 2)
            control_id = 100 + reset_index
            self.assertEqual(authorize_guest(packet(CONTROL_PACKET, get_status, ident=control_id), self.state), "standard-enumeration-control")
            self.assertEqual(authorize_upstream(packet(CONTROL_PACKET, get_status + b"\0\0", ident=control_id), self.state), "standard-control-response")
            if reset_index == 0:
                self.assertEqual(authorize_guest(packet(SET_CONFIGURATION, b"\x01", ident=200), self.state), "set-configuration-1")
                self.assertEqual(authorize_upstream(packet(CONFIGURATION_STATUS, b"\x00\x01", ident=200), self.state), "matched-protocol-status")
                self.assertEqual(authorize_guest(bulk(0x82, requested=0x8000, ident=300), self.state), "bounded-bulk-in-request")
                self.assertEqual(authorize_upstream(bulk(0x82, ident=300), self.state), "matched-bulk-in-response")
            authorize_upstream(packet(INTERFACE_INFO, _expected_interface_info()), self.state)
            authorize_upstream(packet(EP_INFO, _expected_ep_info()), self.state)
            authorize_upstream(packet(DEVICE_CONNECT, connect), self.state)
        with self.assertRaises(GuardViolation):
            authorize_guest(packet(RESET), self.state)

    def test_standard_control_matrix_denies_class_vendor_and_out(self):
        allowed_in = struct.pack("<BBBBHHH", 0x80, 6, 0x80, 0, 0x100, 0, 18)
        self.assertEqual(authorize_guest(packet(CONTROL_PACKET, allowed_in, ident=8), self.state), "standard-enumeration-control")
        set_address = struct.pack("<BBBBHHH", 0, 5, 0, 0, 3, 0, 0)
        self.assertEqual(authorize_guest(packet(CONTROL_PACKET, set_address, ident=9), self.state), "standard-enumeration-control")
        for request_type, request in ((0x40, 1), (0xc0, 1), (0x20, 1), (0, 3), (0, 9)):
            body = struct.pack("<BBBBHHH", request_type & 0x80, request, request_type, 0, 0, 0, 0)
            with self.assertRaises(GuardViolation): authorize_guest(packet(CONTROL_PACKET, body), self.state)

    def test_interface_and_endpoint_topology_are_exact(self):
        state = GuardState(); state.negotiated_caps = DEFAULT_CAPS
        connect = struct.pack("<BBBBHHH", 2, 0xef, 2, 1, 0x27c6, 0x5503, 0x100)
        self.assertEqual(authorize_upstream(packet(INTERFACE_INFO, _expected_interface_info()), state), "interface0-vendor-specific")
        self.assertEqual(authorize_upstream(packet(EP_INFO, _expected_ep_info()), state), "bulk-out01-in82-maxpacket512")
        authorize_upstream(packet(DEVICE_CONNECT, connect), state)
        for mutate_interface in (True, False):
            variant = GuardState(); variant.negotiated_caps = DEFAULT_CAPS
            interface = bytearray(_expected_interface_info())
            endpoint = bytearray(_expected_ep_info())
            if mutate_interface: interface[36] = 0x0a
            else: endpoint[96 + 2] ^= 1
            if mutate_interface:
                with self.assertRaises(GuardViolation): authorize_upstream(packet(INTERFACE_INFO, bytes(interface)), variant)
            else:
                authorize_upstream(packet(INTERFACE_INFO, bytes(interface)), variant)
                with self.assertRaises(GuardViolation): authorize_upstream(packet(EP_INFO, bytes(endpoint)), variant)

    def test_exact_device_filter_only_once(self):
        body = b"-1,0x27c6,0x5503,-1,1\x00"
        self.assertEqual(authorize_guest(packet(FILTER_FILTER, body), self.state), "exact-goodix-device-filter")
        with self.assertRaises(GuardViolation): authorize_guest(packet(FILTER_FILTER, body), self.state)
        other = GuardState()
        with self.assertRaises(GuardViolation): authorize_guest(packet(FILTER_FILTER, bytes([body[0] ^ 1]) + body[1:]), other)

    def test_stream_control_and_unknown_denied(self):
        for kind in (12, 17, 18, 102, 999):
            with self.assertRaises(GuardViolation): authorize_guest(packet(kind), self.state)


class IntegrationTests(unittest.TestCase):
    def assert_closed(self, sock):
        try:
            self.assertEqual(sock.recv(1), b"")
        except ConnectionResetError:
            pass

    def _start(self, directory, timeout=1):
        guest_guard, guest_peer = socket.socketpair()
        upstream_guard, upstream_peer = socket.socketpair()
        guest_peer.settimeout(timeout); upstream_peer.settimeout(timeout)
        audit_path = Path(directory) / "audit.jsonl"
        audit = AuditLog(audit_path)
        guard = UsbRedirGuard(guest_guard, upstream_guard, audit, timeout)
        thread = threading.Thread(target=guard.run); thread.start()
        return guest_peer, upstream_peer, audit, audit_path, thread

    def _negotiate_and_topology(self, guest, upstream, *, caps=DEFAULT_CAPS, upstream_caps=None, wide=True):
        if upstream_caps is None:
            upstream_caps = caps | 1  # usbredirect advertises streams; QEMU streams=off does not.
        guest_hello = hello(caps); upstream_hello = hello(upstream_caps)
        guest.sendall(guest_hello); upstream.sendall(upstream_hello)
        self.assertEqual(recv_exact(upstream, len(guest_hello)), hello(caps & ~1))
        self.assertEqual(recv_exact(guest, len(upstream_hello)), hello(upstream_caps & ~1))
        connect_body = (struct.pack("<BBBBHHH", 2, 0xef, 2, 1, 0x27c6, 0x5503, 0x100)
                        if caps & (1 << 1) else struct.pack("<BBBBHH", 2, 0xef, 2, 1, 0x27c6, 0x5503))
        for kind, body in ((INTERFACE_INFO, _expected_interface_info()),
                           (EP_INFO, _expected_ep_info()),
                           (DEVICE_CONNECT, connect_body)):
            message = frame(kind, body, 1, wide)
            upstream.sendall(message)
            self.assertEqual(recv_exact(guest, len(message)), message)

    def test_denied_out_forwards_zero_bytes_upstream(self):
        with tempfile.TemporaryDirectory() as directory:
            guest, upstream, audit, audit_path, thread = self._start(directory)
            self._negotiate_and_topology(guest, upstream)
            denied = bulk(1, b"\xe0persistent", ident=11).raw
            guest.sendall(denied)
            self.assert_closed(upstream)
            thread.join(2); self.assertFalse(thread.is_alive())
            audit.close()
            self.assertEqual(os.stat(audit_path).st_mode & 0o777, 0o600)
            text = audit_path.read_text()
            self.assertIn('\"decision\":\"deny\"', text)
            self.assertNotIn("persistent", text)
            guest.close(); upstream.close()

    def test_denied_vendor_control_forwards_zero_bytes_upstream(self):
        with tempfile.TemporaryDirectory() as directory:
            guest, upstream, audit, _, thread = self._start(directory)
            self._negotiate_and_topology(guest, upstream)
            vendor = struct.pack("<BBBBHHH", 0, 1, 0x40, 0, 0, 0, 0)
            denied = frame(CONTROL_PACKET, vendor, 22, True)
            guest.sendall(denied)
            self.assert_closed(upstream)
            thread.join(2); self.assertFalse(thread.is_alive())
            audit.close(); guest.close(); upstream.close()

    def test_exact_command00_ack_allows_one_firmware_a8_then_denies_third_out(self):
        with tempfile.TemporaryDirectory() as directory:
            guest, upstream, audit, audit_path, thread = self._start(directory)
            self._negotiate_and_topology(guest, upstream)
            read_request = bulk(0x82, requested=0x8000, ident=10).raw
            guest.sendall(read_request); self.assertEqual(recv_exact(upstream, len(read_request)), read_request)
            outgoing = bulk(1, GOODIX_COMMAND00, ident=11).raw
            guest.sendall(outgoing); self.assertEqual(recv_exact(upstream, len(outgoing)), outgoing)
            get_status = struct.pack("<BBBBHHH", 0x80, 0, 0x80, 0, 0, 0, 2)
            control = packet(CONTROL_PACKET, get_status, ident=12).raw
            guest.sendall(control); self.assertEqual(recv_exact(upstream, len(control)), control)
            control_response = packet(CONTROL_PACKET, get_status + b"\0\0", ident=12).raw
            upstream.sendall(control_response); self.assertEqual(recv_exact(guest, len(control_response)), control_response)
            completion = bulk(1, requested=len(GOODIX_COMMAND00), ident=11).raw
            upstream.sendall(completion); self.assertEqual(recv_exact(guest, len(completion)), completion)
            response = bulk(0x82, GOODIX_COMMAND00_ACK, ident=10).raw
            upstream.sendall(response); self.assertEqual(recv_exact(guest, len(response)), response)
            next_read = bulk(0x82, requested=0x8000, ident=13).raw
            guest.sendall(next_read); self.assertEqual(recv_exact(upstream, len(next_read)), next_read)
            firmware_a8 = bulk(1, GOODIX_FIRMWARE_A8, ident=14).raw
            guest.sendall(firmware_a8); self.assertEqual(recv_exact(upstream, len(firmware_a8)), firmware_a8)
            firmware_completion = bulk(1, requested=len(GOODIX_FIRMWARE_A8), ident=14).raw
            upstream.sendall(firmware_completion); self.assertEqual(recv_exact(guest, len(firmware_completion)), firmware_completion)
            guest.sendall(bulk(1, b"forbidden", ident=15).raw)
            self.assert_closed(guest)
            self.assert_closed(upstream)
            thread.join(2); self.assertFalse(thread.is_alive())
            audit.close(); guest.close(); upstream.close()
            events = [json.loads(line) for line in audit_path.read_text().splitlines()]
            command00 = [event for event in events if event.get("policy") == "goodix-usb-outer-a0-command00-64"]
            self.assertEqual([event["decision"] for event in command00], ["authorize", "forwarded"])
            completion = [event for event in events if event.get("policy") == "command00-out-completion-observe"]
            self.assertEqual([event["decision"] for event in completion], ["authorize", "forwarded"])
            firmware = [event for event in events if event.get("policy") == "goodix-usb-outer-a0-firmware-a8-64"]
            self.assertEqual([event["decision"] for event in firmware], ["authorize", "forwarded"])

    def test_expired_deadline_denies_firmware_a8_before_forward(self):
        with tempfile.TemporaryDirectory() as directory:
            guest_guard, guest = socket.socketpair()
            upstream_guard, upstream = socket.socketpair()
            guest.settimeout(1); upstream.settimeout(1)
            audit = AuditLog(Path(directory) / "audit.jsonl")
            guard = UsbRedirGuard(guest_guard, upstream_guard, audit, 1)
            thread = threading.Thread(target=guard.run); thread.start()
            self._negotiate_and_topology(guest, upstream)
            read_request = bulk(0x82, requested=0x8000, ident=10).raw
            guest.sendall(read_request); self.assertEqual(recv_exact(upstream, len(read_request)), read_request)
            command00 = bulk(1, GOODIX_COMMAND00, ident=11).raw
            guest.sendall(command00); self.assertEqual(recv_exact(upstream, len(command00)), command00)
            completion = bulk(1, requested=64, ident=11).raw
            upstream.sendall(completion); self.assertEqual(recv_exact(guest, len(completion)), completion)
            ack = bulk(0x82, GOODIX_COMMAND00_ACK, ident=10).raw
            upstream.sendall(ack); self.assertEqual(recv_exact(guest, len(ack)), ack)
            with guard.state.condition:
                guard.state.command00_deadline = time.monotonic() - 1
            guest.sendall(bulk(1, GOODIX_FIRMWARE_A8, ident=12).raw)
            self.assert_closed(upstream)
            thread.join(1); self.assertFalse(thread.is_alive())
            audit.close(); guest.close(); upstream.close()

    def test_command00_deadline_closes_sockets_while_audit_is_blocked(self):
        class BlockingAudit:
            def __init__(self):
                self.entered = threading.Event()
                self.release = threading.Event()

            def record(self, direction, packet, decision, reason, policy=""):
                if direction == "guest" and packet is not None and packet.type == BULK_PACKET and decision == "authorize":
                    self.entered.set()
                    self.release.wait(2)

        guest_guard, guest = socket.socketpair()
        upstream_guard, upstream = socket.socketpair()
        guest.settimeout(1); upstream.settimeout(1)
        audit = BlockingAudit()
        guard = UsbRedirGuard(guest_guard, upstream_guard, audit, 0.05)
        thread = threading.Thread(target=guard.run); thread.start()
        self._negotiate_and_topology(guest, upstream)
        started = time.monotonic()
        guest.sendall(bulk(1, GOODIX_COMMAND00, ident=11).raw)
        self.assertTrue(audit.entered.wait(0.5))
        self.assert_closed(upstream)
        self.assertLess(time.monotonic() - started, 0.5)
        audit.release.set()
        thread.join(1); self.assertFalse(thread.is_alive())
        guest.close(); upstream.close()

    def test_mismatched_command00_completion_and_timeout_close(self):
        for mismatch in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                guest, upstream, audit, _, thread = self._start(directory, timeout=0.1)
                self._negotiate_and_topology(guest, upstream)
                command00 = bulk(1, GOODIX_COMMAND00, ident=11).raw
                guest.sendall(command00); recv_exact(upstream, len(command00))
                if mismatch: upstream.sendall(bulk(1, requested=len(GOODIX_COMMAND00), ident=12).raw)
                upstream.settimeout(1)
                self.assert_closed(upstream)
                thread.join(1); self.assertFalse(thread.is_alive())
                audit.close(); guest.close(); upstream.close()

    def test_bilateral_hello_withholding_and_asymmetric_cap5(self):
        with tempfile.TemporaryDirectory() as directory:
            guest, upstream, audit, _, thread = self._start(directory, timeout=0.1)
            guest.sendall(hello()); upstream.settimeout(1)
            self.assert_closed(upstream)
            thread.join(1); audit.close(); guest.close(); upstream.close()
        with tempfile.TemporaryDirectory() as directory:
            guest, upstream, audit, _, thread = self._start(directory, timeout=0.5)
            guest.sendall(hello()); upstream.settimeout(0.05)
            with self.assertRaises(TimeoutError): upstream.recv(1)
            upstream.sendall(frame(HELLO, b"bad")); upstream.settimeout(1)
            self.assert_closed(upstream)
            thread.join(1); audit.close(); guest.close(); upstream.close()
        with tempfile.TemporaryDirectory() as directory:
            guest, upstream, audit, _, thread = self._start(directory)
            guest_caps = DEFAULT_CAPS
            upstream_caps = DEFAULT_CAPS & ~(1 << CAP_64BIT_IDS)
            guest.sendall(hello(guest_caps)); upstream.sendall(hello(upstream_caps))
            self.assertEqual(recv_exact(upstream, len(hello(guest_caps))), hello(guest_caps & ~1))
            self.assertEqual(recv_exact(guest, len(hello(upstream_caps))), hello(upstream_caps & ~1))
            for kind, body in ((INTERFACE_INFO, _expected_interface_info()), (EP_INFO, _expected_ep_info())):
                message = frame(kind, body, 0, False)
                upstream.sendall(message); self.assertEqual(recv_exact(guest, len(message)), message)
            connect = frame(DEVICE_CONNECT, struct.pack("<BBBBHHH", 2, 0xef, 2, 1, 0x27c6, 0x5503, 0x100), 0xfeedbeef, False)
            upstream.sendall(connect); self.assertEqual(recv_exact(guest, len(connect)), connect)
            guest.close(); upstream.close(); thread.join(2); audit.close()


if __name__ == "__main__": unittest.main()
