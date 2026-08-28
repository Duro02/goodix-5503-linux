"""Fail-closed usbredir guard for the fixed Goodix 27c6:5503 loader prefix.

This proxy is intentionally not a general USB firewall.  It forwards only USB
setup needed to enumerate the pinned device and exactly two bulk-OUT transfers:
``e5`` followed by the pinned 64-byte Geneva A8 request.  The next guest
packet, TLS, streams, and unknown protocol operations terminate both connections.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .security import disable_core_dumps

MAX_FRAME: Final = 65_536
MAX_BUFFERED: Final = 2 * MAX_FRAME
DEFAULT_TIMEOUT: Final = 2.0
HELLO: Final = 0
DEVICE_CONNECT: Final = 1
DEVICE_DISCONNECT: Final = 2
RESET: Final = 3
INTERFACE_INFO: Final = 4
EP_INFO: Final = 5
SET_CONFIGURATION: Final = 6
GET_CONFIGURATION: Final = 7
CONFIGURATION_STATUS: Final = 8
SET_ALT_SETTING: Final = 9
GET_ALT_SETTING: Final = 10
ALT_SETTING_STATUS: Final = 11
CANCEL_DATA_PACKET: Final = 21
FILTER_REJECT: Final = 22
FILTER_FILTER: Final = 23
DEVICE_DISCONNECT_ACK: Final = 24
START_BULK_RECEIVING: Final = 25
STOP_BULK_RECEIVING: Final = 26
BULK_RECEIVING_STATUS: Final = 27
CONTROL_PACKET: Final = 100
BULK_PACKET: Final = 101
BUFFERED_BULK_PACKET: Final = 104
CAP_DEVICE_VERSION: Final = 1
CAP_EP_MAX_PACKET: Final = 4
CAP_64BIT_IDS: Final = 5
CAP_32BIT_BULK_LENGTH: Final = 6
_KNOWN_CAPS: Final = 0xFF
GOODIX_A8: Final = bytes.fromhex("0a0a0a0aa80300000001") + bytes(54)


class GuardViolation(RuntimeError):
    """A protocol or policy violation that closes both streams."""


@dataclass(frozen=True)
class Packet:
    type: int
    packet_id: int
    body: bytes
    raw: bytes


class AuditLog:
    def __init__(self, path: Path):
        parent = path.parent
        parent_stat = parent.lstat()
        if not parent.is_dir() or parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o077:
            raise PermissionError("audit parent must be an owner-only directory owned by this user")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        self._fd = os.open(path, flags, 0o600)
        os.fchmod(self._fd, 0o600)
        self._lock = threading.Lock()

    def record(self, direction: str, packet: Packet | None, decision: str, reason: str, policy: str = "") -> None:
        event: dict[str, object] = {
            "time_ns": time.time_ns(), "direction": direction,
            "decision": decision, "reason": reason,
        }
        if packet is not None:
            event.update(type=packet.type, id=packet.packet_id, length=len(packet.body),
                         sha256=hashlib.sha256(packet.raw).hexdigest())
        if policy:
            event["policy"] = policy
        line = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        with self._lock:
            view = memoryview(line)
            while view:
                written = os.write(self._fd, view)
                if written <= 0:
                    raise OSError("audit write made no progress")
                view = view[written:]
            os.fsync(self._fd)

    def close(self) -> None:
        os.close(self._fd)


class GuardState:
    def __init__(self):
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.hellos: dict[str, tuple[int, ...]] = {}
        self.hello_packets: dict[str, Packet] = {}
        self.header_size = 12
        self.bulk_header_size = 8
        self.negotiated_caps = 0
        self.device_connected = False
        self.identity_pinned = False
        self.interface_valid = False
        self.endpoints_valid = False
        self.awaiting_connect = False
        self.filter_seen = False
        self.reset_count = 0
        self.prefix_step = 0
        self.pending_out: tuple[int, str] | None = None
        self.pending_controls: dict[int, tuple[int, int, int, int, int, int]] = {}
        self.pending_status: dict[int, tuple[str, bytes]] = {}
        self.a8_deadline: float | None = None
        self.a8_timeout = DEFAULT_TIMEOUT
        self.negotiation_timeout = DEFAULT_TIMEOUT
        self.a8_completed = False
        self.buffered = 0
        self.stopped = False

    def register_hello(self, direction: str, packet: Packet) -> None:
        body = packet.body
        if len(body) != 68 or b"\0" not in body[:64]:
            raise GuardViolation("hello must contain exactly one capability word")
        caps = struct.unpack("<I", body[64:])[0]
        if caps & ~_KNOWN_CAPS:
            raise GuardViolation("unknown hello capability")
        with self.condition:
            if direction in self.hellos:
                raise GuardViolation("duplicate hello")
            self.hellos[direction] = (caps,)
            self.hello_packets[direction] = packet
            if len(self.hellos) == 2:
                negotiated = self.hellos["guest"][0] & self.hellos["upstream"][0]
                if negotiated & 1:
                    raise GuardViolation("bulk streams capability denied")
                self.negotiated_caps = negotiated
                self.header_size = 16 if negotiated & (1 << CAP_64BIT_IDS) else 12
                self.bulk_header_size = 10 if negotiated & (1 << CAP_32BIT_BULK_LENGTH) else 8
                self.condition.notify_all()

    def wait_negotiated(self) -> None:
        with self.condition:
            if len(self.hellos) != 2:
                if not self.condition.wait_for(lambda: len(self.hellos) == 2 or self.stopped, self.negotiation_timeout):
                    raise GuardViolation("hello negotiation timeout")
            if self.stopped:
                raise GuardViolation("guard stopped")

    def reserve(self, amount: int) -> None:
        with self.lock:
            if self.buffered + amount > MAX_BUFFERED:
                raise GuardViolation("global buffer limit exceeded")
            self.buffered += amount

    def release(self, amount: int) -> None:
        with self.lock:
            self.buffered -= amount


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray(size)
    view = memoryview(data)
    offset = 0
    while offset < size:
        try:
            count = sock.recv_into(view[offset:])
        except TimeoutError as exc:
            data[:] = bytes(len(data))
            raise GuardViolation("stream timeout") from exc
        if count == 0:
            data[:] = bytes(len(data))
            raise GuardViolation("unexpected EOF")
        offset += count
    return bytes(data)


def read_packet(sock: socket.socket, state: GuardState, initial: bool) -> Packet:
    header_size = 12 if initial else state.header_size
    header = _recv_exact(sock, header_size)
    if header_size == 12:
        packet_type, length, packet_id = struct.unpack("<III", header)
    else:
        packet_type, length, packet_id = struct.unpack("<IIQ", header)
    if length > MAX_FRAME - header_size:
        raise GuardViolation("frame exceeds 64 KiB")
    total = header_size + length
    state.reserve(total)
    try:
        body = _recv_exact(sock, length)
        raw = header + body
        return Packet(packet_type, packet_id, body, raw)
    finally:
        state.release(total)


def _bulk_fields(packet: Packet, state: GuardState) -> tuple[int, int, int, int, bytes]:
    size = state.bulk_header_size
    if len(packet.body) < size:
        raise GuardViolation("short bulk header")
    endpoint, status, low, stream_id = struct.unpack("<BBHI", packet.body[:8])
    high = struct.unpack("<H", packet.body[8:10])[0] if size == 10 else 0
    length = low | (high << 16)
    data = packet.body[size:]
    if stream_id != 0:
        raise GuardViolation("nonzero bulk stream denied")
    return endpoint, status, length, stream_id, data


def _control_fields(packet: Packet) -> tuple[int, int, int, int, int, int, int, bytes]:
    if len(packet.body) < 10:
        raise GuardViolation("short control header")
    fields = struct.unpack("<BBBBHHH", packet.body[:10])
    return (*fields, packet.body[10:])


def _authorize_control_request(packet: Packet, state: GuardState) -> str:
    endpoint, request, request_type, status, value, index, length, data = _control_fields(packet)
    if status != 0 or request_type & 0x60 or data:
        raise GuardViolation("class/vendor or data-bearing control denied")
    allowed = False
    if (endpoint, request, request_type, value, index, length) == (0x80, 0, 0x80, 0, 0, 2):
        allowed = True  # GET_STATUS(device)
    elif endpoint == 0x80 and request == 6 and request_type == 0x80:
        descriptor_type = value >> 8
        allowed = descriptor_type in (1, 2, 3, 6, 7, 15) and 0 < length <= 4096
    elif (endpoint, request, request_type, value, index, length) == (0x80, 8, 0x80, 0, 0, 1):
        allowed = True  # GET_CONFIGURATION
    elif (endpoint, request, request_type, value, index, length) == (0x80, 10, 0x81, 0, 0, 1):
        allowed = True  # GET_INTERFACE(interface 0)
    elif endpoint == 0 and request == 5 and request_type == 0 and index == 0 and length == 0:
        allowed = value <= 127  # SET_ADDRESS
    if not allowed or packet.packet_id in state.pending_controls:
        raise GuardViolation("standard control tuple denied")
    state.pending_controls[packet.packet_id] = (endpoint, request, request_type, value, index, length)
    return "standard-enumeration-control"


def _authorize_control_response(packet: Packet, state: GuardState) -> str:
    endpoint, request, request_type, status, value, index, length, data = _control_fields(packet)
    pending = state.pending_controls.pop(packet.packet_id, None)
    if pending is None:
        raise GuardViolation("unmatched control response id")
    expected_endpoint, expected_request, expected_type, expected_value, expected_index, requested = pending
    if (endpoint, request, request_type, value, index) != (
        expected_endpoint, expected_request, expected_type, expected_value, expected_index
    ) or status != 0:
        raise GuardViolation("control response mismatch or failure")
    if request_type & 0x80:
        if length != len(data) or length > requested:
            raise GuardViolation("control response length denied")
    elif length or data:
        raise GuardViolation("control OUT completion data denied")
    return "standard-control-response"


def _expected_interface_info() -> bytes:
    return struct.pack("<I", 1) + bytes(32) + bytes([0xFF]) + bytes(31) + bytes(64)


def _expected_ep_info() -> bytes:
    # usbredirhost EP2I: OUT n -> n, IN n -> 16+n. Endpoints 0/16 are control.
    types = bytearray([0xFF] * 32)
    types[0] = types[16] = 0
    types[1] = types[18] = 2
    intervals = bytes(32)
    interfaces = bytes(32)
    max_packets = [0] * 32
    max_packets[1] = max_packets[18] = 512
    return bytes(types) + intervals + interfaces + struct.pack("<32H", *max_packets)


def authorize_guest(packet: Packet, state: GuardState) -> str:
    if packet.type == HELLO:
        raise GuardViolation("duplicate hello")
    if state.prefix_step == 2:
        raise GuardViolation("awaiting A8 completion; further guest traffic denied")
    if packet.type == FILTER_FILTER:
        # usbredir serializes filter rules as a NUL-terminated text string.
        # This is the exact form emitted by pinned QEMU/libvirt for our rule.
        expected = b"-1,0x27c6,0x5503,-1,1\x00"
        if state.filter_seen or packet.body != expected:
            raise GuardViolation("device filter denied")
        state.filter_seen = True
        return "exact-goodix-device-filter"
    if packet.type == RESET:
        # QEMU can issue the next enumeration reset while usbredirhost is still
        # re-announcing topology from the previous one. The connection's exact
        # topology was already pinned and cannot change during this exchange.
        if state.reset_count >= 3 or packet.body or state.prefix_step or state.pending_out is not None:
            raise GuardViolation("USB enumeration reset denied")
        state.reset_count += 1
        state.device_connected = False
        return "bounded-enumeration-usb-reset"
    if packet.type == CONTROL_PACKET and state.identity_pinned:
        return _authorize_control_request(packet, state)
    if not state.device_connected or not state.interface_valid or not state.endpoints_valid:
        raise GuardViolation("guest operation before pinned topology")
    if packet.type == SET_CONFIGURATION:
        if packet.body != b"\x01" or packet.packet_id in state.pending_status:
            raise GuardViolation("configuration denied")
        state.pending_status[packet.packet_id] = ("configuration", b"\x00\x01")
        return "set-configuration-1"
    if packet.type == GET_CONFIGURATION:
        if packet.body or packet.packet_id in state.pending_status:
            raise GuardViolation("malformed get-configuration")
        state.pending_status[packet.packet_id] = ("configuration", b"\x00\x01")
        return "get-configuration"
    if packet.type == SET_ALT_SETTING:
        if packet.body != b"\x00\x00" or packet.packet_id in state.pending_status:
            raise GuardViolation("alternate setting denied")
        state.pending_status[packet.packet_id] = ("alternate", b"\x00\x00\x00")
        return "set-interface-0-alt-0"
    if packet.type == GET_ALT_SETTING:
        if packet.body != b"\x00" or packet.packet_id in state.pending_status:
            raise GuardViolation("alternate query denied")
        state.pending_status[packet.packet_id] = ("alternate", b"\x00\x00\x00")
        return "get-interface-0-alt"
    if packet.type == START_BULK_RECEIVING:
        if len(packet.body) != 10 or packet.packet_id in state.pending_status:
            raise GuardViolation("malformed bulk receiver")
        stream_id, amount, endpoint, count = struct.unpack("<IIBB", packet.body)
        if stream_id != 0 or amount != 0x8000 or endpoint != 0x82 or not 1 <= count <= 8:
            raise GuardViolation("bulk receiver policy denied")
        state.pending_status[packet.packet_id] = ("bulk-receiving", struct.pack("<IBB", 0, 0x82, 0))
        return "bulk-in-32k-receiver"
    if packet.type == STOP_BULK_RECEIVING:
        if packet.body != struct.pack("<IB", 0, 0x82) or packet.packet_id in state.pending_status:
            raise GuardViolation("bulk stop denied")
        state.pending_status[packet.packet_id] = ("bulk-receiving", struct.pack("<IBB", 0, 0x82, 0))
        return "stop-bulk-in-receiver"
    if packet.type == BULK_PACKET:
        endpoint, status, length, _, data = _bulk_fields(packet, state)
        if status != 0 or endpoint != 0x01 or length != len(data):
            raise GuardViolation("only exact bulk OUT endpoint 01 is permitted")
        if state.pending_out is not None:
            raise GuardViolation("overlapping bulk OUT denied")
        expected = b"\xe5" if state.prefix_step == 0 else GOODIX_A8 if state.prefix_step == 1 else None
        if expected is None or data != expected:
            raise GuardViolation("bulk OUT prefix denied")
        kind = "wake" if state.prefix_step == 0 else "a8"
        state.pending_out = (packet.packet_id, kind)
        state.prefix_step += 1
        if kind == "a8":
            state.a8_deadline = time.monotonic() + state.a8_timeout
        return "goodix-wake-e5" if kind == "wake" else "goodix-usb-a8-64"
    raise GuardViolation(f"guest packet type {packet.type} denied")


def authorize_upstream(packet: Packet, state: GuardState) -> str:
    if packet.type == HELLO:
        raise GuardViolation("duplicate hello")
    # usbredirhost sends interface and endpoint information immediately before
    # DEVICE_CONNECT so QEMU can apply its device filter at connect time.
    if packet.type == INTERFACE_INFO:
        if state.prefix_step or packet.body != _expected_interface_info():
            raise GuardViolation("interface 0 topology mismatch")
        state.device_connected = False
        state.interface_valid = True
        state.endpoints_valid = False
        return "interface0-vendor-specific"
    if packet.type == EP_INFO:
        if state.prefix_step or not state.interface_valid:
            raise GuardViolation("endpoint info order denied")
        if not state.negotiated_caps & (1 << CAP_EP_MAX_PACKET) or packet.body != _expected_ep_info():
            raise GuardViolation("endpoint topology mismatch")
        state.endpoints_valid = True
        state.awaiting_connect = True
        return "bulk-out01-in82-maxpacket512"
    if packet.type == DEVICE_CONNECT:
        expected_length = 10 if state.negotiated_caps & (1 << CAP_DEVICE_VERSION) else 8
        if state.prefix_step or not state.interface_valid or not state.endpoints_valid or not state.awaiting_connect or len(packet.body) != expected_length:
            raise GuardViolation("invalid device connect")
        fields = struct.unpack("<BBBBHH", packet.body[:8])
        if fields[:4] != (2, 0, 0, 0) or fields[4:6] != (0x27C6, 0x5503):
            raise GuardViolation("device identity or USB topology mismatch")
        state.device_connected = True
        state.identity_pinned = True
        state.awaiting_connect = False
        return "goodix-27c6-5503"
    if not state.device_connected:
        raise GuardViolation("packet before device identity")
    status_types = {CONFIGURATION_STATUS: "configuration", ALT_SETTING_STATUS: "alternate",
                    BULK_RECEIVING_STATUS: "bulk-receiving"}
    if packet.type in status_types:
        pending = state.pending_status.pop(packet.packet_id, None)
        if pending != (status_types[packet.type], packet.body):
            raise GuardViolation("unmatched or failed protocol status")
        return "matched-protocol-status"
    if packet.type == CONTROL_PACKET:
        return _authorize_control_response(packet, state)
    if packet.type == BULK_PACKET:
        endpoint, status, length, _, data = _bulk_fields(packet, state)
        if endpoint != 0x01 or status != 0 or length != 0 or data:
            raise GuardViolation("only successful OUT completion is permitted")
        if state.pending_out is None or packet.packet_id != state.pending_out[0]:
            raise GuardViolation("unmatched bulk OUT completion")
        kind = state.pending_out[1]
        state.pending_out = None
        if kind == "a8":
            state.a8_completed = True
            return "a8-out-completion-close"
        return "wake-out-completion"
    if packet.type == BUFFERED_BULK_PACKET:
        if len(packet.body) < 10:
            raise GuardViolation("short buffered bulk")
        stream_id, length, endpoint, status = struct.unpack("<IIBB", packet.body[:10])
        if stream_id or endpoint != 0x82 or status != 0 or length != len(packet.body[10:]) or length > 0x8000:
            raise GuardViolation("buffered bulk denied")
        return "buffered-bulk-in"
    raise GuardViolation(f"upstream packet type {packet.type} denied")


class UsbRedirGuard:
    def __init__(self, guest: socket.socket, upstream: socket.socket, audit: AuditLog, timeout: float):
        self.guest, self.upstream, self.audit = guest, upstream, audit
        self.state = GuardState()
        self.state.a8_timeout = timeout
        self.state.negotiation_timeout = timeout
        self.timeout = timeout
        self.guest.settimeout(timeout)
        self.upstream.settimeout(timeout)
        self._failure: BaseException | None = None

    def _pump(self, direction: str, source: socket.socket, target: socket.socket) -> None:
        packet: Packet | None = None
        try:
            source.settimeout(self.timeout)
            packet = read_packet(source, self.state, initial=True)
            if packet.type != HELLO:
                raise GuardViolation("first packet is not hello")
            self.state.register_hello(direction, packet)
            self.state.wait_negotiated()
            self.audit.record(direction, packet, "authorize", "both hellos validated")
            target.sendall(packet.raw)
            self.audit.record(direction, packet, "forwarded", "hello")
            while True:
                packet = None
                packet = read_packet(source, self.state, initial=False)
                with self.state.condition:
                    policy = (authorize_guest(packet, self.state) if direction == "guest"
                              else authorize_upstream(packet, self.state))
                    completion_close = direction == "upstream" and self.state.a8_completed
                    self.state.condition.notify_all()
                    self.audit.record(direction, packet, "authorize", "policy", policy)
                    target.sendall(packet.raw)
                    self.audit.record(direction, packet, "forwarded", "policy", policy)
                if completion_close:
                    self.close()
                    return
        except BaseException as exc:
            with self.state.lock:
                already_stopped = self.state.stopped
            if already_stopped:
                return
            self._failure = self._failure or exc
            try: self.audit.record(direction, packet, "deny", str(exc))
            except BaseException: pass
            self.close()

    def _completion_watchdog(self) -> None:
        try:
            with self.state.condition:
                while not self.state.stopped and self.state.a8_deadline is None:
                    self.state.condition.wait()
                while not self.state.stopped and not self.state.a8_completed:
                    remaining = self.state.a8_deadline - time.monotonic()  # type: ignore[operator]
                    if remaining <= 0:
                        raise GuardViolation("A8 completion timeout")
                    self.state.condition.wait(remaining)
        except BaseException as exc:
            self._failure = self._failure or exc
            try: self.audit.record("guard", None, "deny", str(exc))
            except BaseException: pass
            self.close()

    def close(self) -> None:
        with self.state.condition:
            self.state.stopped = True
            self.state.condition.notify_all()
        for sock in (self.guest, self.upstream):
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: sock.close()
            except OSError: pass

    def run(self) -> None:
        threads = [threading.Thread(target=self._pump, args=("guest", self.guest, self.upstream)),
                   threading.Thread(target=self._pump, args=("upstream", self.upstream, self.guest)),
                   threading.Thread(target=self._completion_watchdog)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        if self._failure and not isinstance(self._failure, GuardViolation):
            raise self._failure


def _endpoint(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or host not in ("127.0.0.1", "localhost"):
        raise argparse.ArgumentTypeError("endpoint must be loopback HOST:PORT")
    return "127.0.0.1", int(port)


def main(argv: list[str] | None = None) -> int:
    disable_core_dumps()
    if sys.byteorder != "little":
        raise SystemExit("usbredir guard supports little-endian hosts only")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", type=_endpoint, required=True)
    parser.add_argument("--upstream", type=_endpoint, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.listen == args.upstream:
        parser.error("timeout must be positive and endpoints must differ")
    audit = AuditLog(args.audit)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(args.listen)
    listener.listen(1)
    listener.settimeout(args.timeout)
    try:
        upstream = socket.create_connection(args.upstream, args.timeout)
        guest, _ = listener.accept()
        listener.close()  # Exactly one guest; no reconnect.
        UsbRedirGuard(guest, upstream, audit, args.timeout).run()
    finally:
        listener.close()
        audit.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
