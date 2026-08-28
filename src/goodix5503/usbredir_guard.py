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
CAP_64BIT_IDS: Final = 5
CAP_32BIT_BULK_LENGTH: Final = 6
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
        self.hellos: dict[str, int] = {}
        self.header_size = 12
        self.bulk_header_size = 8
        self.negotiated_caps = 0
        self.device_connected = False
        self.filter_seen = False
        self.prefix_step = 0
        self.buffered = 0
        self.stopped = False

    def register_hello(self, direction: str, body: bytes) -> None:
        if len(body) < 64 or (len(body) - 64) % 4 or b"\0" not in body[:64]:
            raise GuardViolation("malformed hello")
        caps = 0
        for (word,) in struct.iter_unpack("<I", body[64:]):
            caps |= word
        with self.condition:
            if direction in self.hellos:
                raise GuardViolation("duplicate hello")
            self.hellos[direction] = caps
            if len(self.hellos) == 2:
                negotiated = self.hellos["guest"] & self.hellos["upstream"]
                self.negotiated_caps = negotiated
                self.header_size = 16 if negotiated & (1 << CAP_64BIT_IDS) else 12
                self.bulk_header_size = 10 if negotiated & (1 << CAP_32BIT_BULK_LENGTH) else 8
                self.condition.notify_all()

    def wait_negotiated(self) -> None:
        with self.condition:
            if len(self.hellos) != 2:
                if not self.condition.wait_for(lambda: len(self.hellos) == 2 or self.stopped, DEFAULT_TIMEOUT):
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
        count = sock.recv_into(view[offset:])
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


def _validate_control(packet: Packet, *, response: bool = False) -> None:
    if len(packet.body) < 10:
        raise GuardViolation("short control header")
    endpoint, request, request_type, status, value, index, length = struct.unpack("<BBBBHHH", packet.body[:10])
    data = packet.body[10:]
    if status != 0 or request_type & 0x60:
        raise GuardViolation("class/vendor control denied")
    direction_in = bool(request_type & 0x80)
    if endpoint not in (0, 0x80):
        raise GuardViolation("control endpoint denied")
    if direction_in:
        if request not in (0, 6, 8, 10) or length > 4096:
            raise GuardViolation("standard control IN denied")
        if (response and len(data) != length) or (not response and data):
            raise GuardViolation("standard control IN data length denied")
    else:
        # SET_ADDRESS is normally emulated by QEMU; it is the sole safe OUT tuple.
        if not (request == 5 and request_type == 0 and index == 0 and length == 0 and not data and value <= 127):
            raise GuardViolation("standard control OUT denied")


def authorize_guest(packet: Packet, state: GuardState) -> str:
    if packet.type == HELLO:
        raise GuardViolation("duplicate hello")
    if state.prefix_step == 2:
        raise GuardViolation("audited prefix complete")
    if packet.type == FILTER_FILTER:
        expected = struct.pack("<iiiii", -1, 0x27C6, 0x5503, -1, 1)
        if state.filter_seen or packet.body != expected:
            raise GuardViolation("device filter denied")
        state.filter_seen = True
        return "exact-goodix-device-filter"
    if not state.device_connected:
        raise GuardViolation("guest operation before device identity")
    if packet.type == SET_CONFIGURATION:
        if packet.body != b"\x01": raise GuardViolation("configuration denied")
        return "set-configuration-1"
    if packet.type == GET_CONFIGURATION:
        if packet.body: raise GuardViolation("malformed get-configuration")
        return "get-configuration"
    if packet.type == SET_ALT_SETTING:
        if packet.body != b"\x00\x00": raise GuardViolation("alternate setting denied")
        return "set-interface-0-alt-0"
    if packet.type == GET_ALT_SETTING:
        if packet.body != b"\x00": raise GuardViolation("alternate query denied")
        return "get-interface-0-alt"
    if packet.type == START_BULK_RECEIVING:
        if len(packet.body) != 10: raise GuardViolation("malformed bulk receiver")
        stream_id, amount, endpoint, count = struct.unpack("<IIBB", packet.body)
        if stream_id != 0 or amount != 0x8000 or endpoint != 0x82 or not 1 <= count <= 8:
            raise GuardViolation("bulk receiver policy denied")
        return "bulk-in-32k-receiver"
    if packet.type == STOP_BULK_RECEIVING:
        if packet.body != struct.pack("<IB", 0, 0x82): raise GuardViolation("bulk stop denied")
        return "stop-bulk-in-receiver"
    if packet.type == CONTROL_PACKET:
        _validate_control(packet)
        return "standard-enumeration-control"
    if packet.type == BULK_PACKET:
        endpoint, status, length, _, data = _bulk_fields(packet, state)
        if status != 0: raise GuardViolation("bulk request status denied")
        if endpoint == 0x82:
            if data or length > 0x8000:
                raise GuardViolation("bulk IN request denied")
            return "bulk-in-request"
        if endpoint != 0x01 or length != len(data): raise GuardViolation("bulk OUT endpoint/length denied")
        expected = b"\xe5" if state.prefix_step == 0 else GOODIX_A8 if state.prefix_step == 1 else None
        if expected is None or data != expected:
            raise GuardViolation("bulk OUT prefix denied")
        state.prefix_step += 1
        return "goodix-wake-e5" if state.prefix_step == 1 else "goodix-usb-a8-64"
    raise GuardViolation(f"guest packet type {packet.type} denied")


def authorize_upstream(packet: Packet, state: GuardState) -> str:
    if packet.type == HELLO:
        raise GuardViolation("duplicate hello")
    if packet.type == DEVICE_CONNECT:
        if state.device_connected or len(packet.body) != 10:
            raise GuardViolation("invalid device connect")
        _, _, _, _, vendor, product, _ = struct.unpack("<BBBBHHH", packet.body)
        if (vendor, product) != (0x27C6, 0x5503):
            raise GuardViolation("device identity mismatch")
        state.device_connected = True
        return "goodix-27c6-5503"
    if not state.device_connected:
        raise GuardViolation("packet before device identity")
    if packet.type == INTERFACE_INFO:
        if len(packet.body) != 132: raise GuardViolation("malformed interface info")
        return "upstream-interface-info"
    if packet.type == EP_INFO:
        expected = 96
        if state.negotiated_caps & (1 << 4): expected += 64
        if state.negotiated_caps & 1: expected += 128
        if len(packet.body) != expected: raise GuardViolation("malformed endpoint info")
        return "upstream-endpoint-info"
    expected_lengths = {CONFIGURATION_STATUS: 2, ALT_SETTING_STATUS: 3,
                        BULK_RECEIVING_STATUS: 6, DEVICE_DISCONNECT: 0,
                        DEVICE_DISCONNECT_ACK: 0, FILTER_REJECT: 0}
    if packet.type in expected_lengths:
        if len(packet.body) != expected_lengths[packet.type]:
            raise GuardViolation("malformed upstream protocol packet")
        return "upstream-protocol"
    if packet.type == CONTROL_PACKET:
        _validate_control(packet, response=True)
        return "standard-control-response"
    if packet.type == BULK_PACKET:
        endpoint, _, length, _, data = _bulk_fields(packet, state)
        if endpoint == 0x82 and length == len(data) and length <= 0x8000:
            return "bulk-in-response"
        if endpoint == 0x01 and length == 0 and not data:
            return "bulk-out-completion"
        raise GuardViolation("upstream bulk endpoint/length denied")
    if packet.type == BUFFERED_BULK_PACKET:
        if len(packet.body) < 10: raise GuardViolation("short buffered bulk")
        stream_id, length, endpoint, _ = struct.unpack("<IIBB", packet.body[:10])
        if stream_id or endpoint != 0x82 or length != len(packet.body[10:]) or length > 0x8000:
            raise GuardViolation("buffered bulk denied")
        return "buffered-bulk-in"
    raise GuardViolation(f"upstream packet type {packet.type} denied")


class UsbRedirGuard:
    def __init__(self, guest: socket.socket, upstream: socket.socket, audit: AuditLog, timeout: float):
        self.guest, self.upstream, self.audit = guest, upstream, audit
        self.state = GuardState()
        self.timeout = timeout
        self.guest.settimeout(timeout)
        self.upstream.settimeout(timeout)
        self._failure: BaseException | None = None

    def _pump(self, direction: str, source: socket.socket, target: socket.socket) -> None:
        try:
            source.settimeout(self.timeout)
            packet = read_packet(source, self.state, initial=True)
            if packet.type != HELLO:
                raise GuardViolation("first packet is not hello")
            self.state.register_hello(direction, packet.body)
            target.sendall(packet.raw)
            self.audit.record(direction, packet, "allow", "hello")
            self.state.wait_negotiated()
            while True:
                packet = read_packet(source, self.state, initial=False)
                policy = authorize_guest(packet, self.state) if direction == "guest" else authorize_upstream(packet, self.state)
                target.sendall(packet.raw)
                self.audit.record(direction, packet, "allow", "policy", policy)
        except BaseException as exc:
            self._failure = self._failure or exc
            try: self.audit.record(direction, locals().get("packet"), "deny", str(exc))
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
                   threading.Thread(target=self._pump, args=("upstream", self.upstream, self.guest))]
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
