"""Conservative probe for the Goodix 27c6:5503 fingerprint sensor.

The transport only permits a small command allowlist. Commands that erase or
write firmware, change PSKs, reset the MCU, or upload sensor configuration are
not implemented and are rejected before any USB transfer.

Protocol framing is based on goodix-fp-linux-dev/goodix-fp-dump (LGPL-2.1-or-
later), pinned reference commit cc43bb3b3154a0bccc0412ae024013c7e1923139.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
from dataclasses import asdict, dataclass
from typing import Final

import usb.core
import usb.util

VENDOR_ID: Final = 0x27C6
PRODUCT_ID: Final = 0x5503

FLAGS_MESSAGE_PROTOCOL: Final = 0xA0
COMMAND_NOP: Final = 0x00
COMMAND_FIRMWARE_VERSION: Final = 0xA8
COMMAND_ACK: Final = 0xB0
COMMAND_PRESET_PSK_READ: Final = 0xE4
COMMAND_GET_IAP_VERSION: Final = 0xF6

# Commands outside this set cannot reach the USB transport through request().
ALLOWED_COMMANDS: Final = frozenset(
    {
        COMMAND_NOP,
        COMMAND_FIRMWARE_VERSION,
        COMMAND_PRESET_PSK_READ,
        COMMAND_GET_IAP_VERSION,
    }
)

# Hash used by the community 5503 implementation. This is not the PSK itself.
KNOWN_5503_PMK_HASH: Final = bytes.fromhex(
    "81b8ff490612022a121a9449ee3aad2792f32b9f3141182cd01019945ee50361"
)
OFFICIAL_PSK_HASH_SELECTOR: Final = 0xBB020001


class ProtocolError(RuntimeError):
    """The device returned malformed or unexpected protocol data."""


class UnsafeCommandError(RuntimeError):
    """A command outside the non-persistent probe allowlist was requested."""


@dataclass(frozen=True)
class ProbeResult:
    vendor_id: str
    product_id: str
    bus: int | None
    address: int | None
    firmware: str
    iap: str | None
    psk_state: str


def _encode_packet(command: int, payload: bytes = b"", *, checksum: bool = True) -> bytes:
    protocol = struct.pack("<BH", command, len(payload) + 1) + payload
    trailer = (0xAA - sum(protocol)) & 0xFF if checksum else 0x88
    protocol += bytes((trailer,))

    header = struct.pack("<BH", FLAGS_MESSAGE_PROTOCOL, len(protocol))
    return header + bytes((sum(header) & 0xFF,)) + protocol


def _decode_packet(data: bytes, expected_command: int, *, checksum: bool = True) -> bytes:
    if len(data) < 8:
        raise ProtocolError("response is too short")

    flags, outer_length = struct.unpack("<BH", data[:3])
    if flags != FLAGS_MESSAGE_PROTOCOL:
        raise ProtocolError(f"unexpected packet flags: 0x{flags:02x}")
    if (sum(data[:3]) & 0xFF) != data[3]:
        raise ProtocolError("invalid packet header checksum")

    packed = data[4 : 4 + outer_length]
    if len(packed) != outer_length or len(packed) < 4:
        raise ProtocolError("truncated packet")

    command, inner_length = struct.unpack("<BH", packed[:3])
    if command != expected_command:
        raise ProtocolError(
            f"unexpected command 0x{command:02x}; expected 0x{expected_command:02x}"
        )
    if inner_length < 1 or len(packed) != 3 + inner_length:
        raise ProtocolError("invalid protocol payload length")

    body_end = 2 + inner_length
    if checksum:
        expected = (0xAA - sum(packed[:body_end])) & 0xFF
        if packed[body_end] != expected:
            raise ProtocolError("invalid protocol checksum")
    elif packed[body_end] != 0x88:
        raise ProtocolError("invalid no-checksum trailer")

    return packed[3:body_end]


def _check_ack(payload: bytes, command: int) -> None:
    if len(payload) < 2 or payload[0] != command or not (payload[1] & 0x01):
        raise ProtocolError(f"device rejected command 0x{command:02x}")


class ReadOnlyUsbSession:
    """USB session whose public request API permits only fixed probe queries."""

    def __init__(self, timeout_seconds: float = 5.0):
        if not math.isfinite(timeout_seconds) or not 0.05 <= timeout_seconds <= 30.0:
            raise ValueError("timeout must be a finite value between 0.05 and 30 seconds")
        self.timeout_ms = max(1, round(timeout_seconds * 1000))
        self._claimed = False
        self._rx_buffer = bytearray()
        self.device = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
        if self.device is None:
            raise RuntimeError("Goodix 27c6:5503 was not found")

        config = self.device.get_active_configuration()
        interface = usb.util.find_descriptor(
            config,
            custom_match=lambda item: item.bInterfaceClass in (0x0A, 0xFF),
        )
        if interface is None:
            raise RuntimeError("vendor/data USB interface was not found")

        self.interface_number = interface.bInterfaceNumber
        self.endpoint_in = usb.util.find_descriptor(
            interface,
            custom_match=lambda ep: usb.util.endpoint_direction(ep.bEndpointAddress)
            == usb.util.ENDPOINT_IN
            and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK,
        )
        self.endpoint_out = usb.util.find_descriptor(
            interface,
            custom_match=lambda ep: usb.util.endpoint_direction(ep.bEndpointAddress)
            == usb.util.ENDPOINT_OUT
            and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK,
        )
        if self.endpoint_in is None or self.endpoint_out is None:
            raise RuntimeError("bulk USB endpoints were not found")

        if self.device.is_kernel_driver_active(self.interface_number):
            raise RuntimeError("a kernel driver owns the fingerprint interface; refusing to detach it")

        self._max_packet_size = max(8, int(self.endpoint_in.wMaxPacketSize) & 0x7FF)
        try:
            usb.util.claim_interface(self.device, self.interface_number)
            self._claimed = True
            self._drain_input()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        try:
            if self._claimed:
                usb.util.release_interface(self.device, self.interface_number)
                self._claimed = False
        finally:
            usb.util.dispose_resources(self.device)

    def __enter__(self) -> "ReadOnlyUsbSession":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def _drain_input(self) -> None:
        while True:
            try:
                self.endpoint_in.read(self._max_packet_size, timeout=100)
            except usb.core.USBTimeoutError:
                self._rx_buffer.clear()
                return

    def __write_packet(self, packet: bytes) -> None:
        padded = packet + b"\x00" * ((-len(packet)) % 0x40)
        for offset in range(0, len(padded), 0x40):
            self.endpoint_out.write(padded[offset : offset + 0x40], self.timeout_ms)

    def _read_frame(self, *, timeout_ms: int | None = None) -> bytes:
        timeout = self.timeout_ms if timeout_ms is None else timeout_ms
        while len(self._rx_buffer) < 4:
            self._rx_buffer.extend(
                self.endpoint_in.read(self._max_packet_size, timeout=timeout).tobytes()
            )

        outer_length = struct.unpack("<H", self._rx_buffer[1:3])[0]
        frame_length = 4 + outer_length
        if outer_length < 4 or frame_length > 0x10000:
            raise ProtocolError("invalid outer frame length")

        while len(self._rx_buffer) < frame_length:
            self._rx_buffer.extend(
                self.endpoint_in.read(self._max_packet_size, timeout=timeout).tobytes()
            )

        frame = bytes(self._rx_buffer[:frame_length])
        del self._rx_buffer[:frame_length]
        # Goodix responses may pad the final USB packet with zero bytes. Do not
        # discard a coalesced next frame, but remove padding-only leftovers.
        if self._rx_buffer and not any(self._rx_buffer):
            self._rx_buffer.clear()
        return frame

    @staticmethod
    def _validate_request(command: int, payload: bytes, checksum: bool) -> None:
        expected = {
            COMMAND_NOP: {(b"", False)},
            COMMAND_FIRMWARE_VERSION: {(b"", True)},
            COMMAND_GET_IAP_VERSION: {(b"\x19\x00", True)},
            COMMAND_PRESET_PSK_READ: {
                (
                    struct.pack(
                        "<IIII", 32, 0, OFFICIAL_PSK_HASH_SELECTOR, 0
                    ),
                    True,
                ),
            },
        }
        if command not in ALLOWED_COMMANDS:
            raise UnsafeCommandError(f"blocked command 0x{command:02x}")
        if (payload, checksum) not in expected[command]:
            raise UnsafeCommandError(f"blocked payload/options for command 0x{command:02x}")

    def request(
        self, command: int, payload: bytes = b"", *, checksum: bool = True
    ) -> bytes:
        self._validate_request(command, payload, checksum)
        self.__write_packet(_encode_packet(command, payload, checksum=checksum))
        if command == COMMAND_NOP:
            # NOP may return nothing, an ACK, or a protocol response depending on
            # firmware. Consume one complete frame if it arrives promptly.
            try:
                self._read_frame(timeout_ms=100)
            except usb.core.USBTimeoutError:
                pass
            return b""

        ack = _decode_packet(self._read_frame(), COMMAND_ACK)
        _check_ack(ack, command)
        return _decode_packet(self._read_frame(), command, checksum=checksum)


def _decode_c_string(payload: bytes) -> str:
    return payload.split(b"\x00", 1)[0].decode("ascii", errors="strict")


def _decode_g_read_chunk(reply: bytes, requested_length: int) -> bytes:
    """Decode the G-read response without assigning meaning to its opaque header."""
    if not reply or reply[0] != 0:
        raise ProtocolError("device rejected PSK metadata read")
    if len(reply) < 9:
        raise ProtocolError("truncated PSK metadata response")

    value = reply[9:]
    if len(value) != requested_length:
        raise ProtocolError(
            f"unexpected PSK metadata length {len(value)}; "
            f"expected {requested_length}"
        )
    return value


def _read_psk_state(session: ReadOnlyUsbSession) -> str:
    # This exact selector and length are used by the official G validation path.
    payload = struct.pack("<IIII", 32, 0, OFFICIAL_PSK_HASH_SELECTOR, 0)
    value = _decode_g_read_chunk(
        session.request(COMMAND_PRESET_PSK_READ, payload), 32
    )
    return "known-community-hash" if value == KNOWN_5503_PMK_HASH else "different-hash"


def probe(*, check_psk_state: bool = False, timeout_seconds: float = 5.0) -> ProbeResult:
    with ReadOnlyUsbSession(timeout_seconds) as session:
        session.request(COMMAND_NOP, checksum=False)
        firmware = _decode_c_string(session.request(COMMAND_FIRMWARE_VERSION))

        iap = _decode_c_string(
            session.request(COMMAND_GET_IAP_VERSION, b"\x19\x00")
        )

        psk_state = _read_psk_state(session) if check_psk_state else "not-queried"
        return ProbeResult(
            vendor_id=f"{VENDOR_ID:04x}",
            product_id=f"{PRODUCT_ID:04x}",
            bus=getattr(session.device, "bus", None),
            address=getattr(session.device, "address", None),
            firmware=firmware,
            iap=iap,
            psk_state=psk_state,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Query non-persistent metadata from Goodix 27c6:5503"
    )
    parser.add_argument(
        "--check-psk-state",
        action="store_true",
        help="compare PSK metadata hash without displaying key material",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    result = probe(check_psk_state=args.check_psk_state, timeout_seconds=args.timeout)
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
