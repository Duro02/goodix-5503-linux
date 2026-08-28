"""Conservative probe for the Goodix 27c6:5503 fingerprint sensor.

The transport only permits a small command allowlist. Commands that erase or
write firmware, change PSKs, reset the MCU, or upload sensor configuration are
not implemented and are rejected before any USB transfer.

Protocol framing is based on goodix-fp-linux-dev/goodix-fp-dump (LGPL-2.1-or-
later), pinned reference commit cc43bb3b3154a0bccc0412ae024013c7e1923139.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import stat
import struct
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

import usb.core
import usb.util

from .security import disable_core_dumps as _disable_core_dumps

VENDOR_ID: Final = 0x27C6
PRODUCT_ID: Final = 0x5503

FLAGS_MESSAGE_PROTOCOL: Final = 0xA0
COMMAND_NOP: Final = 0x00
COMMAND_FIRMWARE_VERSION: Final = 0xA8
COMMAND_ACK: Final = 0xB0
COMMAND_READ_REGISTER: Final = 0x82
COMMAND_READ_OTP: Final = 0xA6
COMMAND_PRESET_PSK_READ: Final = 0xE4
COMMAND_GET_IAP_VERSION: Final = 0xF6

# Commands outside this set cannot reach the USB transport through request().
ALLOWED_COMMANDS: Final = frozenset(
    {
        COMMAND_NOP,
        COMMAND_FIRMWARE_VERSION,
        COMMAND_READ_REGISTER,
        COMMAND_PRESET_PSK_READ,
        COMMAND_GET_IAP_VERSION,
    }
)

# Hash used by the community 5503 implementation. This is not the PSK itself.
KNOWN_5503_PMK_HASH: Final = bytes.fromhex(
    "81b8ff490612022a121a9449ee3aad2792f32b9f3141182cd01019945ee50361"
)
OFFICIAL_PROTECTED_PSK_SELECTOR: Final = 0xBB010002
OFFICIAL_WHITEBOX_PSK_SELECTOR: Final = 0xBB010003
OFFICIAL_R_PSK_HASH_SELECTOR: Final = 0xBB020007
MAX_PROTECTED_RECORD_LENGTH: Final = 4096
PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
BACKUP_DIRECTORY: Final = PROJECT_ROOT / "artifacts" / "device-backup"
PROTECTED_RECORD_BACKUP: Final = BACKUP_DIRECTORY / "psk-record-bb010002.bin"
VERIFICATION_RECORD_BACKUP: Final = BACKUP_DIRECTORY / "psk-record-bb020007.bin"


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
    protected_record_length: int | None
    protected_record_sha256: str | None
    protected_record_backup: str | None
    rollback_set: dict[str, dict[str, int | str]] | None


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


def _decode_chip_id_register(body: bytes) -> int:
    if len(body) != 4:
        raise ProtocolError("chip-ID register response is not exactly 4 bytes")
    normalized = bytes((body[1], body[0], body[3], body[2]))
    return struct.unpack("<I", normalized)[0] >> 8


def _check_ack(payload: bytes, command: int) -> None:
    if len(payload) < 2 or payload[0] != command or not (payload[1] & 0x01):
        raise ProtocolError(f"device rejected command 0x{command:02x}")


_OFFICIAL_LOADER_INITIALIZATION = object()
_OFFICIAL_RESET_DELAYS = (0.042, 0.003)
_OFFICIAL_POST_RESET_SETTLE = 0.600


def _find_unique_device():
    found = usb.core.find(
        idVendor=VENDOR_ID, idProduct=PRODUCT_ID, find_all=True
    )
    devices = list(found) if found is not None else []
    if not devices:
        raise RuntimeError("Goodix 27c6:5503 was not found")
    if len(devices) != 1:
        raise RuntimeError(
            f"expected exactly one Goodix 27c6:5503, found {len(devices)}"
        )
    return devices[0]


def _usb_identity(device) -> tuple[int, int, int, int, tuple[int, ...]]:
    ports = tuple(int(port) for port in (device.port_numbers or ()))
    if not ports:
        raise RuntimeError("fingerprint USB port topology is unavailable")
    return (
        int(device.idVendor),
        int(device.idProduct),
        int(device.bus),
        int(device.address),
        ports,
    )


def _official_device_layout(device, expected_identity=None):
    """Validate the exact pinned device/interface/endpoint layout without claiming."""
    identity = _usb_identity(device)
    if expected_identity is not None and identity != expected_identity:
        raise RuntimeError("fingerprint USB identity/topology changed after reset")
    device_descriptor = (
        int(device.bLength),
        int(device.bDescriptorType),
        int(device.bcdUSB),
        int(device.bDeviceClass),
        int(device.bDeviceSubClass),
        int(device.bDeviceProtocol),
        int(device.bMaxPacketSize0),
        int(device.idVendor),
        int(device.idProduct),
        int(device.bcdDevice),
        int(device.iManufacturer),
        int(device.iProduct),
        int(device.iSerialNumber),
        int(device.bNumConfigurations),
    )
    if device_descriptor != (
        18, 1, 0x0200, 0xEF, 0x02, 0x01, 64,
        VENDOR_ID, PRODUCT_ID, 0x0100, 1, 2, 0, 1,
    ):
        raise RuntimeError("official-loader USB device descriptor changed")
    config = device.get_active_configuration()
    config_descriptor = (
        int(config.bLength),
        int(config.bDescriptorType),
        int(config.wTotalLength),
        int(config.bNumInterfaces),
        int(config.bConfigurationValue),
        int(config.iConfiguration),
        int(config.bmAttributes),
        int(config.bMaxPower),
    )
    if config_descriptor != (9, 2, 0x20, 1, 1, 0, 0xA0, 50):
        raise RuntimeError("official-loader USB configuration changed")
    interfaces = list(config)
    if len(interfaces) != 1:
        raise RuntimeError("official-loader USB interface collection changed")
    interface = interfaces[0]
    interface_descriptor = (
        int(interface.bLength),
        int(interface.bDescriptorType),
        int(interface.bInterfaceNumber),
        int(interface.bAlternateSetting),
        int(interface.bNumEndpoints),
        int(interface.bInterfaceClass),
        int(interface.bInterfaceSubClass),
        int(interface.bInterfaceProtocol),
        int(interface.iInterface),
    )
    if interface_descriptor != (9, 4, 0, 0, 2, 0xFF, 0x00, 0x00, 0):
        raise RuntimeError("official-loader USB interface descriptor changed")
    endpoints = list(interface)
    endpoint_layout = sorted(
        (
            int(endpoint.bLength),
            int(endpoint.bDescriptorType),
            int(endpoint.bEndpointAddress),
            int(endpoint.bmAttributes),
            int(endpoint.wMaxPacketSize),
            int(endpoint.bInterval),
        )
        for endpoint in endpoints
    )
    if endpoint_layout != [
        (7, 5, 0x01, 0x02, 512, 0),
        (7, 5, 0x82, 0x02, 512, 0),
    ]:
        raise RuntimeError("official-loader USB endpoint descriptors changed")
    if device.is_kernel_driver_active(0):
        raise RuntimeError(
            "a kernel driver owns the fingerprint interface; refusing USB reset"
        )
    endpoint_out = next(ep for ep in endpoints if int(ep.bEndpointAddress) == 0x01)
    endpoint_in = next(ep for ep in endpoints if int(ep.bEndpointAddress) == 0x82)
    return identity, interface, endpoint_in, endpoint_out


def _official_loader_usb_reset_sequence(device):
    """Mirror the three pre-command enumeration resets in the pinned trace."""
    try:
        expected_identity, _, _, _ = _official_device_layout(device)
    except BaseException:
        usb.util.dispose_resources(device)
        raise
    for index in range(3):
        try:
            device.reset()
        finally:
            usb.util.dispose_resources(device)
        if index < len(_OFFICIAL_RESET_DELAYS):
            time.sleep(_OFFICIAL_RESET_DELAYS[index])
        device = _find_unique_device()
        try:
            _official_device_layout(device, expected_identity)
        except BaseException:
            usb.util.dispose_resources(device)
            raise
    try:
        reset_completed_at = time.monotonic()
    except BaseException:
        usb.util.dispose_resources(device)
        raise
    return device, reset_completed_at, expected_identity


class ReadOnlyUsbSession:
    """USB session whose public request API permits only fixed probe queries."""

    @classmethod
    def _for_official_loader(cls, timeout_seconds: float = 5.0):
        return cls(
            timeout_seconds,
            _initialization_token=_OFFICIAL_LOADER_INITIALIZATION,
        )

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        *,
        _initialization_token=None,
    ):
        if not math.isfinite(timeout_seconds) or not 0.05 <= timeout_seconds <= 30.0:
            raise ValueError("timeout must be a finite value between 0.05 and 30 seconds")
        self.timeout_ms = max(1, round(timeout_seconds * 1000))
        self._claimed = False
        self._rx_buffer = bytearray()
        if _initialization_token not in (None, _OFFICIAL_LOADER_INITIALIZATION):
            raise ValueError("invalid USB initialization mode")
        self.device = _find_unique_device()
        official_reset_at = None
        official_identity = None
        if _initialization_token is _OFFICIAL_LOADER_INITIALIZATION:
            self.device, official_reset_at, official_identity = (
                _official_loader_usb_reset_sequence(self.device)
            )

        try:
            if _initialization_token is _OFFICIAL_LOADER_INITIALIZATION:
                _, interface, self.endpoint_in, self.endpoint_out = (
                    _official_device_layout(self.device, official_identity)
                )
            else:
                config = self.device.get_active_configuration()
                interface = usb.util.find_descriptor(
                    config,
                    custom_match=lambda item: item.bInterfaceClass in (0x0A, 0xFF),
                )
                if interface is None:
                    raise RuntimeError("vendor/data USB interface was not found")
                self.endpoint_in = usb.util.find_descriptor(
                    interface,
                    custom_match=lambda ep: usb.util.endpoint_direction(
                        ep.bEndpointAddress
                    )
                    == usb.util.ENDPOINT_IN
                    and usb.util.endpoint_type(ep.bmAttributes)
                    == usb.util.ENDPOINT_TYPE_BULK,
                )
                self.endpoint_out = usb.util.find_descriptor(
                    interface,
                    custom_match=lambda ep: usb.util.endpoint_direction(
                        ep.bEndpointAddress
                    )
                    == usb.util.ENDPOINT_OUT
                    and usb.util.endpoint_type(ep.bmAttributes)
                    == usb.util.ENDPOINT_TYPE_BULK,
                )
                if self.endpoint_in is None or self.endpoint_out is None:
                    raise RuntimeError("bulk USB endpoints were not found")

            self.interface_number = int(interface.bInterfaceNumber)
            if self.device.is_kernel_driver_active(self.interface_number):
                raise RuntimeError(
                    "a kernel driver owns the fingerprint interface; refusing to detach it"
                )
            self._max_packet_size = max(
                8, int(self.endpoint_in.wMaxPacketSize) & 0x7FF
            )
            usb.util.claim_interface(self.device, self.interface_number)
            self._claimed = True
            self._drain_input()
            if official_reset_at is not None:
                remaining = _OFFICIAL_POST_RESET_SETTLE - (
                    time.monotonic() - official_reset_at
                )
                if remaining > 0:
                    time.sleep(remaining)
                observed = _find_unique_device()
                try:
                    _official_device_layout(observed, official_identity)
                finally:
                    if observed is not self.device:
                        usb.util.dispose_resources(observed)
                if self.device.is_kernel_driver_active(self.interface_number):
                    raise RuntimeError(
                        "a kernel driver claimed the fingerprint interface after reset"
                    )
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

    def wake_up(self, *, timeout_ms: int | None = None) -> None:
        """Emit the pinned Geneva loader's single raw wake byte."""
        timeout = self.timeout_ms if timeout_ms is None else timeout_ms
        written = self.endpoint_out.write(b"\xe5", timeout)
        if written != 1:
            raise ProtocolError("raw wake byte was not fully written")

    def _drain_input(self) -> None:
        self._rx_buffer.clear()
        for completed in range(5):
            try:
                usb_buffer = self.endpoint_in.read(self._max_packet_size, timeout=100)
            except usb.core.USBTimeoutError:
                return
            memoryview(usb_buffer).cast("B")[:] = b"\x00" * len(usb_buffer)
            if completed == 4:
                raise ProtocolError("initial USB drain transfer capacity reached")

    def __write_packet(self, packet: bytes, *, timeout_ms: int | None = None) -> None:
        timeout = self.timeout_ms if timeout_ms is None else timeout_ms
        if timeout <= 0:
            raise ProtocolError("USB packet write timeout must be positive")
        padded = packet + b"\x00" * ((-len(packet)) % 0x40)
        for offset in range(0, len(padded), 0x40):
            chunk = padded[offset : offset + 0x40]
            written = self.endpoint_out.write(chunk, timeout)
            if written != len(chunk):
                raise ProtocolError("USB packet chunk was not fully written")

    def _read_frame(self, *, timeout_ms: int | None = None) -> bytes:
        timeout = self.timeout_ms if timeout_ms is None else timeout_ms
        deadline = time.monotonic() + timeout / 1000

        def read_chunk() -> None:
            remaining_ms = math.ceil((deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                raise ProtocolError("complete USB frame deadline expired")
            self._rx_buffer.extend(
                self.endpoint_in.read(
                    self._max_packet_size, timeout=min(timeout, remaining_ms)
                ).tobytes()
            )

        while len(self._rx_buffer) < 4:
            read_chunk()

        outer_length = struct.unpack("<H", self._rx_buffer[1:3])[0]
        frame_length = 4 + outer_length
        if outer_length < 4 or frame_length > 0x10000:
            raise ProtocolError("invalid outer frame length")

        while len(self._rx_buffer) < frame_length:
            read_chunk()

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
            COMMAND_READ_REGISTER: {(b"\x00\x00\x00\x04\x00", True)},
            COMMAND_PRESET_PSK_READ: {
                (struct.pack("<II", OFFICIAL_R_PSK_HASH_SELECTOR, 0), True),
            },
        }
        if command not in ALLOWED_COMMANDS:
            raise UnsafeCommandError(f"blocked command 0x{command:02x}")
        if (payload, checksum) not in expected[command]:
            raise UnsafeCommandError(f"blocked payload/options for command 0x{command:02x}")

    def __exchange(
        self, command: int, payload: bytes = b"", *, checksum: bool = True
    ) -> bytes:
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

    def request(
        self, command: int, payload: bytes = b"", *, checksum: bool = True
    ) -> bytes:
        self._validate_request(command, payload, checksum)
        return self.__exchange(command, payload, checksum=checksum)

    def read_chip_id(self) -> int:
        """Read the fixed four-byte MCU chip-ID register used for profile selection."""
        body = self.request(COMMAND_READ_REGISTER, b"\x00\x00\x00\x04\x00")
        # The pinned _McuReadRegister path swaps each returned 16-bit word before
        # DeviceLoader shifts the resulting DWORD by eight for profile lookup.
        return _decode_chip_id_register(body)

    def read_otp(self) -> bytearray:
        """Read fixed calibration data; the caller must wipe the result."""
        _disable_core_dumps()
        otp = bytearray(self.__exchange(COMMAND_READ_OTP, b"\x00\x00"))
        if len(otp) != 64:
            otp[:] = b"\x00" * len(otp)
            raise ProtocolError("5503 OTP response is not exactly 64 bytes")
        return otp

    def __read_record(
        self, selector: int, *, exact_length: int | None = None
    ) -> bytearray:
        payload = struct.pack("<II", selector, 0)
        record = _decode_r_read_response(
            self.__exchange(COMMAND_PRESET_PSK_READ, payload), selector
        )
        valid_length = (
            len(record) == exact_length
            if exact_length is not None
            else 0 < len(record) <= MAX_PROTECTED_RECORD_LENGTH
        )
        if not valid_length:
            record[:] = b"\x00" * len(record)
            expected = (
                f"exactly {exact_length}"
                if exact_length is not None
                else f"1..{MAX_PROTECTED_RECORD_LENGTH}"
            )
            raise ProtocolError(f"record length is not {expected} bytes")
        return record

    def __read_protected_record(self) -> bytearray:
        return self.__read_record(OFFICIAL_PROTECTED_PSK_SELECTOR)

    def protected_record_metadata(self) -> tuple[int, str]:
        """Hash the exact protected record without returning its raw response."""
        _disable_core_dumps()
        protected = self.__read_protected_record()
        try:
            return len(protected), hashlib.sha256(protected).hexdigest()
        finally:
            protected[:] = b"\x00" * len(protected)

    def backup_protected_record(self) -> tuple[int, str, Path]:
        """Save the protected record atomically without returning raw bytes."""
        _disable_core_dumps()
        protected = self.__read_protected_record()
        try:
            digest = hashlib.sha256(protected).hexdigest()
            self.close()
            _drop_sudo_privileges()
            _disable_core_dumps()
            _write_or_verify_secure_backup(PROTECTED_RECORD_BACKUP, protected)
            return len(protected), digest, PROTECTED_RECORD_BACKUP
        finally:
            protected[:] = b"\x00" * len(protected)

    def backup_rollback_set(self) -> dict[str, dict[str, int | str]]:
        """Persist all readable PSK records and report the write-only gap."""
        _disable_core_dumps()
        records: list[tuple[int, Path, bytearray]] = []
        try:
            records.append(
                (
                    OFFICIAL_PROTECTED_PSK_SELECTOR,
                    PROTECTED_RECORD_BACKUP,
                    self.__read_record(OFFICIAL_PROTECTED_PSK_SELECTOR),
                )
            )
            records.append(
                (
                    OFFICIAL_R_PSK_HASH_SELECTOR,
                    VERIFICATION_RECORD_BACKUP,
                    self.__read_record(
                        OFFICIAL_R_PSK_HASH_SELECTOR, exact_length=32
                    ),
                )
            )

            self.close()
            _drop_sudo_privileges()
            _disable_core_dumps()
            result: dict[str, dict[str, int | str]] = {
                f"0x{OFFICIAL_WHITEBOX_PSK_SELECTOR:08x}": {
                    "status": "not-read-write-only-unavailable"
                }
            }
            for selector, path, record in records:
                status = _write_or_verify_secure_backup(path, record)
                result[f"0x{selector:08x}"] = {
                    "length": len(record),
                    "sha256": hashlib.sha256(record).hexdigest(),
                    "path": str(path),
                    "status": status,
                }
            return result
        finally:
            for _selector, _path, record in records:
                record[:] = b"\x00" * len(record)


def _decode_c_string(payload: bytes) -> str:
    return payload.split(b"\x00", 1)[0].decode("ascii", errors="strict")


def _decode_r_read_response(reply: bytes, expected_selector: int) -> bytearray:
    """Decode the official R-family e4 response."""
    if not reply:
        raise ProtocolError("device returned an empty PSK metadata response")
    if reply[0] != 0:
        raise ProtocolError(
            f"device rejected PSK metadata read with status 0x{reply[0]:02x}"
        )
    if len(reply) < 9:
        raise ProtocolError("truncated PSK metadata response")

    selector, value_length = struct.unpack("<II", reply[1:9])
    if selector != expected_selector:
        raise ProtocolError(
            f"unexpected PSK metadata selector 0x{selector:08x}"
        )
    received_length = len(reply) - 9
    if value_length != received_length:
        raise ProtocolError(
            f"invalid PSK metadata length {value_length}; received {received_length}"
        )
    return bytearray(memoryview(reply)[9:])


def _read_psk_state(session: ReadOnlyUsbSession) -> str:
    # The 5503 hardware uses the official R-family selector-only read format.
    payload = struct.pack("<II", OFFICIAL_R_PSK_HASH_SELECTOR, 0)
    value = _decode_r_read_response(
        session.request(COMMAND_PRESET_PSK_READ, payload),
        OFFICIAL_R_PSK_HASH_SELECTOR,
    )
    try:
        if len(value) != 32:
            raise ProtocolError(f"unexpected PSK verification hash length {len(value)}")
        return (
            "known-community-hash"
            if value == KNOWN_5503_PMK_HASH
            else "different-hash"
        )
    finally:
        value[:] = b"\x00" * len(value)


def _sudo_owner() -> tuple[int, int]:
    if os.geteuid() != 0:
        return os.geteuid(), os.getegid()
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
    except (KeyError, ValueError) as error:
        raise RuntimeError("refusing a root-owned backup without SUDO_UID/GID") from error
    if uid <= 0 or gid < 0:
        raise RuntimeError("invalid SUDO_UID/GID for protected-record backup")
    return uid, gid


def _drop_sudo_privileges() -> None:
    if os.geteuid() != 0:
        return
    uid, gid = _sudo_owner()
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        raise RuntimeError("failed to drop sudo privileges permanently")


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(
        directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir(directory: Path, mode: int) -> bool:
    try:
        directory.mkdir(mode=mode)
    except FileExistsError:
        return False
    return True


def _require_real_directory(directory: Path) -> None:
    info = directory.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("protected-record backup path contains a symlink")


def _write_secure_backup(path: Path, protected: bytearray) -> None:
    if os.geteuid() == 0:
        raise RuntimeError("refusing protected-record filesystem access as root")
    artifacts = PROJECT_ROOT / "artifacts"
    directory = path.parent
    if _mkdir(artifacts, 0o700):
        _fsync_directory(PROJECT_ROOT)
    _require_real_directory(artifacts)
    if _mkdir(directory, 0o700):
        _fsync_directory(artifacts)
    _require_real_directory(directory)
    os.chmod(directory, 0o700)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".psk-record-", dir=directory
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(protected)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("short write while saving protected-record backup")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        _fsync_directory(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _verify_secure_backup(path: Path, expected: bytearray) -> None:
    if os.geteuid() == 0:
        raise RuntimeError("refusing protected-record filesystem access as root")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    existing = bytearray(len(expected))
    extra = bytearray(1)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("existing protected-record backup is not regular")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("existing protected-record backup ownership/mode is unsafe")
        if info.st_size != len(expected):
            raise RuntimeError("existing protected-record backup length differs")

        view = memoryview(existing)
        read_count = 0
        while read_count < len(view):
            count = os.readv(descriptor, [view[read_count:]])
            if count == 0:
                break
            read_count += count
        trailing = os.readv(descriptor, [extra])
        if (
            read_count != len(expected)
            or trailing != 0
            or not hmac.compare_digest(existing, expected)
        ):
            raise RuntimeError("existing protected-record backup content differs")
    finally:
        try:
            os.close(descriptor)
        finally:
            existing[:] = b"\x00" * len(existing)
            extra[:] = b"\x00"


def _write_or_verify_secure_backup(path: Path, protected: bytearray) -> str:
    try:
        _verify_secure_backup(path, protected)
        return "verified-existing"
    except FileNotFoundError:
        pass

    try:
        _write_secure_backup(path, protected)
        return "created"
    except FileExistsError:
        _verify_secure_backup(path, protected)
        return "verified-existing"


def probe(
    *,
    check_psk_state: bool = False,
    inspect_protected_record: bool = False,
    backup_protected_record: bool = False,
    backup_rollback_set: bool = False,
    timeout_seconds: float = 5.0,
) -> ProbeResult:
    if inspect_protected_record or backup_protected_record or backup_rollback_set:
        _disable_core_dumps()
    if backup_protected_record or backup_rollback_set:
        _sudo_owner()
    with ReadOnlyUsbSession(timeout_seconds) as session:
        session.request(COMMAND_NOP, checksum=False)
        firmware = _decode_c_string(session.request(COMMAND_FIRMWARE_VERSION))

        iap = _decode_c_string(
            session.request(COMMAND_GET_IAP_VERSION, b"\x19\x00")
        )

        psk_state = _read_psk_state(session) if check_psk_state else "not-queried"
        protected_record_length = None
        protected_record_sha256 = None
        protected_record_backup = None
        rollback_set = None
        if inspect_protected_record:
            protected_record_length, protected_record_sha256 = (
                session.protected_record_metadata()
            )
        elif backup_protected_record:
            length, digest, path = session.backup_protected_record()
            protected_record_length = length
            protected_record_sha256 = digest
            protected_record_backup = str(path)
        elif backup_rollback_set:
            rollback_set = session.backup_rollback_set()

        return ProbeResult(
            vendor_id=f"{VENDOR_ID:04x}",
            product_id=f"{PRODUCT_ID:04x}",
            bus=getattr(session.device, "bus", None),
            address=getattr(session.device, "address", None),
            firmware=firmware,
            iap=iap,
            psk_state=psk_state,
            protected_record_length=protected_record_length,
            protected_record_sha256=protected_record_sha256,
            protected_record_backup=protected_record_backup,
            rollback_set=rollback_set,
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
    protected_group = parser.add_mutually_exclusive_group()
    protected_group.add_argument(
        "--inspect-protected-record",
        action="store_true",
        help="report only the length and SHA-256 of the opaque protected PSK record",
    )
    protected_group.add_argument(
        "--backup-protected-record",
        action="store_true",
        help="atomically save the opaque protected PSK record in artifacts/device-backup",
    )
    protected_group.add_argument(
        "--backup-rollback-set",
        action="store_true",
        help="save readable R-family PSK records and report the write-only record",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    result = probe(
        check_psk_state=args.check_psk_state,
        inspect_protected_record=args.inspect_protected_record,
        backup_protected_record=args.backup_protected_record,
        backup_rollback_set=args.backup_rollback_set,
        timeout_seconds=args.timeout,
    )
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
