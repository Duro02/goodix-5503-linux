import array
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

from goodix5503.probe import (
    COMMAND_ACK,
    COMMAND_FIRMWARE_VERSION,
    COMMAND_PRESET_PSK_READ,
    COMMAND_READ_REGISTER,
    COMMAND_READ_OTP,
    OFFICIAL_PROTECTED_PSK_SELECTOR,
    OFFICIAL_R_PSK_HASH_SELECTOR,
    OFFICIAL_WHITEBOX_PSK_SELECTOR,
    ProtocolError,
    ReadOnlyUsbSession,
    UnsafeCommandError,
    _decode_r_read_response,
    _decode_packet,
    _encode_packet,
    _official_device_layout,
    _official_loader_usb_reset_sequence,
    _usb_identity,
    _verify_secure_backup,
    _write_or_verify_secure_backup,
    _write_secure_backup,
)


class FakeInEndpoint:
    wMaxPacketSize = 64

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.timeouts = []

    def read(self, _size, timeout):
        self.timeouts.append(timeout)
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


class OfficialEndpoint:
    bLength = 7
    bDescriptorType = 5
    bInterval = 0

    def __init__(self, address, *, attributes=2, packet_size=512):
        self.bEndpointAddress = address
        self.bmAttributes = attributes
        self.wMaxPacketSize = packet_size

    def read(self, _size, timeout):
        import usb.core

        self.timeout = timeout
        raise usb.core.USBTimeoutError("quiet")


class OfficialInterface:
    bLength = 9
    bDescriptorType = 4
    iInterface = 0

    def __init__(self, *, number=0, alternate=0, endpoints=None):
        self.bInterfaceNumber = number
        self.bAlternateSetting = alternate
        self.bInterfaceClass = 0xFF
        self.bInterfaceSubClass = 0
        self.bInterfaceProtocol = 0
        self.endpoints = endpoints or [OfficialEndpoint(0x01), OfficialEndpoint(0x82)]
        self.bNumEndpoints = len(self.endpoints)

    def __iter__(self):
        return iter(self.endpoints)


class OfficialConfig:
    bLength = 9
    bDescriptorType = 2
    wTotalLength = 0x20
    bNumInterfaces = 1
    bConfigurationValue = 1
    iConfiguration = 0
    bmAttributes = 0xA0
    bMaxPower = 50

    def __init__(self, interface=None):
        self.interface = interface or OfficialInterface()

    def __iter__(self):
        return iter((self.interface,))


class OfficialDevice:
    bLength = 18
    bDescriptorType = 1
    bcdUSB = 0x0200
    idVendor = 0x27C6
    idProduct = 0x5503
    bus = 3
    address = 2
    port_numbers = (3,)
    bDeviceClass = 0xEF
    bDeviceSubClass = 2
    bDeviceProtocol = 1
    bMaxPacketSize0 = 64
    bcdDevice = 0x0100
    iManufacturer = 1
    iProduct = 2
    iSerialNumber = 0
    bNumConfigurations = 1

    def __init__(self, *, config=None, driver=False):
        self.config = config or OfficialConfig()
        self.driver = driver
        self.reset_calls = 0

    def get_active_configuration(self):
        return self.config

    def is_kernel_driver_active(self, interface):
        if interface != 0:
            raise AssertionError("unexpected interface ownership query")
        return self.driver

    def reset(self):
        self.reset_calls += 1


class PacketTests(unittest.TestCase):
    def test_session_refuses_ambiguous_identical_devices(self):
        with (
            patch("goodix5503.probe.usb.core.find", return_value=[object(), object()]),
            self.assertRaisesRegex(RuntimeError, "expected exactly one"),
        ):
            ReadOnlyUsbSession()

    def test_official_loader_reset_sequence_is_exact_and_reacquires(self):
        class Device:
            idVendor = 0x27C6
            idProduct = 0x5503
            bus = 3
            address = 2
            port_numbers = (3,)

            def __init__(self):
                self.reset_calls = 0

            def reset(self):
                self.reset_calls += 1

        devices = [Device() for _ in range(4)]

        def layout(device, expected=None):
            identity = _usb_identity(device)
            if expected is not None and identity != expected:
                raise RuntimeError("identity/topology changed")
            return identity, None, None, None

        with (
            patch("goodix5503.probe._official_device_layout", side_effect=layout),
            patch(
                "goodix5503.probe._find_unique_device",
                side_effect=devices[1:],
            ) as find_device,
            patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
            patch("goodix5503.probe.time.sleep") as sleep,
            patch("goodix5503.probe.time.monotonic", return_value=123.0),
        ):
            result, reset_at, identity = _official_loader_usb_reset_sequence(
                devices[0]
            )
        self.assertIs(result, devices[3])
        self.assertEqual(reset_at, 123.0)
        self.assertEqual(identity, _usb_identity(devices[0]))
        self.assertEqual([device.reset_calls for device in devices], [1, 1, 1, 0])
        self.assertEqual(find_device.call_count, 3)
        self.assertEqual(dispose.call_args_list, [call(devices[0]), call(devices[1]), call(devices[2])])
        self.assertEqual(sleep.call_args_list, [call(0.042), call(0.003)])

    def test_official_loader_reset_sequence_fails_closed_at_each_reset(self):
        class Device:
            idVendor = 0x27C6
            idProduct = 0x5503
            bus = 3
            address = 2
            port_numbers = (3,)

            def __init__(self, fail=False):
                self.fail = fail
                self.reset_calls = 0

            def reset(self):
                self.reset_calls += 1
                if self.fail:
                    raise RuntimeError("reset failed")

        for failing_index in range(3):
            with self.subTest(failing_index=failing_index):
                devices = [Device(index == failing_index) for index in range(3)]
                with (
                    patch(
                        "goodix5503.probe._official_device_layout",
                        side_effect=lambda device, _expected=None: (
                            _usb_identity(device), None, None, None
                        ),
                    ),
                    patch(
                        "goodix5503.probe._find_unique_device",
                        side_effect=devices[1:],
                    ),
                    patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
                    patch("goodix5503.probe.time.sleep"),
                    self.assertRaisesRegex(RuntimeError, "reset failed"),
                ):
                    _official_loader_usb_reset_sequence(devices[0])
                self.assertEqual(sum(device.reset_calls for device in devices), failing_index + 1)
                self.assertEqual(dispose.call_count, failing_index + 1)

    def test_official_loader_reset_sequence_disposes_on_clock_failure(self):
        devices = [OfficialDevice() for _ in range(4)]
        with (
            patch(
                "goodix5503.probe._find_unique_device",
                side_effect=devices[1:],
            ),
            patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
            patch("goodix5503.probe.time.sleep"),
            patch(
                "goodix5503.probe.time.monotonic",
                side_effect=RuntimeError("clock failed"),
            ),
            self.assertRaisesRegex(RuntimeError, "clock failed"),
        ):
            _official_loader_usb_reset_sequence(devices[0])
        self.assertEqual(
            dispose.call_args_list,
            [call(device) for device in devices],
        )

    def test_official_loader_reset_sequence_rejects_reconnect_or_topology_drift(self):
        class Device:
            idVendor = 0x27C6
            idProduct = 0x5503
            bus = 3
            address = 2
            port_numbers = (3,)

            def reset(self):
                pass

        initial = Device()
        changed = Device()
        changed.address = 4
        def layout(device, expected=None):
            identity = _usb_identity(device)
            if expected is not None and identity != expected:
                raise RuntimeError("identity/topology changed")
            return identity, None, None, None

        with (
            patch("goodix5503.probe._official_device_layout", side_effect=layout),
            patch("goodix5503.probe._find_unique_device", return_value=changed),
            patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
            patch("goodix5503.probe.time.sleep"),
            self.assertRaisesRegex(RuntimeError, "identity/topology changed"),
        ):
            _official_loader_usb_reset_sequence(initial)
        self.assertEqual(dispose.call_args_list, [call(initial), call(changed)])

    def test_official_layout_rejects_driver_before_any_reset(self):
        device = OfficialDevice(driver=True)
        with self.assertRaisesRegex(RuntimeError, "refusing USB reset"):
            _official_device_layout(device)
        self.assertEqual(device.reset_calls, 0)

    def test_official_reset_rejects_driver_between_resets(self):
        initial = OfficialDevice()
        claimed = OfficialDevice(driver=True)
        with (
            patch("goodix5503.probe._find_unique_device", return_value=claimed),
            patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
            patch("goodix5503.probe.time.sleep"),
            self.assertRaisesRegex(RuntimeError, "refusing USB reset"),
        ):
            _official_loader_usb_reset_sequence(initial)
        self.assertEqual(initial.reset_calls, 1)
        self.assertEqual(claimed.reset_calls, 0)
        self.assertEqual(dispose.call_args_list, [call(initial), call(claimed)])

    def test_official_layout_pins_interface_alt_and_endpoint_attributes(self):
        for interface in (
            OfficialInterface(number=1),
            OfficialInterface(alternate=1),
            OfficialInterface(
                endpoints=[
                    OfficialEndpoint(0x01, attributes=3),
                    OfficialEndpoint(0x82),
                ]
            ),
        ):
            with self.subTest(interface=interface):
                device = OfficialDevice(config=OfficialConfig(interface))
                with self.assertRaisesRegex(RuntimeError, "descriptor"):
                    _official_device_layout(device)

    def test_official_layout_pins_complete_device_collection_and_raw_packet_size(self):
        changed_device = OfficialDevice()
        changed_device.bcdDevice = 0x0101

        changed_packet = OfficialDevice()
        changed_packet.config.interface.endpoints[0].wMaxPacketSize = 0x1200

        class ExtraInterfaceConfig(OfficialConfig):
            def __iter__(self):
                return iter((self.interface, OfficialInterface(number=1)))

        extra_interface = OfficialDevice(config=ExtraInterfaceConfig())
        for device in (changed_device, changed_packet, extra_interface):
            with self.subTest(device=device):
                with self.assertRaisesRegex(RuntimeError, "changed"):
                    _official_device_layout(device)

    def test_official_reset_disposes_when_descriptor_property_raises(self):
        class BrokenDevice(OfficialDevice):
            @property
            def bDeviceClass(self):
                raise RuntimeError("descriptor read failed")

        device = BrokenDevice()
        with (
            patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
            self.assertRaisesRegex(RuntimeError, "descriptor read failed"),
        ):
            _official_loader_usb_reset_sequence(device)
        self.assertEqual(device.reset_calls, 0)
        dispose.assert_called_once_with(device)

    def test_official_loader_disposes_when_repeated_descriptor_access_raises(self):
        class FlakyInterface(OfficialInterface):
            def __init__(self):
                self.number_reads = 0
                super().__init__()

            @property
            def bInterfaceNumber(self):
                self.number_reads += 1
                if self.number_reads > 1:
                    raise RuntimeError("interface number read failed")
                return self._number

            @bInterfaceNumber.setter
            def bInterfaceNumber(self, value):
                self._number = value

        class FlakyEndpoint(OfficialEndpoint):
            def __init__(self, address):
                self.packet_reads = 0
                super().__init__(address)

            @property
            def wMaxPacketSize(self):
                self.packet_reads += 1
                if self.packet_reads > 1:
                    raise RuntimeError("packet size read failed")
                return self._packet_size

            @wMaxPacketSize.setter
            def wMaxPacketSize(self, value):
                self._packet_size = value

        devices = (
            OfficialDevice(config=OfficialConfig(FlakyInterface())),
            OfficialDevice(
                config=OfficialConfig(
                    OfficialInterface(
                        endpoints=[OfficialEndpoint(0x01), FlakyEndpoint(0x82)]
                    )
                )
            ),
        )
        for device, message in zip(devices, ("interface number", "packet size")):
            with self.subTest(message=message):
                identity = _usb_identity(device)
                with (
                    patch("goodix5503.probe._find_unique_device", return_value=device),
                    patch(
                        "goodix5503.probe._official_loader_usb_reset_sequence",
                        return_value=(device, 10.0, identity),
                    ),
                    patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
                    self.assertRaisesRegex(RuntimeError, message),
                ):
                    ReadOnlyUsbSession._for_official_loader()
                dispose.assert_called_once_with(device)

    def test_official_loader_session_reacquires_exact_descriptors_and_settles(self):
        device = OfficialDevice()
        identity = _usb_identity(device)
        with (
            patch("goodix5503.probe._find_unique_device", side_effect=(device, device)),
            patch(
                "goodix5503.probe._official_loader_usb_reset_sequence",
                return_value=(device, 10.0, identity),
            ) as resets,
            patch("goodix5503.probe.usb.util.claim_interface") as claim,
            patch("goodix5503.probe.usb.util.release_interface") as release,
            patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
            patch("goodix5503.probe.time.monotonic", return_value=10.2),
            patch("goodix5503.probe.time.sleep") as sleep,
        ):
            session = ReadOnlyUsbSession._for_official_loader()
            self.assertIs(
                session.endpoint_out, device.config.interface.endpoints[0]
            )
            self.assertIs(
                session.endpoint_in, device.config.interface.endpoints[1]
            )
            session.close()
        resets.assert_called_once_with(device)
        claim.assert_called_once_with(device, 0)
        release.assert_called_once_with(device, 0)
        sleep.assert_called_once()
        self.assertAlmostEqual(sleep.call_args.args[0], 0.4)
        dispose.assert_called_once_with(device)

    def test_official_loader_settle_uses_elapsed_time_without_extra_sleep(self):
        device = OfficialDevice()
        identity = _usb_identity(device)
        with (
            patch("goodix5503.probe._find_unique_device", side_effect=(device, device)),
            patch(
                "goodix5503.probe._official_loader_usb_reset_sequence",
                return_value=(device, 10.0, identity),
            ),
            patch("goodix5503.probe.usb.util.claim_interface"),
            patch("goodix5503.probe.usb.util.release_interface"),
            patch("goodix5503.probe.usb.util.dispose_resources"),
            patch("goodix5503.probe.time.monotonic", return_value=10.7),
            patch("goodix5503.probe.time.sleep") as sleep,
        ):
            session = ReadOnlyUsbSession._for_official_loader()
            session.close()
        sleep.assert_not_called()

    def test_generic_session_performs_zero_usb_resets(self):
        device = OfficialDevice()
        with (
            patch("goodix5503.probe._find_unique_device", return_value=device),
            patch("goodix5503.probe._official_loader_usb_reset_sequence") as resets,
            patch("goodix5503.probe.usb.util.claim_interface"),
            patch("goodix5503.probe.usb.util.release_interface"),
            patch("goodix5503.probe.usb.util.dispose_resources"),
            patch("goodix5503.probe.time.sleep") as sleep,
        ):
            session = ReadOnlyUsbSession()
            session.close()
        resets.assert_not_called()
        self.assertEqual(device.reset_calls, 0)
        sleep.assert_not_called()

    def test_official_loader_session_rejects_descriptor_drift_before_claim(self):
        device = OfficialDevice(
            config=OfficialConfig(
                OfficialInterface(
                    endpoints=[OfficialEndpoint(0x02), OfficialEndpoint(0x82)]
                )
            )
        )
        with (
            patch("goodix5503.probe._find_unique_device", return_value=device),
            patch(
                "goodix5503.probe._official_loader_usb_reset_sequence",
                return_value=(device, 10.0, _usb_identity(device)),
            ),
            patch("goodix5503.probe.usb.util.claim_interface") as claim,
            patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
            self.assertRaisesRegex(RuntimeError, "descriptors changed"),
        ):
            ReadOnlyUsbSession._for_official_loader()
        claim.assert_not_called()
        dispose.assert_called_once_with(device)

    def test_official_loader_final_check_closes_on_identity_owner_or_descriptor_drift(self):
        class BrokenDescriptorDevice(OfficialDevice):
            @property
            def bDeviceClass(self):
                raise RuntimeError("descriptor read failed")

        for kind in ("identity", "owner", "descriptor"):
            with self.subTest(kind=kind):
                device = OfficialDevice()
                observed = (
                    BrokenDescriptorDevice()
                    if kind == "descriptor"
                    else OfficialDevice(driver=kind == "owner")
                )
                if kind == "identity":
                    observed.address = 4
                identity = _usb_identity(device)
                with (
                    patch(
                        "goodix5503.probe._find_unique_device",
                        side_effect=(device, observed),
                    ),
                    patch(
                        "goodix5503.probe._official_loader_usb_reset_sequence",
                        return_value=(device, 10.0, identity),
                    ),
                    patch("goodix5503.probe.usb.util.claim_interface"),
                    patch("goodix5503.probe.usb.util.release_interface") as release,
                    patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
                    patch("goodix5503.probe.time.monotonic", return_value=10.7),
                    self.assertRaises(RuntimeError),
                ):
                    ReadOnlyUsbSession._for_official_loader()
                release.assert_called_once_with(device, 0)
                self.assertEqual(
                    dispose.call_args_list,
                    [call(observed), call(device)],
                )

    def test_official_loader_claim_and_drain_failures_close(self):
        for phase in ("claim", "drain"):
            with self.subTest(phase=phase):
                device = OfficialDevice()
                identity = _usb_identity(device)
                if phase == "drain":
                    device.config.interface.endpoints[1].read = lambda *_a, **_k: (
                        (_ for _ in ()).throw(RuntimeError("drain failed"))
                    )
                claim_error = RuntimeError("claim failed") if phase == "claim" else None
                with (
                    patch("goodix5503.probe._find_unique_device", return_value=device),
                    patch(
                        "goodix5503.probe._official_loader_usb_reset_sequence",
                        return_value=(device, 10.0, identity),
                    ),
                    patch(
                        "goodix5503.probe.usb.util.claim_interface",
                        side_effect=claim_error,
                    ),
                    patch("goodix5503.probe.usb.util.release_interface") as release,
                    patch("goodix5503.probe.usb.util.dispose_resources") as dispose,
                    self.assertRaisesRegex(RuntimeError, f"{phase} failed"),
                ):
                    ReadOnlyUsbSession._for_official_loader()
                if phase == "claim":
                    release.assert_not_called()
                else:
                    release.assert_called_once_with(device, 0)
                dispose.assert_called_once_with(device)

    def test_raw_wake_writes_exactly_one_unframed_byte(self):
        class Endpoint:
            def __init__(self):
                self.calls = []

            def write(self, payload, timeout):
                self.calls.append((payload, timeout))
                return len(payload)

        session = object.__new__(ReadOnlyUsbSession)
        session.timeout_ms = 5000
        session.endpoint_out = Endpoint()
        session.wake_up(timeout_ms=123)
        self.assertEqual(session.endpoint_out.calls, [(b"\xe5", 123)])

        session.endpoint_out.write = lambda _payload, _timeout: 0
        with self.assertRaisesRegex(ProtocolError, "not fully"):
            session.wake_up()

    def test_initial_drain_wipes_buffers_and_is_capacity_bounded(self):
        class Endpoint:
            def __init__(self, count):
                self.buffers = [array.array("B", bytes((value,))) for value in range(1, count + 1)]
                self.returned = []

            def read(self, _size, timeout):
                self.assert_timeout = timeout
                if not self.buffers:
                    import usb.core

                    raise usb.core.USBTimeoutError("quiet")
                result = self.buffers.pop(0)
                self.returned.append(result)
                return result

        session = object.__new__(ReadOnlyUsbSession)
        session._max_packet_size = 64
        session._rx_buffer = bytearray(b"stale")
        endpoint = Endpoint(2)
        session.endpoint_in = endpoint
        session._drain_input()
        self.assertEqual(session._rx_buffer, bytearray())
        self.assertEqual(endpoint.assert_timeout, 100)
        self.assertTrue(all(not any(buffer) for buffer in endpoint.returned))

        overflow = Endpoint(5)
        session.endpoint_in = overflow
        with self.assertRaisesRegex(ProtocolError, "capacity"):
            session._drain_input()
        self.assertEqual(len(overflow.returned), 5)
        self.assertTrue(all(not any(buffer) for buffer in overflow.returned))

    def test_framed_writer_rejects_short_usb_chunk(self):
        class Endpoint:
            def __init__(self, written):
                self.written = written
                self.timeouts = []

            def write(self, _payload, timeout):
                self.timeouts.append(timeout)
                return self.written

        session = object.__new__(ReadOnlyUsbSession)
        session.timeout_ms = 5000
        session.endpoint_out = Endpoint(64)
        session._ReadOnlyUsbSession__write_packet(b"packet", timeout_ms=321)
        self.assertEqual(session.endpoint_out.timeouts, [321])
        with self.assertRaisesRegex(ProtocolError, "positive"):
            session._ReadOnlyUsbSession__write_packet(b"packet", timeout_ms=0)
        session.endpoint_out = Endpoint(63)
        with self.assertRaisesRegex(ProtocolError, "not fully"):
            session._ReadOnlyUsbSession__write_packet(b"packet")

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

    def test_only_exact_chip_id_register_read_is_allowed(self):
        payload = b"\x00\x00\x00\x04\x00"
        ReadOnlyUsbSession._validate_request(COMMAND_READ_REGISTER, payload, True)
        for rejected in (b"", b"\x01\x00\x00\x04\x00", b"\x00\x00\x00\x02\x00"):
            with self.subTest(payload=rejected), self.assertRaises(UnsafeCommandError):
                ReadOnlyUsbSession._validate_request(
                    COMMAND_READ_REGISTER, rejected, True
                )

    def test_chip_id_read_uses_fixed_register_and_shift(self):
        session = object.__new__(ReadOnlyUsbSession)
        calls = []

        def request(command, payload):
            calls.append((command, payload))
            return bytes.fromhex("0f000022")

        session.request = request
        self.assertEqual(session.read_chip_id(), 0x220F)
        self.assertEqual(
            calls,
            [(COMMAND_READ_REGISTER, b"\x00\x00\x00\x04\x00")],
        )
        session.request = lambda *_args: b"short"
        with self.assertRaisesRegex(ProtocolError, "exactly 4"):
            session.read_chip_id()

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
            struct.pack("<II", OFFICIAL_WHITEBOX_PSK_SELECTOR, 0),
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

    def test_otp_read_uses_only_fixed_request_and_exact_length(self):
        session = object.__new__(ReadOnlyUsbSession)
        calls = []

        def exchange(command, payload, *, checksum=True):
            calls.append((command, payload, checksum))
            return bytes(range(64))

        session._ReadOnlyUsbSession__exchange = exchange
        with patch("goodix5503.probe._disable_core_dumps") as disable_dumps:
            otp = session.read_otp()
        disable_dumps.assert_called_once_with()
        try:
            self.assertEqual(otp, bytearray(range(64)))
            self.assertEqual(calls, [(COMMAND_READ_OTP, b"\x00\x00", True)])
        finally:
            otp[:] = b"\x00" * len(otp)

        session._ReadOnlyUsbSession__exchange = lambda *_args, **_kwargs: b"short"
        with self.assertRaisesRegex(ProtocolError, "exactly 64"):
            session.read_otp()

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
                "goodix5503.probe._write_or_verify_secure_backup",
                side_effect=lambda _path, _data: order.append("write"),
            ),
        ):
            length, _digest, _path = session.backup_protected_record()
        self.assertEqual(length, len(value))
        self.assertEqual(
            order, ["harden", "close", "drop", "harden", "write"]
        )

    def test_rollback_set_reads_fixed_selectors_and_wipes_records(self):
        values = {
            OFFICIAL_PROTECTED_PSK_SELECTOR: b"protected",
            OFFICIAL_R_PSK_HASH_SELECTOR: b"h" * 32,
        }
        session = object.__new__(ReadOnlyUsbSession)
        calls = []

        def exchange(command, payload, *, checksum=True):
            selector, reserved = struct.unpack("<II", payload)
            calls.append((command, selector, reserved, checksum))
            value = values[selector]
            return b"\x00" + struct.pack("<II", selector, len(value)) + value

        session._ReadOnlyUsbSession__exchange = exchange
        order = []
        session.close = lambda: order.append("close")
        written_records = []

        def save(_path, record):
            order.append("write")
            written_records.append(record)
            return "created"

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
                "goodix5503.probe._write_or_verify_secure_backup",
                side_effect=save,
            ),
        ):
            result = session.backup_rollback_set()

        self.assertEqual(
            [item[1] for item in calls],
            [
                OFFICIAL_PROTECTED_PSK_SELECTOR,
                OFFICIAL_R_PSK_HASH_SELECTOR,
            ],
        )
        self.assertEqual(
            order,
            ["harden", "close", "drop", "harden", "write", "write"],
        )
        self.assertEqual(set(result), {"0xbb010002", "0xbb010003", "0xbb020007"})
        self.assertEqual(
            result["0xbb010003"]["status"],
            "not-read-write-only-unavailable",
        )
        self.assertTrue(all(not any(record) for record in written_records))

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

    def test_existing_secure_backup_is_verified_without_overwrite(self):
        protected = bytearray(b"opaque-protected-record")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "backup.bin"
            path.write_bytes(protected)
            path.chmod(0o600)
            _verify_secure_backup(path, protected)
            self.assertEqual(
                _write_or_verify_secure_backup(path, protected),
                "verified-existing",
            )
            with self.assertRaisesRegex(RuntimeError, "content differs"):
                _verify_secure_backup(path, bytearray(b"Xpaque-protected-record"))
            self.assertEqual(path.read_bytes(), bytes(protected))

    def test_padded_64_byte_response_returns_one_frame(self):
        frame = _encode_packet(COMMAND_ACK, bytes((COMMAND_FIRMWARE_VERSION, 1)))
        session = reader_session(frame + b"\x00" * (64 - len(frame)))
        self.assertEqual(session._read_frame(), frame)
        self.assertEqual(session._rx_buffer, b"")

    def test_fragmented_frame_uses_one_decreasing_operation_deadline(self):
        frame = _encode_packet(COMMAND_FIRMWARE_VERSION, b"version")
        session = reader_session(frame[:2], frame[2:5], frame[5:])
        with patch(
            "goodix5503.probe.time.monotonic",
            side_effect=(100.0, 100.1, 100.2, 100.3),
        ):
            self.assertEqual(session._read_frame(), frame)
        self.assertEqual(len(session.endpoint_in.timeouts), 3)
        self.assertLessEqual(session.endpoint_in.timeouts[0], 5000)
        self.assertGreater(
            session.endpoint_in.timeouts[0], session.endpoint_in.timeouts[1]
        )
        self.assertGreater(
            session.endpoint_in.timeouts[1], session.endpoint_in.timeouts[2]
        )

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
