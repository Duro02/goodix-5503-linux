import struct
import unittest
from unittest.mock import MagicMock, patch

from goodix5503 import provision
from goodix5503.probe import ReadOnlyUsbSession


class ProvisionTests(unittest.TestCase):
    def test_confirmation_is_checked_before_usb_open(self):
        with (
            patch.object(
                provision.ReadOnlyUsbSession,
                "__init__",
                side_effect=AssertionError("USB must not open"),
            ),
            self.assertRaises(provision.ProvisioningError),
        ):
            provision.provision_prepared_pairing(confirmation="wrong")

    def test_session_exposes_no_public_mutator(self):
        self.assertFalse(hasattr(ReadOnlyUsbSession, "write_prepared_whitebox"))

    def test_only_exact_whitebox_tlv_reaches_internal_write_transport(self):
        session = object.__new__(ReadOnlyUsbSession)
        whitebox = bytearray(range(96))
        captured = []

        def exchange(_session, command, payload):
            captured.append((command, bytes(payload)))
            return b"\x00"

        with patch.object(
            ReadOnlyUsbSession,
            "_ReadOnlyUsbSession__exchange",
            autospec=True,
            side_effect=exchange,
        ):
            provision._write_prepared_whitebox(session, whitebox)

        self.assertEqual(
            captured,
            [
                (
                    provision.COMMAND_PRESET_PSK_WRITE_R,
                    struct.pack(
                        "<II", provision.OFFICIAL_WHITEBOX_PSK_SELECTOR, 96
                    )
                    + bytes(range(96)),
                )
            ],
        )
        self.assertEqual(whitebox, bytearray(range(96)))

    def test_nonzero_mcu_write_status_is_rejected(self):
        session = object.__new__(ReadOnlyUsbSession)
        with (
            patch.object(
                ReadOnlyUsbSession,
                "_ReadOnlyUsbSession__exchange",
                autospec=True,
                return_value=b"\x01",
            ),
            self.assertRaisesRegex(Exception, "status 0x01"),
        ):
            provision._write_prepared_whitebox(session, bytearray(96))

    def test_rerun_recognizes_prepared_state_without_another_write(self):
        expected = bytearray(b"\x44" * 32)
        psk = bytearray(b"\x22" * 32)
        whitebox = bytearray(b"\x33" * 96)
        session = MagicMock()

        def request(command, payload=b"", *, checksum=True):
            if command == provision.COMMAND_NOP:
                return b""
            if command == provision.COMMAND_FIRMWARE_VERSION:
                return provision.EXPECTED_FIRMWARE.encode() + b"\x00"
            if command == provision.COMMAND_GET_IAP_VERSION:
                return provision.EXPECTED_IAP.encode() + b"\x00"
            raise AssertionError(f"unexpected command {command:#x}")

        session.request.side_effect = request
        with (
            patch.object(provision, "ReadOnlyUsbSession", return_value=session),
            patch.object(provision, "_drop_sudo_privileges"),
            patch.object(provision, "_disable_core_dumps"),
            patch.object(provision.os, "geteuid", return_value=1000),
            patch.object(
                provision,
                "_read_live_verification",
                return_value=bytearray(expected),
            ),
            patch.object(
                provision,
                "_read_secure_secret",
                return_value=bytearray(b"\x11" * 32),
            ),
            patch.object(
                provision,
                "_load_and_validate_material",
                return_value=(psk, whitebox, expected),
            ),
            patch.object(provision, "_write_prepared_whitebox") as write,
        ):
            result = provision.provision_prepared_pairing(
                confirmation=provision.WRITE_CONFIRMATION
            )

        self.assertEqual(result["operation"], "already-provisioned-no-write")
        write.assert_not_called()
        self.assertEqual(psk, bytearray(32))
        self.assertEqual(whitebox, bytearray(96))
        self.assertEqual(expected, bytearray(32))

    def test_orchestration_checks_old_state_writes_once_and_reads_back(self):
        old = bytearray(b"\x11" * 32)
        psk = bytearray(b"\x22" * 32)
        whitebox = bytearray(b"\x33" * 96)
        expected = bytearray(b"\x44" * 32)
        live_records = [bytes(old), bytes(expected)]

        class FakeSession:
            def __init__(self, _timeout):
                self.writes = []
                self.closed = False

            def request(self, command, payload=b"", *, checksum=True):
                if command == provision.COMMAND_NOP:
                    return b""
                if command == provision.COMMAND_FIRMWARE_VERSION:
                    return provision.EXPECTED_FIRMWARE.encode() + b"\x00"
                if command == provision.COMMAND_GET_IAP_VERSION:
                    return provision.EXPECTED_IAP.encode() + b"\x00"
                if command == provision.COMMAND_PRESET_PSK_READ:
                    value = live_records.pop(0)
                    return (
                        b"\x00"
                        + struct.pack(
                            "<II", provision.OFFICIAL_R_PSK_HASH_SELECTOR, len(value)
                        )
                        + value
                    )
                raise AssertionError(f"unexpected command {command:#x}")

            def close(self):
                self.closed = True

        fake = FakeSession(5)

        def write(_session, value):
            fake.writes.append(bytes(value))

        with (
            patch.object(provision, "ReadOnlyUsbSession", return_value=fake),
            patch.object(provision, "_write_prepared_whitebox", side_effect=write),
            patch.object(provision, "_drop_sudo_privileges"),
            patch.object(provision, "_disable_core_dumps"),
            patch.object(provision.os, "geteuid", return_value=1000),
            patch.object(
                provision, "_read_secure_secret", return_value=bytearray(old)
            ),
            patch.object(
                provision,
                "_load_and_validate_material",
                return_value=(psk, whitebox, expected),
            ),
        ):
            result = provision.provision_prepared_pairing(
                confirmation=provision.WRITE_CONFIRMATION
            )

        self.assertEqual(result["verification"], "matched-prepared-record")
        self.assertEqual(fake.writes, [b"\x33" * 96])
        self.assertTrue(fake.closed)
        self.assertEqual(live_records, [])
        self.assertEqual(psk, bytearray(32))
        self.assertEqual(whitebox, bytearray(96))
        self.assertEqual(expected, bytearray(32))

    def test_close_failure_does_not_replace_ambiguous_write_error(self):
        old = bytearray(b"\x11" * 32)
        psk = bytearray(b"\x22" * 32)
        whitebox = bytearray(b"\x33" * 96)
        expected = bytearray(b"\x44" * 32)
        session = MagicMock()

        def request(command, payload=b"", *, checksum=True):
            if command == provision.COMMAND_NOP:
                return b""
            if command == provision.COMMAND_FIRMWARE_VERSION:
                return provision.EXPECTED_FIRMWARE.encode() + b"\x00"
            if command == provision.COMMAND_GET_IAP_VERSION:
                return provision.EXPECTED_IAP.encode() + b"\x00"
            raise AssertionError(f"unexpected command {command:#x}")

        session.request.side_effect = request
        session.close.side_effect = OSError("injected close failure")
        with (
            patch.object(provision, "ReadOnlyUsbSession", return_value=session),
            patch.object(provision, "_drop_sudo_privileges"),
            patch.object(provision, "_disable_core_dumps"),
            patch.object(provision.os, "geteuid", return_value=1000),
            patch.object(
                provision, "_read_live_verification", return_value=bytearray(old)
            ),
            patch.object(
                provision, "_read_secure_secret", return_value=bytearray(old)
            ),
            patch.object(
                provision,
                "_load_and_validate_material",
                return_value=(psk, whitebox, expected),
            ),
            patch.object(
                provision,
                "_write_prepared_whitebox",
                side_effect=OSError("injected ambiguous write failure"),
            ),
            self.assertRaisesRegex(
                provision.ProvisioningError, "write outcome is ambiguous"
            ) as caught,
        ):
            provision.provision_prepared_pairing(
                confirmation=provision.WRITE_CONFIRMATION
            )

        self.assertTrue(
            any("injected close failure" in note for note in caught.exception.__notes__)
        )
        self.assertEqual(psk, bytearray(32))
        self.assertEqual(whitebox, bytearray(96))
        self.assertEqual(expected, bytearray(32))


if __name__ == "__main__":
    unittest.main()
