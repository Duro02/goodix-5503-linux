import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from goodix5503 import setup


class SetupTests(unittest.TestCase):
    def test_matched_pairing_performs_no_write_or_preparation(self):
        services = []

        def run_json(command):
            self.assertIn("--root-check", command)
            return {"pairing": "matched"}

        with (
            patch.object(setup.os, "geteuid", return_value=1000),
            patch.object(setup, "disable_core_dumps"),
            patch.object(setup, "_service", side_effect=services.append),
            patch.object(setup, "_run_json", side_effect=run_json),
            patch.object(
                setup, "prepare_pairing", side_effect=AssertionError("must not prepare")
            ),
        ):
            result = setup.setup_pairing()

        self.assertEqual(result["operation"], "already-paired-no-write")
        self.assertEqual(services, ["stop", "restart"])

    def test_confirmation_is_required_before_backup_or_generation(self):
        services = []
        with (
            patch.object(setup.os, "geteuid", return_value=1000),
            patch.object(setup, "disable_core_dumps"),
            patch.object(setup, "_service", side_effect=services.append),
            patch.object(setup, "_run_json", return_value={"pairing": "mismatched"}),
            patch.object(setup, "find_pinned_wbdi", return_value=Path("pinned")),
            patch.object(setup.importlib.util, "find_spec", return_value=object()),
            patch("builtins.input", return_value="no"),
            patch.object(
                setup, "prepare_pairing", side_effect=AssertionError("must not prepare")
            ),
            self.assertRaisesRegex(setup.SetupError, "not confirmed"),
        ):
            setup.setup_pairing()
        self.assertEqual(services, ["stop", "restart"])

    def test_full_flow_orders_backup_prepare_write_install_and_final_check(self):
        services = []
        events = []
        check_results = iter(
            [{"pairing": "host-psk-missing"}, {"pairing": "matched"}]
        )

        def run_json(command):
            for mode in setup._ROOT_MODES:
                if mode in command:
                    events.append(mode)
                    if mode == "--root-check":
                        return next(check_results)
                    return {"operation": mode}
            raise AssertionError(command)

        def prepare():
            events.append("prepare")
            return {"operation": "offline-only-no-usb"}

        with (
            patch.object(setup.os, "geteuid", return_value=1000),
            patch.object(setup, "disable_core_dumps"),
            patch.object(setup, "_service", side_effect=services.append),
            patch.object(setup, "_run_json", side_effect=run_json),
            patch.object(setup, "find_pinned_wbdi", return_value=Path("pinned")),
            patch.object(setup.importlib.util, "find_spec", return_value=object()),
            patch.object(setup, "_prepared_pairing_exists", return_value=False),
            patch.object(setup, "prepare_pairing", side_effect=prepare),
            patch("builtins.input", return_value=setup.USER_CONFIRMATION),
        ):
            result = setup.setup_pairing()

        self.assertEqual(result["pairing"], "matched")
        self.assertEqual(
            events,
            [
                "--root-check",
                "--root-backup",
                "prepare",
                "--root-provision",
                "--root-install",
                "--root-check",
            ],
        )
        self.assertEqual(services, ["stop", "restart"])

    def test_committed_resume_preserves_old_backup_and_reaches_host_install(self):
        services = []
        events = []
        check_results = iter(
            [{"pairing": "host-psk-missing"}, {"pairing": "matched"}]
        )

        def run_json(command):
            for mode in setup._ROOT_MODES:
                if mode in command:
                    events.append(mode)
                    if mode == "--root-check":
                        return next(check_results)
                    if mode == "--root-backup":
                        raise AssertionError("resume must preserve the old backup")
                    if mode == "--root-provision":
                        return {"operation": "already-provisioned-no-write"}
                    return {"operation": mode}
            raise AssertionError(command)

        def prepare():
            events.append("prepare")
            return {"operation": "offline-only-no-usb", "key_source": "existing"}

        with (
            patch.object(setup.os, "geteuid", return_value=1000),
            patch.object(setup, "disable_core_dumps"),
            patch.object(setup, "_service", side_effect=services.append),
            patch.object(setup, "_run_json", side_effect=run_json),
            patch.object(setup, "find_pinned_wbdi", return_value=Path("pinned")),
            patch.object(setup.importlib.util, "find_spec", return_value=object()),
            patch.object(setup, "_prepared_pairing_exists", return_value=True),
            patch.object(setup, "prepare_pairing", side_effect=prepare),
            patch("builtins.input", return_value=setup.USER_CONFIRMATION),
        ):
            result = setup.setup_pairing()

        self.assertEqual(result["pairing"], "matched")
        self.assertEqual(
            events,
            [
                "--root-check",
                "prepare",
                "--root-provision",
                "--root-install",
                "--root-check",
            ],
        )
        self.assertEqual(
            result["backup"], {"operation": "preserved-existing-backup"}
        )
        self.assertEqual(services, ["stop", "restart"])

    def test_restart_failure_does_not_replace_primary_setup_error(self):
        services = []

        def service(command):
            services.append(command)
            if command == "restart":
                raise OSError("injected restart failure")

        with (
            patch.object(setup.os, "geteuid", return_value=1000),
            patch.object(setup, "disable_core_dumps"),
            patch.object(setup, "_service", side_effect=service),
            patch.object(
                setup,
                "_run_json",
                side_effect=setup.SetupError("primary setup failure"),
            ),
            self.assertRaisesRegex(setup.SetupError, "primary setup failure") as caught,
        ):
            setup.setup_pairing()

        self.assertEqual(services, ["stop", "restart"])
        self.assertTrue(
            any("injected restart failure" in note for note in caught.exception.__notes__)
        )

    def test_root_provision_requires_exact_confirmation(self):
        with (
            patch.object(setup, "_sudo_identity", return_value=(1000, 1000)),
            patch.object(setup, "provision_prepared_pairing") as provision,
            self.assertRaisesRegex(setup.SetupError, "exact provisioning"),
        ):
            setup._root_provision(None)
        provision.assert_not_called()

    def test_secure_reader_rejects_wrong_owner_or_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "secret"
            path.write_bytes(b"x" * 32)
            path.chmod(0o644)
            with self.assertRaisesRegex(setup.SetupError, "unsafe secret"):
                setup._read_exact_secure_file(
                    path, 32, expected_uid=os.geteuid()
                )
            path.chmod(0o600)
            secret = setup._read_exact_secure_file(
                path, 32, expected_uid=os.geteuid()
            )
            try:
                self.assertEqual(secret, bytearray(b"x" * 32))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            finally:
                secret[:] = b"\x00" * len(secret)

    def test_host_install_requires_matching_live_device_readback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "prepared-psk.bin"
            target = root / "system" / "psk.bin"
            source.write_bytes(b"p" * 32)
            source.chmod(0o600)
            session = MagicMock()
            session.__enter__.return_value = session
            with (
                patch.object(setup, "PSK_PATH", source),
                patch.object(setup, "SYSTEM_PSK_PATH", target),
                patch.object(
                    setup, "_sudo_identity", return_value=(os.geteuid(), os.getegid())
                ),
                patch.object(setup, "disable_core_dumps"),
                patch.object(
                    setup, "calculate_r_verification_record", return_value=bytearray(b"e" * 32)
                ),
                patch.object(setup, "ReadOnlyUsbSession", return_value=session),
                patch.object(
                    setup, "_read_live_verification", return_value=bytearray(b"x" * 32)
                ),
                self.assertRaisesRegex(setup.SetupError, "exact device readback"),
            ):
                setup._root_install()
            self.assertFalse(target.exists())

    def test_root_command_carries_confirmation_only_for_write(self):
        provision = setup._root_command("--root-provision")
        self.assertIn("--write-confirmation", provision)
        self.assertIn(setup.WRITE_CONFIRMATION, provision)
        check = setup._root_command("--root-check")
        self.assertNotIn("--write-confirmation", check)


if __name__ == "__main__":
    unittest.main()
