import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from goodix5503 import pairing


class PairingTests(unittest.TestCase):
    def test_r_verification_known_vectors(self):
        zero = bytearray(32)
        incrementing = bytearray(range(32))
        zero_result = pairing.calculate_r_verification_record(zero)
        incrementing_result = pairing.calculate_r_verification_record(incrementing)
        try:
            self.assertEqual(zero_result, pairing.KNOWN_ZERO_R_VERIFICATION)
            self.assertEqual(
                incrementing_result.hex(),
                "708a55de28b42cefac0215e5e8069ddcf759ea714515c6fea6fb692548c56b23",
            )
        finally:
            zero[:] = b"\x00" * len(zero)
            incrementing[:] = b"\x00" * len(incrementing)
            zero_result[:] = b"\x00" * len(zero_result)
            incrementing_result[:] = b"\x00" * len(incrementing_result)

    def test_prepare_is_exclusive_idempotent_and_wipes_buffers(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            directory = Path(temporary_name) / "device-backup"
            directory.mkdir(mode=0o700)
            paths = {
                "PSK_PATH": directory / "new-pairing-psk.bin",
                "WHITEBOX_PATH": directory / "new-pairing-whitebox-bb010003.bin",
                "VERIFICATION_PATH": directory
                / "new-pairing-verification-bb020007.bin",
            }
            captured = []

            def fill(secret):
                secret[:] = bytes(range(32))

            def encode(psk, _wbdi):
                captured.append(psk)
                return bytearray(b"\xa5" * 96)

            patches = [patch.object(pairing, name, value) for name, value in paths.items()]
            for active_patch in patches:
                active_patch.start()
            try:
                with (
                    patch.object(pairing, "_fill_random_secret", side_effect=fill),
                    patch.object(pairing, "find_pinned_wbdi", return_value=Path("pinned")),
                    patch.object(pairing, "verify_known_vector"),
                    patch.object(pairing, "emulate_whitebox", side_effect=encode),
                ):
                    first = pairing.prepare_pairing()
                self.assertEqual(first["key_source"], "generated")
                self.assertEqual(set(first["statuses"].values()), {"created"})
                self.assertEqual(paths["PSK_PATH"].read_bytes(), bytes(range(32)))
                self.assertEqual(paths["WHITEBOX_PATH"].read_bytes(), b"\xa5" * 96)
                for path in paths.values():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

                with (
                    patch.object(
                        pairing,
                        "_fill_random_secret",
                        side_effect=AssertionError("must reuse existing key"),
                    ),
                    patch.object(pairing, "find_pinned_wbdi", return_value=Path("pinned")),
                    patch.object(pairing, "verify_known_vector"),
                    patch.object(pairing, "emulate_whitebox", side_effect=encode),
                ):
                    second = pairing.prepare_pairing()
                self.assertEqual(second["key_source"], "existing")
                self.assertEqual(
                    set(second["statuses"].values()), {"verified-existing"}
                )
                self.assertTrue(all(value == bytearray(32) for value in captured))
            finally:
                for active_patch in reversed(patches):
                    active_patch.stop()

    def test_partial_random_key_is_wiped_on_generation_failure(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            directory = Path(temporary_name) / "device-backup"
            directory.mkdir(mode=0o700)
            captured = []

            def fail_after_partial_fill(secret):
                captured.append(secret)
                secret[:8] = b"partial!"
                raise OSError("injected random-source failure")

            with (
                patch.object(pairing, "PSK_PATH", directory / "missing-psk"),
                patch.object(pairing, "_fill_random_secret", side_effect=fail_after_partial_fill),
                self.assertRaises(OSError),
            ):
                pairing.prepare_pairing()
            self.assertEqual(captured, [bytearray(32)])

    def test_secure_reader_rejects_unsafe_mode(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            directory = Path(temporary_name) / "private"
            directory.mkdir(mode=0o700)
            path = directory / "secret"
            path.write_bytes(bytes(32))
            path.chmod(0o644)
            with self.assertRaises(pairing.PairingPreparationError):
                pairing._read_secure_secret(path, 32)


if __name__ == "__main__":
    unittest.main()
