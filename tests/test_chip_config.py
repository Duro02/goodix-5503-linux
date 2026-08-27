import importlib.util
import unittest
from pathlib import Path

from goodix5503.chip_config import (
    EXPECTED_ZERO_OTP_CONFIG,
    ChipConfigError,
    _config_checksum,
    _validate_config_checksum,
    emulate_chip_config,
    verify_zero_otp_vector,
)
from goodix5503.whitebox import WhiteboxError, find_pinned_wbdi


class ChipConfigTests(unittest.TestCase):
    def pinned_wbdi_or_skip(self):
        if importlib.util.find_spec("unicorn") is None:
            self.skipTest("unicorn optional dependency is not installed")
        try:
            return find_pinned_wbdi(Path(__file__).resolve().parents[1])
        except WhiteboxError as error:
            self.skipTest(str(error))

    def test_requires_mutable_exact_64_byte_otp(self):
        with self.assertRaises(TypeError):
            emulate_chip_config(bytes(64), Path("unused"))
        with self.assertRaises(ValueError):
            emulate_chip_config(bytearray(63), Path("unused"))

    def test_pinned_official_zero_otp_vector(self):
        verify_zero_otp_vector(self.pinned_wbdi_or_skip())
        self.assertEqual(len(EXPECTED_ZERO_OTP_CONFIG), 256)

    def test_official_checksum_accepts_vector_and_rejects_corruption(self):
        self.assertEqual(
            _config_checksum(EXPECTED_ZERO_OTP_CONFIG[:254]),
            int.from_bytes(EXPECTED_ZERO_OTP_CONFIG[254:], "little"),
        )
        _validate_config_checksum(EXPECTED_ZERO_OTP_CONFIG)
        corrupted = bytearray(EXPECTED_ZERO_OTP_CONFIG)
        corrupted[100] ^= 1
        try:
            with self.assertRaises(ChipConfigError):
                _validate_config_checksum(corrupted)
        finally:
            corrupted[:] = b"\x00" * len(corrupted)


if __name__ == "__main__":
    unittest.main()
