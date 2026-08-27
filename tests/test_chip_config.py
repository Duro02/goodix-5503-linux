import hashlib
import importlib.util
import unittest
from pathlib import Path

from goodix5503.chip_config import (
    EXPECTED_ZERO_OTP_CONFIG,
    LOCAL_RUNTIME_CONFIG_SHA256,
    RUNTIME_CONFIG_PATH,
    ChipConfigError,
    _config_checksum,
    _validate_config_checksum,
    build_local_runtime_config,
    build_runtime_config,
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

    def test_free_local_builder_matches_official_otp_derived_config(self):
        config = build_local_runtime_config()
        try:
            self.assertEqual(hashlib.sha256(config).hexdigest(), LOCAL_RUNTIME_CONFIG_SHA256)
            if RUNTIME_CONFIG_PATH.exists():
                self.assertEqual(config, RUNTIME_CONFIG_PATH.read_bytes())
        finally:
            config[:] = b"\x00" * len(config)

    def test_free_general_builder_matches_static_otp_known_answers(self):
        vectors = (
            ({}, "e60d9c767c140b080a3b69ba89d88c60514373beda4a57da9248940a28f46246"),
            ({42: 0xD7, 43: 0x28}, LOCAL_RUNTIME_CONFIG_SHA256),
            ({42: 0, 43: 0xAB, 45: 0x54}, "8d773ede73c5dfead300019244ce6e1f1850e7bfbf9491b3b822cb01b763b459"),
            ({42: 0x21, 45: 0x21}, "7a86e397c8b55dfea7b892d1d1414dcc221a2c37f59465505f44fca6323d06df"),
            ({27: 0x11}, "240fa4de444ea9354fb2ada9f95c9811f5d6c5b902bbacc0513ef893136ffbbc"),
            ({27: 0x22, 42: 0xD7, 43: 0x28}, "adc6d213eb13588ee4207e0e12002e826810ebff604c24a1ddcc12f4d6cee562"),
        )
        for assignments, expected_hash in vectors:
            with self.subTest(assignments=assignments):
                otp = bytearray(64)
                for offset, value in assignments.items():
                    otp[offset] = value
                config = build_runtime_config(otp)
                try:
                    self.assertEqual(hashlib.sha256(config).hexdigest(), expected_hash)
                    _validate_config_checksum(config)
                finally:
                    otp[:] = b"\x00" * len(otp)
                    config[:] = b"\x00" * len(config)
        with self.assertRaises(ValueError):
            build_runtime_config(bytes(63))

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
