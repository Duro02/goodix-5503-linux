"""Regression checks for the source-level 10063-only firmware gate.

These tests inspect local source only.  They do not import the USB transport,
enumerate a device, or issue a protocol command.
"""

from pathlib import Path
import re
import unittest


DRIVER_SOURCE = (
    Path(__file__).resolve().parents[1] / "libfprint" / "drivers" / "goodix5503.c"
)


class FirmwareGuardStaticTests(unittest.TestCase):
    def test_only_10063_is_accepted_and_10062_has_no_production_literal(self):
        source = DRIVER_SOURCE.read_text(encoding="utf-8")
        expected = re.search(
            r'static const char expected_firmware\[\] = "([^"]+)";', source
        )
        self.assertIsNotNone(expected)
        self.assertEqual(expected.group(1), "GF3258_RTSEC_APP_10063")
        self.assertNotIn("GF3258_RTSEC_APP_10062", source)

    def test_unknown_firmware_fails_before_any_follow_up_device_command(self):
        source = DRIVER_SOURCE.read_text(encoding="utf-8")

        start = source.index("static void\ngoodix5503_firmware_done")
        end = source.index("static void\ngoodix5503_nop_done", start)
        firmware_done = source[start:end]

        reject = firmware_done.index("unsupported Goodix 5503 firmware identity")
        reject_return = firmware_done.index("return;", reject)
        psk = firmware_done.index("GOODIX5503_COMMAND_READ_PSK")
        self.assertLess(reject_return, psk)
        rejected_path = firmware_done[:reject_return]
        self.assertIn("goodix5503_pre_reset_fail", rejected_path)
        self.assertNotIn("goodix5503_command_start", rejected_path)
        for command in (
            "GOODIX5503_COMMAND_READ_PSK",
            "GOODIX5503_COMMAND_RESET",
            "GOODIX5503_COMMAND_CONFIG",
        ):
            self.assertNotIn(command, rejected_path)


if __name__ == "__main__":
    unittest.main()
