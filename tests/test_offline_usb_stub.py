"""Assertions for the USB isolation used by ``run_offline_tests.py``."""

import unittest

from offline_usb_stub import _blocked


class OfflineUsbStubTests(unittest.TestCase):
    def test_runner_replaces_usb_enumeration_with_the_inert_guard(self):
        import usb.core
        import usb.util

        self.assertIs(usb.core.find, _blocked)
        self.assertIs(usb.util.claim_interface, _blocked)
        self.assertIs(usb.util.dispose_resources, _blocked)


if __name__ == "__main__":
    unittest.main()
