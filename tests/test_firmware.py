import unittest

from goodix5503.firmware import (
    FirmwareSupport,
    classify_firmware,
)


class FirmwareSupportTests(unittest.TestCase):

    def test_supported_10063(self):
        self.assertEqual(
            classify_firmware(
                "GF3258_RTSEC_APP_10063",
                "MILAN_RTSEC_IAP_10027",
            ),
            FirmwareSupport.SUPPORTED,
        )

    def test_experimental_10062(self):
        self.assertEqual(
            classify_firmware(
                "GF3258_RTSEC_APP_10062",
                "MILAN_RTSEC_IAP_10027",
            ),
            FirmwareSupport.EXPERIMENTAL,
        )

    def test_unknown_firmware(self):
        self.assertEqual(
            classify_firmware(
                "GF3258_RTSEC_APP_10061",
                "MILAN_RTSEC_IAP_10027",
            ),
            FirmwareSupport.UNKNOWN,
        )

    def test_wrong_iap(self):
        self.assertEqual(
            classify_firmware(
                "GF3258_RTSEC_APP_10062",
                "MILAN_RTSEC_IAP_10026",
            ),
            FirmwareSupport.UNKNOWN,
        )


if __name__ == "__main__":
    unittest.main()
