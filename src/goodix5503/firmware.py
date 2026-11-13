from enum import Enum


class FirmwareSupport(Enum):
    SUPPORTED = "supported"
    EXPERIMENTAL = "experimental"
    UNKNOWN = "unknown"


def classify_firmware(firmware: str, iap: str) -> FirmwareSupport:
    if iap != "MILAN_RTSEC_IAP_10027":
        return FirmwareSupport.UNKNOWN

    if firmware == "GF3258_RTSEC_APP_10063":
        return FirmwareSupport.SUPPORTED

    if firmware == "GF3258_RTSEC_APP_10062":
        return FirmwareSupport.EXPERIMENTAL

    return FirmwareSupport.UNKNOWN
