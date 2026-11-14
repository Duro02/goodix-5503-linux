"""Inert PyUSB replacement used only by the offline Python test runner.

It is deliberately installed before importing ``goodix5503``.  Any accidental
enumeration, interface claim, transfer, or resource release fails immediately
instead of reaching a host USB backend.
"""

from __future__ import annotations

import sys
from types import ModuleType


class USBTimeoutError(TimeoutError):
    """Compatibility exception used by fake endpoint tests."""


def _blocked(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("offline test suite attempted to access USB")


def install() -> None:
    """Force later ``usb`` imports to use an inert in-memory module tree."""
    usb = ModuleType("usb")
    core = ModuleType("usb.core")
    util = ModuleType("usb.util")

    core.USBTimeoutError = USBTimeoutError
    core.find = _blocked
    util.find_descriptor = _blocked
    util.claim_interface = _blocked
    util.release_interface = _blocked
    util.dispose_resources = _blocked
    util.endpoint_direction = _blocked
    util.endpoint_type = _blocked
    util.ENDPOINT_IN = 0x80
    util.ENDPOINT_OUT = 0x00
    util.ENDPOINT_TYPE_BULK = 0x02

    usb.core = core
    usb.util = util
    sys.modules["usb"] = usb
    sys.modules["usb.core"] = core
    sys.modules["usb.util"] = util
