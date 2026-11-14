#!/usr/bin/env python3
"""Run all Python regression tests without a PyUSB installation or USB access."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from offline_usb_stub import install


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TEST_DIRECTORY = REPOSITORY_ROOT / "tests"


def main() -> int:
    sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
    install()
    suite = unittest.defaultTestLoader.discover(
        str(TEST_DIRECTORY), pattern="test_*.py", top_level_dir=str(TEST_DIRECTORY)
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
