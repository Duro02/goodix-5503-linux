import builtins
import unittest
from array import array
from unittest.mock import patch

import usb.core

from goodix5503.wake_diagnostic import (
    WAKE_DIAGNOSTIC_CONFIRMATION,
    WakeDiagnosticError,
    observe_one_wake,
)


class WakeDiagnosticTests(unittest.TestCase):
    def test_gate_prevents_usb_open(self):
        with patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession") as session:
            with self.assertRaisesRegex(WakeDiagnosticError, "review is not complete"):
                observe_one_wake(WAKE_DIAGNOSTIC_CONFIRMATION)
            session.assert_not_called()

    def test_observes_complete_transfer_boundaries_and_no_commands(self):
        class Endpoint:
            def __init__(self):
                self.responses = [array("B", b"\xe5"), array("B", b"\xa0\x01\x02\x03")]
                self.returned = []
                self.calls = []

            def read(self, size, timeout):
                self.calls.append((size, timeout))
                if self.responses:
                    response = self.responses.pop(0)
                    self.returned.append(response)
                    return response
                raise usb.core.USBTimeoutError("done")

        class Session:
            def __init__(self, timeout):
                self.timeout = timeout
                self.endpoint_in = Endpoint()
                self._max_packet_size = 64
                self.wakes = []
                self.closed = False

            def wake_up(self, *, timeout_ms):
                self.wakes.append(timeout_ms)

            def close(self):
                self.closed = True

        sessions = []

        def make_session(timeout):
            session = Session(timeout)
            sessions.append(session)
            return session

        with (
            patch("goodix5503.wake_diagnostic.WAKE_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", side_effect=make_session),
            patch("goodix5503.wake_diagnostic.time.sleep") as sleep,
            patch("goodix5503.wake_diagnostic.time.monotonic", return_value=10.0),
        ):
            result = observe_one_wake(
                WAKE_DIAGNOSTIC_CONFIRMATION,
                usb_timeout_seconds=1.0,
            )

        session = sessions[0]
        self.assertEqual(session.wakes, [1000])
        sleep.assert_called_once_with(0.050)
        self.assertEqual(
            result,
            {
                "operation": "runtime-only-memory-geneva-wake-observation",
                "transfer_count": 2,
                "transfers": [
                    {"length": 1, "hex": "e5"},
                    {"length": 4, "hex": "a0010203"},
                ],
            },
        )
        self.assertEqual(session.endpoint_in.calls, [(64, 500)] * 3)
        self.assertTrue(all(not any(buffer) for buffer in session.endpoint_in.returned))
        self.assertTrue(session.closed)

    def test_wrong_confirmation_prevents_usb_and_core_dump_calls(self):
        with (
            patch("goodix5503.wake_diagnostic.disable_core_dumps") as disable,
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession") as session,
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "exact wake"):
                observe_one_wake("wrong")
            disable.assert_not_called()
            session.assert_not_called()

    def test_wipes_all_buffers_even_when_close_fails(self):
        raw = array("B", b"sensitive")
        tracked = []

        class Endpoint:
            calls = 0

            def read(self, _size, _timeout=None, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    return raw
                raise usb.core.USBTimeoutError("done")

        class Session:
            endpoint_in = Endpoint()
            _max_packet_size = 64

            def wake_up(self, **_kwargs):
                pass

            def close(self):
                raise RuntimeError("close failed")

        def tracking_bytearray(value=b""):
            result = builtins.bytearray(value)
            tracked.append(result)
            return result

        with (
            patch("goodix5503.wake_diagnostic.WAKE_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic.bytearray", side_effect=tracking_bytearray, create=True),
            patch("goodix5503.wake_diagnostic.time.sleep"),
            patch("goodix5503.wake_diagnostic.time.monotonic", return_value=10.0),
        ):
            with self.assertRaisesRegex(RuntimeError, "close failed"):
                observe_one_wake(WAKE_DIAGNOSTIC_CONFIRMATION)
        self.assertFalse(any(raw))
        self.assertTrue(tracked)
        self.assertTrue(all(not any(buffer) for buffer in tracked))

    def test_ninth_transfer_fails_capacity_and_wipes_every_buffer(self):
        raw_buffers = [array("B", bytes((value,))) for value in range(1, 10)]
        tracked = []

        class Endpoint:
            def read(self, _size, _timeout=None, **_kwargs):
                return raw_buffers.pop(0)

        class Session:
            endpoint_in = Endpoint()
            _max_packet_size = 64

            def wake_up(self, **_kwargs):
                pass

            def close(self):
                pass

        originals = list(raw_buffers)

        def tracking_bytearray(value=b""):
            result = builtins.bytearray(value)
            tracked.append(result)
            return result

        with (
            patch("goodix5503.wake_diagnostic.WAKE_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic.bytearray", side_effect=tracking_bytearray, create=True),
            patch("goodix5503.wake_diagnostic.time.sleep"),
            patch("goodix5503.wake_diagnostic.time.monotonic", return_value=10.0),
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "capacity"):
                observe_one_wake(WAKE_DIAGNOSTIC_CONFIRMATION)
        self.assertTrue(all(not any(buffer) for buffer in originals))
        self.assertEqual(len(tracked), 9)
        self.assertTrue(all(not any(buffer) for buffer in tracked))

    def test_core_dumps_are_disabled_before_usb_open(self):
        events = []

        def open_session(_timeout):
            events.append("open")
            raise RuntimeError("stop")

        with (
            patch("goodix5503.wake_diagnostic.WAKE_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.disable_core_dumps", side_effect=lambda: events.append("core")),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", side_effect=open_session),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                observe_one_wake(WAKE_DIAGNOSTIC_CONFIRMATION)
        self.assertEqual(events, ["core", "open"])


if __name__ == "__main__":
    unittest.main()
