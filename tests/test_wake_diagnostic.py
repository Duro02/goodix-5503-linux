import builtins
import hashlib
import threading
import unittest
from array import array
from unittest.mock import patch

import usb.core

from goodix5503.probe import COMMAND_FIRMWARE_VERSION, ReadOnlyUsbSession, _encode_packet
from goodix5503.wake_diagnostic import (
    OFFICIAL_GENEVA_A8_DIAGNOSTIC_CONFIRMATION,
    OFFICIAL_GENEVA_A8_REQUEST,
    QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION,
    WAKE_A8_DIAGNOSTIC_CONFIRMATION,
    WAKE_DIAGNOSTIC_CONFIRMATION,
    WakeDiagnosticError,
    _write_official_geneva_a8,
    observe_one_official_geneva_a8,
    observe_one_queued_wake_a8,
    observe_one_wake,
    observe_one_wake_a8,
)


class WakeDiagnosticTests(unittest.TestCase):
    def test_gate_prevents_usb_open(self):
        with patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession") as session:
            with self.assertRaisesRegex(WakeDiagnosticError, "review is not complete"):
                observe_one_wake(WAKE_DIAGNOSTIC_CONFIRMATION)
            session.assert_not_called()

    def test_official_a8_gate_prevents_usb_open(self):
        with patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession") as session:
            with self.assertRaisesRegex(WakeDiagnosticError, "review is not complete"):
                observe_one_official_geneva_a8(OFFICIAL_GENEVA_A8_DIAGNOSTIC_CONFIRMATION)
            session.assert_not_called()

    def test_official_geneva_a8_exact_single_write_kat(self):
        self.assertEqual(
            OFFICIAL_GENEVA_A8_REQUEST[:10].hex(),
            "0a0a0a0aa80300000001",
        )
        self.assertEqual(OFFICIAL_GENEVA_A8_REQUEST[10:], bytes(54))
        self.assertEqual(len(OFFICIAL_GENEVA_A8_REQUEST), 64)
        self.assertEqual(
            hashlib.sha256(OFFICIAL_GENEVA_A8_REQUEST).hexdigest(),
            "bf1386becef79cbee10a0783f6cf129b575bd95e1354863712244f5ab6950ab2",
        )

    def test_official_geneva_a8_writer_rejects_short_write_and_timeout(self):
        class Endpoint:
            def __init__(self, written):
                self.written = written
                self.calls = []

            def write(self, payload, timeout):
                self.calls.append((bytes(payload), timeout))
                return self.written

        session = object.__new__(ReadOnlyUsbSession)
        session.endpoint_out = Endpoint(64)
        _write_official_geneva_a8(session, 432)
        self.assertEqual(
            session.endpoint_out.calls,
            [(OFFICIAL_GENEVA_A8_REQUEST, 432)],
        )
        session.endpoint_out = Endpoint(63)
        with self.assertRaisesRegex(WakeDiagnosticError, "not fully"):
            _write_official_geneva_a8(session, 432)
        with self.assertRaisesRegex(WakeDiagnosticError, "positive"):
            _write_official_geneva_a8(session, 0)

    def test_official_a8_queues_reader_then_writes_padded_usb_kat_once(self):
        release = threading.Event()
        clock = [10.0]
        writes = []

        class InEndpoint:
            def read(self, size, timeout):
                self.last = (size, timeout)
                release.wait(timeout=1.0)
                threading.Event().wait(0.020)
                clock[0] = 13.250
                raise usb.core.USBTimeoutError("done")

        class OutEndpoint:
            def write(self, payload, timeout):
                writes.append((bytes(payload), timeout))
                release.set()
                return len(payload)

        class Session:
            endpoint_in = InEndpoint()
            endpoint_out = OutEndpoint()

            def wake_up(self, **_kwargs):
                pass

            def close(self):
                pass

        with (
            patch("goodix5503.wake_diagnostic.OFFICIAL_GENEVA_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.time.sleep"),
            patch("goodix5503.wake_diagnostic.time.monotonic", side_effect=lambda: clock[0]),
        ):
            result = observe_one_official_geneva_a8(
                OFFICIAL_GENEVA_A8_DIAGNOSTIC_CONFIRMATION
            )
        self.assertEqual(Session.endpoint_in.last, (0x8000, 3250))
        self.assertEqual(writes, [(OFFICIAL_GENEVA_A8_REQUEST, 3250)])
        self.assertEqual(result["transfer_count"], 0)
        self.assertEqual(
            result["operation"],
            "runtime-only-memory-official-geneva-wake-a8-observation",
        )

    def test_queued_a8_gate_prevents_usb_open(self):
        with patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession") as session:
            with self.assertRaisesRegex(WakeDiagnosticError, "review is not complete"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)
            session.assert_not_called()

    def test_a8_gate_prevents_usb_open(self):
        with patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession") as session:
            with self.assertRaisesRegex(WakeDiagnosticError, "review is not complete"):
                observe_one_wake_a8(WAKE_A8_DIAGNOSTIC_CONFIRMATION)
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

    def test_a8_observation_writes_one_exact_framed_read_after_wake(self):
        events = []

        class Endpoint:
            def read(self, _size, timeout):
                events.append(("read", timeout))
                raise usb.core.USBTimeoutError("done")

        class Session:
            endpoint_in = Endpoint()
            _max_packet_size = 64

            def wake_up(self, **kwargs):
                events.append(("wake", kwargs["timeout_ms"]))

            def _ReadOnlyUsbSession__write_packet(self, packet):
                events.append(("write", packet))

            def close(self):
                events.append(("close",))

        with (
            patch("goodix5503.wake_diagnostic.WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges", side_effect=lambda: events.append(("drop",))),
            patch("goodix5503.wake_diagnostic.time.sleep", side_effect=lambda delay: events.append(("sleep", delay))),
            patch("goodix5503.wake_diagnostic.time.monotonic", return_value=10.0),
        ):
            result = observe_one_wake_a8(WAKE_A8_DIAGNOSTIC_CONFIRMATION)
        self.assertEqual(
            events,
            [
                ("drop",),
                ("wake", 1000),
                ("sleep", 0.050),
                ("write", _encode_packet(COMMAND_FIRMWARE_VERSION)),
                ("read", 500),
                ("close",),
            ],
        )
        self.assertEqual(result["transfer_count"], 0)
        self.assertEqual(result["operation"], "runtime-only-memory-geneva-wake-a8-observation")

    def test_queued_a8_keeps_reader_live_and_decreases_all_deadlines(self):
        events = []
        release = threading.Event()

        class Clock:
            def __init__(self):
                self.value = 10.0
                self.lock = threading.Lock()

            def __call__(self):
                with self.lock:
                    return self.value

            def advance(self, seconds):
                with self.lock:
                    self.value += seconds

            def set(self, value):
                with self.lock:
                    self.value = value

        clock = Clock()

        class Endpoint:
            def read(self, size, timeout):
                events.append(("read", size, timeout))
                release.wait(timeout=1.0)
                threading.Event().wait(0.020)
                clock.set(13.250)
                raise usb.core.USBTimeoutError("done")

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **kwargs):
                events.append(("wake", kwargs["timeout_ms"]))
                clock.advance(0.100)

            def _ReadOnlyUsbSession__write_packet(self, packet, **kwargs):
                events.append(("write", packet, kwargs["timeout_ms"]))
                clock.advance(0.200)
                release.set()

            def close(self):
                events.append(("close",))

        def sleep(delay):
            events.append(("sleep", delay))
            clock.advance(delay)

        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges", side_effect=lambda: events.append(("drop",))),
            patch("goodix5503.wake_diagnostic.time.sleep", side_effect=sleep),
            patch("goodix5503.wake_diagnostic.time.monotonic", side_effect=clock),
        ):
            result = observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)
        self.assertEqual(events[0], ("drop",))
        self.assertEqual(events[1], ("read", 0x8000, 3250))
        self.assertEqual(events[2:], [
            ("sleep", 0.025),
            ("wake", 3225),
            ("sleep", 0.050),
            ("write", _encode_packet(COMMAND_FIRMWARE_VERSION), 3075),
            ("close",),
        ])
        self.assertEqual(result["transfer_count"], 0)
        self.assertEqual(
            result["operation"],
            "runtime-only-memory-geneva-queued-wake-a8-observation",
        )
        self.assertEqual(
            result["timing_ms"],
            {
                "wake_completed": 125,
                "a8_started": 175,
                "a8_completed": 375,
                "deadline": 3250,
            },
        )

    def test_queued_slow_wake_cannot_consume_settle_budget(self):
        clock = [10.0]
        events = []

        class Endpoint:
            def read(self, _size, _timeout=None, **_kwargs):
                threading.Event().wait(0.050)
                raise usb.core.USBTimeoutError("done")

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **_kwargs):
                events.append("wake")
                clock[0] += 3.225

            def _ReadOnlyUsbSession__write_packet(self, _packet, **_kwargs):
                events.append("a8")

            def close(self):
                events.append("close")

        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.time.sleep"),
            patch("goodix5503.wake_diagnostic.time.monotonic", side_effect=lambda: clock[0]),
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "cannot cover settle"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)
        self.assertEqual(events, ["wake", "close"])

    def test_queued_settle_deadline_expiry_prevents_a8(self):
        clock = [10.0]
        events = []

        class Endpoint:
            def read(self, _size, _timeout=None, **_kwargs):
                threading.Event().wait(0.100)
                raise usb.core.USBTimeoutError("done")

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **_kwargs):
                events.append("wake")
                clock[0] += 3.100

            def _ReadOnlyUsbSession__write_packet(self, _packet, **_kwargs):
                events.append("a8")

            def close(self):
                events.append("close")

        def sleep(delay):
            if delay == 0.050:
                clock[0] += 0.200

        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.time.sleep", side_effect=sleep),
            patch("goodix5503.wake_diagnostic.time.monotonic", side_effect=lambda: clock[0]),
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "expired before A8"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)
        self.assertEqual(events, ["wake", "close"])

    def test_queued_reader_timeout_before_absolute_deadline_is_fatal(self):
        release = threading.Event()
        clock = [10.0]

        class Endpoint:
            def read(self, _size, _timeout=None, **_kwargs):
                release.wait(timeout=1.0)
                threading.Event().wait(0.020)
                raise usb.core.USBTimeoutError("early")

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **_kwargs):
                pass

            def _ReadOnlyUsbSession__write_packet(self, _packet, **_kwargs):
                release.set()

            def close(self):
                pass

        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.time.sleep"),
            patch("goodix5503.wake_diagnostic.time.monotonic", side_effect=lambda: clock[0]),
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "stopped before its deadline"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)

    def test_queued_a8_write_overrun_is_fatal(self):
        release = threading.Event()
        clock = [10.0]

        class Endpoint:
            def read(self, _size, _timeout=None, **_kwargs):
                release.wait(timeout=1.0)
                threading.Event().wait(0.020)
                raise usb.core.USBTimeoutError("done")

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **_kwargs):
                pass

            def _ReadOnlyUsbSession__write_packet(self, _packet, **_kwargs):
                clock[0] += 3.300
                release.set()

            def close(self):
                pass

        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.time.sleep"),
            patch("goodix5503.wake_diagnostic.time.monotonic", side_effect=lambda: clock[0]),
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "A8 write exceeded"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)

    def test_queued_reader_stopping_early_during_a8_is_fatal(self):
        release = threading.Event()
        stopped = threading.Event()

        class Endpoint:
            def read(self, _size, _timeout=None, **_kwargs):
                release.wait(timeout=1.0)
                stopped.set()
                raise usb.core.USBTimeoutError("done")

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **_kwargs):
                pass

            def _ReadOnlyUsbSession__write_packet(self, _packet, **_kwargs):
                release.set()
                self_test.assertTrue(stopped.wait(timeout=1.0))
                threading.Event().wait(0.020)

            def close(self):
                pass

        self_test = self
        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.time.sleep"),
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "stopped before its deadline"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)

    def test_queued_reader_failure_prevents_wake_and_a8(self):
        failed = threading.Event()
        events = []

        class Endpoint:
            def read(self, _size, _timeout=None, **_kwargs):
                failed.set()
                raise RuntimeError("pipe failed")

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **_kwargs):
                events.append("wake")

            def close(self):
                events.append("close")

        def barrier(delay):
            if delay == 0.025:
                self.assertTrue(failed.wait(timeout=1.0))

        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.time.sleep", side_effect=barrier),
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "stopped before wake"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)
        self.assertEqual(events, ["close"])

    def test_queued_capture_wipes_buffers_when_close_fails(self):
        raw = array("B", b"queued")
        release = threading.Event()
        tracked = []

        class Endpoint:
            calls = 0

            def read(self, _size, _timeout=None, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    return raw
                release.wait(timeout=1.0)
                threading.Event().wait(0.020)
                raise usb.core.USBTimeoutError("done")

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **_kwargs):
                pass

            def _ReadOnlyUsbSession__write_packet(self, _packet, **_kwargs):
                release.set()

            def close(self):
                raise RuntimeError("close failed")

        def tracking_bytearray(value=b""):
            result = builtins.bytearray(value)
            tracked.append(result)
            return result

        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.bytearray", side_effect=tracking_bytearray, create=True),
            patch("goodix5503.wake_diagnostic.time.sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, "close failed"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)
        self.assertFalse(any(raw))
        self.assertTrue(tracked)
        self.assertTrue(all(not any(buffer) for buffer in tracked))

    def test_queued_ninth_transfer_fails_before_wake_and_wipes(self):
        raw_buffers = [array("B", bytes((value,))) for value in range(1, 10)]
        originals = list(raw_buffers)
        overflow = threading.Event()
        tracked = []
        events = []

        class Endpoint:
            def read(self, _size, _timeout=None, **_kwargs):
                result = raw_buffers.pop(0)
                if len(raw_buffers) == 0:
                    overflow.set()
                return result

        class Session:
            endpoint_in = Endpoint()

            def wake_up(self, **_kwargs):
                events.append("wake")

            def close(self):
                events.append("close")

        def tracking_bytearray(value=b""):
            result = builtins.bytearray(value)
            tracked.append(result)
            return result

        def barrier(delay):
            if delay == 0.025:
                self.assertTrue(overflow.wait(timeout=1.0))

        with (
            patch("goodix5503.wake_diagnostic.QUEUED_WAKE_A8_DIAGNOSTIC_REVIEW_COMPLETE", True),
            patch("goodix5503.wake_diagnostic.ReadOnlyUsbSession", return_value=Session()),
            patch("goodix5503.wake_diagnostic._drop_sudo_privileges"),
            patch("goodix5503.wake_diagnostic.bytearray", side_effect=tracking_bytearray, create=True),
            patch("goodix5503.wake_diagnostic.time.sleep", side_effect=barrier),
        ):
            with self.assertRaisesRegex(WakeDiagnosticError, "stopped before wake"):
                observe_one_queued_wake_a8(QUEUED_WAKE_A8_DIAGNOSTIC_CONFIRMATION)
        self.assertEqual(events, ["close"])
        self.assertTrue(all(not any(buffer) for buffer in originals))
        self.assertEqual(len(tracked), 9)
        self.assertTrue(all(not any(buffer) for buffer in tracked))

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
