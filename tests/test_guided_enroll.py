import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "goodix_enroll", Path(__file__).resolve().parents[1] / "tools/goodix_enroll.py")
enroll = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enroll)


class FakeTimers:
    def __init__(self):
        self.now = 0.0
        self.sources = {}
        self.next_id = 0

    def schedule(self, milliseconds, callback):
        self.next_id += 1
        self.sources[self.next_id] = (self.now + milliseconds / 1000, callback)
        return self.next_id

    def remove(self, source):
        del self.sources[source]

    def advance(self, seconds):
        end = self.now + seconds
        while self.sources:
            source = min(self.sources, key=lambda item: self.sources[item][0])
            when, callback = self.sources[source]
            if when > end:
                break
            del self.sources[source]
            self.now = when
            callback()
        self.now = end


class GuidedEnrollmentTests(unittest.TestCase):
    def make_prompts(self):
        timers = FakeTimers()
        emitted = []
        prompts = enroll.ReadyPrompts(lambda: emitted.append(timers.now),
                                     timers.schedule, timers.remove,
                                     lambda: timers.now)
        prompts.start()
        return prompts, timers, emitted

    def test_ready_before_or_after_progress_obeys_pause(self):
        for ready_first in (True, False):
            prompts, timers, emitted = self.make_prompts()
            if ready_first:
                prompts.set_needed(True)
            prompts.pause(1, True)
            prompts.set_needed(True)
            timers.advance(2.49)
            self.assertEqual(emitted, [])
            timers.advance(0.02)
            self.assertEqual(len(emitted), 1)
            prompts.set_needed(True)
            timers.advance(10)
            self.assertEqual(len(emitted), 1)

    def test_lift_and_cancellation_remove_pending_prompts(self):
        prompts, timers, emitted = self.make_prompts()
        prompts.pause(1, True)
        prompts.set_needed(True)
        timers.advance(1)
        prompts.set_needed(False)
        self.assertEqual(timers.sources, {})
        timers.advance(2)
        self.assertEqual(emitted, [])
        prompts.set_needed(True)
        timers.advance(0.01)
        self.assertEqual(len(emitted), 1)
        prompts.pause(2, True)
        prompts.stop()
        self.assertEqual(timers.sources, {})
        timers.advance(10)
        self.assertEqual(len(emitted), 1)

    def test_group_break_survives_early_retry_and_late_readiness(self):
        prompts, timers, emitted = self.make_prompts()
        prompts.set_needed(True)
        prompts.pause(10, True)
        timers.advance(1)
        prompts.pause(10, False)  # Early touch must not shorten the group break.
        timers.advance(4.99)
        self.assertEqual(emitted, [])
        timers.advance(0.02)
        self.assertEqual(len(emitted), 1)
        prompts.set_needed(False)
        prompts.pause(40, True)
        timers.advance(10)  # Selection or lift may take longer than the pause.
        self.assertEqual(len(emitted), 1)
        prompts.set_needed(True)
        timers.advance(0.01)
        self.assertEqual(len(emitted), 2)

    def test_retry_does_not_shift_guidance_batch(self):
        state = enroll.Progress()
        state.receive("enroll-stage-passed", False)  # fprintd duplicate check
        for _ in range(10):
            state.receive("enroll-stage-passed", False)
        state.receive("enroll-finger-not-centered", False)
        self.assertEqual(state.completed, 10)
        self.assertIn("整只手", enroll.guidance(state.completed, True))

    def test_checks_are_distinct_from_training_and_end_with_lift(self):
        self.assertIn("Press 40/40", enroll.guidance(39, False))
        self.assertIn("Check 1/8", enroll.guidance(40, False))
        self.assertIn("Check 8/8", enroll.guidance(47, False))
        self.assertIn("Lift", enroll.guidance(48, False))

    def test_failed_check_or_cancellation_is_not_success(self):
        for result in ("enroll-failed", "enroll-disconnected", "enroll-unknown-error"):
            state = enroll.Progress()
            for _ in range(47):
                state.receive("enroll-stage-passed", False)
            state.receive(result, True)
            self.assertTrue(state.terminal)
            self.assertFalse(state.success)

    def test_completion_requires_all_stages_and_terminal_success(self):
        state = enroll.Progress()
        state.receive("enroll-completed", True)
        self.assertFalse(state.success)
        state = enroll.Progress()
        for _ in range(48):
            state.receive("enroll-stage-passed", False)
        self.assertEqual(state.completed, 47)
        self.assertFalse(state.success)
        state.receive("enroll-completed", True)
        self.assertTrue(state.success)
        self.assertEqual(state.completed, 48)
        with self.assertRaises(ValueError):
            state.receive("enroll-stage-passed", False)

    def test_precheck_does_not_consume_training_sample(self):
        state = enroll.Progress()
        self.assertIn("查重", state.prompt(True))
        state.receive("enroll-retry-scan", False)
        self.assertFalse(state.precheck_done)
        state.receive("enroll-stage-passed", False)
        self.assertTrue(state.precheck_done)
        self.assertEqual(state.completed, 0)
        self.assertIn("采样 1/40", state.prompt(True))
        for _ in range(40):
            state.receive("enroll-stage-passed", False)
        self.assertIn("检查 1/8", state.prompt(True))

    def test_existing_finger_requires_explicit_replacement(self):
        finger = "right-index-finger"
        enroll.check_replacement([], finger, False)
        enroll.check_replacement(["left-index-finger"], finger, False)
        with self.assertRaisesRegex(ValueError, "--replace"):
            enroll.check_replacement([finger], finger, False)
        enroll.check_replacement([finger], finger, True)


if __name__ == "__main__":
    unittest.main()
