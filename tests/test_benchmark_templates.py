import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "benchmark_templates", Path(__file__).resolve().parents[1] / "tools/benchmark_templates.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class TemplateLogTests(unittest.TestCase):
    def complete(self):
        return "\n".join([
            "dumped fingerprint image to /run/test/frame.pgm",
            "report_verify_status: result verify-match",
            "report_verify_status: result verify-no-match",  # later cancellation
        ])

    def test_first_result_is_not_replaced_by_cancellation(self):
        capture = benchmark.parse_capture(self.complete())
        self.assertEqual(capture["result"], "verify-match")
        self.assertEqual(capture["image"], "/run/test/frame.pgm")

    def test_multiple_presses_are_not_combined(self):
        with self.assertRaises(ValueError):
            benchmark.parse_capture(self.complete() + "\n" + self.complete())

    def test_missing_dump_stops_measurement(self):
        with self.assertRaises(ValueError):
            benchmark.parse_capture("report_verify_status: result verify-match")

    def test_unfinished_capture_stops_measurement(self):
        with self.assertRaises(ValueError):
            benchmark.parse_capture("dumped fingerprint image to /run/test/frame.pgm")

    def test_low_feature_retry_counts_as_rejection(self):
        text = self.complete().replace("verify-match", "verify-retry-scan")
        self.assertEqual(benchmark.parse_capture(text)["result"], "verify-retry-scan")

    def test_transport_failure_is_not_a_normal_score(self):
        with self.assertRaises(ValueError):
            benchmark.parse_capture(self.complete().replace("verify-match", "verify-disconnected"))

    def test_result_from_an_earlier_capture_is_not_reused(self):
        with self.assertRaises(ValueError):
            benchmark.parse_capture("report_verify_status: result verify-match\n" + self.complete())


if __name__ == "__main__":
    unittest.main()
