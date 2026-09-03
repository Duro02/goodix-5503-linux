import importlib.util
import unittest
from pathlib import Path

from goodix5503.whitebox import (
    WhiteboxError,
    _clear_emulated_secrets,
    _wipe_secret_regions,
    emulate_whitebox,
    find_pinned_wbdi,
    trace_whitebox,
    verify_known_vector,
)


class WhiteboxTests(unittest.TestCase):
    def test_requires_mutable_exact_32_byte_psk(self):
        with self.assertRaises(TypeError):
            emulate_whitebox(bytes(32), Path("unused"))
        with self.assertRaises(ValueError):
            emulate_whitebox(bytearray(b"short"), Path("unused"))

    def pinned_wbdi_or_skip(self):
        if importlib.util.find_spec("unicorn") is None:
            self.skipTest("unicorn optional dependency is not installed")
        project_root = Path(__file__).resolve().parents[1]
        try:
            return find_pinned_wbdi(project_root)
        except WhiteboxError as error:
            self.skipTest(str(error))

    def test_pinned_official_zero_vector(self):
        verify_known_vector(self.pinned_wbdi_or_skip())

    def test_cleanup_attempts_every_region_after_failure(self):
        class FailingMemory:
            def __init__(self):
                self.writes = []
                self.unmaps = []

            def mem_write(self, address, _data):
                self.writes.append(address)
                if address == 0x1000:
                    raise RuntimeError("injected wipe failure")

            def mem_unmap(self, address, size):
                self.unmaps.append((address, size))

        memory = FailingMemory()
        with self.assertRaises(WhiteboxError):
            _wipe_secret_regions(memory, ((0x1000, 0x1000), (0x3000, 0x1000)))
        self.assertEqual(memory.writes, [0x1000, 0x3000])
        self.assertEqual(memory.unmaps, [(0x1000, 0x1000), (0x3000, 0x1000)])

    def test_register_cleanup_failure_does_not_skip_memory_cleanup(self):
        class FailingRegisters:
            def __init__(self):
                self.registers = []
                self.writes = []
                self.unmaps = []

            def reg_write(self, register, _value):
                self.registers.append(register)
                if register == 1:
                    raise RuntimeError("injected register failure")

            def mem_write(self, address, _data):
                self.writes.append(address)

            def mem_unmap(self, address, size):
                self.unmaps.append((address, size))

        state = FailingRegisters()
        with self.assertRaises(WhiteboxError):
            _clear_emulated_secrets(state, (1, 2), ((0x1000, 0x1000),))
        self.assertEqual(state.registers, [1, 2])
        self.assertEqual(state.writes, [0x1000])
        self.assertEqual(state.unmaps, [(0x1000, 0x1000)])

    def test_fixed_length_inputs_follow_identical_guest_control_flow(self):
        wbdi = self.pinned_wbdi_or_skip()
        psks = [bytearray(32), bytearray(b"\xff" * 32), bytearray(range(32))]
        outputs = []
        traces = []
        try:
            for psk in psks:
                output, trace = trace_whitebox(psk, wbdi)
                outputs.append(output)
                traces.append(trace)
            self.assertEqual(traces[0], traces[1])
            self.assertEqual(traces[0], traces[2])
            self.assertEqual(traces[0].instruction_count, 127_592)
            self.assertEqual(
                traces[0].address_sha256,
                "baf436c5c0c979c9dee4f1f586e2a6d8713b75e54ac8547b36bf0c7c66476a2e",
            )
            self.assertEqual(len(traces[0].helper_calls), 33)
            self.assertEqual(len({bytes(output) for output in outputs}), 3)
        finally:
            for psk in psks:
                psk[:] = b"\x00" * len(psk)
            for output in outputs:
                output[:] = b"\x00" * len(output)
