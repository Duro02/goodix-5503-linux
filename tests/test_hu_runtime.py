import unittest

from goodix5503.hu_runtime import (
    HuRuntimeError,
    RightInfoClass,
    build_hu_fdt_down_request,
    build_hu_image_request,
    build_hu_manual_fdt_request,
    classify_hu_right_info,
    derive_hu_dac_field,
    gf3258_dn2_otp_integrity,
    goodix_crc8,
    hu_fdt_bases_within_delta,
    parse_hu_manual_fdt_response,
)


def _defeat_long_crc_predicates(otp: bytearray) -> None:
    left = otp[0x0B:0x16] + otp[0x1C:0x1D] + otp[0x32:0x3C]
    right = otp[0x16:0x1C] + otp[0x1D:0x24] + otp[0x28:0x32]
    otp[0x3D] = goodix_crc8(left) ^ 0xFF
    otp[0x3F] = goodix_crc8(right) ^ 0xFF


class HuRuntimeTests(unittest.TestCase):
    def test_crc_known_vectors(self):
        self.assertEqual(goodix_crc8(b""), 0xFF)
        self.assertEqual(goodix_crc8(bytes(23)), 0xFF)
        self.assertEqual(goodix_crc8(b"123456789"), 0x0B)

    def test_dn2_whole_otp_integrity_known_vectors_and_corruption(self):
        sequential = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b687c3e68"
        )
        zero_valid = bytes.fromhex("00" * 60 + "ffff00ff")
        for otp in (sequential, zero_valid):
            with self.subTest(otp=otp[-4:]):
                self.assertTrue(gf3258_dn2_otp_integrity(otp))
                for offset in (0x3C, 0x3D, 0x3F):
                    corrupt = bytearray(otp)
                    corrupt[offset] ^= 1
                    self.assertFalse(gf3258_dn2_otp_integrity(corrupt))
        self.assertFalse(gf3258_dn2_otp_integrity(bytes(64)))
        self.assertFalse(gf3258_dn2_otp_integrity(bytes(63)))
        self.assertFalse(gf3258_dn2_otp_integrity(bytes(65)))

    def test_long_predicate_a_selects_otp_32(self):
        otp = bytearray(64)
        otp[0x0B:0x16] = bytes(range(1, 12))
        otp[0x1C] = 0x91
        otp[0x32:0x3C] = bytes(range(0x20, 0x2A))
        otp[0x3D] = goodix_crc8(
            otp[0x0B:0x16] + otp[0x1C:0x1D] + otp[0x32:0x3C]
        )
        self.assertEqual(classify_hu_right_info(otp), RightInfoClass.OTP_32)

    def test_long_predicate_c_selects_otp_2e(self):
        otp = bytearray(64)
        otp[0x16:0x1C] = bytes(range(0x31, 0x37))
        otp[0x1D:0x24] = bytes(range(0x41, 0x48))
        otp[0x28:0x32] = bytes(range(0x51, 0x5B))
        otp[0x3D] = goodix_crc8(
            otp[0x0B:0x16] + otp[0x1C:0x1D] + otp[0x32:0x3C]
        ) ^ 0xFF
        otp[0x3E] = goodix_crc8(otp[0x32:0x36]) ^ 0xFF
        otp[0x3F] = goodix_crc8(
            otp[0x16:0x1C] + otp[0x1D:0x24] + otp[0x28:0x32]
        )
        self.assertEqual(classify_hu_right_info(otp), RightInfoClass.OTP_2E)

    def test_left_family_has_priority_when_both_long_predicates_pass(self):
        otp = bytearray(range(64))
        otp[0x3D] = goodix_crc8(
            otp[0x0B:0x16] + otp[0x1C:0x1D] + otp[0x32:0x3C]
        )
        otp[0x3F] = goodix_crc8(
            otp[0x16:0x1C] + otp[0x1D:0x24] + otp[0x28:0x32]
        )
        self.assertEqual(classify_hu_right_info(otp), RightInfoClass.OTP_32)

    def test_class_one_selects_otp_32_bytes(self):
        otp = bytearray(64)
        otp[0x32:0x36] = b"\x11\x22\x33\x44"
        otp[0x3E] = goodix_crc8(otp[0x32:0x36])
        otp[0x3D] = goodix_crc8(
            otp[0x0B:0x16] + otp[0x1C:0x1D] + otp[0x32:0x3C]
        ) ^ 0xFF
        self.assertEqual(classify_hu_right_info(otp), RightInfoClass.OTP_32)
        self.assertEqual(
            derive_hu_dac_field(otp),
            bytearray.fromhex("1100220033004400"),
        )

    def test_class_two_selects_otp_2e_bytes(self):
        otp = bytearray(64)
        otp[0x2E:0x32] = b"\x51\x62\x73\x84"
        otp[0x16] = goodix_crc8(otp[0x2E:0x32])
        otp[0x3E] = goodix_crc8(otp[0x32:0x36]) ^ 0xFF
        _defeat_long_crc_predicates(otp)
        self.assertEqual(classify_hu_right_info(otp), RightInfoClass.OTP_2E)
        self.assertEqual(
            derive_hu_dac_field(otp),
            bytearray.fromhex("5100620073008400"),
        )

    def test_fallback_repairs_single_mismatch_from_other_three_left_values(self):
        otp = bytearray(64)
        otp[0x2E:0x32] = b"\x0a\x14\x1e\x28"
        otp[0x32:0x36] = b"\x0a\x14\xff\x28"
        otp[0x16] = goodix_crc8(otp[0x2E:0x32]) ^ 0xFF
        otp[0x3E] = goodix_crc8(otp[0x32:0x36]) ^ 0xFF
        _defeat_long_crc_predicates(otp)
        self.assertEqual(classify_hu_right_info(otp), RightInfoClass.REPAIRED)
        self.assertEqual(otp[0x30], 0x17)
        self.assertEqual(otp[0x34], 0x17)

    def test_invalid_right_info_fails_closed(self):
        otp = bytearray(64)
        otp[0x2E:0x32] = b"\x01\x02\x03\x04"
        otp[0x32:0x36] = b"\x05\x06\x07\x08"
        otp[0x16] = goodix_crc8(otp[0x2E:0x32]) ^ 0xFF
        otp[0x3E] = goodix_crc8(otp[0x32:0x36]) ^ 0xFF
        _defeat_long_crc_predicates(otp)
        with self.assertRaisesRegex(HuRuntimeError, "classification failed"):
            derive_hu_dac_field(otp)

    def test_builds_local_hu_image_and_fresh_fdt_requests(self):
        dac = bytearray.fromhex("8b0084008c008800")
        self.assertEqual(
            build_hu_image_request(dac),
            bytes.fromhex("01008b0084008c008800"),
        )
        self.assertEqual(
            build_hu_manual_fdt_request(dac, bytes(12)),
            bytes.fromhex("0d018b0084008c008800800080008000800080008000"),
        )
        self.assertEqual(
            build_hu_fdt_down_request(dac, bytes(12)),
            bytes.fromhex("0c018b0084008c008800800080008000800080008000"),
        )

    def test_manual_fdt_response_builds_raw_and_transformed_forms(self):
        base = bytes.fromhex("349678915592aa85008cfe86")
        response = bytes.fromhex("82013f00") + base
        raw, transformed = parse_hu_manual_fdt_response(response)
        try:
            self.assertEqual(raw, base)
            self.assertEqual(
                transformed,
                bytearray.fromhex("801a80bc802a80d58000807f"),
            )
        finally:
            raw[:] = b"\x00" * len(raw)
            transformed[:] = b"\x00" * len(transformed)
        for malformed in (bytes(15), bytes(17)):
            with self.assertRaisesRegex(HuRuntimeError, "exactly 16"):
                parse_hu_manual_fdt_response(malformed)

    def test_fdt_delta_comparison_is_inclusive_for_all_six_words(self):
        first = bytes.fromhex("100020003000400050006000")
        at_limit = bytes.fromhex("15001b0035003b0055005b00")
        over_limit = bytearray(at_limit)
        over_limit[10:12] = b"\x5a\x00"
        self.assertTrue(hu_fdt_bases_within_delta(first, at_limit, 5))
        self.assertFalse(hu_fdt_bases_within_delta(first, over_limit, 5))
        with self.assertRaises(HuRuntimeError):
            hu_fdt_bases_within_delta(first, bytes(10), 5)

    def test_fdt_request_preserves_only_base_high_bytes(self):
        dac = bytes.fromhex("1100220033004400")
        base = bytes.fromhex("349678915592aa85008cfe86")
        request = build_hu_manual_fdt_request(dac, base, mode_nibble=2)
        self.assertEqual(request[:10], bytes.fromhex("2d011100220033004400"))
        self.assertEqual(request[10:], bytes.fromhex("8096809180928085808c8086"))

    def test_rejects_wrong_lengths_and_mode(self):
        with self.assertRaises(HuRuntimeError):
            classify_hu_right_info(bytearray(63))
        with self.assertRaises(HuRuntimeError):
            build_hu_image_request(bytes(7))
        with self.assertRaises(HuRuntimeError):
            build_hu_manual_fdt_request(bytes(8), bytes(11))
        with self.assertRaises(HuRuntimeError):
            build_hu_manual_fdt_request(bytes(8), bytes(12), mode_nibble=16)


if __name__ == "__main__":
    unittest.main()
