/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <glib.h>
#include <string.h>

#include "goodix5503-config.h"

static guint8
crc_segments (const guint8 *otp, const guint8 (*segments)[2], gsize count)
{
  g_autoptr(GByteArray) joined = g_byte_array_new ();

  for (gsize index = 0; index < count; index++)
    g_byte_array_append (joined, otp + segments[index][0], segments[index][1]);
  return goodix5503_crc8 (joined->data, joined->len);
}

static void
seal_otp (guint8 otp[GOODIX5503_OTP_SIZE])
{
  static const guint8 mt[][2] = { { 0x16, 6 }, { 0x1d, 7 }, { 0x28, 10 } };
  static const guint8 ft[][2] = { { 0x0b, 11 }, { 0x1c, 1 }, { 0x32, 10 }, { 0x3e, 1 } };
  static const guint8 whole[][2] = { { 0x00, 11 }, { 0x24, 4 } };

  otp[0x3f] = crc_segments (otp, mt, G_N_ELEMENTS (mt));
  otp[0x3d] = crc_segments (otp, ft, G_N_ELEMENTS (ft));
  otp[0x3c] = crc_segments (otp, whole, G_N_ELEMENTS (whole));
}

static void
test_crc_and_integrity (void)
{
  guint8 otp[GOODIX5503_OTP_SIZE] = { 0 };

  g_assert_cmphex (goodix5503_crc8 (NULL, 0), ==, 0xff);
  otp[0x32] = 0x8b;
  otp[0x33] = 0x84;
  otp[0x34] = 0x8c;
  otp[0x35] = 0x88;
  otp[0x3e] = goodix5503_crc8 (otp + 0x32, 4);
  seal_otp (otp);
  g_assert_true (goodix5503_otp_has_valid_integrity (otp));
  otp[0] ^= 1;
  g_assert_false (goodix5503_otp_has_valid_integrity (otp));
}

static void
test_dac_derivation (void)
{
  guint8 otp[GOODIX5503_OTP_SIZE] = { 0 };
  guint8 dac[GOODIX5503_DAC_SIZE] = { 0 };
  const guint8 expected[GOODIX5503_DAC_SIZE] =
    { 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00 };
  g_autoptr(GError) error = NULL;

  memcpy (otp + 0x32, (guint8[]) { 0x8b, 0x84, 0x8c, 0x88 }, 4);
  otp[0x3e] = goodix5503_crc8 (otp + 0x32, 4);
  g_assert_true (goodix5503_derive_dac (otp, dac, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (dac, sizeof dac, expected, sizeof expected);

  memset (otp, 0, sizeof otp);
  otp[0x2e] = 1;
  otp[0x2f] = 2;
  otp[0x30] = 3;
  otp[0x31] = 4;
  otp[0x32] = 9;
  otp[0x33] = 8;
  otp[0x34] = 7;
  otp[0x35] = 6;
  otp[0x16] = goodix5503_crc8 (otp + 0x2e, 4) ^ 0xff;
  otp[0x3e] = goodix5503_crc8 (otp + 0x32, 4) ^ 0xff;
  g_assert_false (goodix5503_derive_dac (otp, dac, &error));
  g_assert_error (error, GOODIX5503_CONFIG_ERROR,
                  GOODIX5503_CONFIG_ERROR_RIGHT_INFO);
}

static void
test_runtime_config_vectors (void)
{
  guint8 otp[GOODIX5503_OTP_SIZE] = { 0 };
  guint8 config[GOODIX5503_CONFIG_SIZE] = { 0 };
  g_autoptr(GError) error = NULL;
  g_autofree gchar *digest = NULL;

  g_assert_true (goodix5503_build_runtime_config (otp, config, &error));
  g_assert_no_error (error);
  g_assert_true (goodix5503_config_has_valid_checksum (config));
  g_assert_cmphex (config[0xeb], ==, 0x00);
  g_assert_cmphex (config[0xc8], ==, 0x15);
  digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256, config,
                                        sizeof config);
  g_assert_cmpstr (digest, ==,
                   "e60d9c767c140b080a3b69ba89d88c60514373beda4a57da9248940a28f46246");
  g_clear_pointer (&digest, g_free);

  otp[42] = 0xd7;
  otp[43] = 0x28;
  otp[27] = 0x22;
  g_assert_true (goodix5503_build_runtime_config (otp, config, &error));
  g_assert_no_error (error);
  g_assert_cmphex (config[0xeb], ==, 0xe0);
  g_assert_cmphex (config[0xec], ==, 0x00);
  g_assert_cmphex (config[0xc7], ==, 0x80);
  g_assert_cmphex (config[0xc8], ==, 0x15);
  g_assert_cmphex (config[0xb3], ==, 0x06);
  g_assert_true (goodix5503_config_has_valid_checksum (config));
  digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256, config,
                                        sizeof config);
  g_assert_cmpstr (digest, ==,
                   "adc6d213eb13588ee4207e0e12002e826810ebff604c24a1ddcc12f4d6cee562");
  g_clear_pointer (&digest, g_free);

  config[100] ^= 1;
  g_assert_false (goodix5503_config_has_valid_checksum (config));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix5503/config/crc-integrity",
                   test_crc_and_integrity);
  g_test_add_func ("/goodix5503/config/dac", test_dac_derivation);
  g_test_add_func ("/goodix5503/config/runtime-vectors",
                   test_runtime_config_vectors);
  return g_test_run ();
}
