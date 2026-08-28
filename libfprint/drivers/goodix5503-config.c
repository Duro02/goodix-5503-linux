/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix5503-config.h"

#include <string.h>

G_DEFINE_QUARK (goodix5503-config-error-quark, goodix5503_config_error)

static const guint8 zero_otp_config[GOODIX5503_CONFIG_SIZE] = {
  0x58, 0x11, 0x60, 0x71, 0x2c, 0x9d, 0x2c, 0xc9, 0x1c, 0xe5, 0x18, 0xfd, 0x00, 0xfd, 0x00, 0xfd,
  0x03, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x04, 0x00, 0x84, 0x00, 0xc0, 0xb3, 0x86, 0x00, 0xbb,
  0xc4, 0x88, 0x00, 0xba, 0xba, 0x8a, 0x00, 0xb2, 0xb2, 0x8c, 0x00, 0xaa, 0xaa, 0x8e, 0x00, 0xc1,
  0xc1, 0x90, 0x00, 0xbb, 0xbb, 0x92, 0x00, 0xb1, 0xb1, 0x94, 0x00, 0x00, 0xa8, 0x96, 0x00, 0x00,
  0xb6, 0x98, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x00, 0x00, 0xd2, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00,
  0x00, 0xd6, 0x00, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x00, 0x50, 0x00, 0x01, 0x05, 0xd0, 0x00, 0x00,
  0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78, 0x56, 0x74, 0x00, 0x34, 0x12, 0x20, 0x00, 0x10,
  0x40, 0x2a, 0x01, 0x02, 0x04, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x32, 0x00, 0x80, 0x00, 0x01,
  0x00, 0x5c, 0x00, 0x80, 0x00, 0x56, 0x00, 0x24, 0x20, 0x58, 0x00, 0x03, 0x00, 0x32, 0x00, 0x0c,
  0x02, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00, 0x58, 0x82, 0x00, 0x80, 0x15, 0x2a, 0x01, 0x82,
  0x03, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14, 0x00, 0x80, 0x00, 0x01, 0x00, 0x5c, 0x00, 0x00,
  0x01, 0x56, 0x00, 0x04, 0x20, 0x58, 0x00, 0x03, 0x00, 0x32, 0x00, 0x0c, 0x02, 0x66, 0x00, 0x00,
  0x02, 0x7c, 0x00, 0x00, 0x58, 0x82, 0x00, 0x80, 0x15, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0x00,
  0x01, 0x54, 0x00, 0x00, 0x01, 0x62, 0x00, 0x08, 0x04, 0x64, 0x00, 0x10, 0x00, 0x66, 0x00, 0x00,
  0x02, 0x7c, 0x00, 0x00, 0x58, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0x00, 0x01, 0x52, 0x00, 0x08,
  0x00, 0x54, 0x00, 0x00, 0x01, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00, 0x58, 0x00, 0xa5, 0x74,
};

static guint8
crc8_update (guint8 crc, const guint8 *data, gsize length)
{
  for (gsize index = 0; index < length; index++)
    {
      crc ^= data[index];
      for (guint bit = 0; bit < 8; bit++)
        crc = crc & 0x80 ? (crc << 1) ^ 0x07 : crc << 1;
    }
  return crc;
}

guint8
goodix5503_crc8 (const guint8 *data, gsize length)
{
  g_return_val_if_fail (data != NULL || length == 0, 0);
  return crc8_update (0, data, length) ^ 0xff;
}

static guint8
crc_segments (const guint8 *otp, const guint8 (*segments)[2], gsize count)
{
  guint8 crc = 0;

  for (gsize index = 0; index < count; index++)
    crc = crc8_update (crc, otp + segments[index][0], segments[index][1]);
  return crc ^ 0xff;
}

gboolean
goodix5503_otp_has_valid_integrity (const guint8 otp[GOODIX5503_OTP_SIZE])
{
  static const guint8 mt[][2] = { { 0x16, 6 }, { 0x1d, 7 }, { 0x28, 10 } };
  static const guint8 ft[][2] = { { 0x0b, 11 }, { 0x1c, 1 }, { 0x32, 10 }, { 0x3e, 1 } };
  static const guint8 whole[][2] = { { 0x00, 11 }, { 0x24, 4 } };

  g_return_val_if_fail (otp != NULL, FALSE);
  return crc_segments (otp, mt, G_N_ELEMENTS (mt)) == otp[0x3f] &&
         crc_segments (otp, ft, G_N_ELEMENTS (ft)) == otp[0x3d] &&
         crc_segments (otp, whole, G_N_ELEMENTS (whole)) == otp[0x3c];
}

static gboolean
all_nonzero (const guint8 *data, gsize length)
{
  for (gsize index = 0; index < length; index++)
    if (data[index] == 0)
      return FALSE;
  return TRUE;
}

gboolean
goodix5503_derive_dac (guint8   otp[GOODIX5503_OTP_SIZE],
                        guint8   dac[GOODIX5503_DAC_SIZE],
                        GError **error)
{
  static const guint8 left[][2] = { { 0x0b, 11 }, { 0x1c, 1 }, { 0x32, 10 } };
  static const guint8 right[][2] = { { 0x16, 6 }, { 0x1d, 7 }, { 0x28, 10 } };
  const guint8 *selected = NULL;
  gboolean equal[4];
  guint equal_count = 0;

  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (otp == NULL || dac == NULL)
    goto invalid;

  if (crc_segments (otp, left, G_N_ELEMENTS (left)) == otp[0x3d] ||
      (all_nonzero (otp + 0x32, 4) &&
       goodix5503_crc8 (otp + 0x32, 4) == otp[0x3e]))
    selected = otp + 0x32;
  else if (crc_segments (otp, right, G_N_ELEMENTS (right)) == otp[0x3f] ||
           (all_nonzero (otp + 0x2e, 4) &&
            goodix5503_crc8 (otp + 0x2e, 4) == otp[0x16]))
    selected = otp + 0x2e;
  else
    {
      for (guint index = 0; index < 4; index++)
        {
          equal[index] = otp[0x2e + index] == otp[0x32 + index];
          equal_count += equal[index];
        }
      if (equal_count < 3)
        goto invalid;
      if (equal_count == 3)
        {
          guint mismatch = 0;
          guint sum = 0;

          while (equal[mismatch])
            mismatch++;
          for (guint index = 0; index < 4; index++)
            if (index != mismatch)
              sum += otp[0x2e + index];
          otp[0x2e + mismatch] = sum / 3;
          otp[0x32 + mismatch] = sum / 3;
        }
      selected = otp + 0x32;
    }

  for (guint index = 0; index < 4; index++)
    {
      dac[index * 2] = selected[index];
      dac[index * 2 + 1] = 0;
    }
  return TRUE;

invalid:
  g_set_error_literal (error, GOODIX5503_CONFIG_ERROR,
                       GOODIX5503_CONFIG_ERROR_RIGHT_INFO,
                       "Goodix OTP right-info classification failed");
  return FALSE;
}

static guint16
config_checksum (const guint8 config[254])
{
  guint32 sum = 0xa5a5;

  for (guint offset = 0; offset < 254; offset += 2)
    sum += config[offset] | ((guint16) config[offset + 1] << 8);
  return -sum;
}

gboolean
goodix5503_config_has_valid_checksum (const guint8 config[GOODIX5503_CONFIG_SIZE])
{
  guint16 expected;
  guint16 received;

  g_return_val_if_fail (config != NULL, FALSE);
  expected = config_checksum (config);
  received = config[254] | ((guint16) config[255] << 8);
  return expected == received;
}

gboolean
goodix5503_build_runtime_config (const guint8 otp[GOODIX5503_OTP_SIZE],
                                  guint8       config[GOODIX5503_CONFIG_SIZE],
                                  GError     **error)
{
  guint8 calibration;
  guint8 complement;
  guint8 repeated;
  guint8 inverse;
  guint8 selector;
  guint8 first;
  guint8 second;
  guint8 third;
  gint decoded = -1;
  guint16 checksum;

  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (otp == NULL || config == NULL)
    {
      g_set_error_literal (error, GOODIX5503_CONFIG_ERROR,
                           GOODIX5503_CONFIG_ERROR_LENGTH,
                           "Goodix OTP/config buffer is missing");
      return FALSE;
    }

  memcpy (config, zero_otp_config, sizeof zero_otp_config);
  calibration = otp[42];
  complement = otp[43];
  repeated = otp[45];
  inverse = ~complement;
  if ((calibration != 0 && calibration == inverse) ||
      (repeated != 0 && repeated == inverse) ||
      (calibration != 0 && repeated == calibration))
    {
      guint16 tcode = ((calibration >> 4) + 1) << 4;
      guint16 scaled = ((calibration & 0x0f) + 2) * 100;
      guint8 fdt = ((((scaled * 256) / tcode) / 3) >> 4) & 0xff;

      config[0xeb] = tcode & 0xff;
      config[0xec] = tcode >> 8;
      config[0xc7] = 0x80;
      config[0xc8] = fdt;
    }

  selector = otp[27];
  first = selector & 3;
  second = (selector >> 4) & 3;
  third = ((guint8) ~selector >> 2) & 3;
  if (first == second || first == third)
    decoded = first;
  else if (second == third)
    decoded = second;
  if (decoded > 0)
    config[0xb3] = decoded + 4;

  checksum = config_checksum (config);
  config[254] = checksum & 0xff;
  config[255] = checksum >> 8;
  if (!goodix5503_config_has_valid_checksum (config))
    {
      g_set_error_literal (error, GOODIX5503_CONFIG_ERROR,
                           GOODIX5503_CONFIG_ERROR_INTEGRITY,
                           "Goodix runtime config checksum failed");
      return FALSE;
    }
  return TRUE;
}
