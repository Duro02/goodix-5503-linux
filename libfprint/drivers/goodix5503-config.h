/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define GOODIX5503_OTP_SIZE 64
#define GOODIX5503_CONFIG_SIZE 256
#define GOODIX5503_DAC_SIZE 8

typedef enum
{
  GOODIX5503_CONFIG_ERROR_LENGTH,
  GOODIX5503_CONFIG_ERROR_INTEGRITY,
  GOODIX5503_CONFIG_ERROR_RIGHT_INFO,
} Goodix5503ConfigError;

#define GOODIX5503_CONFIG_ERROR (goodix5503_config_error_quark ())
GQuark goodix5503_config_error_quark (void);

guint8 goodix5503_crc8 (const guint8 *data, gsize length);
gboolean goodix5503_otp_has_valid_integrity (const guint8 otp[GOODIX5503_OTP_SIZE]);

gboolean goodix5503_derive_dac (guint8   otp[GOODIX5503_OTP_SIZE],
                                 guint8   dac[GOODIX5503_DAC_SIZE],
                                 GError **error);

gboolean goodix5503_build_runtime_config (const guint8 otp[GOODIX5503_OTP_SIZE],
                                           guint8       config[GOODIX5503_CONFIG_SIZE],
                                           GError     **error);

gboolean goodix5503_config_has_valid_checksum (const guint8 config[GOODIX5503_CONFIG_SIZE]);

G_END_DECLS
