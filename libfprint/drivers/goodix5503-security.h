/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define GOODIX5503_SECURITY_PSK_SIZE 32
#define GOODIX5503_VERIFICATION_SIZE 32

typedef enum
{
  GOODIX5503_SECURITY_ERROR_CRYPTO,
} Goodix5503SecurityError;

#define GOODIX5503_SECURITY_ERROR (goodix5503_security_error_quark ())
GQuark goodix5503_security_error_quark (void);

gboolean goodix5503_derive_verification_record (
  const guint8 psk[GOODIX5503_SECURITY_PSK_SIZE],
  guint8       verification[GOODIX5503_VERIFICATION_SIZE],
  GError     **error);

gboolean goodix5503_verification_equal (
  const guint8 first[GOODIX5503_VERIFICATION_SIZE],
  const guint8 second[GOODIX5503_VERIFICATION_SIZE]);

G_END_DECLS
