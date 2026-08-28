/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <glib.h>
#include <openssl/crypto.h>

#include "goodix5503-security.h"

static void
test_verification_known_answer (void)
{
  guint8 psk[GOODIX5503_SECURITY_PSK_SIZE] = { 0 };
  guint8 verification[GOODIX5503_VERIFICATION_SIZE] = { 0 };
  const guint8 expected[GOODIX5503_VERIFICATION_SIZE] = {
    0x81, 0xb8, 0xff, 0x49, 0x06, 0x12, 0x02, 0x2a,
    0x12, 0x1a, 0x94, 0x49, 0xee, 0x3a, 0xad, 0x27,
    0x92, 0xf3, 0x2b, 0x9f, 0x31, 0x41, 0x18, 0x2c,
    0xd0, 0x10, 0x19, 0x94, 0x5e, 0xe5, 0x03, 0x61,
  };
  g_autoptr(GError) error = NULL;

  g_assert_true (goodix5503_derive_verification_record (
    psk, verification, &error));
  g_assert_no_error (error);
  g_assert_true (goodix5503_verification_equal (verification, expected));
  verification[0] ^= 1;
  g_assert_false (goodix5503_verification_equal (verification, expected));
  OPENSSL_cleanse (verification, sizeof verification);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix5503/security/verification-kat",
                   test_verification_known_answer);
  return g_test_run ();
}
