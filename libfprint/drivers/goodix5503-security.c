/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "goodix5503-security.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

G_DEFINE_QUARK (goodix5503-security-error-quark, goodix5503_security_error)

#define GOODIX5503_PSK_PATH "/var/lib/fprint/goodix5503/psk.bin"

gboolean
goodix5503_load_host_psk (guint8   psk[GOODIX5503_SECURITY_PSK_SIZE],
                           GError **error)
{
  struct stat status;
  gsize offset = 0;
  guint8 extra;
  int descriptor = -1;
  gboolean result = FALSE;

  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (psk == NULL)
    goto state_error;
  descriptor = open (GOODIX5503_PSK_PATH,
                     O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
  if (descriptor < 0 || fstat (descriptor, &status) != 0 ||
      !S_ISREG (status.st_mode) || status.st_uid != 0 || status.st_nlink != 1 ||
      (status.st_mode & 0777) != 0600 ||
      status.st_size != GOODIX5503_SECURITY_PSK_SIZE)
    goto state_error;

  while (offset < GOODIX5503_SECURITY_PSK_SIZE)
    {
      ssize_t count = read (descriptor, psk + offset,
                            GOODIX5503_SECURITY_PSK_SIZE - offset);

      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        goto state_error;
      offset += count;
    }
  if (read (descriptor, &extra, 1) != 0)
    goto state_error;
  result = TRUE;
  goto out;

state_error:
  g_set_error_literal (error, GOODIX5503_SECURITY_ERROR,
                       GOODIX5503_SECURITY_ERROR_STATE,
                       "Goodix host PSK state is unavailable or unsafe");
  if (psk)
    OPENSSL_cleanse (psk, GOODIX5503_SECURITY_PSK_SIZE);
out:
  if (descriptor >= 0)
    close (descriptor);
  return result;
}

gboolean
goodix5503_derive_verification_record (
  const guint8 psk[GOODIX5503_SECURITY_PSK_SIZE],
  guint8       verification[GOODIX5503_VERIFICATION_SIZE],
  GError     **error)
{
  guint8 raw_pmk[68] = { 0 };
  guint8 pmk[64] = { 0 };
  guint8 message[64];
  unsigned int output_len = 0;
  gboolean result = FALSE;

  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (psk == NULL || verification == NULL)
    goto crypto_error;

  raw_pmk[1] = GOODIX5503_SECURITY_PSK_SIZE;
  raw_pmk[35] = GOODIX5503_SECURITY_PSK_SIZE;
  memcpy (raw_pmk + 36, psk, GOODIX5503_SECURITY_PSK_SIZE);
  for (guint index = 0; index < sizeof message; index++)
    message[index] = sizeof message - index;

  if (!EVP_Digest (raw_pmk, sizeof raw_pmk, pmk, NULL, EVP_sha256 (), NULL) ||
      HMAC (EVP_sha256 (), pmk, sizeof pmk, message, sizeof message,
            verification, &output_len) == NULL ||
      output_len != GOODIX5503_VERIFICATION_SIZE)
    goto crypto_error;
  result = TRUE;
  goto out;

crypto_error:
  g_set_error_literal (error, GOODIX5503_SECURITY_ERROR,
                       GOODIX5503_SECURITY_ERROR_CRYPTO,
                       "Goodix PSK verification derivation failed");
out:
  OPENSSL_cleanse (raw_pmk, sizeof raw_pmk);
  OPENSSL_cleanse (pmk, sizeof pmk);
  OPENSSL_cleanse (message, sizeof message);
  if (!result && verification != NULL)
    OPENSSL_cleanse (verification, GOODIX5503_VERIFICATION_SIZE);
  return result;
}

gboolean
goodix5503_verification_equal (
  const guint8 first[GOODIX5503_VERIFICATION_SIZE],
  const guint8 second[GOODIX5503_VERIFICATION_SIZE])
{
  g_return_val_if_fail (first != NULL && second != NULL, FALSE);
  return CRYPTO_memcmp (first, second, GOODIX5503_VERIFICATION_SIZE) == 0;
}
