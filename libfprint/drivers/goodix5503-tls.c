/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix5503-tls.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>

struct _Goodix5503Tls
{
  SSL_CTX *context;
  SSL *ssl;
  GByteArray *plaintext;
  guint8 psk[GOODIX5503_PSK_SIZE];
  gboolean established;
};

G_DEFINE_QUARK (goodix5503-tls-error-quark, goodix5503_tls_error)

static unsigned int
psk_server_callback (SSL           *ssl,
                     const char    *identity,
                     unsigned char *psk,
                     unsigned int   max_psk_len)
{
  Goodix5503Tls *tls = SSL_get_app_data (ssl);

  (void) identity;
  if (tls == NULL || max_psk_len < GOODIX5503_PSK_SIZE)
    return 0;
  memcpy (psk, tls->psk, GOODIX5503_PSK_SIZE);
  return GOODIX5503_PSK_SIZE;
}

static gboolean
set_protocol_error (GError **error, const char *message)
{
  g_set_error_literal (error, GOODIX5503_TLS_ERROR,
                       GOODIX5503_TLS_ERROR_PROTOCOL, message);
  return FALSE;
}

Goodix5503Tls *
goodix5503_tls_new (const guint8 psk[GOODIX5503_PSK_SIZE],
                    GError      **error)
{
  Goodix5503Tls *tls;
  BIO *read_bio = NULL;
  BIO *write_bio = NULL;

  g_return_val_if_fail (error == NULL || *error == NULL, NULL);
  if (psk == NULL)
    {
      g_set_error_literal (error, GOODIX5503_TLS_ERROR,
                           GOODIX5503_TLS_ERROR_SETUP,
                           "Goodix TLS PSK is missing");
      return NULL;
    }

  tls = g_new0 (Goodix5503Tls, 1);
  memcpy (tls->psk, psk, GOODIX5503_PSK_SIZE);
  tls->plaintext = g_byte_array_sized_new (GOODIX5503_MAX_TLS_PLAINTEXT);
  tls->context = SSL_CTX_new (TLS_server_method ());
  if (tls->context == NULL ||
      !SSL_CTX_set_min_proto_version (tls->context, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version (tls->context, TLS1_2_VERSION) ||
      !SSL_CTX_set_cipher_list (tls->context, "PSK-AES128-CBC-SHA256"))
    goto setup_error;
  SSL_CTX_set_options (tls->context, SSL_OP_NO_TICKET);
  SSL_CTX_set_psk_server_callback (tls->context, psk_server_callback);

  tls->ssl = SSL_new (tls->context);
  read_bio = BIO_new (BIO_s_mem ());
  write_bio = BIO_new (BIO_s_mem ());
  if (tls->ssl == NULL || read_bio == NULL || write_bio == NULL)
    goto setup_error;
  BIO_set_mem_eof_return (read_bio, -1);
  BIO_set_mem_eof_return (write_bio, -1);
  SSL_set_bio (tls->ssl, read_bio, write_bio);
  read_bio = write_bio = NULL;
  SSL_set_app_data (tls->ssl, tls);
  SSL_set_accept_state (tls->ssl);
  return tls;

setup_error:
  BIO_free (read_bio);
  BIO_free (write_bio);
  goodix5503_tls_free (tls);
  g_set_error_literal (error, GOODIX5503_TLS_ERROR,
                       GOODIX5503_TLS_ERROR_SETUP,
                       "failed to initialize fixed Goodix TLS profile");
  return NULL;
}

void
goodix5503_tls_free (Goodix5503Tls *tls)
{
  if (tls == NULL)
    return;
  if (tls->plaintext)
    {
      OPENSSL_cleanse (tls->plaintext->data, tls->plaintext->len);
      g_byte_array_unref (tls->plaintext);
    }
  SSL_free (tls->ssl);
  SSL_CTX_free (tls->context);
  OPENSSL_cleanse (tls->psk, sizeof tls->psk);
  g_free (tls);
}

static gboolean
collect_plaintext (Goodix5503Tls *tls, GError **error)
{
  guint8 chunk[4096];

  while (TRUE)
    {
      size_t count = 0;
      int result = SSL_read_ex (tls->ssl, chunk, sizeof chunk, &count);

      if (result == 1)
        {
          if (count > GOODIX5503_MAX_TLS_PLAINTEXT - tls->plaintext->len)
            {
              OPENSSL_cleanse (chunk, sizeof chunk);
              g_set_error_literal (error, GOODIX5503_TLS_ERROR,
                                   GOODIX5503_TLS_ERROR_LENGTH,
                                   "Goodix TLS plaintext exceeded its bound");
              return FALSE;
            }
          g_byte_array_append (tls->plaintext, chunk, count);
          OPENSSL_cleanse (chunk, sizeof chunk);
          continue;
        }

      OPENSSL_cleanse (chunk, sizeof chunk);
      switch (SSL_get_error (tls->ssl, result))
        {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          return TRUE;
        case SSL_ERROR_ZERO_RETURN:
          return TRUE;
        default:
          return set_protocol_error (error, "Goodix TLS application decode failed");
        }
    }
}

gboolean
goodix5503_tls_feed_ciphertext (Goodix5503Tls  *tls,
                                 const guint8   *data,
                                 gsize           data_len,
                                 GError        **error)
{
  BIO *read_bio;
  int result;

  g_return_val_if_fail (tls != NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if ((data_len > 0 && data == NULL) || data_len > GOODIX5503_MAX_TLS_FLIGHT)
    {
      g_set_error_literal (error, GOODIX5503_TLS_ERROR,
                           GOODIX5503_TLS_ERROR_LENGTH,
                           "invalid Goodix TLS ciphertext length");
      return FALSE;
    }

  read_bio = SSL_get_rbio (tls->ssl);
  if (data_len > 0 && BIO_write (read_bio, data, data_len) != (int) data_len)
    return set_protocol_error (error, "failed to buffer Goodix TLS ciphertext");

  if (!tls->established)
    {
      result = SSL_do_handshake (tls->ssl);
      if (result == 1)
        tls->established = TRUE;
      else
        {
          int ssl_error = SSL_get_error (tls->ssl, result);

          if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
            return set_protocol_error (error, "Goodix TLS handshake failed");
        }
    }
  if (tls->established)
    return collect_plaintext (tls, error);
  return TRUE;
}

GByteArray *
goodix5503_tls_drain_ciphertext (Goodix5503Tls  *tls,
                                  GError        **error)
{
  BIO *write_bio;
  gsize pending;
  GByteArray *output;
  int count;

  g_return_val_if_fail (tls != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);
  write_bio = SSL_get_wbio (tls->ssl);
  pending = BIO_ctrl_pending (write_bio);
  if (pending > GOODIX5503_MAX_TLS_FLIGHT)
    {
      g_set_error_literal (error, GOODIX5503_TLS_ERROR,
                           GOODIX5503_TLS_ERROR_LENGTH,
                           "Goodix TLS server flight exceeded its bound");
      return NULL;
    }

  output = g_byte_array_sized_new (pending);
  if (pending == 0)
    return output;
  g_byte_array_set_size (output, pending);
  count = BIO_read (write_bio, output->data, pending);
  if (count != (int) pending)
    {
      g_byte_array_unref (output);
      set_protocol_error (error, "failed to drain Goodix TLS server flight");
      return NULL;
    }
  return output;
}

GByteArray *
goodix5503_tls_take_plaintext (Goodix5503Tls  *tls,
                                GError        **error)
{
  GByteArray *result;

  g_return_val_if_fail (tls != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);
  if (tls->plaintext->len == 0)
    {
      g_set_error_literal (error, GOODIX5503_TLS_ERROR,
                           GOODIX5503_TLS_ERROR_LENGTH,
                           "Goodix TLS has no plaintext available");
      return NULL;
    }
  result = tls->plaintext;
  tls->plaintext = g_byte_array_sized_new (GOODIX5503_MAX_TLS_PLAINTEXT);
  return result;
}

gboolean
goodix5503_tls_is_established (Goodix5503Tls *tls)
{
  g_return_val_if_fail (tls != NULL, FALSE);
  return tls->established;
}
