/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <glib.h>
#include <openssl/ssl.h>
#include <string.h>

#include "goodix5503-tls.h"

static const guint8 test_psk[GOODIX5503_PSK_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static unsigned int
client_psk_callback (SSL           *ssl,
                     const char    *hint,
                     char          *identity,
                     unsigned int   max_identity_len,
                     unsigned char *psk,
                     unsigned int   max_psk_len)
{
  const char name[] = "goodix-test";

  (void) ssl;
  (void) hint;
  if (max_identity_len < sizeof name || max_psk_len < sizeof test_psk)
    return 0;
  memcpy (identity, name, sizeof name);
  memcpy (psk, test_psk, sizeof test_psk);
  return sizeof test_psk;
}

static GByteArray *
drain_bio (BIO *bio)
{
  gsize pending = BIO_ctrl_pending (bio);
  GByteArray *output = g_byte_array_sized_new (pending);

  if (pending == 0)
    return output;
  g_byte_array_set_size (output, pending);
  g_assert_cmpint (BIO_read (bio, output->data, pending), ==, (int) pending);
  return output;
}

static void
test_tls12_psk_handshake_and_plaintext (void)
{
  g_autoptr(Goodix5503Tls) server = NULL;
  g_autoptr(GByteArray) flight = NULL;
  g_autoptr(GByteArray) plaintext = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *application = g_malloc (GOODIX5503_MAX_TLS_PLAINTEXT);
  SSL_CTX *client_context = NULL;
  SSL *client = NULL;
  BIO *client_read = NULL;
  BIO *client_write = NULL;
  gboolean established = FALSE;

  server = goodix5503_tls_new (test_psk, &error);
  g_assert_no_error (error);
  g_assert_nonnull (server);

  client_context = SSL_CTX_new (TLS_client_method ());
  g_assert_nonnull (client_context);
  g_assert_true (SSL_CTX_set_min_proto_version (client_context, TLS1_2_VERSION));
  g_assert_true (SSL_CTX_set_max_proto_version (client_context, TLS1_2_VERSION));
  g_assert_true (SSL_CTX_set_cipher_list (client_context,
                                          "PSK-AES128-CBC-SHA256"));
  SSL_CTX_set_options (client_context, SSL_OP_NO_TICKET);
  SSL_CTX_set_psk_client_callback (client_context, client_psk_callback);

  client = SSL_new (client_context);
  client_read = BIO_new (BIO_s_mem ());
  client_write = BIO_new (BIO_s_mem ());
  g_assert_nonnull (client);
  g_assert_nonnull (client_read);
  g_assert_nonnull (client_write);
  BIO_set_mem_eof_return (client_read, -1);
  BIO_set_mem_eof_return (client_write, -1);
  SSL_set_bio (client, client_read, client_write);
  client_read = client_write = NULL;
  SSL_set_connect_state (client);

  for (guint iteration = 0; iteration < 16; iteration++)
    {
      int result = SSL_do_handshake (client);
      int ssl_error = result == 1 ? SSL_ERROR_NONE : SSL_get_error (client, result);

      g_assert_true (result == 1 || ssl_error == SSL_ERROR_WANT_READ ||
                     ssl_error == SSL_ERROR_WANT_WRITE);
      g_clear_pointer (&flight, g_byte_array_unref);
      flight = drain_bio (SSL_get_wbio (client));
      if (flight->len > 0)
        {
          g_assert_true (goodix5503_tls_feed_ciphertext (
            server, flight->data, flight->len, &error));
          g_assert_no_error (error);
        }
      g_clear_pointer (&flight, g_byte_array_unref);
      flight = goodix5503_tls_drain_ciphertext (server, &error);
      g_assert_no_error (error);
      if (flight->len > 0)
        g_assert_cmpint (BIO_write (SSL_get_rbio (client), flight->data,
                                    flight->len), ==, (int) flight->len);
      if (SSL_is_init_finished (client) &&
          goodix5503_tls_is_established (server))
        {
          established = TRUE;
          break;
        }
    }
  g_assert_true (established);
  g_assert_cmpstr (SSL_get_cipher_name (client), ==,
                   "PSK-AES128-CBC-SHA256");

  for (gsize index = 0; index < GOODIX5503_MAX_TLS_PLAINTEXT; index++)
    application[index] = index & 0xff;
  {
    size_t written = 0;
    g_assert_true (SSL_write_ex (client, application,
                                 GOODIX5503_MAX_TLS_PLAINTEXT, &written));
    g_assert_cmpuint (written, ==, GOODIX5503_MAX_TLS_PLAINTEXT);
  }
  g_clear_pointer (&flight, g_byte_array_unref);
  flight = drain_bio (SSL_get_wbio (client));
  g_assert_true (goodix5503_tls_feed_ciphertext (
    server, flight->data, flight->len, &error));
  g_assert_no_error (error);
  plaintext = goodix5503_tls_take_plaintext (server, &error);
  g_assert_no_error (error);
  g_assert_cmpmem (plaintext->data, plaintext->len, application,
                   GOODIX5503_MAX_TLS_PLAINTEXT);

  OPENSSL_cleanse (application, GOODIX5503_MAX_TLS_PLAINTEXT);
  OPENSSL_cleanse (plaintext->data, plaintext->len);
  SSL_free (client);
  SSL_CTX_free (client_context);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix5503/tls/psk-handshake-plaintext",
                   test_tls12_psk_handshake_and_plaintext);
  return g_test_run ();
}
