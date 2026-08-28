/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define GOODIX5503_PSK_SIZE 32
#define GOODIX5503_MAX_TLS_FLIGHT 32768
#define GOODIX5503_MAX_TLS_PLAINTEXT 7684

typedef struct _Goodix5503Tls Goodix5503Tls;

typedef enum
{
  GOODIX5503_TLS_ERROR_SETUP,
  GOODIX5503_TLS_ERROR_PROTOCOL,
  GOODIX5503_TLS_ERROR_LENGTH,
} Goodix5503TlsError;

#define GOODIX5503_TLS_ERROR (goodix5503_tls_error_quark ())
GQuark goodix5503_tls_error_quark (void);

Goodix5503Tls *goodix5503_tls_new (const guint8 psk[GOODIX5503_PSK_SIZE],
                                   GError      **error);
void goodix5503_tls_free (Goodix5503Tls *tls);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (Goodix5503Tls, goodix5503_tls_free)

gboolean goodix5503_tls_feed_ciphertext (Goodix5503Tls  *tls,
                                          const guint8   *data,
                                          gsize           data_len,
                                          GError        **error);
GByteArray *goodix5503_tls_drain_ciphertext (Goodix5503Tls  *tls,
                                             GError        **error);
GByteArray *goodix5503_tls_take_plaintext (Goodix5503Tls  *tls,
                                           GError        **error);
gboolean goodix5503_tls_is_established (Goodix5503Tls *tls);

G_END_DECLS
