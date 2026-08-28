/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define GOODIX5503_IMAGE_WIDTH 80
#define GOODIX5503_IMAGE_HEIGHT 64
#define GOODIX5503_PIXEL_COUNT (GOODIX5503_IMAGE_WIDTH * GOODIX5503_IMAGE_HEIGHT)
#define GOODIX5503_PACKED_IMAGE_SIZE 7680

typedef enum
{
  GOODIX5503_PROTO_ERROR_INVALID,
  GOODIX5503_PROTO_ERROR_LENGTH,
  GOODIX5503_PROTO_ERROR_CHECKSUM,
  GOODIX5503_PROTO_ERROR_NO_CONTRAST,
} Goodix5503ProtoError;

#define GOODIX5503_PROTO_ERROR (goodix5503_proto_error_quark ())
GQuark goodix5503_proto_error_quark (void);

GByteArray *goodix5503_packet_encode (guint8         command,
                                      const guint8  *payload,
                                      gsize          payload_len,
                                      gboolean       checksum,
                                      GError       **error);

gboolean goodix5503_packet_decode (const guint8  *packet,
                                    gsize          packet_len,
                                    guint8         expected_command,
                                    gboolean       checksum,
                                    GByteArray   **body,
                                    GError       **error);

gboolean goodix5503_decode_packed_image (const guint8  *packed,
                                          gsize          packed_len,
                                          guint16       *pixels,
                                          gsize          pixel_count,
                                          GError       **error);

gboolean goodix5503_build_difference_image (const guint16  *background,
                                             const guint16  *finger,
                                             gsize           pixel_count,
                                             guint8          *output,
                                             GError        **error);

G_END_DECLS
