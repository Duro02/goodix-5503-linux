/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define GOODIX5503_IMAGE_WIDTH 80
#define GOODIX5503_IMAGE_HEIGHT 64
#define GOODIX5503_PIXEL_COUNT (GOODIX5503_IMAGE_WIDTH * GOODIX5503_IMAGE_HEIGHT)
#define GOODIX5503_PACKED_IMAGE_SIZE 7680
#define GOODIX5503_FDT_BASE_SIZE 12
#define GOODIX5503_FDT_RESPONSE_SIZE 16
#define GOODIX5503_DAC_SIZE 8
#define GOODIX5503_FDT_REQUEST_SIZE 22

typedef struct _Goodix5503FrameBuffer Goodix5503FrameBuffer;

typedef struct
{
  gboolean ack;
  gboolean image_prelude;
  gboolean done;
} Goodix5503CaptureState;

typedef enum
{
  GOODIX5503_COMMAND_WAIT_ACK,
  GOODIX5503_COMMAND_WAIT_DATA,
  GOODIX5503_COMMAND_DONE,
} Goodix5503CommandState;

typedef enum
{
  GOODIX5503_PROTO_ERROR_INVALID,
  GOODIX5503_PROTO_ERROR_LENGTH,
  GOODIX5503_PROTO_ERROR_CHECKSUM,
  GOODIX5503_PROTO_ERROR_NO_CONTRAST,
} Goodix5503ProtoError;

#define GOODIX5503_PROTO_ERROR (goodix5503_proto_error_quark ())
GQuark goodix5503_proto_error_quark (void);

Goodix5503FrameBuffer *goodix5503_frame_buffer_new (void);
void goodix5503_frame_buffer_free (Goodix5503FrameBuffer *buffer);
gsize goodix5503_frame_buffer_length (Goodix5503FrameBuffer *buffer);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (Goodix5503FrameBuffer,
                               goodix5503_frame_buffer_free)

gboolean goodix5503_frame_buffer_append (Goodix5503FrameBuffer  *buffer,
                                          const guint8           *data,
                                          gsize                   data_len,
                                          GError                **error);

gboolean goodix5503_frame_buffer_take (Goodix5503FrameBuffer  *buffer,
                                        GByteArray            **frame,
                                        GError                **error);

GByteArray *goodix5503_outer_encode (guint8         flags,
                                      const guint8  *payload,
                                      gsize          payload_len,
                                      GError       **error);

gboolean goodix5503_outer_decode (const guint8  *frame,
                                   gsize          frame_len,
                                   guint8         expected_flags,
                                   GByteArray   **payload,
                                   GError       **error);

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

gboolean goodix5503_capture_consume_frame (Goodix5503CaptureState  *state,
                                            const guint8            *frame,
                                            gsize                    frame_len,
                                            GByteArray             **encrypted_envelope,
                                            GError                 **error);

gboolean goodix5503_command_consume_frame (guint8                   expected_command,
                                            gboolean                 expect_data,
                                            gboolean                 data_checksum,
                                            Goodix5503CommandState  *state,
                                            const guint8            *frame,
                                            gsize                    frame_len,
                                            GByteArray             **body,
                                            GError                 **error);

gboolean goodix5503_parse_fdt_response (const guint8  *response,
                                         gsize          response_len,
                                         guint16       *interrupt,
                                         guint16       *touch_flag,
                                         guint8         raw_base[GOODIX5503_FDT_BASE_SIZE],
                                         guint8         transformed_base[GOODIX5503_FDT_BASE_SIZE],
                                         GError       **error);

gboolean goodix5503_build_fdt_request (guint8         selector,
                                        const guint8   dac[GOODIX5503_DAC_SIZE],
                                        const guint8   base[GOODIX5503_FDT_BASE_SIZE],
                                        guint8         request[GOODIX5503_FDT_REQUEST_SIZE],
                                        GError       **error);

gboolean goodix5503_fdt_bases_within_delta (const guint8 first[GOODIX5503_FDT_BASE_SIZE],
                                             const guint8 second[GOODIX5503_FDT_BASE_SIZE],
                                             guint16      delta);

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
