/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix5503-proto.h"

#define GOODIX_MESSAGE_FLAGS 0xa0
#define GOODIX_CHECKSUM_TARGET 0xaa
#define GOODIX_NO_CHECKSUM_TRAILER 0x88
#define GOODIX5503_MAX_FRAME_SIZE 32768
#define GOODIX5503_MAX_BUFFER_SIZE (GOODIX5503_MAX_FRAME_SIZE * 2)

struct _Goodix5503FrameBuffer
{
  GByteArray *bytes;
};

G_DEFINE_QUARK (goodix5503-proto-error-quark, goodix5503_proto_error)

static guint16
read_le16 (const guint8 *data)
{
  return (guint16) data[0] | ((guint16) data[1] << 8);
}

static void
write_le16 (guint8 *data, guint16 value)
{
  data[0] = value & 0xff;
  data[1] = value >> 8;
}

static void
append_le16 (GByteArray *array, guint16 value)
{
  const guint8 encoded[2] = { value & 0xff, value >> 8 };
  g_byte_array_append (array, encoded, sizeof encoded);
}

static guint8
sum8 (const guint8 *data, gsize length)
{
  guint sum = 0;

  for (gsize index = 0; index < length; index++)
    sum += data[index];
  return sum & 0xff;
}

Goodix5503FrameBuffer *
goodix5503_frame_buffer_new (void)
{
  Goodix5503FrameBuffer *buffer = g_new0 (Goodix5503FrameBuffer, 1);

  buffer->bytes = g_byte_array_sized_new (GOODIX5503_MAX_FRAME_SIZE);
  return buffer;
}

void
goodix5503_frame_buffer_free (Goodix5503FrameBuffer *buffer)
{
  if (buffer == NULL)
    return;
  g_clear_pointer (&buffer->bytes, g_byte_array_unref);
  g_free (buffer);
}

gsize
goodix5503_frame_buffer_length (Goodix5503FrameBuffer *buffer)
{
  g_return_val_if_fail (buffer != NULL, 0);
  return buffer->bytes->len;
}

gboolean
goodix5503_frame_buffer_append (Goodix5503FrameBuffer  *buffer,
                                 const guint8           *data,
                                 gsize                   data_len,
                                 GError                **error)
{
  g_return_val_if_fail (buffer != NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if ((data_len > 0 && data == NULL) ||
      data_len > GOODIX5503_MAX_BUFFER_SIZE - buffer->bytes->len)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "Goodix USB frame buffer exceeded its bound");
      return FALSE;
    }
  if (data_len > 0)
    g_byte_array_append (buffer->bytes, data, data_len);
  return TRUE;
}

gboolean
goodix5503_frame_buffer_take (Goodix5503FrameBuffer  *buffer,
                               GByteArray            **frame,
                               GError                **error)
{
  guint16 payload_len;
  gsize frame_len;

  g_return_val_if_fail (buffer != NULL, FALSE);
  g_return_val_if_fail (frame != NULL && *frame == NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (buffer->bytes->len < 4)
    return FALSE;
  if (sum8 (buffer->bytes->data, 3) != buffer->bytes->data[3])
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_CHECKSUM,
                           "invalid Goodix USB frame header checksum");
      return FALSE;
    }
  payload_len = read_le16 (buffer->bytes->data + 1);
  frame_len = (gsize) payload_len + 4;
  if (frame_len > GOODIX5503_MAX_FRAME_SIZE)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "Goodix USB frame exceeded its bound");
      return FALSE;
    }
  if (buffer->bytes->len < frame_len)
    return FALSE;

  *frame = g_byte_array_sized_new (frame_len);
  g_byte_array_append (*frame, buffer->bytes->data, frame_len);
  g_byte_array_remove_range (buffer->bytes, 0, frame_len);
  return TRUE;
}

GByteArray *
goodix5503_packet_encode (guint8         command,
                           const guint8  *payload,
                           gsize          payload_len,
                           gboolean       checksum,
                           GError       **error)
{
  g_autoptr(GByteArray) protocol = NULL;
  GByteArray *packet;
  guint8 header[4];
  guint8 trailer;

  g_return_val_if_fail (error == NULL || *error == NULL, NULL);
  if (payload_len > G_MAXUINT16 - 1 || (payload_len > 0 && payload == NULL))
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "invalid Goodix request payload length");
      return NULL;
    }

  protocol = g_byte_array_sized_new (payload_len + 4);
  g_byte_array_append (protocol, &command, 1);
  append_le16 (protocol, payload_len + 1);
  if (payload_len > 0)
    g_byte_array_append (protocol, payload, payload_len);
  trailer = checksum ? (GOODIX_CHECKSUM_TARGET - sum8 (protocol->data,
                                                        protocol->len)) & 0xff
                     : GOODIX_NO_CHECKSUM_TRAILER;
  g_byte_array_append (protocol, &trailer, 1);

  header[0] = GOODIX_MESSAGE_FLAGS;
  header[1] = protocol->len & 0xff;
  header[2] = protocol->len >> 8;
  header[3] = sum8 (header, 3);
  packet = g_byte_array_sized_new (sizeof header + protocol->len);
  g_byte_array_append (packet, header, sizeof header);
  g_byte_array_append (packet, protocol->data, protocol->len);
  return packet;
}

gboolean
goodix5503_packet_decode (const guint8  *packet,
                           gsize          packet_len,
                           guint8         expected_command,
                           gboolean       checksum,
                           GByteArray   **body,
                           GError       **error)
{
  guint16 outer_len;
  guint16 inner_len;
  const guint8 *protocol;
  gsize body_len;
  guint8 expected_trailer;

  g_return_val_if_fail (body != NULL && *body == NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (packet == NULL || packet_len < 8)
    goto length_error;
  if (packet[0] != GOODIX_MESSAGE_FLAGS)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_INVALID,
                           "unexpected Goodix packet flags");
      return FALSE;
    }
  if (sum8 (packet, 3) != packet[3])
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_CHECKSUM,
                           "invalid Goodix header checksum");
      return FALSE;
    }

  outer_len = read_le16 (packet + 1);
  if (outer_len < 4 || packet_len != (gsize) outer_len + 4)
    goto length_error;
  protocol = packet + 4;
  if (protocol[0] != expected_command)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_INVALID,
                           "unexpected Goodix response command");
      return FALSE;
    }
  inner_len = read_le16 (protocol + 1);
  if (inner_len < 1 || outer_len != (guint16) (3 + inner_len))
    goto length_error;

  body_len = inner_len - 1;
  expected_trailer = checksum
                     ? (GOODIX_CHECKSUM_TARGET - sum8 (protocol, 3 + body_len)) & 0xff
                     : GOODIX_NO_CHECKSUM_TRAILER;
  if (protocol[3 + body_len] != expected_trailer)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_CHECKSUM,
                           "invalid Goodix protocol trailer");
      return FALSE;
    }

  *body = g_byte_array_sized_new (body_len);
  if (body_len > 0)
    g_byte_array_append (*body, protocol + 3, body_len);
  return TRUE;

length_error:
  g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                       GOODIX5503_PROTO_ERROR_LENGTH,
                       "invalid Goodix packet length");
  return FALSE;
}

static gboolean
decode_outer (const guint8  *frame,
              gsize          frame_len,
              guint8         expected_flags,
              GByteArray   **payload,
              GError       **error)
{
  guint16 payload_len;

  if (frame == NULL || frame_len < 4 || frame[0] != expected_flags)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_INVALID,
                           "unexpected Goodix outer frame flags");
      return FALSE;
    }
  if (sum8 (frame, 3) != frame[3])
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_CHECKSUM,
                           "invalid Goodix outer frame checksum");
      return FALSE;
    }
  payload_len = read_le16 (frame + 1);
  if (frame_len != (gsize) payload_len + 4)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "invalid Goodix outer frame length");
      return FALSE;
    }
  *payload = g_byte_array_sized_new (payload_len);
  g_byte_array_append (*payload, frame + 4, payload_len);
  return TRUE;
}

static gboolean
validate_image_tls_records (const guint8 *data, gsize length, GError **error)
{
  gsize offset = 0;

  if (length == 0)
    goto invalid;
  while (offset < length)
    {
      guint16 record_len;

      if (length - offset < 5 || data[offset] != 23 ||
          data[offset + 1] != 0x03 || data[offset + 2] != 0x03)
        goto invalid;
      record_len = ((guint16) data[offset + 3] << 8) | data[offset + 4];
      if (record_len == 0 || record_len > 0x4000 + 2048 ||
          record_len > length - offset - 5)
        goto invalid;
      offset += 5 + record_len;
    }
  return TRUE;

invalid:
  g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                       GOODIX5503_PROTO_ERROR_INVALID,
                       "invalid Goodix image TLS record boundary");
  return FALSE;
}

gboolean
goodix5503_capture_consume_frame (Goodix5503CaptureState  *state,
                                   const guint8            *frame,
                                   gsize                    frame_len,
                                   GByteArray             **encrypted_envelope,
                                   GError                 **error)
{
  g_autoptr(GByteArray) body = NULL;

  g_return_val_if_fail (state != NULL, FALSE);
  g_return_val_if_fail (encrypted_envelope != NULL &&
                        *encrypted_envelope == NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (state->done)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_INVALID,
                           "duplicate Goodix image frame");
      return FALSE;
    }

  if (!state->ack)
    {
      if (!goodix5503_packet_decode (frame, frame_len, 0xb0, TRUE,
                                     &body, error))
        return FALSE;
      if (body->len != 2 || body->data[0] != 0x20 ||
          !(body->data[1] & 1))
        {
          g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                               GOODIX5503_PROTO_ERROR_INVALID,
                               "Goodix image acknowledgement was rejected");
          return FALSE;
        }
      state->ack = TRUE;
      return TRUE;
    }

  if (frame_len > 0 && frame[0] == GOODIX_MESSAGE_FLAGS)
    {
      guint8 command;

      if (frame_len < 8)
        {
          g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                               GOODIX5503_PROTO_ERROR_LENGTH,
                               "truncated Goodix image prelude");
          return FALSE;
        }
      command = frame[4];
      if (command == 0xd0 && !state->delayed_tls_completion &&
          !state->image_prelude)
        {
          if (!goodix5503_packet_decode (frame, frame_len, command, TRUE,
                                         &body, error))
            return FALSE;
          if (body->len > 16)
            {
              g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                                   GOODIX5503_PROTO_ERROR_LENGTH,
                                   "delayed Goodix TLS completion is too large");
              return FALSE;
            }
          state->delayed_tls_completion = TRUE;
          return TRUE;
        }
      if (command == 0x20 && !state->image_prelude)
        {
          if (!goodix5503_packet_decode (frame, frame_len, command, TRUE,
                                         &body, error))
            return FALSE;
          if (body->len != 1 || body->data[0] != 1)
            {
              g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                                   GOODIX5503_PROTO_ERROR_INVALID,
                                   "Goodix image prelude was rejected");
              return FALSE;
            }
          state->image_prelude = TRUE;
          return TRUE;
        }
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_INVALID,
                           "unexpected Goodix image prelude order");
      return FALSE;
    }

  if (!decode_outer (frame, frame_len, 0xb2, encrypted_envelope, error))
    return FALSE;
  if ((*encrypted_envelope)->len <= 9)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "Goodix encrypted image envelope is too short");
      g_clear_pointer (encrypted_envelope, g_byte_array_unref);
      return FALSE;
    }
  if (!validate_image_tls_records ((*encrypted_envelope)->data + 9,
                                   (*encrypted_envelope)->len - 9, error))
    {
      g_clear_pointer (encrypted_envelope, g_byte_array_unref);
      return FALSE;
    }
  state->done = TRUE;
  return TRUE;
}

gboolean
goodix5503_command_consume_frame (guint8                   expected_command,
                                   gboolean                 expect_data,
                                   gboolean                 data_checksum,
                                   Goodix5503CommandState  *state,
                                   const guint8            *frame,
                                   gsize                    frame_len,
                                   GByteArray             **body,
                                   GError                 **error)
{
  g_autoptr(GByteArray) decoded = NULL;

  g_return_val_if_fail (state != NULL, FALSE);
  g_return_val_if_fail (body != NULL && *body == NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (*state == GOODIX5503_COMMAND_DONE)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_INVALID,
                           "duplicate Goodix command frame");
      return FALSE;
    }

  if (*state == GOODIX5503_COMMAND_WAIT_ACK)
    {
      if (!goodix5503_packet_decode (frame, frame_len, 0xb0, TRUE,
                                     &decoded, error))
        return FALSE;
      if (decoded->len != 2 || decoded->data[0] != expected_command ||
          !(decoded->data[1] & 1))
        {
          g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                               GOODIX5503_PROTO_ERROR_INVALID,
                               "Goodix command acknowledgement was rejected");
          return FALSE;
        }
      if (expect_data)
        {
          *state = GOODIX5503_COMMAND_WAIT_DATA;
          return TRUE;
        }
      *state = GOODIX5503_COMMAND_DONE;
      *body = g_byte_array_new ();
      return TRUE;
    }

  if (!goodix5503_packet_decode (frame, frame_len, expected_command,
                                 data_checksum, body, error))
    return FALSE;
  *state = GOODIX5503_COMMAND_DONE;
  return TRUE;
}

gboolean
goodix5503_parse_fdt_response (const guint8  *response,
                                gsize          response_len,
                                guint16       *interrupt,
                                guint16       *touch_flag,
                                guint8         raw_base[GOODIX5503_FDT_BASE_SIZE],
                                guint8         transformed_base[GOODIX5503_FDT_BASE_SIZE],
                                GError       **error)
{
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (response == NULL || interrupt == NULL || touch_flag == NULL ||
      raw_base == NULL || transformed_base == NULL ||
      response_len != GOODIX5503_FDT_RESPONSE_SIZE)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "invalid Goodix FDT response length");
      return FALSE;
    }

  *interrupt = read_le16 (response);
  *touch_flag = read_le16 (response + 2);
  memcpy (raw_base, response + 4, GOODIX5503_FDT_BASE_SIZE);
  for (gsize offset = 0; offset < GOODIX5503_FDT_BASE_SIZE; offset += 2)
    {
      guint16 word = read_le16 (raw_base + offset);

      write_le16 (transformed_base + offset,
                  ((((guint32) word >> 1) << 8) | 0x0080) & 0xffff);
    }
  return TRUE;
}

gboolean
goodix5503_build_fdt_request (guint8         selector,
                               const guint8   dac[GOODIX5503_DAC_SIZE],
                               const guint8   base[GOODIX5503_FDT_BASE_SIZE],
                               guint8         request[GOODIX5503_FDT_REQUEST_SIZE],
                               GError       **error)
{
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if ((selector & 0x0f) < 0x0c || (selector & 0x0f) > 0x0e ||
      dac == NULL || base == NULL || request == NULL)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_INVALID,
                           "invalid Goodix FDT request");
      return FALSE;
    }

  request[0] = selector;
  request[1] = 1;
  memcpy (request + 2, dac, GOODIX5503_DAC_SIZE);
  for (gsize offset = 0; offset < GOODIX5503_FDT_BASE_SIZE; offset += 2)
    write_le16 (request + 2 + GOODIX5503_DAC_SIZE + offset,
                (read_le16 (base + offset) & 0xff00) | 0x0080);
  return TRUE;
}

gboolean
goodix5503_fdt_bases_within_delta (const guint8 first[GOODIX5503_FDT_BASE_SIZE],
                                    const guint8 second[GOODIX5503_FDT_BASE_SIZE],
                                    guint16      delta)
{
  g_return_val_if_fail (first != NULL && second != NULL, FALSE);

  for (gsize offset = 0; offset < GOODIX5503_FDT_BASE_SIZE; offset += 2)
    if (ABS ((gint) read_le16 (first + offset) -
             (gint) read_le16 (second + offset)) > delta)
      return FALSE;
  return TRUE;
}

gboolean
goodix5503_decode_packed_image (const guint8  *packed,
                                 gsize          packed_len,
                                 guint16       *pixels,
                                 gsize          pixel_count,
                                 GError       **error)
{
  gsize output = 0;

  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (packed == NULL || pixels == NULL ||
      packed_len != GOODIX5503_PACKED_IMAGE_SIZE ||
      pixel_count != GOODIX5503_PIXEL_COUNT)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "invalid Goodix packed image length");
      return FALSE;
    }

  for (gsize offset = 0; offset < packed_len; offset += 6)
    {
      const guint8 *chunk = packed + offset;

      pixels[output++] = ((chunk[0] & 0x0f) << 8) | chunk[1];
      pixels[output++] = (chunk[3] << 4) | (chunk[0] >> 4);
      pixels[output++] = ((chunk[5] & 0x0f) << 8) | chunk[2];
      pixels[output++] = (chunk[4] << 4) | (chunk[5] >> 4);
    }
  return TRUE;
}

gboolean
goodix5503_build_difference_image (const guint16  *background,
                                    const guint16  *finger,
                                    gsize           pixel_count,
                                    guint8          *output,
                                    GError        **error)
{
  guint16 minimum = G_MAXUINT16;
  guint16 maximum = 0;

  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
  if (background == NULL || finger == NULL || output == NULL ||
      pixel_count != GOODIX5503_PIXEL_COUNT)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "invalid Goodix difference image length");
      return FALSE;
    }

  for (gsize index = 0; index < pixel_count; index++)
    {
      guint16 difference = ABS ((gint) background[index] -
                                (gint) finger[index]);

      minimum = MIN (minimum, difference);
      maximum = MAX (maximum, difference);
    }
  if (minimum == maximum)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_NO_CONTRAST,
                           "Goodix finger frame has no relative contrast");
      return FALSE;
    }

  for (gsize index = 0; index < pixel_count; index++)
    {
      guint16 difference = ABS ((gint) background[index] -
                                (gint) finger[index]);

      output[index] = ((guint32) difference - minimum) * 255 /
                      (maximum - minimum);
    }
  return TRUE;
}
