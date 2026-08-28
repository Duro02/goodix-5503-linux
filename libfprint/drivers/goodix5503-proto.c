/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix5503-proto.h"

#define GOODIX_MESSAGE_FLAGS 0xa0
#define GOODIX_CHECKSUM_TARGET 0xaa
#define GOODIX_NO_CHECKSUM_TRAILER 0x88

G_DEFINE_QUARK (goodix5503-proto-error-quark, goodix5503_proto_error)

static guint16
read_le16 (const guint8 *data)
{
  return (guint16) data[0] | ((guint16) data[1] << 8);
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
