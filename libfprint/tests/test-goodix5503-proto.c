/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <glib.h>
#include <string.h>

#include "goodix5503-proto.h"

static void
test_packet_round_trip (void)
{
  const guint8 payload[] = { 0x01, 0x00, 0x8b, 0x00 };
  g_autoptr(GByteArray) packet = NULL;
  g_autoptr(GByteArray) body = NULL;
  g_autoptr(GError) error = NULL;

  packet = goodix5503_packet_encode (0x20, payload, sizeof payload, TRUE, &error);
  g_assert_no_error (error);
  g_assert_nonnull (packet);
  g_assert_true (goodix5503_packet_decode (packet->data, packet->len, 0x20,
                                           TRUE, &body, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (body->data, body->len, payload, sizeof payload);
}

static void
test_no_checksum_packet (void)
{
  const guint8 payload[] = { 0x82, 0x01, 0x3f, 0x00 };
  g_autoptr(GByteArray) packet = NULL;
  g_autoptr(GByteArray) body = NULL;
  g_autoptr(GError) error = NULL;

  packet = goodix5503_packet_encode (0x36, payload, sizeof payload, FALSE, &error);
  g_assert_no_error (error);
  g_assert_cmphex (packet->data[packet->len - 1], ==, 0x88);
  g_assert_true (goodix5503_packet_decode (packet->data, packet->len, 0x36,
                                           FALSE, &body, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (body->data, body->len, payload, sizeof payload);
}

static void
test_packet_rejects_mutations (void)
{
  g_autoptr(GByteArray) packet = NULL;
  g_autoptr(GByteArray) body = NULL;
  g_autoptr(GError) error = NULL;

  packet = goodix5503_packet_encode (0x20, NULL, 0, TRUE, &error);
  g_assert_no_error (error);

  packet->data[3] ^= 1;
  g_assert_false (goodix5503_packet_decode (packet->data, packet->len, 0x20,
                                            TRUE, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_CHECKSUM);
  g_clear_error (&error);
  packet->data[3] ^= 1;

  packet->data[packet->len - 1] ^= 1;
  g_assert_false (goodix5503_packet_decode (packet->data, packet->len, 0x20,
                                            TRUE, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_CHECKSUM);
  g_clear_error (&error);
  packet->data[packet->len - 1] ^= 1;

  g_assert_false (goodix5503_packet_decode (packet->data, packet->len - 1, 0x20,
                                            TRUE, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_LENGTH);
  g_clear_error (&error);

  g_assert_false (goodix5503_packet_decode (packet->data, packet->len, 0x21,
                                            TRUE, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
}

static void
test_packed_decoder (void)
{
  const guint8 group[] = { 0xa5, 0x34, 0x67, 0x89, 0xbc, 0xd2 };
  g_autofree guint8 *packed = g_malloc (GOODIX5503_PACKED_IMAGE_SIZE);
  g_autofree guint16 *pixels = g_new0 (guint16, GOODIX5503_PIXEL_COUNT);
  g_autoptr(GError) error = NULL;

  for (gsize offset = 0; offset < GOODIX5503_PACKED_IMAGE_SIZE;
       offset += sizeof group)
    memcpy (packed + offset, group, sizeof group);

  g_assert_true (goodix5503_decode_packed_image (
    packed, GOODIX5503_PACKED_IMAGE_SIZE, pixels, GOODIX5503_PIXEL_COUNT,
    &error));
  g_assert_no_error (error);
  g_assert_cmphex (pixels[0], ==, 0x534);
  g_assert_cmphex (pixels[1], ==, 0x89a);
  g_assert_cmphex (pixels[2], ==, 0x267);
  g_assert_cmphex (pixels[3], ==, 0xbcd);

  g_assert_false (goodix5503_decode_packed_image (
    packed, GOODIX5503_PACKED_IMAGE_SIZE - 1, pixels,
    GOODIX5503_PIXEL_COUNT, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_LENGTH);
}

static void
test_difference_image (void)
{
  g_autofree guint16 *background = g_new0 (guint16, GOODIX5503_PIXEL_COUNT);
  g_autofree guint16 *finger = g_new0 (guint16, GOODIX5503_PIXEL_COUNT);
  g_autofree guint8 *output = g_malloc0 (GOODIX5503_PIXEL_COUNT);
  g_autoptr(GError) error = NULL;

  for (gsize index = 0; index < GOODIX5503_PIXEL_COUNT; index++)
    finger[index] = index % 4096;
  g_assert_true (goodix5503_build_difference_image (
    background, finger, GOODIX5503_PIXEL_COUNT, output, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (output[0], ==, 0);
  g_assert_cmpuint (output[4095], ==, 255);

  memset (finger, 0, GOODIX5503_PIXEL_COUNT * sizeof *finger);
  g_assert_false (goodix5503_build_difference_image (
    background, finger, GOODIX5503_PIXEL_COUNT, output, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_NO_CONTRAST);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix5503/packet/round-trip", test_packet_round_trip);
  g_test_add_func ("/goodix5503/packet/no-checksum", test_no_checksum_packet);
  g_test_add_func ("/goodix5503/packet/reject-mutations",
                   test_packet_rejects_mutations);
  g_test_add_func ("/goodix5503/image/decode", test_packed_decoder);
  g_test_add_func ("/goodix5503/image/difference", test_difference_image);
  return g_test_run ();
}
