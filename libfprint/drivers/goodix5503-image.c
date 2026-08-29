/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix5503-image.h"

#include <openssl/crypto.h>

FpImage *
goodix5503_image_new_from_frames (
  const guint8 background[GOODIX5503_PACKED_IMAGE_SIZE],
  const guint8 finger[GOODIX5503_PACKED_IMAGE_SIZE],
  GError **error)
{
  g_autofree guint16 *background_pixels = NULL;
  g_autofree guint16 *finger_pixels = NULL;
  FpImage *image = NULL;

  g_return_val_if_fail (error == NULL || *error == NULL, NULL);
  if (background == NULL || finger == NULL)
    {
      g_set_error_literal (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_LENGTH,
                           "Goodix image frame is missing");
      return NULL;
    }

  background_pixels = g_new0 (guint16, GOODIX5503_PIXEL_COUNT);
  finger_pixels = g_new0 (guint16, GOODIX5503_PIXEL_COUNT);
  if (!goodix5503_decode_packed_image (
        background, GOODIX5503_PACKED_IMAGE_SIZE, background_pixels,
        GOODIX5503_PIXEL_COUNT, error) ||
      !goodix5503_decode_packed_image (
        finger, GOODIX5503_PACKED_IMAGE_SIZE, finger_pixels,
        GOODIX5503_PIXEL_COUNT, error))
    goto out;

  image = fp_image_new (GOODIX5503_SIGFM_IMAGE_WIDTH,
                        GOODIX5503_SIGFM_IMAGE_HEIGHT);
  image->ppmm = 500.0 / 25.4;
  if (!goodix5503_build_difference_image (
        background_pixels, finger_pixels, GOODIX5503_PIXEL_COUNT,
        image->data, error))
    g_clear_object (&image);

out:
  OPENSSL_cleanse (background_pixels,
                   GOODIX5503_PIXEL_COUNT * sizeof *background_pixels);
  OPENSSL_cleanse (finger_pixels,
                   GOODIX5503_PIXEL_COUNT * sizeof *finger_pixels);
  return image;
}
