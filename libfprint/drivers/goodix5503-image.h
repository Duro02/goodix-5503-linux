/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "drivers_api.h"
#include "goodix5503-proto.h"

G_BEGIN_DECLS

FpImage *goodix5503_image_new_from_frames (
  const guint8 background[GOODIX5503_PACKED_IMAGE_SIZE],
  const guint8 finger[GOODIX5503_PACKED_IMAGE_SIZE],
  GError **error);

G_END_DECLS
