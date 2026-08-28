/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Goodix GF3258/Milan 5503 image-device integration scaffold. */

#define FP_COMPONENT "goodix5503"
#include "fpi-log.h"
#include "drivers_api.h"
#include "goodix5503-proto.h"

struct _FpiDeviceGoodix5503
{
  FpImageDevice parent;
  GCancellable *cancellable;
  gboolean interface_claimed;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix5503, fpi_device_goodix5503,
                      FPI, DEVICE_GOODIX5503, FpImageDevice)
G_DEFINE_TYPE (FpiDeviceGoodix5503, fpi_device_goodix5503,
               FP_TYPE_IMAGE_DEVICE)

static void
goodix5503_open (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);
  g_autoptr(GError) error = NULL;

  if (!g_usb_device_claim_interface (
        fpi_device_get_usb_device (FP_DEVICE (device)), 0, 0, &error))
    {
      fpi_image_device_open_complete (device, g_steal_pointer (&error));
      return;
    }

  self->interface_claimed = TRUE;
  self->cancellable = g_cancellable_new ();
  fpi_image_device_open_complete (device, NULL);
}

static void
goodix5503_close (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);
  g_autoptr(GError) error = NULL;

  if (self->cancellable)
    g_cancellable_cancel (self->cancellable);
  g_clear_object (&self->cancellable);

  if (self->interface_claimed)
    {
      g_usb_device_release_interface (
        fpi_device_get_usb_device (FP_DEVICE (device)), 0, 0, &error);
      self->interface_claimed = FALSE;
    }
  fpi_image_device_close_complete (device, g_steal_pointer (&error));
}

static void
goodix5503_activate (FpImageDevice *device)
{
  /* Keep the explicit development build fail-closed until the bounded
   * activation/TLS state machine is connected. */
  fpi_image_device_activate_complete (
    device,
    fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                              "Goodix 5503 transport is not connected yet"));
}

static void
goodix5503_deactivate (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  if (self->cancellable)
    g_cancellable_cancel (self->cancellable);
  fpi_image_device_deactivate_complete (device, NULL);
}

static void
goodix5503_change_state (FpImageDevice *device,
                          FpiImageDeviceState state)
{
  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    fpi_image_device_session_error (
      device, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                        "Goodix 5503 capture is not connected yet"));
}

static const FpIdEntry goodix5503_id_table[] = {
  { .vid = 0x27c6, .pid = 0x5503 },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_goodix5503_init (FpiDeviceGoodix5503 *self)
{
  self->cancellable = NULL;
  self->interface_claimed = FALSE;
}

static void
fpi_device_goodix5503_class_init (FpiDeviceGoodix5503Class *klass)
{
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *image_class = FP_IMAGE_DEVICE_CLASS (klass);

  device_class->id = FP_COMPONENT;
  device_class->full_name = "Goodix GF3258 Milan 5503";
  device_class->type = FP_DEVICE_TYPE_USB;
  device_class->id_table = goodix5503_id_table;
  device_class->scan_type = FP_SCAN_TYPE_PRESS;

  image_class->img_width = GOODIX5503_IMAGE_WIDTH;
  image_class->img_height = GOODIX5503_IMAGE_HEIGHT;
  image_class->img_open = goodix5503_open;
  image_class->img_close = goodix5503_close;
  image_class->activate = goodix5503_activate;
  image_class->deactivate = goodix5503_deactivate;
  image_class->change_state = goodix5503_change_state;
}
