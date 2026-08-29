/* Memory-only first-capture smoke test for the development libfprint driver. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <fprint.h>
#include "fpi-image-device.h"

static void
wipe_buffer (void *buffer, size_t length)
{
  volatile unsigned char *cursor = buffer;

  while (length-- > 0)
    *cursor++ = 0;
}

static void
disable_core_dumps (void)
{
  const struct rlimit limit = { 0, 0 };

  if (setrlimit (RLIMIT_CORE, &limit) != 0)
    _Exit (2);
}

static void
state_changed (GObject *object, GParamSpec *spec, gpointer user_data)
{
  FpiImageDeviceState state;

  (void) spec;
  (void) user_data;
  g_object_get (object, "fpi-image-device-state", &state, NULL);
  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    {
      puts ("PLACE FINGER ON SENSOR NOW");
      fflush (stdout);
    }
  else if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF)
    {
      puts ("REMOVE FINGER NOW");
      fflush (stdout);
    }
}

int
main (void)
{
  g_autoptr(FpContext) context = NULL;
  g_autoptr(FpDevice) device = NULL;
  g_autoptr(FpImage) image = NULL;
  g_autoptr(GError) error = NULL;
  GPtrArray *devices;
  const guchar *data;
  const guchar *binarized;
  gsize data_len = 0;
  gsize binarized_len = 0;
  int status = 1;

  disable_core_dumps ();
  context = fp_context_new ();
  devices = fp_context_get_devices (context);
  for (guint index = 0; index < devices->len; index++)
    {
      FpDevice *candidate = g_ptr_array_index (devices, index);

      if (g_strcmp0 (fp_device_get_driver (candidate), "goodix5503") == 0)
        {
          device = g_object_ref (candidate);
          break;
        }
    }
  if (device == NULL)
    {
      fprintf (stderr, "Goodix 5503 development device was not found\n");
      goto out;
    }
  g_signal_connect (device, "notify::fpi-image-device-state",
                    G_CALLBACK (state_changed), NULL);
  if (!fp_device_open_sync (device, NULL, &error))
    {
      fprintf (stderr, "Goodix 5503 open failed\n");
      goto out;
    }

  puts ("KEEP FINGER OFF SENSOR DURING CALIBRATION");
  fflush (stdout);
  image = fp_device_capture_sync (device, TRUE, NULL, &error);
  if (image == NULL)
    {
      fprintf (stderr, "Goodix 5503 memory-only capture failed: %s\n",
               error ? error->message : "unknown bounded runtime error");
      goto close;
    }
  puts ("LIBFPRINT MEMORY-ONLY CAPTURE SUCCEEDED");
  fflush (stdout);
  status = 0;

close:
  data = image ? fp_image_get_data (image, &data_len) : NULL;
  if (data)
    wipe_buffer ((gpointer) data, data_len);
  binarized = image ? fp_image_get_binarized (image, &binarized_len) : NULL;
  if (binarized)
    wipe_buffer ((gpointer) binarized, binarized_len);
  g_clear_object (&image);
  if (!fp_device_close_sync (device, NULL, NULL) && status == 0)
    status = 1;
out:
  return status;
}
