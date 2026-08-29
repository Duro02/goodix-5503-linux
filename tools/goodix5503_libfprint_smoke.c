/* Memory-only capture/enroll smoke tests for the development libfprint driver. */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef GOODIX5503_REQUIRE_INSTALLED_LIBFPRINT
#include <dlfcn.h>
#include <limits.h>
#endif
#include <sys/prctl.h>
#include <sys/resource.h>

#include <fprint.h>
#ifndef GOODIX5503_REQUIRE_INSTALLED_LIBFPRINT
#include "fpi-image-device.h"
#else
typedef enum
{
  FPI_IMAGE_DEVICE_STATE_INACTIVE,
  FPI_IMAGE_DEVICE_STATE_ACTIVATING,
  FPI_IMAGE_DEVICE_STATE_DEACTIVATING,
  FPI_IMAGE_DEVICE_STATE_IDLE,
  FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON,
  FPI_IMAGE_DEVICE_STATE_CAPTURE,
  FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF,
} FpiImageDeviceState;
#endif

static gboolean expect_different_finger;

#ifdef GOODIX5503_REQUIRE_INSTALLED_LIBFPRINT
static void
require_installed_libfprint (void)
{
  const char expected[] = "/usr/lib/libfprint-2.so.2.0.0";
  char resolved[PATH_MAX];
  Dl_info info;
  void *symbol;

  symbol = dlsym (RTLD_DEFAULT, "fp_context_new");
  if (symbol == NULL || dladdr (symbol, &info) == 0 || info.dli_fname == NULL ||
      realpath (info.dli_fname, resolved) == NULL ||
      strcmp (resolved, expected) != 0)
    {
      fputs ("Installed libfprint validation refused non-/usr library\n", stderr);
      _Exit (2);
    }
}
#endif

static void
disable_core_dumps (void)
{
  const struct rlimit limit = { 0, 0 };

  if (setrlimit (RLIMIT_CORE, &limit) != 0 ||
      prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
      prctl (PR_GET_DUMPABLE, 0, 0, 0, 0) != 0)
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
      puts (expect_different_finger
              ? "PLACE A DIFFERENT FINGER ON SENSOR NOW"
              : "PLACE FINGER ON SENSOR NOW");
      fflush (stdout);
    }
  else if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF)
    {
      puts ("REMOVE FINGER NOW");
      fflush (stdout);
    }
}

static void
enroll_progress (FpDevice *device, gint completed_stages, FpPrint *print,
                 gpointer user_data, GError *error)
{
  (void) device;
  (void) completed_stages;
  (void) print;
  (void) user_data;
  puts (error ? "ENROLLMENT SAMPLE RETRY REQUIRED"
              : "ENROLLMENT SAMPLE ACCEPTED");
  fflush (stdout);
}

int
main (int argc, char **argv)
{
  g_autoptr(FpContext) context = NULL;
  g_autoptr(FpDevice) device = NULL;
  g_autoptr(FpImage) image = NULL;
  g_autoptr(FpPrint) template_print = NULL;
  g_autoptr(FpPrint) enrolled_print = NULL;
  g_autoptr(FpPrint) verify_print = NULL;
  g_autoptr(GError) error = NULL;
  GPtrArray *devices;
  gboolean enroll_verify = FALSE;
  gboolean match = FALSE;
  int status = 1;

  if (argc == 2 && g_strcmp0 (argv[1], "--enroll-verify") == 0)
    enroll_verify = TRUE;
#ifdef GOODIX5503_REQUIRE_INSTALLED_LIBFPRINT
  else if (argc == 2 &&
           g_strcmp0 (argv[1], "--check-installed-library") == 0)
    {
      disable_core_dumps ();
      require_installed_libfprint ();
      puts ("INSTALLED LIBFPRINT PATH VERIFIED");
      return 0;
    }
#endif
  else if (argc != 1)
    {
      fprintf (stderr,
               "usage: %s [--enroll-verify|--check-installed-library]\n",
               argv[0]);
      return 2;
    }

  disable_core_dumps ();
#ifdef GOODIX5503_REQUIRE_INSTALLED_LIBFPRINT
  require_installed_libfprint ();
#endif
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
  if (enroll_verify)
    {
      template_print = fp_print_new (device);
      fp_print_set_finger (template_print, FP_FINGER_LEFT_INDEX);
      enrolled_print = fp_device_enroll_sync (
        device, g_steal_pointer (&template_print), NULL,
        enroll_progress, NULL, &error);
      if (enrolled_print == NULL)
        {
          fprintf (stderr, "Goodix 5503 memory-only enrollment failed: %s\n",
                   error ? error->message : "unknown error");
          goto close;
        }
      puts ("LIBFPRINT MEMORY-ONLY ENROLLMENT SUCCEEDED");
      fflush (stdout);
      for (guint attempt = 0; attempt < 3 && !match; attempt++)
        {
          g_clear_object (&verify_print);
          g_clear_error (&error);
          if (!fp_device_verify_sync (device, enrolled_print, NULL, NULL, NULL,
                                      &match, &verify_print, &error))
            {
              if (error && error->domain == FP_DEVICE_RETRY)
                {
                  puts ("VERIFY SAMPLE RETRY REQUIRED");
                  fflush (stdout);
                  continue;
                }
              fprintf (stderr,
                       "Goodix 5503 memory-only verification operation failed\n");
              goto close;
            }
          if (!match)
            {
              puts ("VERIFY DID NOT MATCH");
              fflush (stdout);
            }
        }
      if (!match)
        {
          fprintf (stderr,
                   "Goodix 5503 memory-only verification did not match\n");
          goto close;
        }
      puts ("LIBFPRINT MEMORY-ONLY VERIFY MATCHED");
      puts ("NEXT VERIFY MUST USE A DIFFERENT FINGER");
      fflush (stdout);
      expect_different_finger = TRUE;
      match = FALSE;
      g_clear_object (&verify_print);
      g_clear_error (&error);
      if (!fp_device_verify_sync (device, enrolled_print, NULL, NULL, NULL,
                                  &match, &verify_print, &error))
        {
          fprintf (stderr,
                   "Goodix 5503 different-finger verification failed\n");
          goto close;
        }
      if (match)
        {
          fprintf (stderr,
                   "Goodix 5503 different finger unexpectedly matched\n");
          goto close;
        }
      puts ("LIBFPRINT MEMORY-ONLY DIFFERENT FINGER REJECTED");
      fflush (stdout);
      status = 0;
    }
  else
    {
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
    }

close:
  g_clear_object (&image);
  g_clear_object (&verify_print);
  g_clear_object (&enrolled_print);
  g_clear_object (&template_print);
  if (!fp_device_close_sync (device, NULL, NULL) && status == 0)
    status = 1;
out:
  return status;
}
