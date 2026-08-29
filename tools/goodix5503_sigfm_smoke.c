/* Memory-only SIGFM enrollment and same/different-finger validation. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include <fprint.h>
#include "fpi-image-device.h"
#include "fpi-image.h"
#include "goodix5503_sensitive.h"
#include "sigfm.hpp"

#define ENROLL_SAMPLES 8
#define MAX_CAPTURE_ATTEMPTS 16
#define MIN_KEYPOINTS 20
#define MATCH_THRESHOLD 150

typedef struct
{
  SigfmImgInfo *landscape;
  SigfmImgInfo *portrait;
} FeaturePair;

static gboolean expect_different_finger;

static void
wipe_buffer (void *buffer, size_t length)
{
  volatile unsigned char *cursor = buffer;

  while (length-- > 0)
    *cursor++ = 0;
}

static void
wipe_image (FpImage *image)
{
  if (image->data)
    wipe_buffer (image->data, image->width * image->height);
  if (image->binarized)
    wipe_buffer (image->binarized, image->width * image->height);
  if (image->minutiae)
    {
      g_ptr_array_set_free_func (image->minutiae, NULL);
      for (guint index = 0; index < image->minutiae->len; index++)
        {
          goodix5503_sensitive_minutia_free (
            g_ptr_array_index (image->minutiae, index));
        }
      g_clear_pointer (&image->minutiae, g_ptr_array_unref);
    }
}

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
feature_pair_free (FeaturePair *pair)
{
  if (pair == NULL)
    return;
  g_clear_pointer (&pair->landscape, sigfm_free_info);
  g_clear_pointer (&pair->portrait, sigfm_free_info);
  wipe_buffer (pair, sizeof *pair);
  g_free (pair);
}

static FeaturePair *
capture_features (FpDevice *device, GError **error)
{
  g_autoptr(FpImage) image = NULL;
  const guchar *data;
  gsize data_len = 0;
  FeaturePair *features = g_new0 (FeaturePair, 1);

  image = fp_device_capture_sync (device, TRUE, NULL, error);
  if (image == NULL)
    goto out;
  data = fp_image_get_data (image, &data_len);
  if (data == NULL || data_len != 80 * 64 ||
      fp_image_get_width (image) != 80 || fp_image_get_height (image) != 64)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "unexpected Goodix image dimensions");
      goto out;
    }
  features->landscape = sigfm_extract (data, 80, 64);
  features->portrait = sigfm_extract (data, 64, 80);
  if (features->landscape == NULL ||
      sigfm_keypoints_count (features->landscape) < MIN_KEYPOINTS)
    g_clear_pointer (&features->landscape, sigfm_free_info);
  if (features->portrait == NULL ||
      sigfm_keypoints_count (features->portrait) < MIN_KEYPOINTS)
    g_clear_pointer (&features->portrait, sigfm_free_info);

out:
  if (image)
    wipe_image (image);
  if (features->landscape == NULL && features->portrait == NULL)
    g_clear_pointer (&features, feature_pair_free);
  return features;
}

static gboolean
matches_any (FeaturePair *probe, FeaturePair **enrolled, GError **error)
{
  int best = 0;

  for (guint index = 0; index < ENROLL_SAMPLES; index++)
    {
      SigfmImgInfo *probe_orientations[] = {
        probe->landscape, probe->portrait,
      };
      SigfmImgInfo *enrolled_orientations[] = {
        enrolled[index]->landscape, enrolled[index]->portrait,
      };

      for (guint orientation = 0; orientation < 2; orientation++)
        {
          int score;

          if (probe_orientations[orientation] == NULL ||
              enrolled_orientations[orientation] == NULL)
            continue;
          score = sigfm_match_score (probe_orientations[orientation],
                                     enrolled_orientations[orientation]);
          if (score < 0)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                                   "SIGFM matching failed");
              return FALSE;
            }
          best = MAX (best, score);
        }
    }
  return best >= MATCH_THRESHOLD;
}

int
main (void)
{
  g_autoptr(FpContext) context = NULL;
  g_autoptr(FpDevice) device = NULL;
  g_autoptr(GError) error = NULL;
  FeaturePair *enrolled[ENROLL_SAMPLES] = { 0 };
  FeaturePair *probe = NULL;
  GPtrArray *devices;
  guint accepted = 0;
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
  if (device == NULL || !fp_device_open_sync (device, NULL, &error))
    {
      fputs ("Goodix 5503 development device open failed\n", stderr);
      goto out;
    }
  g_signal_connect (device, "notify::fpi-image-device-state",
                    G_CALLBACK (state_changed), NULL);
  puts ("KEEP FINGER OFF SENSOR DURING EACH CALIBRATION");
  fflush (stdout);

  for (guint attempt = 0;
       attempt < MAX_CAPTURE_ATTEMPTS && accepted < ENROLL_SAMPLES; attempt++)
    {
      g_clear_error (&error);
      enrolled[accepted] = capture_features (device, &error);
      if (enrolled[accepted] == NULL)
        {
          puts ("SIGFM ENROLLMENT SAMPLE RETRY REQUIRED");
          fflush (stdout);
          continue;
        }
      accepted++;
      puts ("SIGFM ENROLLMENT SAMPLE ACCEPTED");
      fflush (stdout);
    }
  if (accepted != ENROLL_SAMPLES)
    {
      fputs ("Goodix 5503 memory-only SIGFM enrollment failed\n", stderr);
      goto close;
    }
  puts ("MEMORY-ONLY SIGFM ENROLLMENT SUCCEEDED");
  fflush (stdout);

  for (guint attempt = 0; attempt < 3; attempt++)
    {
      gboolean matched;

      g_clear_error (&error);
      probe = capture_features (device, &error);
      if (probe == NULL)
        {
          puts ("SIGFM VERIFY SAMPLE RETRY REQUIRED");
          fflush (stdout);
          continue;
        }
      matched = matches_any (probe, enrolled, &error);
      g_clear_pointer (&probe, feature_pair_free);
      if (error)
        goto close;
      if (matched)
        {
          puts ("MEMORY-ONLY SIGFM SAME FINGER MATCHED");
          fflush (stdout);
          goto different_finger;
        }
      puts ("SIGFM SAME FINGER DID NOT MATCH");
      fflush (stdout);
    }
  fputs ("Goodix 5503 memory-only SIGFM same-finger verification failed\n",
         stderr);
  goto close;

different_finger:
  puts ("NEXT VERIFY MUST USE A DIFFERENT FINGER");
  fflush (stdout);
  expect_different_finger = TRUE;
  g_clear_error (&error);
  probe = capture_features (device, &error);
  if (probe == NULL)
    {
      fputs ("Goodix 5503 different-finger sample was unusable\n", stderr);
      goto close;
    }
  if (matches_any (probe, enrolled, &error))
    {
      fputs ("Goodix 5503 different finger unexpectedly matched\n", stderr);
      goto close;
    }
  if (error)
    goto close;
  puts ("MEMORY-ONLY SIGFM DIFFERENT FINGER REJECTED");
  fflush (stdout);
  status = 0;

close:
  g_clear_pointer (&probe, feature_pair_free);
  for (guint index = 0; index < ENROLL_SAMPLES; index++)
    g_clear_pointer (&enrolled[index], feature_pair_free);
  if (!fp_device_close_sync (device, NULL, NULL) && status == 0)
    status = 1;
out:
  return status;
}
