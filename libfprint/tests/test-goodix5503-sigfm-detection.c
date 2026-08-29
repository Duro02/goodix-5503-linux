/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <glib.h>
#include <math.h>

#include "fpi-image.h"

typedef enum
{
  DETECT_NBIS,
  DETECT_SIGFM,
} DetectKind;

typedef struct
{
  GMainLoop *loop;
  guint pending;
  guint busy;
  guint cancelled;
} TestState;

typedef struct
{
  TestState *state;
  DetectKind kind;
  gboolean owner;
} Request;

static void
detected (GObject *source, GAsyncResult *result, gpointer user_data)
{
  Request *request = user_data;
  g_autoptr(GError) error = NULL;
  gboolean success;

  if (request->kind == DETECT_SIGFM)
    success = fpi_image_detect_sigfm_finish (FP_IMAGE (source), result, &error);
  else
    success = fp_image_detect_minutiae_finish (FP_IMAGE (source), result, &error);
  if (!success && g_error_matches (error, G_IO_ERROR,
                                   G_IO_ERROR_ADDRESS_IN_USE))
    request->state->busy++;
  if (!success && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    request->state->cancelled++;
  if (!request->owner)
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_ADDRESS_IN_USE);
  else
    g_assert_false (g_error_matches (error, G_IO_ERROR,
                                     G_IO_ERROR_ADDRESS_IN_USE));
  request->state->pending--;
  if (request->state->pending == 0)
    g_main_loop_quit (request->state->loop);
  g_free (request);
}

static void
start_request (FpImage *image, GCancellable *cancellable, DetectKind kind,
               gboolean owner, TestState *state)
{
  Request *request = g_new0 (Request, 1);

  request->state = state;
  request->kind = kind;
  request->owner = owner;
  state->pending++;
  if (kind == DETECT_SIGFM)
    fpi_image_detect_sigfm (image, cancellable, detected, request);
  else
    fp_image_detect_minutiae (image, cancellable, detected, request);
}

static void
nbis_detected (GObject *source, GAsyncResult *result, gpointer user_data)
{
  GMainLoop *loop = user_data;
  g_autoptr(GError) error = NULL;

  g_assert_true (fp_image_detect_minutiae_finish (FP_IMAGE (source), result,
                                                   &error));
  g_assert_no_error (error);
  g_main_loop_quit (loop);
}

static FpImage *
new_nbis_pattern (void)
{
  FpImage *image = fp_image_new (256, 256);

  image->ppmm = 500.0 / 25.4;
  for (guint y = 0; y < image->height; y++)
    for (guint x = 0; x < image->width; x++)
      {
        double dx = (double) x - 128.0;
        double dy = (double) y - 150.0;
        double radius = sqrt (dx * dx + dy * dy);
        double angle = atan2 (dy, dx);
        double ridge = sin (radius * 0.55 + sin (angle * 2.0) * 6.0);
        gboolean inside = dx * dx / (112.0 * 112.0) +
                          dy * dy / (132.0 * 132.0) < 1.0;

        image->data[y * image->width + x] =
          inside ? (ridge > 0.0 ? 35 : 225) : 255;
      }
  return image;
}

static void
run_nbis_lifecycle (void)
{
  g_autoptr(FpImage) image = new_nbis_pattern ();
  for (guint pass = 0; pass < 2; pass++)
    {
      GMainLoop *loop = g_main_loop_new (NULL, FALSE);

      fp_image_detect_minutiae (image, NULL, nbis_detected, loop);
      g_main_loop_run (loop);
      g_main_loop_unref (loop);
      g_assert_nonnull (fp_image_get_minutiae (image));
      g_assert_cmpuint (fp_image_get_minutiae (image)->len, >, 0);
      /* A second successful pass replaces and securely releases the first
       * result before the image finalizer releases the replacement. */
    }
}

static FpImage *
new_pattern (void)
{
  FpImage *image = fp_image_new (80, 64);

  image->ppmm = 500.0 / 25.4;
  for (guint y = 0; y < image->height; y++)
    for (guint x = 0; x < image->width; x++)
      image->data[y * image->width + x] =
        ((x / 5 + y / 5) & 1) ? 220 : ((x * 17 + y * 29) & 63);
  return image;
}

static void
run_overlap (DetectKind owner_kind, DetectKind rejected_kind)
{
  g_autoptr(FpImage) image = new_pattern ();
  g_autoptr(GCancellable) cancellable = g_cancellable_new ();
  TestState state = { g_main_loop_new (NULL, FALSE), 0, 0, 0 };

  start_request (image, cancellable, owner_kind, TRUE, &state);
  start_request (image, NULL, rejected_kind, FALSE, &state);
  g_cancellable_cancel (cancellable);
  g_main_loop_run (state.loop);
  g_assert_cmpuint (state.busy, ==, 1);
  g_assert_cmpuint (state.cancelled, ==, 1);
  g_main_loop_unref (state.loop);

  state = (TestState) { g_main_loop_new (NULL, FALSE), 0, 0, 0 };
  g_clear_object (&cancellable);
  cancellable = g_cancellable_new ();
  start_request (image, cancellable, DETECT_SIGFM, TRUE, &state);
  g_cancellable_cancel (cancellable);
  g_main_loop_run (state.loop);
  g_assert_cmpuint (state.busy, ==, 0);
  g_assert_cmpuint (state.cancelled, ==, 1);
  g_main_loop_unref (state.loop);
}

int
main (void)
{
  run_overlap (DETECT_SIGFM, DETECT_SIGFM);
  run_overlap (DETECT_NBIS, DETECT_SIGFM);
  run_nbis_lifecycle ();
  return 0;
}
