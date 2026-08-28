/* Memory-only libfprint/NBIS quality gate for one processed Goodix frame. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <gio/gio.h>
#include "fpi-image.h"

#define IMAGE_WIDTH 80
#define IMAGE_HEIGHT 64
#define IMAGE_LENGTH (IMAGE_WIDTH * IMAGE_HEIGHT)

typedef struct
{
  GMainLoop *loop;
  gboolean usable;
  GError *error;
} Detection;

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
    {
      fprintf (stderr, "failed to disable core dumps\n");
      _Exit (2);
    }
}

static gboolean
read_exact_frame (guint8 frame[IMAGE_LENGTH])
{
  size_t offset = 0;
  int extra;

  while (offset < IMAGE_LENGTH)
    {
      size_t count = fread (frame + offset, 1, IMAGE_LENGTH - offset, stdin);

      if (count == 0)
        {
          if (ferror (stdin) && errno == EINTR)
            {
              clearerr (stdin);
              continue;
            }
          return FALSE;
        }
      offset += count;
    }

  extra = fgetc (stdin);
  return extra == EOF && !ferror (stdin);
}

static void
minutiae_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  Detection *detection = user_data;

  detection->usable = fp_image_detect_minutiae_finish (
    FP_IMAGE (source), result, &detection->error);
  g_main_loop_quit (detection->loop);
}

int
main (void)
{
  guint8 frame[IMAGE_LENGTH];
  g_autoptr(FpImage) image = NULL;
  Detection detection = { 0 };
  const gdouble assumed_ppmm = 500.0 / 25.4;
  int status = 1;

  disable_core_dumps ();
  if (!read_exact_frame (frame))
    {
      fprintf (stderr, "expected exactly %u image bytes on stdin\n",
               IMAGE_LENGTH);
      goto out;
    }

  image = fp_image_new (IMAGE_WIDTH, IMAGE_HEIGHT);
  image->ppmm = assumed_ppmm;
  memcpy (image->data, frame, IMAGE_LENGTH);
  wipe_buffer (frame, sizeof frame);

  detection.loop = g_main_loop_new (NULL, FALSE);
  fp_image_detect_minutiae (image, NULL, minutiae_done, &detection);
  g_main_loop_run (detection.loop);

  /* The caller needs only a category, never a minutiae count or image metric. */
  puts (detection.usable ? "usable" : "unusable");
  status = 0;

out:
  wipe_buffer (frame, sizeof frame);
  if (image)
    {
      wipe_buffer (image->data, IMAGE_LENGTH);
      if (image->binarized)
        wipe_buffer (image->binarized, IMAGE_LENGTH);
    }
  g_clear_error (&detection.error);
  g_clear_pointer (&detection.loop, g_main_loop_unref);
  return status;
}
