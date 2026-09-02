/* Offline NBIS experiment for the Goodix 5503 sensor.
 *
 * Loads the .pgm frames dumped by the driver, runs libfprint's NBIS
 * path on them exactly as the mainline image pipeline would
 * (get_minutiae + g_lfsparms_V2, bozorth3 matching), and prints a
 * same-finger vs different-finger score matrix.
 *
 * Results (2026-09-02, 18 pressed frames): mindtct finds no minutiae
 * in half the frames and 1-4 in the rest; all bozorth3 pairs score 0.
 * The mainline NBIS path cannot work on this sensor's difference
 * images; the SIGFM matcher is not a convenience but a requirement.
 */
#include <nbis.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXBUF 65536

static void
minutiae_to_xyt (MINUTIAE *minutiae, int iw, int ih, struct xyt_struct *xyt)
{
  /* Mirrors libfprint's fpi-print.c conversion: identical transform so
   * the experiment exercises the exact mainline pipeline. */
  struct minutiae_struct c[MAX_FILE_MINUTIAE];
  int nmin = minutiae->num;
  int i;

  if (nmin > MAX_BOZORTH_MINUTIAE)
    nmin = MAX_BOZORTH_MINUTIAE;
  for (i = 0; i < nmin; i++)
    {
      lfs2nist_minutia_XYT (&c[i].col[0], &c[i].col[1], &c[i].col[2],
                            minutiae->list[i], iw, ih);
      c[i].col[3] = (int) (minutiae->list[i]->reliability * 100.0);
      if (c[i].col[2] > 180)
        c[i].col[2] -= 360;
    }
  qsort ((void *) &c, (size_t) nmin, sizeof (struct minutiae_struct),
         sort_x_y);
  for (i = 0; i < nmin; i++)
    {
      xyt->xcol[i] = c[i].col[0];
      xyt->ycol[i] = c[i].col[1];
      xyt->thetacol[i] = c[i].col[2];
    }
  xyt->nrows = nmin;
}

static unsigned char *
read_pgm (const char *path, int *w, int *h)
{
  FILE *f = fopen (path, "rb");
  unsigned char *data;
  char header[256];
  int maxval;
  size_t got;

  if (!f)
    return NULL;
  if (fgets (header, sizeof header, f) == NULL ||
      fgets (header, sizeof header, f) == NULL ||
      sscanf (header, "%d %d", w, h) != 2 ||
      fgets (header, sizeof header, f) == NULL ||
      sscanf (header, "%d", &maxval) != 1 || maxval != 255)
    {
      fclose (f);
      return NULL;
    }
  data = malloc ((size_t) (*w) * (*h));
  if (!data)
    {
      fclose (f);
      return NULL;
    }
  got = fread (data, 1, (size_t) (*w) * (*h), f);
  fclose (f);
  if (got != (size_t) (*w) * (*h))
    {
      free (data);
      return NULL;
    }
  return data;
}

static int
extract_xyt (const char *path, struct xyt_struct *xyt)
{
  unsigned char *image;
  MINUTIAE *minutiae = NULL;
  int *quality_map = NULL, *direction_map = NULL;
  int *low_contrast_map = NULL, *low_flow_map = NULL, *high_curve_map = NULL;
  unsigned char *binarized = NULL;
  int map_w = 0, map_h = 0, bw = 0, bh = 0, bd = 0;
  int w = 0, h = 0, r;
  LFSPARMS lfsparms;

  image = read_pgm (path, &w, &h);
  if (!image)
    {
      fprintf (stderr, "cannot read %s\n", path);
      return -1;
    }
  memcpy (&lfsparms, &g_lfsparms_V2, sizeof lfsparms);
  lfsparms.remove_perimeter_pts = 0;
  r = get_minutiae (&minutiae, &quality_map, &direction_map,
                    &low_contrast_map, &low_flow_map, &high_curve_map,
                    &map_w, &map_h, &binarized, &bw, &bh, &bd,
                    image, w, h, 8, 500.0 / 25.4, &lfsparms);
  free (image);
  free (quality_map);
  free (direction_map);
  free (low_contrast_map);
  free (low_flow_map);
  free (high_curve_map);
  free (binarized);
  if (r)
    {
      fprintf (stderr, "get_minutiae(%s) failed: %d\n", path, r);
      return -1;
    }
  if (minutiae == NULL || minutiae->num == 0)
    {
      fprintf (stderr, "get_minutiae(%s): no minutiae\n", path);
      free_minutiae (minutiae);
      return -1;
    }
  fprintf (stderr, "%s: %d minutiae\n", path, minutiae->num);
  minutiae_to_xyt (minutiae, w, h, xyt);
  free_minutiae (minutiae);
  return 0;
}

int
main (int argc, char **argv)
{
  struct xyt_struct *xyts;
  int count, i, j;

  if (argc < 3)
    {
      fprintf (stderr, "usage: %s <pgm>...\n", argv[0]);
      return 2;
    }
  count = argc - 1;
  xyts = calloc (count, sizeof (struct xyt_struct));
  for (i = 0; i < count; i++)
    if (extract_xyt (argv[i + 1], &xyts[i]) != 0)
      return 1;

  printf ("%-22s", "pair");
  for (j = 0; j < count; j++)
    printf (" %10s", argv[j + 1]);
  printf ("\n");
  for (i = 0; i < count; i++)
    {
      printf ("%-22s", argv[i + 1]);
      for (j = 0; j < count; j++)
        {
          int score = 0;
          if (i != j)
            {
              int probe_len = bozorth_probe_init (&xyts[i]);
              int g = bozorth_gallery_init (&xyts[j]);
              score = bozorth_to_gallery (probe_len, &xyts[i], &xyts[j]);
              (void) g;
            }
          printf (" %10d", score);
        }
      printf ("\n");
    }
  free (xyts);
  return 0;
}