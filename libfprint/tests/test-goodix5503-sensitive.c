/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <glib.h>

#include "fpi-minutiae.h"
#include "goodix5503_sensitive.h"

int
main (void)
{
  for (gint neighbors = 1; neighbors < 5; neighbors++)
    {
      struct fp_minutia *minutia = g_new0 (struct fp_minutia, 1);

      minutia->num_nbrs = neighbors;
      minutia->nbrs = g_new (gint, 5);
      minutia->ridge_counts = g_new (gint, neighbors);
      memset (minutia->nbrs, 0x5a, 5 * sizeof *minutia->nbrs);
      memset (minutia->ridge_counts, 0xa5,
              neighbors * sizeof *minutia->ridge_counts);
      goodix5503_sensitive_minutia_free (minutia);
    }
  return 0;
}
