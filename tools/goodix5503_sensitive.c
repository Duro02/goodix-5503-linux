/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix5503_sensitive.h"

#include <glib.h>

#include "fpi-minutiae.h"

#define NBIS_MAX_NEIGHBORS 5

static void
wipe_buffer (void *buffer, gsize length)
{
  volatile guint8 *cursor = buffer;

  while (length-- > 0)
    *cursor++ = 0;
}

void
goodix5503_sensitive_minutia_free (struct fp_minutia *minutia)
{
  gsize ridge_count = 0;

  if (minutia == NULL)
    return;
  if (minutia->num_nbrs >= 0 && minutia->num_nbrs <= NBIS_MAX_NEIGHBORS)
    ridge_count = minutia->num_nbrs;
  if (minutia->nbrs)
    {
      wipe_buffer (minutia->nbrs,
                   NBIS_MAX_NEIGHBORS * sizeof *minutia->nbrs);
      g_clear_pointer (&minutia->nbrs, g_free);
    }
  if (minutia->ridge_counts)
    {
      wipe_buffer (minutia->ridge_counts,
                   ridge_count * sizeof *minutia->ridge_counts);
      g_clear_pointer (&minutia->ridge_counts, g_free);
    }
  wipe_buffer (minutia, sizeof *minutia);
  g_free (minutia);
}
