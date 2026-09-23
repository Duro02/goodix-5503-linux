/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "sigfm.hpp"

#include <stdlib.h>

SigfmImgInfo *sigfm_extract (const SigfmPix *pix, int width, int height)
{
  (void) pix; (void) width; (void) height; return NULL;
}
void sigfm_free_info (SigfmImgInfo *info) { (void) info; }
int sigfm_match_score (SigfmImgInfo *frame, SigfmImgInfo *enrolled)
{
  (void) frame; (void) enrolled; return -1;
}
int sigfm_is_redundant (SigfmImgInfo *frame, SigfmImgInfo *enrolled,
                        int identity_threshold)
{
  (void) frame; (void) enrolled; (void) identity_threshold; return -1;
}
int sigfm_keypoints_count (SigfmImgInfo *info) { (void) info; return 0; }
SigfmImgInfo *sigfm_copy_info (const SigfmImgInfo *info)
{
  (void) info; return NULL;
}
unsigned char *sigfm_serialize (const SigfmImgInfo *info, size_t *length)
{
  (void) info; if (length) *length = 0; return NULL;
}
SigfmImgInfo *sigfm_deserialize (const unsigned char *data, size_t length)
{
  (void) data; (void) length; return NULL;
}
void sigfm_free_serialized (unsigned char *data, size_t length)
{
  volatile unsigned char *cursor = data;
  while (data && length-- > 0) *cursor++ = 0;
  free (data);
}
int sigfm_equal (const SigfmImgInfo *left, const SigfmImgInfo *right)
{
  return left == right;
}
int sigfm_select_enrollment (SigfmImgInfo *const *samples, size_t count,
                             int threshold, unsigned *indices, size_t capacity)
{
  (void) samples; (void) count; (void) threshold;
  (void) indices; (void) capacity; return -1;
}
