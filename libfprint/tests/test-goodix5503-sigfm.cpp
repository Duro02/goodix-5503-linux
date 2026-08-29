// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sigfm.hpp"

#include <array>
#include <cassert>

int
main ()
{
  std::array<SigfmPix, 64> flat = { 0 };
  SigfmImgInfo *info;

  assert (sigfm_keypoints_count (nullptr) == 0);
  assert (sigfm_extract (nullptr, 8, 8) == nullptr);
  assert (sigfm_extract (flat.data (), 0, 8) == nullptr);
  assert (sigfm_extract (flat.data (), 8, -1) == nullptr);
  assert (sigfm_match_score (nullptr, nullptr) == 0);

  info = sigfm_extract (flat.data (), 8, 8);
  assert (info != nullptr);
  assert (sigfm_keypoints_count (info) == 0);
  assert (sigfm_match_score (info, info) == 0);
  sigfm_free_info (info);
  return 0;
}
