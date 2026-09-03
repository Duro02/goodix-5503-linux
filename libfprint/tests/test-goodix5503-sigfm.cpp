// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sigfm.hpp"

#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <unistd.h>

static std::string
capture_null_match_stderr ()
{
  FILE *capture = tmpfile ();
  assert (capture != nullptr);
  fflush (stderr);
  int saved_stderr = dup (STDERR_FILENO);
  assert (saved_stderr >= 0);
  assert (dup2 (fileno (capture), STDERR_FILENO) >= 0);
  assert (sigfm_match_score (nullptr, nullptr) == 0);
  fflush (stderr);
  assert (dup2 (saved_stderr, STDERR_FILENO) >= 0);
  close (saved_stderr);

  assert (fseek (capture, 0, SEEK_END) == 0);
  long length = ftell (capture);
  assert (length >= 0);
  assert (fseek (capture, 0, SEEK_SET) == 0);
  std::string output (static_cast<std::size_t> (length), '\0');
  if (!output.empty ())
    assert (fread (output.data (), 1, output.size (), capture) == output.size ());
  fclose (capture);
  return output;
}

static std::vector<SigfmPix>
synthetic_pattern ()
{
  std::vector<SigfmPix> image (80 * 64);
  for (int y = 0; y < 64; y++)
    for (int x = 0; x < 80; x++)
      image[y * 80 + x] = static_cast<SigfmPix> (
        ((x / 5 + y / 5) & 1) ? 220 : ((x * 17 + y * 29) & 63));
  return image;
}

int
main ()
{
  std::array<SigfmPix, 64> flat{};
  auto pattern = synthetic_pattern ();
  SigfmImgInfo *info;
  SigfmImgInfo *copy;
  SigfmImgInfo *roundtrip;
  unsigned char *serialized;
  size_t length = 0;

  assert (sigfm_keypoints_count (nullptr) == 0);
  assert (sigfm_extract (nullptr, 8, 8) == nullptr);
  assert (sigfm_extract (flat.data (), 0, 8) == nullptr);
  assert (sigfm_extract (flat.data (), 8, -1) == nullptr);
  unsetenv ("GOODIX5503_SIGFM_DEBUG");
  assert (capture_null_match_stderr ().empty ());
  assert (setenv ("GOODIX5503_SIGFM_DEBUG", "1", 1) == 0);
  assert (capture_null_match_stderr ().find ("SIGFM features") !=
          std::string::npos);
  unsetenv ("GOODIX5503_SIGFM_DEBUG");

  info = sigfm_extract (flat.data (), 8, 8);
  assert (info != nullptr);
  assert (sigfm_keypoints_count (info) == 0);
  assert (sigfm_match_score (info, info) == 0);
  assert (sigfm_serialize (info, &length) == nullptr);
  sigfm_free_info (info);

  info = sigfm_extract (pattern.data (), 80, 64);
  assert (info != nullptr);
  assert (sigfm_keypoints_count (info) > 0);
  assert (sigfm_keypoints_count (info) <= 512);
  copy = sigfm_copy_info (info);
  assert (copy != nullptr && sigfm_equal (info, copy));
  serialized = sigfm_serialize (info, &length);
  assert (serialized != nullptr && length > 20 && length <= 1024 * 1024);
  roundtrip = sigfm_deserialize (serialized, length);
  assert (roundtrip != nullptr && sigfm_equal (info, roundtrip));

  std::vector<unsigned char> corrupt (serialized, serialized + length);
  const size_t offsets[] = { 0, 4, 6, 8, 12, 14, 16 };
  for (size_t offset : offsets)
    {
      corrupt[offset] ^= 0x80;
      assert (sigfm_deserialize (corrupt.data (), corrupt.size ()) == nullptr);
      corrupt[offset] ^= 0x80;
    }
  const size_t truncations[] = { 1, 4, 6, 8, 12, 16, 19, 20, length - 1 };
  for (size_t truncated : truncations)
    assert (sigfm_deserialize (serialized, truncated) == nullptr);
  corrupt.push_back (0);
  assert (sigfm_deserialize (corrupt.data (), corrupt.size ()) == nullptr);

  corrupt.assign (serialized, serialized + length);
  const std::uint32_t extreme_coordinates[] = {
    0x7f7fffffU, /* FLT_MAX */
    0xff7fffffU, /* -FLT_MAX */
  };
  for (std::uint32_t bits : extreme_coordinates)
    {
      corrupt[20] = static_cast<unsigned char> (bits);
      corrupt[21] = static_cast<unsigned char> (bits >> 8);
      corrupt[22] = static_cast<unsigned char> (bits >> 16);
      corrupt[23] = static_cast<unsigned char> (bits >> 24);
      assert (sigfm_deserialize (corrupt.data (), corrupt.size ()) == nullptr);
    }

  sigfm_free_serialized (serialized, length);
  sigfm_free_info (roundtrip);
  sigfm_free_info (copy);
  sigfm_free_info (info);
  return 0;
}
