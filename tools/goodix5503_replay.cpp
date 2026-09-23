/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Read-only replay against an explicitly supplied local SIGFM gallery.
 * Usage: goodix5503-replay TEMPLATE MANIFEST [REFERENCE_MANIFEST]
 * Manifest: one GROUP<TAB>/absolute/frame.pgm per line.
 * The optional reference manifest supplies 8 to 24 supervised enrollment
 * images for a second, fixed gallery. It must not contain evaluation presses
 * or other frames from the same presses. Neither gallery is updated here.
 * Output contains biometric statistics; keep it in a private local directory.
 * No device access, template updates, or changes to authentication thresholds.
 */
#include "sigfm.hpp"

#include <openssl/crypto.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <opencv2/core.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

/* NBIS has legacy macros that collide with OpenCV enum names. */
extern "C" {
#include "fp-print-private.h"
#include "goodix5503-proto.h"
}

struct SensitiveBytes
{
  std::vector<unsigned char> data;
  ~SensitiveBytes () { OPENSSL_cleanse (data.data (), data.size ()); }
};

static bool
read_template (const char *path, SensitiveBytes& bytes)
{
  std::ifstream file (path, std::ios::binary | std::ios::ate);
  if (!file)
    return false;
  auto length = file.tellg ();
  if (length <= 0 || length > 32 * 1024 * 1024)
    return false;
  bytes.data.resize (static_cast<std::size_t> (length));
  file.seekg (0);
  return static_cast<bool> (file.read (
    reinterpret_cast<char *> (bytes.data.data ()), bytes.data.size ()));
}

static bool
read_pgm (const std::string& path, SensitiveBytes& pixels)
{
  std::ifstream file (path, std::ios::binary);
  std::string magic;
  int width = 0, height = 0, maximum = 0;
  if (!(file >> magic >> width >> height >> maximum) || magic != "P5" ||
      width != GOODIX5503_SIGFM_IMAGE_WIDTH ||
      height != GOODIX5503_SIGFM_IMAGE_HEIGHT || maximum != 255 ||
      file.get () != '\n')
    return false;
  pixels.data.resize (GOODIX5503_PIXEL_COUNT);
  if (!file.read (reinterpret_cast<char *> (pixels.data.data ()), pixels.data.size ()))
    return false;
  return file.peek () == std::char_traits<char>::eof ();
}

int
main (int argc, char **argv)
{
  if (argc != 3 && argc != 4)
    {
      std::cerr << "Usage: goodix5503-replay TEMPLATE MANIFEST [REFERENCE_MANIFEST]\n";
      return 2;
    }
  struct rlimit core = { 0, 0 };
  if (setrlimit (RLIMIT_CORE, &core) != 0 ||
      prctl (PR_SET_DUMPABLE, 0) != 0 || prctl (PR_GET_DUMPABLE) != 0)
    return 2;
  cv::setNumThreads (1);
  unsetenv ("GOODIX5503_SIGFM_DEBUG");

  SensitiveBytes serialized;
  if (!read_template (argv[1], serialized))
    {
      std::cerr << "Cannot read bounded template file\n";
      return 2;
    }
  g_autoptr(GError) error = nullptr;
  g_autoptr(FpPrint) gallery = fp_print_deserialize (
    serialized.data.data (), serialized.data.size (), &error);
  if (gallery == nullptr || gallery->type != FPI_PRINT_SIGFM ||
      g_strcmp0 (gallery->driver, "goodix5503") != 0 ||
      gallery->prints == nullptr || gallery->prints->len < 8 ||
      gallery->prints->len > 24)
    {
      std::cerr << "Not a supported Goodix SIGFM gallery\n";
      return 2;
    }
  using Info = std::unique_ptr<SigfmImgInfo, decltype (&sigfm_free_info)>;
  std::vector<Info> references;
  if (argc == 4)
    {
      std::ifstream input (argv[3]);
      if (!input)
        return 2;
      std::string line;
      while (std::getline (input, line))
        {
          auto tab = line.find ('\t');
          SensitiveBytes pixels;
          if (references.size () >= 24 || tab == std::string::npos ||
              line.find ('\t', tab + 1) != std::string::npos ||
              !read_pgm (line.substr (tab + 1), pixels))
            return 2;
          Info info (sigfm_extract (pixels.data.data (),
                                   GOODIX5503_SIGFM_IMAGE_WIDTH,
                                   GOODIX5503_SIGFM_IMAGE_HEIGHT), sigfm_free_info);
          if (!info || sigfm_keypoints_count (info.get ()) < 20)
            return 2;
          references.push_back (std::move (info));
        }
      if (input.bad () || references.size () < 8)
        return 2;
    }
  std::ifstream manifest (argv[2]);
  if (!manifest)
    return 2;
  std::cout << "group\timage\tkeypoints\tmax_score\tbest_sample";
  if (argc == 4)
    std::cout << "\treference_score\tbest_reference";
  std::cout << '\n';
  std::string line;
  while (std::getline (manifest, line))
    {
      auto tab = line.find ('\t');
      if (tab == std::string::npos || line.find ('\t', tab + 1) != std::string::npos)
        return 2;
      auto path = line.substr (tab + 1);
      SensitiveBytes pixels;
      if (!read_pgm (path, pixels))
        {
          std::cerr << "Invalid or unavailable 64x80 PGM in manifest\n";
          return 2;
        }
      Info probe (
        sigfm_extract (pixels.data.data (), GOODIX5503_SIGFM_IMAGE_WIDTH,
                        GOODIX5503_SIGFM_IMAGE_HEIGHT), sigfm_free_info);
      if (!probe)
        return 2;
      int maximum = 0;
      guint best = 0;
      for (guint i = 0; i < gallery->prints->len; i++)
        {
          int score = sigfm_match_score (probe.get (),
            static_cast<SigfmImgInfo *> (g_ptr_array_index (gallery->prints, i)));
          if (score < 0)
            return 2;
          if (score > maximum)
            {
              maximum = score;
              best = i + 1;
            }
        }
      std::cout << line.substr (0, tab) << '\t' << path << '\t'
                << sigfm_keypoints_count (probe.get ()) << '\t'
                << maximum << '\t' << best;
      if (argc == 4)
        {
          maximum = 0;
          best = 0;
          for (std::size_t i = 0; i < references.size (); i++)
            {
              int score = sigfm_match_score (probe.get (), references[i].get ());
              if (score < 0)
                return 2;
              if (score > maximum)
                {
                  maximum = score;
                  best = i + 1;
                }
            }
          std::cout << '\t' << maximum << '\t' << best;
        }
      std::cout << '\n';
    }
  return manifest.bad () || !std::cout ? 2 : 0;
}
