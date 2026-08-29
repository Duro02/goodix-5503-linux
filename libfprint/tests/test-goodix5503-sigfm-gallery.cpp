// SPDX-License-Identifier: LGPL-2.1-or-later
#include <cassert>
#include <cstring>
#include <vector>

#include "sigfm/sigfm.hpp"
extern "C" {
#include "fp-print-private.h"
#include "fpi-print.h"
}

static std::vector<SigfmPix> pattern (guint stage)
{
  std::vector<SigfmPix> image (80 * 64);
  for (int y = 0; y < 64; y++)
    for (int x = 0; x < 80; x++)
      image[y * 80 + x] =
        ((((x + static_cast<int> (stage) * 3) / 5 + y / 5) & 1) ? 220 :
         ((x * 17 + y * 29 + static_cast<int> (stage) * 11) & 63));
  return image;
}

static FpPrint *single (SigfmImgInfo *info)
{
  FpPrint *print = FP_PRINT (g_object_new (FP_TYPE_PRINT,
                                           "driver", "goodix5503",
                                           "device-id", "synthetic",
                                           NULL));
  g_object_ref_sink (print);
  fpi_print_set_type (print, FPI_PRINT_SIGFM);
  g_ptr_array_add (print->prints, sigfm_copy_info (info));
  return print;
}

int main ()
{
  auto image = pattern (0);
  SigfmImgInfo *info = sigfm_extract (image.data (), 80, 64);
  g_autoptr(FpPrint) gallery = nullptr;
  g_autoptr(GError) error = nullptr;
  guchar *serialized = nullptr;
  gsize serialized_len = 0;

  assert (info != nullptr);
  gallery = FP_PRINT (g_object_new (FP_TYPE_PRINT,
                                    "driver", "goodix5503",
                                    "device-id", "synthetic",
                                    NULL));
  g_object_ref_sink (gallery);
  fpi_print_set_type (gallery, FPI_PRINT_SIGFM);
  for (guint stage = 0; stage < 8; stage++)
    {
      auto stage_image = pattern (stage);
      SigfmImgInfo *stage_info =
        sigfm_extract (stage_image.data (), 80, 64);
      assert (stage_info != nullptr);
      g_autoptr(FpPrint) sample = single (stage_info);
      sigfm_free_info (stage_info);
      assert (fpi_print_add_print (gallery, sample, &error));
      assert (error == nullptr);
      assert (gallery->prints->len == stage + 1);
      if (stage == 6)
        {
          serialized = reinterpret_cast<guchar *> (0x1);
          serialized_len = 123;
          assert (!fp_print_serialize (gallery, &serialized, &serialized_len,
                                       &error));
          assert (error != nullptr && serialized == nullptr &&
                  serialized_len == 0);
          g_clear_error (&error);
        }
    }
  {
    g_autoptr(FpPrint) sample = single (info);
    assert (!fpi_print_add_print (gallery, sample, &error));
    assert (error != nullptr && gallery->prints->len == 8);
    g_clear_error (&error);
  }
  assert (fp_print_serialize (gallery, &serialized, &serialized_len, &error));
  assert (serialized != nullptr && serialized_len > 3 && error == nullptr);
  {
    g_autoptr(FpPrint) roundtrip =
      fp_print_deserialize (serialized, serialized_len, &error);
    guchar *reserialized = nullptr;
    gsize reserialized_len = 0;

    assert (roundtrip != nullptr && error == nullptr);
    assert (fp_print_equal (gallery, roundtrip));
    assert (fp_print_serialize (roundtrip, &reserialized, &reserialized_len,
                                &error));
    assert (error == nullptr && reserialized_len == serialized_len);
    assert (std::memcmp (serialized, reserialized, serialized_len) == 0);
    std::memset (reserialized, 0, reserialized_len);
    g_free (reserialized);
  }
  std::memset (serialized, 0, serialized_len);
  g_free (serialized);
  sigfm_free_info (info);
  return 0;
}
