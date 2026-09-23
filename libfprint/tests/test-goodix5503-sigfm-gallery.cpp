// SPDX-License-Identifier: LGPL-2.1-or-later
#include <cassert>
#include <cstring>
#include <functional>
#include <vector>

#include "sigfm/sigfm.hpp"
#include "sigfm/img-info.hpp"
extern "C" {
#include "fp-print-private.h"
#include "fpi-print.h"
#include "fpi-image.h"
// The C device class has a vfunc named after a C++ keyword.
#define delete delete_device
#include "fp-image-device-private.h"
#undef delete
}

typedef struct { FpImageDevice parent; } EnrollmentDevice;
typedef struct { FpImageDeviceClass parent; } EnrollmentDeviceClass;
static std::vector<SigfmPix> pattern (guint stage);
GType enrollment_device_get_type (void);
G_DEFINE_TYPE (EnrollmentDevice, enrollment_device, FP_TYPE_IMAGE_DEVICE)

static void enrollment_device_init (EnrollmentDevice *) {}
static void enrollment_device_class_init (EnrollmentDeviceClass *klass)
{
  auto *device = FP_DEVICE_CLASS (klass);
  auto *image = FP_IMAGE_DEVICE_CLASS (klass);
  device->id = "goodix5503-test";
  device->full_name = "Synthetic enrollment test";
  device->type = FP_DEVICE_TYPE_VIRTUAL;
  device->nr_enroll_stages = SIGFM_ENROLL_TOTAL_STAGES;
  device->temp_hot_seconds = -1;
  device->scan_type = FP_SCAN_TYPE_PRESS;
  image->algorithm = FPI_DEVICE_ALGO_SIGFM;
  image->sigfm_threshold = 150;
  image->img_width = 80;
  image->img_height = 64;
  image->img_open = [](FpImageDevice *self) { fpi_image_device_open_complete (self, nullptr); };
  image->img_close = [](FpImageDevice *self) { fpi_image_device_close_complete (self, nullptr); };
  fpi_device_class_auto_initialize_features (device);
  device->features = static_cast<FpDeviceFeature> (device->features & ~FP_DEVICE_FEATURE_UPDATE_PRINT);
}

struct SessionResult
{
  bool done = false;
  int stage = 0;
  FpPrint *print = nullptr;
  GError *error = nullptr;
  ~SessionResult () { g_clear_object (&print); g_clear_error (&error); }
};

static void spin_until (const std::function<bool ()>& condition)
{
  const gint64 deadline = g_get_monotonic_time () + 15 * G_TIME_SPAN_SECOND;
  while (!condition ())
    {
      assert (g_get_monotonic_time () < deadline);
      g_main_context_iteration (nullptr, FALSE);
      g_usleep (1000);
    }
}

static FpImageDevicePrivate *image_private (FpDevice *device)
{
  return &G_STRUCT_MEMBER (FpImageDevicePrivate, device,
    g_type_class_get_instance_private_offset (g_type_class_peek_static (FP_TYPE_IMAGE_DEVICE)));
}

static void test_enrollment_session (guint pass_checks, bool cancel_selection)
{
  g_autoptr(FpDevice) device = FP_DEVICE (g_object_new (enrollment_device_get_type (), nullptr));
  g_autoptr(GError) error = nullptr;
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  assert (fp_device_open_sync (device, nullptr, &error) && !error);
  g_autoptr(FpPrint) candidate = fp_print_new (device);
  g_object_ref_sink (candidate);
  auto *priv = image_private (device);
  SessionResult result;
  fp_device_enroll (device, candidate, cancel,
    [](FpDevice *, gint stage, FpPrint *, gpointer data, GError *) {
      static_cast<SessionResult *> (data)->stage = stage;
    }, &result, nullptr,
    [](GObject *object, GAsyncResult *finished, gpointer data) {
      auto *out = static_cast<SessionResult *> (data);
      out->print = fp_device_enroll_finish (FP_DEVICE (object), finished, &out->error);
      out->done = true;
    }, &result);
  const auto ready = [&] { return priv->state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON; };
  spin_until (ready);
  // A rejected training attempt must not advance progress or retain data.
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (device), TRUE);
  fpi_image_device_retry_scan (FP_IMAGE_DEVICE (device), FP_DEVICE_RETRY_GENERAL);
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (device), FALSE);
  spin_until (ready);
  assert (result.stage == 0 && priv->sigfm_enroll_samples->len == 0);

  std::vector<std::vector<SigfmPix>> frames;
  for (guint i = 0; i < 100 && result.stage < SIGFM_ENROLL_POOL_SAMPLES; i++)
    {
      auto bytes = pattern (i);
      frames.push_back (bytes);
      FpImage *image = fp_image_new (80, 64);
      std::memcpy (image->data, bytes.data (), bytes.size ());
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (device), TRUE);
      fpi_image_device_image_captured (FP_IMAGE_DEVICE (device), image);
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (device), FALSE);
      spin_until ([&] {
        return result.done || ready () ||
          (cancel_selection && priv->enroll_stage == SIGFM_ENROLL_POOL_SAMPLES);
      });
      assert (!result.done);
      if (cancel_selection && priv->enroll_stage == SIGFM_ENROLL_POOL_SAMPLES)
        break;
    }
  if (cancel_selection)
    {
      assert (priv->enroll_stage == SIGFM_ENROLL_POOL_SAMPLES);
      assert (priv->minutiae_scan_active && !priv->finger_present);
      assert (priv->state == FPI_IMAGE_DEVICE_STATE_IDLE); // No premature next DOWN.
      g_cancellable_cancel (cancel);
      spin_until ([&] { return result.done; });
      assert (!result.print && g_error_matches (result.error, G_IO_ERROR, G_IO_ERROR_CANCELLED));
      assert (!priv->sigfm_enroll_samples && !priv->minutiae_scan_active);
    }
  else
    {
      assert (result.stage == SIGFM_ENROLL_POOL_SAMPLES && !priv->sigfm_enroll_samples);
      FpPrint *gallery = nullptr;
      fpi_device_get_enroll_data (device, &gallery);
      assert (gallery->prints->len == SIGFM_ENROLL_TARGET_SAMPLES);
      std::vector<SigfmPix> matching;
      for (const auto& bytes : frames)
        {
          auto *info = sigfm_extract (bytes.data (), 80, 64);
          int score = sigfm_match_score (info, static_cast<SigfmImgInfo *> (gallery->prints->pdata[0]));
          sigfm_free_info (info);
          if (score >= 150) { matching = bytes; break; }
        }
      assert (!matching.empty ());
      for (guint i = 0; i < SIGFM_ENROLL_CHECK_SAMPLES; i++)
        {
          spin_until (ready);
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (device), TRUE);
          if (i < pass_checks)
            {
              FpImage *image = fp_image_new (80, 64);
              std::memcpy (image->data, matching.data (), matching.size ());
              fpi_image_device_image_captured (FP_IMAGE_DEVICE (device), image);
              spin_until ([&] { return !priv->minutiae_scan_active; });
            }
          else
            fpi_image_device_retry_scan (FP_IMAGE_DEVICE (device), FP_DEVICE_RETRY_GENERAL);
          if (i + 1 == SIGFM_ENROLL_CHECK_SAMPLES && pass_checks >= SIGFM_ENROLL_CHECK_REQUIRED)
            assert (!result.done && priv->enroll_final_stage && priv->finger_present);
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (device), FALSE);
          spin_until ([&] { return result.done || ready (); });
        }
      spin_until ([&] { return result.done; });
      if (pass_checks >= SIGFM_ENROLL_CHECK_REQUIRED)
        assert (result.print && !result.error && result.print->prints->len == SIGFM_ENROLL_TARGET_SAMPLES);
      else
        assert (!result.print && result.error);
    }
  assert (fp_device_close_sync (device, nullptr, &error) && !error);
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

static void test_selection_requires_cross_press_support ()
{
  auto image = pattern (0);
  SigfmImgInfo *base = sigfm_extract (image.data (), 80, 64);
  assert (base && sigfm_keypoints_count (base) >= 20);
  SigfmImgInfo *pool[SIGFM_ENROLL_POOL_SAMPLES];
  for (guint i = 0; i < SIGFM_ENROLL_POOL_SAMPLES; i++)
    {
      pool[i] = sigfm_copy_info (base);
      /* Four independent pairs and two isolated samples per group. Paired
       * views have an 8px shift, so enrollment retains their extra coverage.
       * Isolated samples match themselves perfectly but no other press. */
      guint within = i % SIGFM_ENROLL_BATCH_SAMPLES;
      guint identity = (i / SIGFM_ENROLL_BATCH_SAMPLES) * 10 +
                       (within < 8 ? within / 2 : within);
      cv::RNG rng (identity + 4101);
      rng.fill (pool[i]->descriptors, cv::RNG::UNIFORM, 0, 255);
      if (within < 8 && within % 2)
        for (auto& point : pool[i]->keypoints)
          point.pt.x += 8;
    }
  unsigned selected[SIGFM_ENROLL_TARGET_SAMPLES];
  assert (sigfm_select_enrollment (pool, SIGFM_ENROLL_POOL_SAMPLES, 150,
                                    selected, SIGFM_ENROLL_TARGET_SAMPLES) == 0);
  unsigned groups[4] = {};
  for (auto index : selected)
    {
      assert (index % SIGFM_ENROLL_BATCH_SAMPLES < 8);
      assert (sigfm_match_score (pool[index], pool[index ^ 1]) >= 150);
      groups[index / SIGFM_ENROLL_BATCH_SAMPLES]++;
    }
  for (auto count : groups)
    assert (count == SIGFM_ENROLL_BATCH_KEEP);
  for (auto *info : pool)
    sigfm_free_info (info);
  sigfm_free_info (base);
}

static void test_fresh_enrollment ()
{
  auto image = pattern (0);
  SigfmImgInfo *base = sigfm_extract (image.data (), 80, 64);
  assert (base && sigfm_keypoints_count (base) >= 20);
  g_autoptr(FpPrint) gallery = single (base);
  g_ptr_array_set_size (gallery->prints, 0);
  g_autoptr(GPtrArray) pool = g_ptr_array_new_with_free_func (
    reinterpret_cast<GDestroyNotify> (sigfm_free_info));
  g_autoptr(GError) error = nullptr;
  for (guint i = 0; i < SIGFM_ENROLL_POOL_SAMPLES; i++)
    {
      auto *info = sigfm_copy_info (base);
      cv::RNG rng (i + 731);
      rng.fill (info->descriptors, cv::RNG::UNIFORM, 0, 255);
      g_autoptr(FpPrint) sample = single (info);
      sigfm_free_info (info);
      assert (fpi_print_sigfm_enroll_collect (pool, sample, 150, &error));
      assert (!error && pool->len == i + 1 && gallery->prints->len == 0);
      if (i == 0)
        {
          assert (!fpi_print_sigfm_enroll_collect (pool, sample, 150, &error));
          assert (g_error_matches (error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_CENTER_FINGER));
          assert (pool->len == 1);
          g_clear_error (&error);
        }
      if (i == SIGFM_ENROLL_POOL_SAMPLES - 2)
        {
          assert (!fpi_print_sigfm_enroll_select (gallery, pool, 150, &error));
          assert (error && gallery->prints->len == 0);
          g_clear_error (&error);
        }
    }
  {
    g_autoptr(FpPrint) extra = single (base);
    assert (!fpi_print_sigfm_enroll_collect (pool, extra, 150, &error));
    assert (error && pool->len == SIGFM_ENROLL_POOL_SAMPLES);
    g_clear_error (&error);
  }
  assert (fpi_print_sigfm_enroll_select (gallery, pool, 150, &error));
  assert (!error && gallery->prints->len == SIGFM_ENROLL_TARGET_SAMPLES);
  unsigned batches[4] = {};
  bool seen[SIGFM_ENROLL_POOL_SAMPLES] = {};
  for (guint i = 0; i < gallery->prints->len; i++)
    {
      auto *chosen = static_cast<SigfmImgInfo *> (gallery->prints->pdata[i]);
      bool found = false;
      for (guint j = 0; j < pool->len; j++)
        if (sigfm_equal (chosen, static_cast<SigfmImgInfo *> (pool->pdata[j])))
          {
            assert (!found && !seen[j] && chosen != pool->pdata[j]);
            found = true;
            seen[j] = true;
            batches[j / SIGFM_ENROLL_BATCH_SAMPLES]++;
          }
      assert (found);
    }
  for (auto count : batches)
    assert (count == SIGFM_ENROLL_BATCH_KEEP);
  assert (!fpi_print_sigfm_enroll_select (gallery, pool, 150, &error));
  assert (error && gallery->prints->len == SIGFM_ENROLL_TARGET_SAMPLES);
  g_clear_error (&error);
  g_clear_pointer (&pool, g_ptr_array_unref);
  sigfm_free_info (base);

  guchar *before = nullptr, *after = nullptr;
  gsize before_size = 0, after_size = 0;
  assert (fp_print_serialize (gallery, &before, &before_size, &error));
  g_autoptr(FpPrint) matching = single (static_cast<SigfmImgInfo *> (gallery->prints->pdata[0]));
  for (guint passes : { 5u, 6u })
    {
      guint checked = 0, matched = 0;
      for (guint i = 0; i < SIGFM_ENROLL_CHECK_SAMPLES; i++)
        {
          gint result = fpi_print_sigfm_enroll_check (
            gallery, i < passes ? matching : nullptr, 150, &checked, &matched, &error);
          assert (checked == i + 1 && matched == (i < passes ? i + 1 : passes));
          if (i + 1 < SIGFM_ENROLL_CHECK_SAMPLES)
            assert (result == 0 && !error);
          else if (passes < SIGFM_ENROLL_CHECK_REQUIRED)
            assert (result == -1 && error);
          else
            assert (result == 1 && !error);
        }
      g_clear_error (&error);
      assert (fpi_print_sigfm_enroll_check (
        gallery, matching, 150, &checked, &matched, &error) == -1);
      assert (error && checked == SIGFM_ENROLL_CHECK_SAMPLES);
      g_clear_error (&error);
    }
  assert (fp_print_serialize (gallery, &after, &after_size, &error));
  assert (before_size == after_size && std::memcmp (before, after, before_size) == 0);
  std::memset (before, 0, before_size);
  std::memset (after, 0, after_size);
  g_free (before);
  g_free (after);
}

int main ()
{
  test_selection_requires_cross_press_support ();
  test_fresh_enrollment ();
  test_enrollment_session (6, false);
  test_enrollment_session (5, false);
  test_enrollment_session (0, true);
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
  for (guint stage = 0; stage < 24; stage++)
    {
      auto stage_image = pattern (stage);
      SigfmImgInfo *stage_info =
        sigfm_extract (stage_image.data (), 80, 64);
      assert (stage_info != nullptr);
      g_autoptr(FpPrint) sample = single (stage_info);
      sigfm_free_info (stage_info);
      if (stage == 0)
        assert (!fpi_print_sigfm_is_duplicate (gallery, sample, 150, &error));
      assert (error == nullptr);
      assert (fpi_print_add_print (gallery, sample, &error));
      assert (error == nullptr);
      assert (gallery->prints->len == stage + 1);
      if (stage == 0)
        {
          g_autoptr(FpPrint) duplicate = single (info);
          assert (fpi_print_sigfm_is_duplicate (gallery, duplicate, 150,
                                                &error));
          assert (error == nullptr);
          auto *shifted_info = sigfm_copy_info (info);
          for (auto& kp : shifted_info->keypoints)
            kp.pt.x += 8;
          assert (sigfm_match_score (shifted_info, info) >= 150);
          g_autoptr(FpPrint) overlapping_view = single (shifted_info);
          sigfm_free_info (shifted_info);
          assert (!fpi_print_sigfm_is_duplicate (gallery, overlapping_view, 150,
                                                 &error));
          assert (error == nullptr);
        }
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
    assert (error != nullptr && gallery->prints->len == 24);
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
