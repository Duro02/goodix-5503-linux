// SPDX-License-Identifier: LGPL-2.1-or-later
#include <cassert>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <vector>

extern "C" {
#include <fprint.h>
#include "fpi-sensitive-data.h"
}

struct SensitiveOwner
{
  bool destroyed;
  guint8 data[16];
};

static void sensitive_destroy (gpointer user_data)
{
  auto *owner = static_cast<SensitiveOwner *> (user_data);
  std::memset (owner->data, 0, sizeof owner->data);
  owner->destroyed = true;
}

static void append_u16 (std::vector<guint8>& out, std::uint16_t value)
{
  out.push_back (value);
  out.push_back (value >> 8);
}

static void append_u32 (std::vector<guint8>& out, std::uint32_t value)
{
  for (unsigned shift = 0; shift < 32; shift += 8)
    out.push_back (value >> shift);
}

static void append_float (std::vector<guint8>& out, float value)
{
  std::uint32_t bits;
  std::memcpy (&bits, &value, sizeof bits);
  append_u32 (out, bits);
}

static std::vector<guint8> make_sample ()
{
  std::vector<guint8> sample = { 'G', '5', '5', 'S' };
  append_u16 (sample, 3);
  append_u16 (sample, 0);
  append_u32 (sample, 1);
  append_u16 (sample, 128);
  append_u16 (sample, 1);
  append_u32 (sample, 128 * sizeof (float));
  append_float (sample, 10.0f);
  append_float (sample, 10.0f);
  append_float (sample, 1.0f);
  append_float (sample, 0.0f);
  append_float (sample, 1.0f);
  append_u32 (sample, 0);
  append_u32 (sample, 0);
  for (guint index = 0; index < 128; index++)
    append_float (sample, static_cast<float> (index) / 128.0f);
  return sample;
}

static std::vector<guint8>
make_fp3 (GVariant *print_data)
{
  GVariantBuilder builder = G_VARIANT_BUILDER_INIT (
    G_VARIANT_TYPE ("(issbymsmsia{sv}v)"));
  g_variant_builder_add (&builder, "i", 3);
  g_variant_builder_add (&builder, "s", "goodix5503");
  g_variant_builder_add (&builder, "s", "synthetic");
  g_variant_builder_add (&builder, "b", FALSE);
  g_variant_builder_add (&builder, "y", 1);
  g_variant_builder_add (&builder, "ms", nullptr);
  g_variant_builder_add (&builder, "ms", nullptr);
  g_variant_builder_add (&builder, "i", G_MININT32);
  g_variant_builder_open (&builder, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_close (&builder);
  g_variant_builder_add (&builder, "v", print_data);
  g_autoptr(GVariant) value = g_variant_ref_sink (g_variant_builder_end (&builder));
  std::vector<guint8> bytes (3 + g_variant_get_size (value));
  std::memcpy (bytes.data (), "FP3", 3);
  g_variant_get_data (value);
  g_variant_store (value, bytes.data () + 3);
  return bytes;
}

static GVariant *make_gallery (guint count = 24)
{
  auto sample = make_sample ();
  GVariantBuilder nested = G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE ("(aay)"));
  g_variant_builder_open (&nested, G_VARIANT_TYPE ("aay"));
  for (guint index = 0; index < count; index++)
    g_variant_builder_add_value (
      &nested, g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                          sample.data (), sample.size (), 1));
  g_variant_builder_close (&nested);
  return g_variant_builder_end (&nested);
}

int main ()
{
  SensitiveOwner owner = { false, { 1, 2, 3, 4 } };
  g_autoptr(GVariant) sensitive = g_variant_ref_sink (
    fpi_sensitive_byte_array_new_take (owner.data, sizeof owner.data,
                                       sensitive_destroy, &owner));
  assert (sensitive != nullptr && !owner.destroyed);
  g_clear_pointer (&sensitive, g_variant_unref);
  assert (owner.destroyed);
  for (guint8 byte : owner.data)
    assert (byte == 0);

  g_autoptr(GError) error = nullptr;
  g_autoptr(FpPrint) print = nullptr;
  g_autoptr(FpPrint) restored = nullptr;
  guchar *serialized = nullptr;
  gsize serialized_len = 0;

  auto fp3 = make_fp3 (make_gallery ());
  print = fp_print_deserialize (fp3.data (), fp3.size (), &error);
  assert (error == nullptr && print != nullptr);
  assert (fp_print_serialize (print, &serialized, &serialized_len, &error));
  assert (error == nullptr && serialized != nullptr && serialized_len > 3);
  restored = fp_print_deserialize (serialized, serialized_len, &error);
  assert (error == nullptr && restored != nullptr);
  assert (fp_print_equal (print, restored));
  std::memset (serialized, 0, serialized_len);
  g_free (serialized);

  for (guint count : { 7U, 25U })
    {
      auto wrong_count = make_fp3 (make_gallery (count));
      g_clear_object (&print);
      print = fp_print_deserialize (wrong_count.data (), wrong_count.size (),
                                    &error);
      assert (print == nullptr && error != nullptr);
      g_clear_error (&error);
    }

  auto wrong_shape = make_fp3 (g_variant_new ("(s)", "wrong"));
  g_clear_object (&print);
  print = fp_print_deserialize (wrong_shape.data (), wrong_shape.size (), &error);
  assert (print == nullptr && error != nullptr);
  g_clear_error (&error);

  GVariantBuilder strings = G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE ("(as)"));
  g_variant_builder_open (&strings, G_VARIANT_TYPE ("as"));
  g_variant_builder_add (&strings, "s", "wrong");
  g_variant_builder_close (&strings);
  auto wrong_sample = make_fp3 (g_variant_builder_end (&strings));
  print = fp_print_deserialize (wrong_sample.data (), wrong_sample.size (), &error);
  assert (print == nullptr && error != nullptr);
  return 0;
}
