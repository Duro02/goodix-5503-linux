/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Goodix GF3258/Milan 5503 image-device integration. */

#define FP_COMPONENT "goodix5503"
#include "fpi-log.h"
#include "drivers_api.h"
#include "goodix5503-config.h"
#include "goodix5503-image.h"
#include "goodix5503-proto.h"
#include "goodix5503-security.h"
#include "goodix5503-tls.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <sys/prctl.h>

#define GOODIX5503_EP_OUT 0x01
#define GOODIX5503_EP_IN 0x82
#define GOODIX5503_TRANSFER_SIZE 32768
#define GOODIX5503_TRANSFER_TIMEOUT_MS 1500
#define GOODIX5503_QUEUED_OUT_DELAY_MS 25
#define GOODIX5503_USB_PACKET_SIZE 64
#define GOODIX5503_COMMAND_ACK 0xb0
#define GOODIX5503_COMMAND_NOP 0x00
#define GOODIX5503_COMMAND_FIRMWARE 0xa8
#define GOODIX5503_COMMAND_READ_PSK 0xe4
#define GOODIX5503_COMMAND_RESET 0xa2
#define GOODIX5503_COMMAND_READ_REGISTER 0x82
#define GOODIX5503_COMMAND_READ_OTP 0xa6
#define GOODIX5503_COMMAND_POV_CHECK 0xd6
#define GOODIX5503_COMMAND_TLS 0xd0
#define GOODIX5503_COMMAND_CONFIG 0x90
#define GOODIX5503_COMMAND_DRIVER_STATE 0xc4
#define GOODIX5503_COMMAND_FDT_MANUAL 0x36
#define GOODIX5503_COMMAND_IDLE 0x70
#define GOODIX5503_TLS_FLAGS 0xb0
#define GOODIX5503_MAX_FRESH_ATTEMPTS 10
#define GOODIX5503_FRESH_RETRY_MS 500
#define GOODIX5503_MAX_TLS_CLIENT_FRAMES 3
#define GOODIX5503_CAPTURE_DISCARD 0
#define GOODIX5503_CAPTURE_BACKGROUND 1
#define GOODIX5503_CAPTURE_FINGER 2
#define GOODIX5503_R_PSK_HASH_SELECTOR 0xbb020007
#define GOODIX5503_EXPECTED_CHIP_ID 0x220f

static const char expected_firmware[] = "GF3258_RTSEC_APP_10063";
static const char expected_post_reset_firmware[] = "GF3208_RTSEC_APP_10063";

static gboolean
goodix5503_firmware_identity_matches (GByteArray *body, const gchar *expected)
{
  gsize expected_len = strlen (expected) + 1;

  if (body->len < expected_len ||
      memcmp (body->data, expected, expected_len) != 0)
    return FALSE;
  for (gsize index = expected_len; index < body->len; index++)
    if (body->data[index] != 0)
      return FALSE;
  return TRUE;
}

typedef struct _FpiDeviceGoodix5503 FpiDeviceGoodix5503;
typedef void (*Goodix5503CommandCallback) (FpiDeviceGoodix5503 *self,
                                           GByteArray          *body,
                                           GError              *error);
typedef void (*Goodix5503OuterCallback) (FpiDeviceGoodix5503 *self,
                                         GByteArray          *frame,
                                         GError              *error);
typedef void (*Goodix5503ImageCallback) (FpiDeviceGoodix5503 *self,
                                         GError              *error);

struct _FpiDeviceGoodix5503
{
  FpImageDevice parent;
  GCancellable *transaction_cancel;
  Goodix5503FrameBuffer *frame_buffer;
  Goodix5503CommandState command_state;
  Goodix5503CommandCallback command_callback;
  Goodix5503OuterCallback outer_callback;
  GByteArray *command_response;
  GByteArray *outer_response;
  GError *command_error;
  GError *outer_error;
  guint8 expected_command;
  gboolean expect_data;
  gboolean data_checksum;
  gboolean interface_claimed;
  gboolean out_done;
  gboolean read_active;
  GByteArray *usb_out;
  gsize usb_out_offset;
  gboolean outer_expect_read;
  gboolean deactivating;
  gboolean closing;
  const gchar *stage;
  guint8 psk[GOODIX5503_SECURITY_PSK_SIZE];
  guint8 expected_verification[GOODIX5503_VERIFICATION_SIZE];
  guint8 otp[GOODIX5503_OTP_SIZE];
  guint8 dac[GOODIX5503_DAC_SIZE];
  guint8 config[GOODIX5503_CONFIG_SIZE];
  Goodix5503Tls *tls;
  guint tls_client_frames;
  Goodix5503CaptureState capture_state;
  Goodix5503ImageCallback image_callback;
  GError *primary_error;
  GSource *delay_source;
  gboolean reset_attempted;
  gboolean cleanup_active;
  guint capture_destination;
  gboolean session_clean;
  gboolean activation_reported;
  struct
  {
    /* Survives fp_device close: the powered sensor retains its TLS session,
     * runtime configuration and calibration, so re-opening only needs a
     * liveness probe and a fresh down-detection base. An all-zero
     * down_base marks the warm state as invalidated. */
    guint8 dac[GOODIX5503_DAC_SIZE];
    guint16 delta;
    guint8 down_base[GOODIX5503_FDT_BASE_SIZE];
    guint8 background[GOODIX5503_PACKED_IMAGE_SIZE];
    Goodix5503Tls *tls;
    guint probe_retries;
  } warm;
  gboolean warm_rearmed;
  Goodix5503FdtRuntime fdt_runtime;
  gboolean activated;
  guint fresh_attempt;
  guint16 fdt_delta;
  guint8 fresh_raw[3][GOODIX5503_FDT_BASE_SIZE];
  guint8 fresh_transformed[3][GOODIX5503_FDT_BASE_SIZE];
  guint8 background[GOODIX5503_PACKED_IMAGE_SIZE];
  guint8 finger[GOODIX5503_PACKED_IMAGE_SIZE];
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix5503, fpi_device_goodix5503,
                      FPI, DEVICE_GOODIX5503, FpImageDevice)
G_DEFINE_TYPE (FpiDeviceGoodix5503, fpi_device_goodix5503,
               FP_TYPE_IMAGE_DEVICE)

typedef struct
{
  gsize length;
  guint8 data[];
} Goodix5503OutBuffer;

static guint8 *
goodix5503_padded_out_buffer (const guint8 *data, gsize length,
                              gsize *padded_length)
{
  Goodix5503OutBuffer *buffer;
  gsize padded;

  g_assert (data != NULL && length > 0);
  padded = ((length + GOODIX5503_USB_PACKET_SIZE - 1) /
            GOODIX5503_USB_PACKET_SIZE) * GOODIX5503_USB_PACKET_SIZE;
  buffer = g_malloc0 (sizeof *buffer + padded);
  buffer->length = padded;
  memcpy (buffer->data, data, length);
  *padded_length = padded;
  return buffer->data;
}

static void
goodix5503_out_buffer_free (gpointer data)
{
  Goodix5503OutBuffer *buffer;

  if (data == NULL)
    return;
  buffer = (Goodix5503OutBuffer *) ((guint8 *) data -
                                    G_STRUCT_OFFSET (Goodix5503OutBuffer, data));
  OPENSSL_cleanse (buffer->data, buffer->length);
  g_free (buffer);
}

static gboolean
goodix5503_disable_process_dumps (GError **error)
{
  if (prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) == 0)
    return TRUE;
  g_set_error_literal (error, G_IO_ERROR, g_io_error_from_errno (errno),
                       "failed to disable process dumps before loading PSK");
  return FALSE;
}

static void goodix5503_submit_read (FpiDeviceGoodix5503 *self);
static void goodix5503_command_submit_out (FpiDeviceGoodix5503 *self);

static void
goodix5503_command_delayed_out (FpDevice *device, gpointer user_data)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  (void) user_data;
  self->delay_source = NULL;
  goodix5503_command_submit_out (self);
}
static void goodix5503_outer_submit_out (FpiDeviceGoodix5503 *self);
static void goodix5503_close_finish (FpiDeviceGoodix5503 *self);

static void
goodix5503_fdt_pending_clear (FpiDeviceGoodix5503 *self)
{
  goodix5503_fdt_runtime_pending_clear (&self->fdt_runtime);
}

static void
goodix5503_fdt_session_reset (FpiDeviceGoodix5503 *self)
{
  goodix5503_fdt_runtime_reset (&self->fdt_runtime);
}

static gboolean
goodix5503_warm_available (FpiDeviceGoodix5503 *self)
{
  /* An all-zero down_base marks the warm state as invalidated. */
  guint8 zero[GOODIX5503_FDT_BASE_SIZE] = { 0 };

  return memcmp (self->warm.down_base, zero, sizeof zero) != 0;
}

static void
goodix5503_warm_invalidate (FpiDeviceGoodix5503 *self)
{
  memset (self->warm.down_base, 0, sizeof self->warm.down_base);
}

static void
goodix5503_usb_out_clear (FpiDeviceGoodix5503 *self)
{
  if (self->usb_out)
    OPENSSL_cleanse (self->usb_out->data, self->usb_out->len);
  g_clear_pointer (&self->usb_out, g_byte_array_unref);
  self->usb_out_offset = 0;
}

static void
goodix5503_usb_out_set (FpiDeviceGoodix5503 *self, GByteArray *packet)
{
  gsize padded = ((packet->len + GOODIX5503_USB_PACKET_SIZE - 1) /
                  GOODIX5503_USB_PACKET_SIZE) * GOODIX5503_USB_PACKET_SIZE;

  g_assert (self->usb_out == NULL);
  self->usb_out = g_byte_array_sized_new (padded);
  g_byte_array_set_size (self->usb_out, padded);
  memset (self->usb_out->data, 0, padded);
  memcpy (self->usb_out->data, packet->data, packet->len);
  self->usb_out_offset = 0;
}

static void
goodix5503_command_clear (FpiDeviceGoodix5503 *self)
{
  g_clear_object (&self->transaction_cancel);
  goodix5503_usb_out_clear (self);
  g_clear_pointer (&self->command_response, g_byte_array_unref);
  g_clear_error (&self->command_error);
  self->command_callback = NULL;
  self->out_done = FALSE;
  self->read_active = FALSE;
}

static void
goodix5503_command_maybe_complete (FpiDeviceGoodix5503 *self)
{
  Goodix5503CommandCallback callback;
  GByteArray *response;
  GError *error;

  if (self->command_callback == NULL || !self->out_done || self->read_active)
    return;
  if (self->command_error == NULL && self->command_response == NULL)
    return;

  if (self->closing)
    {
      if (self->command_response)
        OPENSSL_cleanse (self->command_response->data,
                         self->command_response->len);
      goodix5503_command_clear (self);
      goodix5503_close_finish (self);
      return;
    }
  callback = self->command_callback;
  response = g_steal_pointer (&self->command_response);
  error = g_steal_pointer (&self->command_error);
  if (self->deactivating && error == NULL)
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                 "Goodix operation cancelled");
  goodix5503_command_clear (self);
  callback (self, response, error);
  if (self->deactivating && self->command_callback == NULL &&
      self->outer_callback == NULL)
    {
      self->deactivating = FALSE;
      fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (self), NULL);
    }
}

static void
goodix5503_command_fail (FpiDeviceGoodix5503 *self, GError *error)
{
  if (self->command_error == NULL)
    self->command_error = error;
  else
    g_error_free (error);
  if (self->transaction_cancel)
    g_cancellable_cancel (self->transaction_cancel);
}

static void
goodix5503_out_done (FpiUsbTransfer *transfer,
                      FpDevice       *device,
                      gpointer        user_data,
                      GError         *error)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  (void) transfer;
  (void) user_data;
  if (error)
    {
      self->out_done = TRUE;
      goodix5503_command_fail (self, error);
    }
  else if (self->usb_out_offset < self->usb_out->len)
    {
      goodix5503_command_submit_out (self);
      return;
    }
  else
    self->out_done = TRUE;
  goodix5503_command_maybe_complete (self);
}

static void
goodix5503_command_submit_out (FpiDeviceGoodix5503 *self)
{
  FpiUsbTransfer *transfer;
  guint8 *chunk;
  gsize chunk_len;

  g_assert (self->usb_out &&
            self->usb_out_offset + GOODIX5503_USB_PACKET_SIZE <=
              self->usb_out->len);
  chunk = goodix5503_padded_out_buffer (
    self->usb_out->data + self->usb_out_offset,
    GOODIX5503_USB_PACKET_SIZE, &chunk_len);
  self->usb_out_offset += GOODIX5503_USB_PACKET_SIZE;
  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk_full (transfer, GOODIX5503_EP_OUT, chunk,
                                   chunk_len, goodix5503_out_buffer_free);
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (transfer, GOODIX5503_TRANSFER_TIMEOUT_MS,
                           self->transaction_cancel, goodix5503_out_done,
                           NULL);
}

static void
goodix5503_read_done (FpiUsbTransfer *transfer,
                       FpDevice       *device,
                       gpointer        user_data,
                       GError         *error)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);
  g_autoptr(GByteArray) frame = NULL;

  (void) user_data;
  self->read_active = FALSE;
  if (error)
    {
      if (self->command_error == NULL)
        goodix5503_command_fail (self, error);
      else
        g_error_free (error);
      goodix5503_command_maybe_complete (self);
      return;
    }

  if (!goodix5503_frame_buffer_append (self->frame_buffer, transfer->buffer,
                                       transfer->actual_length,
                                       &self->command_error))
    {
      goodix5503_command_fail (self, g_steal_pointer (&self->command_error));
      goodix5503_command_maybe_complete (self);
      return;
    }

  while (goodix5503_frame_buffer_take (self->frame_buffer, &frame,
                                       &self->command_error))
    {
      g_autoptr(GByteArray) body = NULL;

      if (!goodix5503_command_consume_frame (
            self->expected_command, self->expect_data, self->data_checksum,
            &self->command_state, frame->data, frame->len, &body,
            &self->command_error))
        break;
      g_clear_pointer (&frame, g_byte_array_unref);
      if (self->command_state == GOODIX5503_COMMAND_DONE)
        {
          self->command_response = g_steal_pointer (&body);
          break;
        }
    }

  if (self->command_error)
    goodix5503_command_fail (self, g_steal_pointer (&self->command_error));
  else if (self->command_response == NULL)
    goodix5503_submit_read (self);
  goodix5503_command_maybe_complete (self);
}

static void
goodix5503_submit_read (FpiDeviceGoodix5503 *self)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (self));

  self->read_active = TRUE;
  fpi_usb_transfer_fill_bulk (transfer, GOODIX5503_EP_IN,
                              GOODIX5503_TRANSFER_SIZE);
  fpi_usb_transfer_submit (transfer, GOODIX5503_TRANSFER_TIMEOUT_MS,
                           self->transaction_cancel, goodix5503_read_done,
                           NULL);
}

static void
goodix5503_command_start (FpiDeviceGoodix5503  *self,
                           guint8                 command,
                           const guint8          *payload,
                           gsize                  payload_len,
                           gboolean               expect_data,
                           gboolean               data_checksum,
                           Goodix5503CommandCallback callback)
{
  g_autoptr(GByteArray) packet = NULL;
  g_autoptr(GError) error = NULL;
  g_assert (self->command_callback == NULL);
  packet = goodix5503_packet_encode (command, payload, payload_len, TRUE,
                                     &error);
  if (packet == NULL)
    {
      callback (self, NULL, g_steal_pointer (&error));
      return;
    }

  self->transaction_cancel = g_cancellable_new ();
  if (self->frame_buffer == NULL)
    self->frame_buffer = goodix5503_frame_buffer_new ();
  self->command_state = GOODIX5503_COMMAND_WAIT_ACK;
  self->command_callback = callback;
  self->expected_command = command;
  self->expect_data = expect_data;
  self->data_checksum = data_checksum;
  self->out_done = FALSE;
  self->read_active = FALSE;

  /* Queue endpoint-82 IN before the fixed endpoint-01 OUT. */
  goodix5503_submit_read (self);
  goodix5503_usb_out_set (self, packet);
  self->delay_source = fpi_device_add_timeout (
    FP_DEVICE (self), GOODIX5503_QUEUED_OUT_DELAY_MS,
    goodix5503_command_delayed_out, NULL, NULL);
}

static void
goodix5503_outer_clear (FpiDeviceGoodix5503 *self)
{
  g_clear_object (&self->transaction_cancel);
  goodix5503_usb_out_clear (self);
  g_clear_pointer (&self->outer_response, g_byte_array_unref);
  g_clear_error (&self->outer_error);
  self->outer_callback = NULL;
  self->out_done = FALSE;
  self->read_active = FALSE;
  self->outer_expect_read = FALSE;
}

static void
goodix5503_outer_maybe_complete (FpiDeviceGoodix5503 *self)
{
  Goodix5503OuterCallback callback;
  GByteArray *response;
  GError *error;

  if (self->outer_callback == NULL || !self->out_done || self->read_active)
    return;
  if (self->outer_error == NULL && self->outer_response == NULL &&
      self->outer_expect_read)
    return;

  if (self->closing)
    {
      if (self->outer_response)
        OPENSSL_cleanse (self->outer_response->data, self->outer_response->len);
      goodix5503_outer_clear (self);
      goodix5503_close_finish (self);
      return;
    }
  callback = self->outer_callback;
  response = g_steal_pointer (&self->outer_response);
  error = g_steal_pointer (&self->outer_error);
  if (self->deactivating && error == NULL)
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                 "Goodix TLS operation cancelled");
  goodix5503_outer_clear (self);
  callback (self, response, error);
  if (self->deactivating && self->outer_callback == NULL &&
      self->command_callback == NULL)
    {
      self->deactivating = FALSE;
      fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (self), NULL);
    }
}

static void
goodix5503_outer_fail (FpiDeviceGoodix5503 *self, GError *error)
{
  if (self->outer_error == NULL)
    self->outer_error = error;
  else
    g_error_free (error);
  if (self->transaction_cancel)
    g_cancellable_cancel (self->transaction_cancel);
}

static void
goodix5503_outer_out_done (FpiUsbTransfer *transfer,
                            FpDevice       *device,
                            gpointer        user_data,
                            GError         *error)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  (void) transfer;
  (void) user_data;
  if (error)
    {
      self->out_done = TRUE;
      goodix5503_outer_fail (self, error);
    }
  else if (self->usb_out_offset < self->usb_out->len)
    {
      goodix5503_outer_submit_out (self);
      return;
    }
  else
    {
      self->out_done = TRUE;
      if (self->image_callback)
        self->stage = "image capture response";
    }
  goodix5503_outer_maybe_complete (self);
}

static void
goodix5503_outer_submit_out (FpiDeviceGoodix5503 *self)
{
  FpiUsbTransfer *transfer;
  guint8 *chunk;
  gsize chunk_len;

  g_assert (self->usb_out &&
            self->usb_out_offset + GOODIX5503_USB_PACKET_SIZE <=
              self->usb_out->len);
  chunk = goodix5503_padded_out_buffer (
    self->usb_out->data + self->usb_out_offset,
    GOODIX5503_USB_PACKET_SIZE, &chunk_len);
  self->usb_out_offset += GOODIX5503_USB_PACKET_SIZE;
  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk_full (transfer, GOODIX5503_EP_OUT, chunk,
                                   chunk_len, goodix5503_out_buffer_free);
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (transfer, GOODIX5503_TRANSFER_TIMEOUT_MS,
                           self->transaction_cancel, goodix5503_outer_out_done,
                           NULL);
}

static void goodix5503_outer_submit_read (FpiDeviceGoodix5503 *self);

static void
goodix5503_outer_process_buffer (FpiDeviceGoodix5503 *self)
{
  g_autoptr(GByteArray) frame = NULL;

  if (goodix5503_frame_buffer_take (self->frame_buffer, &frame,
                                    &self->outer_error))
    self->outer_response = g_steal_pointer (&frame);
  if (self->outer_error)
    goodix5503_outer_fail (self, g_steal_pointer (&self->outer_error));
  else if (self->outer_response == NULL)
    goodix5503_outer_submit_read (self);
  goodix5503_outer_maybe_complete (self);
}

static void
goodix5503_outer_read_done (FpiUsbTransfer *transfer,
                             FpDevice       *device,
                             gpointer        user_data,
                             GError         *error)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  (void) user_data;
  self->read_active = FALSE;
  if (error)
    {
      if (self->outer_error == NULL)
        goodix5503_outer_fail (self, error);
      else
        g_error_free (error);
      goodix5503_outer_maybe_complete (self);
      return;
    }
  if (!goodix5503_frame_buffer_append (self->frame_buffer, transfer->buffer,
                                       transfer->actual_length,
                                       &self->outer_error))
    {
      goodix5503_outer_fail (self, g_steal_pointer (&self->outer_error));
      goodix5503_outer_maybe_complete (self);
      return;
    }
  goodix5503_outer_process_buffer (self);
}

static void
goodix5503_outer_submit_read (FpiDeviceGoodix5503 *self)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (self));

  self->read_active = TRUE;
  fpi_usb_transfer_fill_bulk (transfer, GOODIX5503_EP_IN,
                              GOODIX5503_TRANSFER_SIZE);
  fpi_usb_transfer_submit (transfer, GOODIX5503_TRANSFER_TIMEOUT_MS,
                           self->transaction_cancel,
                           goodix5503_outer_read_done, NULL);
}

static void
goodix5503_outer_delayed_out (FpDevice *device, gpointer user_data)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  (void) user_data;
  self->delay_source = NULL;
  if (self->image_callback)
    self->stage = "image capture OUT";
  goodix5503_outer_submit_out (self);
}

static void
goodix5503_outer_start_delayed (FpiDeviceGoodix5503 *self,
                                 GByteArray          *packet,
                                 gboolean             expect_read,
                                 guint                out_delay_ms,
                                 Goodix5503OuterCallback callback)
{
  g_assert (self->command_callback == NULL && self->outer_callback == NULL);
  g_assert (packet != NULL || expect_read);
  self->transaction_cancel = g_cancellable_new ();
  if (self->frame_buffer == NULL)
    self->frame_buffer = goodix5503_frame_buffer_new ();
  self->outer_callback = callback;
  self->outer_expect_read = expect_read;
  self->out_done = packet == NULL;
  self->read_active = FALSE;

  if (expect_read && goodix5503_frame_buffer_length (self->frame_buffer) > 0)
    {
      g_assert (packet == NULL);
      goodix5503_outer_process_buffer (self);
      return;
    }
  if (expect_read)
    goodix5503_outer_submit_read (self);
  if (packet)
    {
      goodix5503_usb_out_set (self, packet);
      if (out_delay_ms > 0)
        self->delay_source = fpi_device_add_timeout (
          FP_DEVICE (self), out_delay_ms, goodix5503_outer_delayed_out,
          NULL, NULL);
      else
        goodix5503_outer_submit_out (self);
    }
}

static void
goodix5503_outer_start (FpiDeviceGoodix5503 *self,
                         GByteArray          *packet,
                         gboolean             expect_read,
                         Goodix5503OuterCallback callback)
{
  goodix5503_outer_start_delayed (self, packet, expect_read, 0, callback);
}

static void goodix5503_activation_fail (FpiDeviceGoodix5503 *self,
                                        GError              *error);

static void
goodix5503_pre_reset_fail (FpiDeviceGoodix5503 *self, GError *error)
{
  if (error && self->stage)
    g_prefix_error (&error, "%s: ", self->stage);
  g_clear_pointer (&self->tls, goodix5503_tls_free);
  g_clear_pointer (&self->frame_buffer, goodix5503_frame_buffer_free);
  OPENSSL_cleanse (self->psk, sizeof self->psk);
  OPENSSL_cleanse (self->expected_verification,
                   sizeof self->expected_verification);
  OPENSSL_cleanse (self->otp, sizeof self->otp);
  OPENSSL_cleanse (self->dac, sizeof self->dac);
  OPENSSL_cleanse (self->config, sizeof self->config);
  OPENSSL_cleanse (self->fresh_raw, sizeof self->fresh_raw);
  OPENSSL_cleanse (self->fresh_transformed, sizeof self->fresh_transformed);
  OPENSSL_cleanse (self->background, sizeof self->background);
  OPENSSL_cleanse (self->finger, sizeof self->finger);
  goodix5503_warm_invalidate (self);
  self->session_clean = FALSE;
  self->activation_reported = TRUE;
  goodix5503_fdt_session_reset (self);
  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self), error);
}

static void
goodix5503_cleanup_done (FpiDeviceGoodix5503 *self,
                          GByteArray          *body,
                          GError              *error)
{
  g_clear_pointer (&body, g_byte_array_unref);
  g_clear_error (&error);
  self->cleanup_active = FALSE;
  self->reset_attempted = FALSE;
  g_clear_pointer (&self->tls, goodix5503_tls_free);
  g_clear_pointer (&self->frame_buffer, goodix5503_frame_buffer_free);
  OPENSSL_cleanse (self->psk, sizeof self->psk);
  OPENSSL_cleanse (self->expected_verification,
                   sizeof self->expected_verification);
  OPENSSL_cleanse (self->otp, sizeof self->otp);
  OPENSSL_cleanse (self->dac, sizeof self->dac);
  OPENSSL_cleanse (self->config, sizeof self->config);
  OPENSSL_cleanse (self->fresh_raw, sizeof self->fresh_raw);
  OPENSSL_cleanse (self->fresh_transformed, sizeof self->fresh_transformed);
  OPENSSL_cleanse (self->background, sizeof self->background);
  OPENSSL_cleanse (self->finger, sizeof self->finger);
  goodix5503_warm_invalidate (self);
  self->session_clean = FALSE;
  goodix5503_fdt_session_reset (self);
  if (self->activated)
    {
      self->activated = FALSE;
      self->deactivating = FALSE;
      g_clear_error (&self->primary_error);
      fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (self), NULL);
    }
  else
    fpi_image_device_activate_complete (
      FP_IMAGE_DEVICE (self), g_steal_pointer (&self->primary_error));
}

static void
goodix5503_activation_fail (FpiDeviceGoodix5503 *self, GError *error)
{
  static const guint8 reset_payload[] = { 0x05, 0x14 };

  if (error && self->primary_error == NULL && self->stage)
    g_prefix_error (&error, "%s: ", self->stage);
  fp_dbg ("ACTIVATION_FAIL: stage=%s reset_attempted=%d deactivating=%d err=%s",
          self->stage ? self->stage : "?", self->reset_attempted,
          self->deactivating, error ? error->message : "none");
  self->session_clean = FALSE;
  if (self->primary_error == NULL)
    self->primary_error = error;
  else
    g_clear_error (&error);
  if (!self->reset_attempted || self->cleanup_active)
    {
      goodix5503_pre_reset_fail (self,
                                 g_steal_pointer (&self->primary_error));
      return;
    }

  self->cleanup_active = TRUE;
  goodix5503_command_start (self, GOODIX5503_COMMAND_RESET,
                            reset_payload, sizeof reset_payload, TRUE, TRUE,
                            goodix5503_cleanup_done);
}

static void
goodix5503_capture_frame_done (FpiDeviceGoodix5503 *self,
                                GByteArray          *frame,
                                GError              *error)
{
  g_autoptr(GByteArray) owned_frame = frame;
  g_autoptr(GByteArray) envelope = NULL;
  g_autoptr(GByteArray) plaintext = NULL;
  Goodix5503ImageCallback callback;

  if (error ||
      !goodix5503_capture_consume_frame (&self->capture_state,
                                         frame ? frame->data : NULL,
                                         frame ? frame->len : 0,
                                         &envelope, &error))
    goto fail;
  if (frame)
    OPENSSL_cleanse (frame->data, frame->len);
  if (!self->capture_state.done)
    {
      if (self->capture_state.image_prelude)
        self->stage = "image capture encrypted envelope";
      else if (self->capture_state.ack)
        self->stage = "image capture after ACK";
      goodix5503_outer_start (self, NULL, TRUE,
                              goodix5503_capture_frame_done);
      return;
    }

  if (!goodix5503_tls_feed_ciphertext (self->tls,
                                        envelope->data + 9,
                                        envelope->len - 9, &error))
    goto fail;
  plaintext = goodix5503_tls_take_plaintext (self->tls, &error);
  if (plaintext == NULL || plaintext->len != GOODIX5503_MAX_TLS_PLAINTEXT)
    {
      if (error == NULL)
        error = g_error_new_literal (GOODIX5503_TLS_ERROR,
                                     GOODIX5503_TLS_ERROR_LENGTH,
                                     "invalid Goodix image plaintext length");
      goto fail;
    }
  if (self->capture_destination == GOODIX5503_CAPTURE_BACKGROUND)
    memcpy (self->background, plaintext->data,
            GOODIX5503_PACKED_IMAGE_SIZE);
  else if (self->capture_destination == GOODIX5503_CAPTURE_FINGER)
    memcpy (self->finger, plaintext->data, GOODIX5503_PACKED_IMAGE_SIZE);
  OPENSSL_cleanse (envelope->data, envelope->len);
  OPENSSL_cleanse (plaintext->data, plaintext->len);
  callback = self->image_callback;
  self->image_callback = NULL;
  callback (self, NULL);
  return;

fail:
  if (frame)
    OPENSSL_cleanse (frame->data, frame->len);
  if (envelope)
    OPENSSL_cleanse (envelope->data, envelope->len);
  if (plaintext)
    OPENSSL_cleanse (plaintext->data, plaintext->len);
  if (error && (self->deactivating || self->closing ||
                g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
                g_error_matches (error, G_USB_DEVICE_ERROR,
                                 G_USB_DEVICE_ERROR_CANCELLED)))
    {
      /* Externally initiated cancellation: never a device fault, so the
       * warm state survives. */
      self->image_callback = NULL;
      return;
    }
  callback = self->image_callback;
  self->image_callback = NULL;
  callback (self, error);
}

static void
goodix5503_capture_image (FpiDeviceGoodix5503 *self,
                           guint                destination,
                           Goodix5503ImageCallback callback)
{
  guint8 payload[10] = { 0x01, 0x00 };
  g_autoptr(GByteArray) packet = NULL;
  g_autoptr(GError) error = NULL;

  g_assert (self->image_callback == NULL);
  memcpy (payload + 2, self->dac, sizeof self->dac);
  packet = goodix5503_packet_encode (0x20, payload, sizeof payload, TRUE,
                                     &error);
  OPENSSL_cleanse (payload, sizeof payload);
  if (packet == NULL)
    {
      callback (self, g_steal_pointer (&error));
      return;
    }
  memset (&self->capture_state, 0, sizeof self->capture_state);
  self->capture_destination = destination;
  self->image_callback = callback;
  self->stage = destination == GOODIX5503_CAPTURE_BACKGROUND
                  ? "fresh-base background capture queued read"
                  : "image capture queued read";
  goodix5503_outer_start_delayed (self, packet, TRUE,
                                  GOODIX5503_QUEUED_OUT_DELAY_MS,
                                  goodix5503_capture_frame_done);
}

static void goodix5503_fresh_attempt_start (FpiDeviceGoodix5503 *self);

static gboolean
goodix5503_parse_fdt_slot (FpiDeviceGoodix5503 *self,
                            guint                 slot,
                            GByteArray           *body,
                            GError              **error)
{
  guint16 interrupt = 0;
  guint16 touch_flag = 0;
  gboolean parsed;

  parsed = goodix5503_parse_fdt_response (
    body->data, body->len, &interrupt, &touch_flag,
    self->fresh_raw[slot], self->fresh_transformed[slot], error);
  OPENSSL_cleanse (&interrupt, sizeof interrupt);
  OPENSSL_cleanse (&touch_flag, sizeof touch_flag);
  return parsed;
}

static void
goodix5503_fresh_retry_delay (FpDevice *device, gpointer user_data)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  (void) user_data;
  self->delay_source = NULL;
  goodix5503_fresh_attempt_start (self);
}

static void
goodix5503_fresh_retry (FpiDeviceGoodix5503 *self)
{
  OPENSSL_cleanse (self->fresh_raw, sizeof self->fresh_raw);
  OPENSSL_cleanse (self->fresh_transformed, sizeof self->fresh_transformed);
  OPENSSL_cleanse (self->background, sizeof self->background);
  self->fresh_attempt++;
  if (self->fresh_attempt >= GOODIX5503_MAX_FRESH_ATTEMPTS)
    {
      goodix5503_activation_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                        "Goodix fresh FDT base did not stabilize"));
      return;
    }
  /* On-demand activation races the user's finger: the fingerprint prompt
   * appears while the fresh-base sequence is still running, and read pairs
   * taken under a changing touch never stabilize. Space the attempts out so
   * a held finger can be lifted without exhausting the budget. */
  self->delay_source = fpi_device_add_timeout (
    FP_DEVICE (self), GOODIX5503_FRESH_RETRY_MS,
    goodix5503_fresh_retry_delay, NULL, NULL);
}

static void
goodix5503_fdt2_done (FpiDeviceGoodix5503 *self,
                      GByteArray          *body,
                      GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;

  if (error || !goodix5503_parse_fdt_slot (self, 2, body, &error))
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  if (!goodix5503_fdt_bases_within_delta (self->fresh_raw[1],
                                           self->fresh_raw[2],
                                           self->fdt_delta))
    {
      goodix5503_fresh_retry (self);
      return;
    }

  goodix5503_fdt_session_reset (self);
  memcpy (self->fdt_runtime.down_base, self->fresh_transformed[2],
          sizeof self->fdt_runtime.down_base);

  /* Arm the warm-session state: the powered sensor now holds the TLS
   * session, runtime configuration and calibration across host releases,
   * so the next activation can skip the cold sequence. */
  self->warm.probe_retries = 0;
  self->session_clean = TRUE;
  memcpy (self->warm.dac, self->dac, sizeof self->warm.dac);
  self->warm.delta = self->fdt_delta;
  memcpy (self->warm.down_base, self->fdt_runtime.down_base,
          sizeof self->warm.down_base);
  memcpy (self->warm.background, self->background,
          sizeof self->warm.background);
  OPENSSL_cleanse (self->fresh_raw, sizeof self->fresh_raw);
  OPENSSL_cleanse (self->fresh_transformed, sizeof self->fresh_transformed);
  OPENSSL_cleanse (self->psk, sizeof self->psk);
  OPENSSL_cleanse (self->expected_verification,
                   sizeof self->expected_verification);
  OPENSSL_cleanse (self->otp, sizeof self->otp);
  OPENSSL_cleanse (self->config, sizeof self->config);
  self->activated = TRUE;
  if (!self->activation_reported)
    {
      self->activation_reported = TRUE;
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self), NULL);
    }
}

static void
goodix5503_candidate_done (FpiDeviceGoodix5503 *self, GError *error)
{
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE];
  guint8 zero_base[GOODIX5503_FDT_BASE_SIZE] = { 0 };

  if (error || !goodix5503_build_fdt_request (0x0d, self->dac, zero_base,
                                               request, &error))
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "fresh-base FDT 3";
  goodix5503_command_start (self, GOODIX5503_COMMAND_FDT_MANUAL,
                            request, sizeof request, TRUE, TRUE,
                            goodix5503_fdt2_done);
  OPENSSL_cleanse (request, sizeof request);
}

static void
goodix5503_delta_done (FpiDeviceGoodix5503 *self,
                       GByteArray          *body,
                       GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  guint16 delta = 0;

  if (error ||
      !goodix5503_parse_delta_response (body ? body->data : NULL,
                                        body ? body->len : 0,
                                        &delta, &error))
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->fdt_delta = delta;
  if (!goodix5503_fdt_bases_within_delta (self->fresh_raw[0],
                                           self->fresh_raw[1],
                                           self->fdt_delta))
    {
      goodix5503_fresh_retry (self);
      return;
    }
  goodix5503_capture_image (self, GOODIX5503_CAPTURE_BACKGROUND,
                            goodix5503_candidate_done);
}

static void
goodix5503_idle_done (FpiDeviceGoodix5503 *self,
                      GByteArray          *body,
                      GError              *error)
{
  static const guint8 delta_payload[] = { 0x00, 0x82, 0x00, 0x02, 0x00 };

  g_clear_pointer (&body, g_byte_array_unref);
  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "fresh-base delta read";
  goodix5503_command_start (self, GOODIX5503_COMMAND_READ_REGISTER,
                            delta_payload, sizeof delta_payload, TRUE, TRUE,
                            goodix5503_delta_done);
}

static void
goodix5503_fdt1_done (FpiDeviceGoodix5503 *self,
                      GByteArray          *body,
                      GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  static const guint8 idle_payload[] = { 0x14, 0x00 };

  if (error || !goodix5503_parse_fdt_slot (self, 1, body, &error))
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "fresh-base idle";
  goodix5503_command_start (self, GOODIX5503_COMMAND_IDLE,
                            idle_payload, sizeof idle_payload, FALSE, TRUE,
                            goodix5503_idle_done);
}

static void
goodix5503_nav_done (FpiDeviceGoodix5503 *self, GError *error)
{
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE];
  guint8 zero_base[GOODIX5503_FDT_BASE_SIZE] = { 0 };

  if (error || !goodix5503_build_fdt_request (0x0d, self->dac, zero_base,
                                               request, &error))
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "fresh-base FDT 2";
  goodix5503_command_start (self, GOODIX5503_COMMAND_FDT_MANUAL,
                            request, sizeof request, TRUE, TRUE,
                            goodix5503_fdt1_done);
  OPENSSL_cleanse (request, sizeof request);
}

static void
goodix5503_fdt0_done (FpiDeviceGoodix5503 *self,
                      GByteArray          *body,
                      GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;

  if (error || !goodix5503_parse_fdt_slot (self, 0, body, &error))
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "fresh-base discard capture";
  goodix5503_capture_image (self, GOODIX5503_CAPTURE_DISCARD,
                            goodix5503_nav_done);
}

static void
goodix5503_fresh_attempt_start (FpiDeviceGoodix5503 *self)
{
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE];
  guint8 zero_base[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  g_autoptr(GError) error = NULL;

  if (!goodix5503_build_fdt_request (0x0d, self->dac, zero_base,
                                     request, &error))
    {
      goodix5503_activation_fail (self, g_steal_pointer (&error));
      return;
    }
  self->stage = "fresh-base FDT 1";
  goodix5503_command_start (self, GOODIX5503_COMMAND_FDT_MANUAL,
                            request, sizeof request, TRUE, TRUE,
                            goodix5503_fdt0_done);
  OPENSSL_cleanse (request, sizeof request);
}

static void
goodix5503_driver_state_done (FpiDeviceGoodix5503 *self,
                               GByteArray          *body,
                               GError              *error)
{
  g_clear_pointer (&body, g_byte_array_unref);
  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->fresh_attempt = 0;
  goodix5503_fresh_attempt_start (self);
}

static void
goodix5503_config_done (FpiDeviceGoodix5503 *self,
                        GByteArray          *body,
                        GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  static const guint8 state_payload[] = { 0x01, 0x00 };

  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  if (body->len < 1 || body->len > 2 || body->data[0] != 1)
    {
      goodix5503_activation_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                        "Goodix config upload was rejected"));
      return;
    }
  self->stage = "driver-state command";
  goodix5503_command_start (self, GOODIX5503_COMMAND_DRIVER_STATE,
                            state_payload, sizeof state_payload, FALSE, TRUE,
                            goodix5503_driver_state_done);
}

static void
goodix5503_tls_completion_done (FpiDeviceGoodix5503 *self,
                                 GByteArray          *frame,
                                 GError              *error)
{
  g_autoptr(GByteArray) owned_frame = frame;
  g_autoptr(GByteArray) body = NULL;

  if (error && g_error_matches (error, G_USB_DEVICE_ERROR,
                                G_USB_DEVICE_ERROR_TIMED_OUT))
    g_clear_error (&error);
  if (error ||
      (frame &&
       (!goodix5503_packet_decode (frame->data, frame->len,
                                   GOODIX5503_COMMAND_TLS, TRUE,
                                   &body, &error) ||
        body->len > 16)))
    {
      if (error == NULL)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                          "invalid Goodix TLS completion");
      if (frame)
        OPENSSL_cleanse (frame->data, frame->len);
      if (body)
        OPENSSL_cleanse (body->data, body->len);
      goodix5503_activation_fail (self, error);
      return;
    }
  if (frame)
    OPENSSL_cleanse (frame->data, frame->len);
  if (body)
    OPENSSL_cleanse (body->data, body->len);
  self->stage = "configuration upload";
  goodix5503_command_start (self, GOODIX5503_COMMAND_CONFIG,
                            self->config, sizeof self->config, TRUE, TRUE,
                            goodix5503_config_done);
}

static void
goodix5503_tls_final_sent (FpiDeviceGoodix5503 *self,
                           GByteArray          *frame,
                           GError              *error)
{
  g_clear_pointer (&frame, g_byte_array_unref);
  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "TLS device completion";
  goodix5503_outer_start (self, NULL, TRUE,
                          goodix5503_tls_completion_done);
}

static void
goodix5503_tls_client_finished (FpiDeviceGoodix5503 *self,
                                GByteArray          *frame,
                                GError              *error)
{
  g_autoptr(GByteArray) owned_frame = frame;
  g_autoptr(GByteArray) payload = NULL;
  g_autoptr(GByteArray) flight = NULL;
  g_autoptr(GByteArray) packet = NULL;

  if (error ||
      !goodix5503_outer_decode (frame ? frame->data : NULL,
                                frame ? frame->len : 0,
                                GOODIX5503_TLS_FLAGS, &payload, &error) ||
      !goodix5503_tls_feed_ciphertext (self->tls, payload->data,
                                       payload->len, &error))
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->tls_client_frames++;
  if (self->tls_client_frames < GOODIX5503_MAX_TLS_CLIENT_FRAMES)
    {
      self->stage = "TLS client handshake frames";
      goodix5503_outer_start (self, NULL, TRUE,
                              goodix5503_tls_client_finished);
      return;
    }
  if (self->tls_client_frames != GOODIX5503_MAX_TLS_CLIENT_FRAMES ||
      !goodix5503_tls_is_established (self->tls))
    {
      goodix5503_activation_fail (
        self, g_error_new_literal (GOODIX5503_TLS_ERROR,
                                   GOODIX5503_TLS_ERROR_PROTOCOL,
                                   "Goodix TLS handshake did not finish"));
      return;
    }
  flight = goodix5503_tls_drain_ciphertext (self->tls, &error);
  if (flight == NULL || flight->len == 0 ||
      (packet = goodix5503_outer_encode (GOODIX5503_TLS_FLAGS,
                                         flight->data, flight->len,
                                         &error)) == NULL)
    {
      if (error == NULL)
        error = g_error_new_literal (GOODIX5503_TLS_ERROR,
                                     GOODIX5503_TLS_ERROR_PROTOCOL,
                                     "Goodix TLS final server flight is empty");
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "TLS final server flight";
  goodix5503_outer_start (self, packet, FALSE, goodix5503_tls_final_sent);
}

static void
goodix5503_tls_client_hello (FpiDeviceGoodix5503 *self,
                             GByteArray          *frame,
                             GError              *error)
{
  g_autoptr(GByteArray) owned_frame = frame;
  g_autoptr(GByteArray) payload = NULL;
  g_autoptr(GByteArray) flight = NULL;
  g_autoptr(GByteArray) packet = NULL;

  if (error ||
      !goodix5503_outer_decode (frame ? frame->data : NULL,
                                frame ? frame->len : 0,
                                GOODIX5503_TLS_FLAGS, &payload, &error) ||
      !goodix5503_tls_feed_ciphertext (self->tls, payload->data,
                                       payload->len, &error))
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  flight = goodix5503_tls_drain_ciphertext (self->tls, &error);
  if (flight == NULL || flight->len == 0 ||
      (packet = goodix5503_outer_encode (GOODIX5503_TLS_FLAGS,
                                         flight->data, flight->len,
                                         &error)) == NULL)
    {
      if (error == NULL)
        error = g_error_new_literal (GOODIX5503_TLS_ERROR,
                                     GOODIX5503_TLS_ERROR_PROTOCOL,
                                     "Goodix TLS first server flight is empty");
      goodix5503_activation_fail (self, error);
      return;
    }
  self->tls_client_frames = 0;
  self->stage = "TLS client handshake frames";
  goodix5503_outer_start (self, packet, TRUE,
                          goodix5503_tls_client_finished);
}

static void
goodix5503_tls_request_done (FpiDeviceGoodix5503 *self,
                              GByteArray          *body,
                              GError              *error)
{
  g_clear_pointer (&body, g_byte_array_unref);
  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->tls = goodix5503_tls_new (self->psk, &error);
  if (self->tls == NULL)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "TLS client hello";
  goodix5503_outer_start (self, NULL, TRUE, goodix5503_tls_client_hello);
}

static void
goodix5503_pov_done (FpiDeviceGoodix5503 *self,
                      GByteArray          *body,
                      GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  static const guint8 tls_payload[] = { 0x00, 0x00 };

  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  if (body->len > 1)
    {
      goodix5503_activation_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                        "invalid Goodix POV response"));
      return;
    }
  self->stage = "TLS command";
  goodix5503_command_start (self, GOODIX5503_COMMAND_TLS,
                            tls_payload, sizeof tls_payload, FALSE, TRUE,
                            goodix5503_tls_request_done);
}

static void
goodix5503_otp_done (FpiDeviceGoodix5503 *self,
                      GByteArray          *body,
                      GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  static const guint8 pov_payload[] = { 0x00, 0x00 };

  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  if (body->len != GOODIX5503_OTP_SIZE)
    {
      goodix5503_activation_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                        "invalid Goodix OTP length"));
      return;
    }
  memcpy (self->otp, body->data, sizeof self->otp);
  OPENSSL_cleanse (body->data, body->len);
  if (!goodix5503_otp_has_valid_integrity (self->otp) ||
      !goodix5503_derive_dac (self->otp, self->dac, &error) ||
      !goodix5503_build_runtime_config (self->otp, self->config, &error))
    {
      if (error == NULL)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                          "Goodix OTP integrity failed");
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "POV check";
  goodix5503_command_start (self, GOODIX5503_COMMAND_POV_CHECK,
                            pov_payload, sizeof pov_payload, TRUE, TRUE,
                            goodix5503_pov_done);
}

static void
goodix5503_cold_nop_done (FpiDeviceGoodix5503 *self,
                           GByteArray          *body,
                           GError              *error)
{
  static const guint8 otp_payload[] = { 0x00, 0x00 };

  g_clear_pointer (&body, g_byte_array_unref);
  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  self->stage = "OTP read";
  goodix5503_command_start (self, GOODIX5503_COMMAND_READ_OTP,
                            otp_payload, sizeof otp_payload, TRUE, TRUE,
                            goodix5503_otp_done);
}

static void
goodix5503_chip_done (FpiDeviceGoodix5503 *self,
                       GByteArray          *body,
                       GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  static const guint8 nop_payload[] = { 0x00, 0x00, 0x00, 0x00 };
  guint32 normalized;
  guint32 chip_id;

  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  if (body->len != 4)
    {
      goodix5503_activation_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                        "invalid Goodix chip-ID response"));
      return;
    }
  normalized = body->data[1] | ((guint32) body->data[0] << 8) |
               ((guint32) body->data[3] << 16) |
               ((guint32) body->data[2] << 24);
  chip_id = normalized >> 8;
  if (chip_id != GOODIX5503_EXPECTED_CHIP_ID)
    {
      goodix5503_activation_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                        "unsupported Goodix MCU chip ID"));
      return;
    }
  self->stage = "post-reset NOP";
  goodix5503_command_start (self, GOODIX5503_COMMAND_NOP,
                            nop_payload, sizeof nop_payload, FALSE, TRUE,
                            goodix5503_cold_nop_done);
}

static void
goodix5503_read_chip_after_reset (FpDevice *device, gpointer user_data)
{
  static const guint8 payload[] = { 0x00, 0x00, 0x00, 0x04, 0x00 };

  (void) user_data;
  FPI_DEVICE_GOODIX5503 (device)->delay_source = NULL;
  FPI_DEVICE_GOODIX5503 (device)->stage = "chip-ID read";
  goodix5503_command_start (FPI_DEVICE_GOODIX5503 (device),
                            GOODIX5503_COMMAND_READ_REGISTER,
                            payload, sizeof payload, TRUE, TRUE,
                            goodix5503_chip_done);
}

static void
goodix5503_reset_done (FpiDeviceGoodix5503 *self,
                        GByteArray          *body,
                        GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;

  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  if (body->len > 4)
    {
      goodix5503_activation_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                        "invalid Goodix reset response"));
      return;
    }
  self->delay_source = fpi_device_add_timeout (
    FP_DEVICE (self), 10, goodix5503_read_chip_after_reset, NULL, NULL);
}

static guint32
read_le32 (const guint8 *data)
{
  return (guint32) data[0] | ((guint32) data[1] << 8) |
         ((guint32) data[2] << 16) | ((guint32) data[3] << 24);
}

static void
goodix5503_verification_done (FpiDeviceGoodix5503 *self,
                              GByteArray          *body,
                              GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  gboolean valid;

  if (error)
    {
      goodix5503_pre_reset_fail (self, error);
      return;
    }
  valid = body->len == 41 && body->data[0] == 0 &&
          read_le32 (body->data + 1) == GOODIX5503_R_PSK_HASH_SELECTOR &&
          read_le32 (body->data + 5) == GOODIX5503_VERIFICATION_SIZE &&
          goodix5503_verification_equal (body->data + 9,
                                         self->expected_verification);
  OPENSSL_cleanse (body->data, body->len);
  if (!valid)
    {
      goodix5503_pre_reset_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                        "Goodix device PSK verification failed"));
      return;
    }

  {
    static const guint8 reset_payload[] = { 0x05, 0x14 };

    self->reset_attempted = TRUE;
    self->stage = "device reset";
    goodix5503_command_start (self, GOODIX5503_COMMAND_RESET,
                              reset_payload, sizeof reset_payload, TRUE, TRUE,
                              goodix5503_reset_done);
  }
}

static void
goodix5503_firmware_done (FpiDeviceGoodix5503 *self,
                           GByteArray          *body,
                           GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;

  if (error)
    {
      goodix5503_pre_reset_fail (self, error);
      return;
    }
  if (!goodix5503_firmware_identity_matches (body, expected_firmware) &&
      !goodix5503_firmware_identity_matches (body,
                                              expected_post_reset_firmware))
    {
      g_autofree gchar *identity = NULL;
      gsize text_len = 0;
      gboolean printable = TRUE;

      while (text_len < body->len && body->data[text_len] != 0)
        {
          printable &= g_ascii_isprint (body->data[text_len]);
          text_len++;
        }
      if (printable && text_len < body->len)
        identity = g_strndup ((const gchar *) body->data, text_len);
      goodix5503_pre_reset_fail (
        self, fpi_device_error_new_msg (
          FP_DEVICE_ERROR_NOT_SUPPORTED,
          "unsupported Goodix 5503 firmware identity: %s",
          identity ? identity : "non-printable response"));
      return;
    }

  if (!goodix5503_disable_process_dumps (&error) ||
      !goodix5503_load_host_psk (self->psk, &error) ||
      !goodix5503_derive_verification_record (
        self->psk, self->expected_verification, &error))
    {
      goodix5503_pre_reset_fail (self, error);
      return;
    }
  {
    static const guint8 payload[] = {
      0x07, 0x00, 0x02, 0xbb, 0x00, 0x00, 0x00, 0x00,
    };

    self->stage = "PSK verification";
    goodix5503_command_start (self, GOODIX5503_COMMAND_READ_PSK,
                              payload, sizeof payload, TRUE, TRUE,
                              goodix5503_verification_done);
  }
}

static void
goodix5503_nop_done (FpiDeviceGoodix5503 *self,
                     GByteArray          *body,
                     GError              *error)
{
  static const guint8 payload[] = { 0x00, 0x00 };

  g_clear_pointer (&body, g_byte_array_unref);
  if (error)
    {
      goodix5503_pre_reset_fail (self, error);
      return;
    }
  self->stage = "firmware identity";
  goodix5503_command_start (self, GOODIX5503_COMMAND_FIRMWARE,
                            payload, sizeof payload, TRUE, TRUE,
                            goodix5503_firmware_done);
}

static void
goodix5503_open (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);
  g_autoptr(GError) error = NULL;

  if (!g_usb_device_claim_interface (
        fpi_device_get_usb_device (FP_DEVICE (device)), 0, 0, &error))
    {
      fpi_image_device_open_complete (device, g_steal_pointer (&error));
      return;
    }
  self->interface_claimed = TRUE;
  fpi_image_device_open_complete (device, NULL);
}

static void
goodix5503_close_finish (FpiDeviceGoodix5503 *self)
{
  g_autoptr(GError) error = NULL;

  g_assert (self->command_callback == NULL && self->outer_callback == NULL);
  fp_dbg ("close_finish entry: warm=%d", goodix5503_warm_available (self));
  self->closing = FALSE;
  if (self->delay_source)
    {
      g_source_destroy (self->delay_source);
      self->delay_source = NULL;
    }
  goodix5503_command_clear (self);
  goodix5503_outer_clear (self);
  g_clear_pointer (&self->frame_buffer, goodix5503_frame_buffer_free);
  if (self->tls != NULL)
    {
      /* Always stash the live TLS context and current calibration: the
       * powered sensor retains them across the close, and the next
       * activation revalidates the idle envelope with its probe. */
      fp_dbg ("warm state stashed across close");
      self->warm.tls = g_steal_pointer (&self->tls);
      memcpy (self->warm.dac, self->dac, sizeof self->warm.dac);
      self->warm.delta = self->fdt_delta;
      memcpy (self->warm.down_base, self->fdt_runtime.down_base,
              sizeof self->warm.down_base);
      memcpy (self->warm.background, self->background,
              sizeof self->warm.background);
    }
  else if (self->warm.tls != NULL)
    {
      g_clear_pointer (&self->warm.tls, goodix5503_tls_free);
    }
  OPENSSL_cleanse (self->psk, sizeof self->psk);
  OPENSSL_cleanse (self->expected_verification,
                   sizeof self->expected_verification);
  OPENSSL_cleanse (self->otp, sizeof self->otp);
  OPENSSL_cleanse (self->dac, sizeof self->dac);
  OPENSSL_cleanse (self->config, sizeof self->config);
  OPENSSL_cleanse (self->fresh_raw, sizeof self->fresh_raw);
  OPENSSL_cleanse (self->fresh_transformed, sizeof self->fresh_transformed);
  OPENSSL_cleanse (self->background, sizeof self->background);
  OPENSSL_cleanse (self->finger, sizeof self->finger);
  goodix5503_fdt_session_reset (self);
  g_clear_error (&self->primary_error);
  if (self->interface_claimed)
    {
      g_usb_device_release_interface (
        fpi_device_get_usb_device (FP_DEVICE (self)), 0, 0, &error);
      self->interface_claimed = FALSE;
    }
  fpi_image_device_close_complete (FP_IMAGE_DEVICE (self),
                                   g_steal_pointer (&error));
}

static void
goodix5503_close (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  if (self->transaction_cancel || self->command_callback ||
      self->outer_callback || self->read_active)
    {
      self->closing = TRUE;
      if (self->transaction_cancel)
        g_cancellable_cancel (self->transaction_cancel);
      return;
    }
  goodix5503_close_finish (self);
}

static void goodix5503_warm_probe_done (FpiDeviceGoodix5503 *self,
                                        GByteArray          *body,
                                        GError              *error);

static void
goodix5503_activate (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);
  static const guint8 payload[] = { 0x00, 0x00, 0x00, 0x00 };

  fp_dbg ("activate entry: warm=%d", goodix5503_warm_available (self));
  self->activation_reported = FALSE;
  if (goodix5503_warm_available (self))
    {
      /* Warm re-activation: the sensor kept power across the host-side
       * release and close, so the TLS session, runtime configuration and
       * the idle-calibrated base survive indefinitely. Hardware-verified
       * (2026-08-30): restoring the state and arming detects a finger
       * immediately — whether it is already resting on the sensor (the
       * 0x32 event fires within ~60 ms of the arm) or arrives later. No
       * probe is needed; if the device state was lost (suspend, power
       * cycle) the arm completion falls back to the cold sequence. */
      memcpy (self->dac, self->warm.dac, sizeof self->dac);
      self->fdt_delta = self->warm.delta;
      memcpy (self->fdt_runtime.down_base, self->warm.down_base,
              sizeof self->fdt_runtime.down_base);
      memcpy (self->background, self->warm.background,
              sizeof self->warm.background);
      if (self->warm.tls != NULL)
        {
          /* Reopen after a close: adopt the stashed context. Without an
           * intervening close the live context never left self->tls and
           * warm.tls is NULL. */
          self->tls = g_steal_pointer (&self->warm.tls);
        }
      self->session_clean = TRUE;
      self->warm_rearmed = TRUE;

      self->stage = "warm probe";
      fp_dbg ("warm activation: state restored; probing to absorb residual/drift");
      guint8 request[GOODIX5503_FDT_REQUEST_SIZE];
      g_autoptr(GError) error = NULL;

      if (goodix5503_build_fdt_request (0x0d, self->dac,
                                        self->fdt_runtime.down_base, request,
                                        &error))
        {
          goodix5503_command_start (self, GOODIX5503_COMMAND_FDT_MANUAL,
                                    request, sizeof request, TRUE, TRUE,
                                    goodix5503_warm_probe_done);
          OPENSSL_cleanse (request, sizeof request);
          return;
        }
      self->warm_rearmed = TRUE;
      self->activated = TRUE;
      self->activation_reported = TRUE;
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self), NULL);
      return;
    }

  goodix5503_warm_invalidate (self);
  self->stage = "preflight NOP";
  fp_dbg ("cold activation sequence start");
  goodix5503_command_start (FPI_DEVICE_GOODIX5503 (device),
                            GOODIX5503_COMMAND_NOP,
                            payload, sizeof payload, FALSE, TRUE,
                            goodix5503_nop_done);
}

static void
goodix5503_warm_probe_done (FpiDeviceGoodix5503 *self,
                            GByteArray          *body,
                            GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  guint16 interrupt = 0;
  guint16 touch_flag = 0;
  guint8 raw[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint8 transformed[GOODIX5503_FDT_BASE_SIZE] = { 0 };

  if (error || !goodix5503_parse_fdt_response (body ? body->data : NULL,
                                               body ? body->len : 0, &interrupt,
                                               &touch_flag, raw, transformed,
                                               &error))
    {
      fp_dbg ("warm probe failed: %s", error ? error->message : "unknown");
      if (self->deactivating || self->closing)
        {
          /* Release-path cancellation: the warm state survives. */
          return;
        }
      if (!g_error_matches (error, G_USB_DEVICE_ERROR,
                            G_USB_DEVICE_ERROR_TIMED_OUT) &&
          self->warm.probe_retries < 2)
        {
          /* A release cancellation can leave a stale frame queued; the
           * failed probe read consumed it. Re-probe before giving up. */
          self->warm.probe_retries++;
          goodix5503_activate (FP_IMAGE_DEVICE (self));
          return;
        }
      /* Silent device: the warm state did not survive. Recover with the
       * full cold sequence inside the same activation. */
      goodix5503_warm_invalidate (self);
      fp_dbg ("warm probe silent, falling back to cold path");
      goodix5503_activate (FP_IMAGE_DEVICE (self));
      return;
    }

  /* 吸收残影与漂移:按下检测基线重建为当前读数(官方抬指后基线更新的
   * 同款机制)。残影导致的“假按下”因此不再触发:稳定残影 ≈ 基线,
   * 只有真正的表面变化才会触发 0x32 事件。 */
  goodix5503_fdt_next_down_base (raw, self->fdt_runtime.down_base);
  memcpy (self->warm.down_base, self->fdt_runtime.down_base,
          sizeof self->warm.down_base);
  self->warm.probe_retries = 0;
  self->session_clean = TRUE;
  self->warm_rearmed = TRUE;

  self->stage = "warm re-arm";
  fp_dbg ("warm probe ok: base rebuilt from current idle");
  self->activated = TRUE;
  self->activation_reported = TRUE;
  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self), NULL);
}

static void
goodix5503_deactivate (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  fp_dbg ("deactivate entry: warm=%d clean=%d reset_attempted=%d deactivating=%d",
          goodix5503_warm_available (self), self->session_clean,
          self->reset_attempted, self->deactivating);
  self->deactivating = TRUE;
  self->warm_rearmed = FALSE;
  if (goodix5503_warm_available (self))
    {
      /* Keep the calibrated base, delta and TLS state for the warm
       * re-activation path; only clear the per-operation FDT session. */
      goodix5503_fdt_runtime_pending_clear (&self->fdt_runtime);
      goodix5503_fdt_coordinator_reset (&self->fdt_runtime.coordinator);
      fp_dbg ("deactivate: keeping warm state for next activation");
    }
  else
    {
      goodix5503_fdt_session_reset (self);
    }
  if (self->transaction_cancel)
    {
      /* A queued OUT may still be behind its 25 ms IN-first barrier. Let the
       * source submit against the cancelled cancellable so both callbacks
       * retire and the transaction can complete. */
      g_cancellable_cancel (self->transaction_cancel);
      return;
    }
  if (self->delay_source)
    {
      g_source_destroy (self->delay_source);
      self->delay_source = NULL;
    }
  if (self->reset_attempted && !self->session_clean)
    {
      /* Failed or cancelled session: run the fixed cleanup so the device
       * is recovered before it is released. */
      goodix5503_activation_fail (
        self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "Goodix activation cancelled"));
      return;
    }
  self->reset_attempted = FALSE;
  self->session_clean = FALSE;
  self->activation_reported = FALSE;
  self->deactivating = FALSE;
  fpi_image_device_deactivate_complete (device, NULL);
}

static void
goodix5503_runtime_error (FpiDeviceGoodix5503 *self, GError *error)
{
  /* Activation failures use goodix5503_activation_fail() directly. A runtime
   * failure is terminal for the active session, so invalidate the generation
   * and wipe every FDT base/pending field before libfprint can re-enter us. */
  fp_dbg ("RUNTIME_ERROR: err=%s deactivating=%d",
          error ? error->message : "none", self->deactivating);
  if (self->deactivating && error &&
      (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
       g_error_matches (error, G_USB_DEVICE_ERROR,
                        G_USB_DEVICE_ERROR_CANCELLED)))
    {
      /* The failure is the externally initiated cancellation of a pending
       * transfer as part of the release/teardown itself (it can retire
       * after the deactivation completed). Not a device fault: the warm
       * state survives and the releasing caller completes the
       * deactivation. */
      fp_dbg ("runtime error is a benign release cancellation: warm state kept");
      return;
    }
  goodix5503_warm_invalidate (self);
  self->session_clean = FALSE;
  goodix5503_fdt_session_reset (self);
  if (self->deactivating)
    goodix5503_activation_fail (self, error);
  else
    fpi_image_device_session_error (FP_IMAGE_DEVICE (self), error);
}

static void
goodix5503_finger_image_done (FpiDeviceGoodix5503 *self, GError *error)
{
  g_autoptr(FpImage) image = NULL;

  if (error)
    {
      goodix5503_fdt_pending_clear (self);
      goodix5503_runtime_error (self, error);
      return;
    }
  image = goodix5503_image_new_from_frames (self->background, self->finger,
                                             &error);
  OPENSSL_cleanse (self->finger, sizeof self->finger);
  if (image == NULL)
    {
      if (g_error_matches (error, GOODIX5503_PROTO_ERROR,
                           GOODIX5503_PROTO_ERROR_NO_CONTRAST))
        {
          FpiDeviceAction action =
            fpi_device_get_current_action (FP_DEVICE (self));

          g_clear_error (&error);
          goodix5503_fdt_pending_clear (self);
          goodix5503_fdt_coordinator_retry_idle (&self->fdt_runtime.coordinator);
          fpi_image_device_retry_scan (FP_IMAGE_DEVICE (self),
                                       FP_DEVICE_RETRY_GENERAL);
          if (action == FPI_DEVICE_ACTION_ENROLL)
            fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self),
                                                    FALSE);
          return;
        }
      goodix5503_fdt_pending_clear (self);
      goodix5503_runtime_error (self, error);
      return;
    }
  fpi_image_device_image_captured (FP_IMAGE_DEVICE (self),
                                   g_steal_pointer (&image));
}

static void goodix5503_fdt_watch_start (FpiDeviceGoodix5503 *self,
                                         gboolean              finger_on);

static GError *
goodix5503_fdt_phase_error (void)
{
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                    "unexpected Goodix FDT phase");
}

static void
goodix5503_fdt_up_base_ready (FpiDeviceGoodix5503 *self,
                              GByteArray          *body,
                              GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;
  guint8 raw[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint8 transformed[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint16 interrupt = 0;
  guint16 touch_flag = 0;

  if (error ||
      self->fdt_runtime.coordinator.phase !=
        GOODIX5503_FDT_PHASE_PREPARE_UP_BASE ||
      !self->fdt_runtime.pending_valid ||
      !goodix5503_parse_fdt_response (
        body ? body->data : NULL, body ? body->len : 0, &interrupt,
        &touch_flag, raw, transformed, &error))
    goto fail;

  /* McuParseFdt makes an exact command-0x36 response a pure mask event.
   * HandleFdt replaces the persistent mask from body+2 before DN2 combines
   * it with the accepted-down event mask for up-base generation. */
  self->fdt_runtime.area_mask = touch_flag;
  if (!goodix5503_generate_fdt_up_base (
        raw, self->fdt_runtime.pending_raw, self->fdt_runtime.area_mask,
        self->fdt_runtime.pending_touch_flag, self->fdt_delta,
        self->fdt_runtime.up_base, &error))
    goto fail;

  OPENSSL_cleanse (body->data, body->len);
  OPENSSL_cleanse (raw, sizeof raw);
  OPENSSL_cleanse (transformed, sizeof transformed);
  OPENSSL_cleanse (&interrupt, sizeof interrupt);
  OPENSSL_cleanse (&touch_flag, sizeof touch_flag);
  OPENSSL_cleanse (self->fdt_runtime.pending_raw, sizeof self->fdt_runtime.pending_raw);
  self->fdt_runtime.pending_touch_flag = 0;
  self->fdt_runtime.pending_valid = FALSE;
  goodix5503_fdt_coordinator_up_base_ready (&self->fdt_runtime.coordinator);
  goodix5503_fdt_watch_start (self, FALSE);
  return;

fail:
  if (body)
    OPENSSL_cleanse (body->data, body->len);
  OPENSSL_cleanse (raw, sizeof raw);
  OPENSSL_cleanse (transformed, sizeof transformed);
  OPENSSL_cleanse (&interrupt, sizeof interrupt);
  OPENSSL_cleanse (&touch_flag, sizeof touch_flag);
  goodix5503_fdt_pending_clear (self);
  goodix5503_runtime_error (
    self, error ? error : goodix5503_fdt_phase_error ());
}

static gboolean
goodix5503_fdt_event_wait_active (FpiDeviceGoodix5503 *self)
{
  return goodix5503_fdt_coordinator_wait_active (&self->fdt_runtime.coordinator);
}

static void
goodix5503_fdt_event_received (FpiDeviceGoodix5503 *self,
                               GByteArray          *frame,
                               GError              *error)
{
  g_autoptr(GByteArray) owned_frame = frame;
  g_autoptr(GByteArray) body = NULL;
  guint8 raw[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint8 transformed[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint16 interrupt = 0;
  guint16 touch_flag = 0;
  Goodix5503FdtEventAction action = GOODIX5503_FDT_EVENT_REJECT;

  if (error && g_error_matches (error, G_USB_DEVICE_ERROR,
                                G_USB_DEVICE_ERROR_TIMED_OUT) &&
      !self->deactivating && goodix5503_fdt_event_wait_active (self))
    {
      g_clear_error (&error);
      goodix5503_outer_start (self, NULL, TRUE,
                              goodix5503_fdt_event_received);
      return;
    }
  if (error && (self->deactivating || self->closing ||
                g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
                g_error_matches (error, G_USB_DEVICE_ERROR,
                                 G_USB_DEVICE_ERROR_CANCELLED)))
    {
      /* Externally initiated cancellation (release path or the fprintd
       * idle watchdog): never a device fault, so the warm state survives
       * for the next activation; outer_maybe_complete drives the
       * deactivation when one is in progress. */
      return;
    }
  if (error || !goodix5503_fdt_event_wait_active (self) ||
      !goodix5503_packet_decode (frame ? frame->data : NULL,
                                 frame ? frame->len : 0,
                                 self->fdt_runtime.coordinator.armed_command, TRUE,
                                 &body, &error) ||
      !goodix5503_parse_fdt_response (
        body ? body->data : NULL, body ? body->len : 0, &interrupt,
        &touch_flag, raw, transformed, &error))
    {
      if (frame)
        OPENSSL_cleanse (frame->data, frame->len);
      if (body)
        OPENSSL_cleanse (body->data, body->len);
      OPENSSL_cleanse (raw, sizeof raw);
      OPENSSL_cleanse (transformed, sizeof transformed);
      OPENSSL_cleanse (&interrupt, sizeof interrupt);
      OPENSSL_cleanse (&touch_flag, sizeof touch_flag);
      fp_dbg ("event read failed un-guarded: domain=%s code=%d msg=%s deactivating=%d",
              g_quark_to_string (error->domain), error->code, error->message,
              self->deactivating);
      goodix5503_runtime_error (
        self, error ? error : goodix5503_fdt_phase_error ());
      return;
    }

  action = goodix5503_fdt_coordinator_event (
    &self->fdt_runtime.coordinator, self->fdt_runtime.coordinator.armed_command,
    self->fdt_runtime.coordinator.event_generation);
  OPENSSL_cleanse (frame->data, frame->len);
  OPENSSL_cleanse (body->data, body->len);
  OPENSSL_cleanse (&interrupt, sizeof interrupt);
  if (action == GOODIX5503_FDT_EVENT_REJECT)
    {
      OPENSSL_cleanse (raw, sizeof raw);
      OPENSSL_cleanse (transformed, sizeof transformed);
      OPENSSL_cleanse (&touch_flag, sizeof touch_flag);
      fp_dbg ("event read failed un-guarded: domain=%s code=%d msg=%s deactivating=%d",
              g_quark_to_string (error->domain), error->code, error->message,
              self->deactivating);
      goodix5503_runtime_error (self, goodix5503_fdt_phase_error ());
      return;
    }
  if (action == GOODIX5503_FDT_EVENT_CAPTURE_DOWN)
    {
      memcpy (self->fdt_runtime.pending_raw, raw,
              sizeof self->fdt_runtime.pending_raw);
      self->fdt_runtime.pending_touch_flag = touch_flag;
      self->fdt_runtime.pending_valid = TRUE;
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), TRUE);
      goodix5503_capture_image (self, GOODIX5503_CAPTURE_FINGER,
                                goodix5503_finger_image_done);
    }
  else
    {
      goodix5503_fdt_next_down_base (raw, self->fdt_runtime.down_base);
      if (fpi_device_get_current_action (FP_DEVICE (self)) ==
          FPI_DEVICE_ACTION_ENROLL)
        goodix5503_fdt_watch_start (self, TRUE);
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), FALSE);
    }
  OPENSSL_cleanse (raw, sizeof raw);
  OPENSSL_cleanse (transformed, sizeof transformed);
  OPENSSL_cleanse (&touch_flag, sizeof touch_flag);
}

static void
goodix5503_fdt_arm_done (FpiDeviceGoodix5503 *self,
                          GByteArray          *body,
                          GError              *error)
{
  Goodix5503FdtArmAckAction action = GOODIX5503_FDT_ARM_ACK_REJECT;

  g_clear_pointer (&body, g_byte_array_unref);
  if (!error)
    action = goodix5503_fdt_coordinator_arm_ack (
      &self->fdt_runtime.coordinator);
  if (error || action == GOODIX5503_FDT_ARM_ACK_REJECT)
    {
      if (error && (self->deactivating || self->closing ||
                    g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
                    g_error_matches (error, G_USB_DEVICE_ERROR,
                                     G_USB_DEVICE_ERROR_CANCELLED)))
        {
          /* Externally initiated cancellation: after a successful match
           * the fprintd teardown cancels the just-armed wait-for-lift
           * transaction. Never a device fault — the warm state survives
           * and the cancelling deactivate/close drives completion. */
          fp_dbg ("arm cancelled during teardown: warm state kept");
          return;
        }
      if (self->warm_rearmed && !self->deactivating && !self->closing)
        {
          /* The warm state did not survive (suspend, re-enumeration,
           * stale endpoint data). Fall back to the full cold sequence
           * within the same activation instead of erroring out. */
          self->warm_rearmed = FALSE;
          goodix5503_warm_invalidate (self);
          fp_dbg ("warm arm failed, falling back to cold path");
          goodix5503_activate (FP_IMAGE_DEVICE (self));
          return;
        }
      goodix5503_runtime_error (
        self, error ? error : goodix5503_fdt_phase_error ());
      return;
    }
  if (action == GOODIX5503_FDT_ARM_ACK_REARM_UP)
    {
      /* Pinned GF3258 issues the HandleFdtDown arm and then the
       * ReqOnCaptureData arm with the same generated suffix. No event read is
       * started until both fixed transactions are acknowledged. */
      goodix5503_fdt_watch_start (self, FALSE);
      return;
    }

  goodix5503_outer_start (self, NULL, TRUE,
                          goodix5503_fdt_event_received);
}

static void
goodix5503_fdt_prepare_up_base (FpiDeviceGoodix5503 *self)
{
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE];
  g_autoptr(GError) error = NULL;

  if (self->deactivating || self->closing)
    return;
  if (self->fdt_runtime.coordinator.phase != GOODIX5503_FDT_PHASE_CAPTURE ||
      !self->fdt_runtime.pending_valid)
    {
      goodix5503_runtime_error (self, goodix5503_fdt_phase_error ());
      return;
    }
  goodix5503_fdt_coordinator_prepare_up (&self->fdt_runtime.coordinator);
  if (!goodix5503_build_fdt_request (0x0d, self->dac,
                                     self->fdt_runtime.down_base, request, &error))
    {
      goodix5503_fdt_pending_clear (self);
      goodix5503_runtime_error (self, g_steal_pointer (&error));
      return;
    }
  goodix5503_command_start (self, GOODIX5503_COMMAND_FDT_MANUAL,
                            request, sizeof request, TRUE, TRUE,
                            goodix5503_fdt_up_base_ready);
  OPENSSL_cleanse (request, sizeof request);
}

static void
goodix5503_fdt_watch_start (FpiDeviceGoodix5503 *self, gboolean finger_on)
{
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE];
  g_autoptr(GError) error = NULL;
  guint8 command = 0;
  guint generation = 0;

  if (self->deactivating || self->closing)
    return;
  if (!goodix5503_fdt_coordinator_start_arm (
        &self->fdt_runtime.coordinator, finger_on, self->dac,
        self->fdt_runtime.down_base, self->fdt_runtime.up_base, request,
        &command, &generation, &error))
    {
      goodix5503_runtime_error (self, g_steal_pointer (&error));
      return;
    }
  (void) generation;
  goodix5503_command_start (self, command, request, sizeof request,
                            FALSE, TRUE, goodix5503_fdt_arm_done);
  OPENSSL_cleanse (request, sizeof request);
}

static void
goodix5503_change_state (FpImageDevice *device,
                          FpiImageDeviceState state)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);
  Goodix5503FdtStateAction action;

  if (state != FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON &&
      state != FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF)
    return;
  action = goodix5503_fdt_coordinator_state_action (
    &self->fdt_runtime.coordinator,
    state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON);
  switch (action)
    {
    case GOODIX5503_FDT_STATE_ARM_DOWN:
      goodix5503_fdt_watch_start (self, TRUE);
      break;
    case GOODIX5503_FDT_STATE_PREPARE_UP_BASE:
      goodix5503_fdt_prepare_up_base (self);
      break;
    case GOODIX5503_FDT_STATE_NOOP:
      break;
    case GOODIX5503_FDT_STATE_REJECT:
    default:
      goodix5503_runtime_error (self, goodix5503_fdt_phase_error ());
      break;
    }
}

static const FpIdEntry goodix5503_id_table[] = {
  { .vid = 0x27c6, .pid = 0x5503 },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_goodix5503_init (FpiDeviceGoodix5503 *self)
{
  self->interface_claimed = FALSE;
  self->deactivating = FALSE;
  goodix5503_fdt_session_reset (self);
}

static void
fpi_device_goodix5503_finalize (GObject *object)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (object);

  g_clear_pointer (&self->warm.tls, goodix5503_tls_free);
  G_OBJECT_CLASS (fpi_device_goodix5503_parent_class)->finalize (object);
}

static void
fpi_device_goodix5503_class_init (FpiDeviceGoodix5503Class *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *image_class = FP_IMAGE_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_goodix5503_finalize;

  device_class->id = FP_COMPONENT;
  device_class->full_name = "Goodix GF3258 Milan 5503";
  device_class->type = FP_DEVICE_TYPE_USB;
  device_class->id_table = goodix5503_id_table;
  device_class->scan_type = FP_SCAN_TYPE_PRESS;
  device_class->nr_enroll_stages = 8;
  device_class->features &= ~FP_DEVICE_FEATURE_UPDATE_PRINT;

  image_class->algorithm = FPI_DEVICE_ALGO_SIGFM;
  image_class->sigfm_threshold = 150;
  image_class->img_width = GOODIX5503_SIGFM_IMAGE_WIDTH;
  image_class->img_height = GOODIX5503_SIGFM_IMAGE_HEIGHT;
  image_class->img_open = goodix5503_open;
  image_class->img_close = goodix5503_close;
  image_class->activate = goodix5503_activate;
  image_class->deactivate = goodix5503_deactivate;
  image_class->change_state = goodix5503_change_state;
}
