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

#include <openssl/crypto.h>

#define GOODIX5503_EP_OUT 0x01
#define GOODIX5503_EP_IN 0x82
#define GOODIX5503_TRANSFER_SIZE 32768
#define GOODIX5503_TRANSFER_TIMEOUT_MS 1500
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
#define GOODIX5503_MAX_FRESH_ATTEMPTS 3
#define GOODIX5503_CAPTURE_DISCARD 0
#define GOODIX5503_CAPTURE_BACKGROUND 1
#define GOODIX5503_CAPTURE_FINGER 2
#define GOODIX5503_R_PSK_HASH_SELECTOR 0xbb020007
#define GOODIX5503_EXPECTED_CHIP_ID 0x220f

static const char expected_firmware[] = "GF3258_RTSEC_APP_10063";

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
  gboolean outer_expect_read;
  gboolean deactivating;
  gboolean closing;
  guint8 psk[GOODIX5503_SECURITY_PSK_SIZE];
  guint8 expected_verification[GOODIX5503_VERIFICATION_SIZE];
  guint8 otp[GOODIX5503_OTP_SIZE];
  guint8 dac[GOODIX5503_DAC_SIZE];
  guint8 config[GOODIX5503_CONFIG_SIZE];
  Goodix5503Tls *tls;
  Goodix5503CaptureState capture_state;
  Goodix5503ImageCallback image_callback;
  GError *primary_error;
  GSource *delay_source;
  gboolean reset_attempted;
  gboolean cleanup_active;
  guint capture_destination;
  guint8 fdt_event_command;
  gboolean activated;
  guint fresh_attempt;
  guint16 fdt_delta;
  guint8 fresh_raw[3][GOODIX5503_FDT_BASE_SIZE];
  guint8 fresh_transformed[3][GOODIX5503_FDT_BASE_SIZE];
  guint8 fdt_base[GOODIX5503_FDT_BASE_SIZE];
  guint8 background[GOODIX5503_PACKED_IMAGE_SIZE];
  guint8 finger[GOODIX5503_PACKED_IMAGE_SIZE];
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix5503, fpi_device_goodix5503,
                      FPI, DEVICE_GOODIX5503, FpImageDevice)
G_DEFINE_TYPE (FpiDeviceGoodix5503, fpi_device_goodix5503,
               FP_TYPE_IMAGE_DEVICE)

static void goodix5503_submit_read (FpiDeviceGoodix5503 *self);
static void goodix5503_close_finish (FpiDeviceGoodix5503 *self);

static void
goodix5503_command_clear (FpiDeviceGoodix5503 *self)
{
  g_clear_object (&self->transaction_cancel);
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
  self->out_done = TRUE;
  if (error)
    goodix5503_command_fail (self, error);
  goodix5503_command_maybe_complete (self);
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
  FpiUsbTransfer *transfer;
  guint8 *out_buffer;
  gsize out_len;

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
  out_len = packet->len;
  out_buffer = g_memdup2 (packet->data, out_len);
  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk_full (transfer, GOODIX5503_EP_OUT, out_buffer,
                                   out_len, g_free);
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (transfer, GOODIX5503_TRANSFER_TIMEOUT_MS,
                           self->transaction_cancel, goodix5503_out_done,
                           NULL);
}

static void
goodix5503_outer_clear (FpiDeviceGoodix5503 *self)
{
  g_clear_object (&self->transaction_cancel);
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
  self->out_done = TRUE;
  if (error)
    goodix5503_outer_fail (self, error);
  goodix5503_outer_maybe_complete (self);
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
goodix5503_outer_start (FpiDeviceGoodix5503 *self,
                         GByteArray          *packet,
                         gboolean             expect_read,
                         Goodix5503OuterCallback callback)
{
  FpiUsbTransfer *transfer;

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
      guint8 *out_buffer = g_memdup2 (packet->data, packet->len);

      transfer = fpi_usb_transfer_new (FP_DEVICE (self));
      fpi_usb_transfer_fill_bulk_full (transfer, GOODIX5503_EP_OUT,
                                       out_buffer, packet->len, g_free);
      transfer->short_is_error = TRUE;
      fpi_usb_transfer_submit (transfer, GOODIX5503_TRANSFER_TIMEOUT_MS,
                               self->transaction_cancel,
                               goodix5503_outer_out_done, NULL);
    }
}

static void goodix5503_activation_fail (FpiDeviceGoodix5503 *self,
                                        GError              *error);

static void
goodix5503_pre_reset_fail (FpiDeviceGoodix5503 *self, GError *error)
{
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
  OPENSSL_cleanse (self->fdt_base, sizeof self->fdt_base);
  OPENSSL_cleanse (self->background, sizeof self->background);
  OPENSSL_cleanse (self->finger, sizeof self->finger);
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
  OPENSSL_cleanse (self->fdt_base, sizeof self->fdt_base);
  OPENSSL_cleanse (self->background, sizeof self->background);
  OPENSSL_cleanse (self->finger, sizeof self->finger);
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
  goodix5503_outer_start (self, packet, TRUE,
                          goodix5503_capture_frame_done);
}

static void goodix5503_fresh_attempt_start (FpiDeviceGoodix5503 *self);

static gboolean
goodix5503_parse_fdt_slot (FpiDeviceGoodix5503 *self,
                            guint                 slot,
                            GByteArray           *body,
                            GError              **error)
{
  guint16 interrupt;
  guint16 touch_flag;

  return goodix5503_parse_fdt_response (
    body->data, body->len, &interrupt, &touch_flag,
    self->fresh_raw[slot], self->fresh_transformed[slot], error);
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
  goodix5503_fresh_attempt_start (self);
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

  memcpy (self->fdt_base, self->fresh_transformed[2], sizeof self->fdt_base);
  OPENSSL_cleanse (self->fresh_raw, sizeof self->fresh_raw);
  OPENSSL_cleanse (self->fresh_transformed, sizeof self->fresh_transformed);
  OPENSSL_cleanse (self->psk, sizeof self->psk);
  OPENSSL_cleanse (self->expected_verification,
                   sizeof self->expected_verification);
  OPENSSL_cleanse (self->otp, sizeof self->otp);
  OPENSSL_cleanse (self->config, sizeof self->config);
  self->activated = TRUE;
  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self), NULL);
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
  goodix5503_command_start (self, GOODIX5503_COMMAND_FDT_MANUAL,
                            request, sizeof request, TRUE, FALSE,
                            goodix5503_fdt2_done);
  OPENSSL_cleanse (request, sizeof request);
}

static void
goodix5503_delta_done (FpiDeviceGoodix5503 *self,
                       GByteArray          *body,
                       GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;

  if (error)
    {
      goodix5503_activation_fail (self, error);
      return;
    }
  if (body->len != 2)
    {
      goodix5503_activation_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                        "invalid Goodix FDT delta response"));
      return;
    }
  self->fdt_delta = body->data[1];
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
  goodix5503_command_start (self, GOODIX5503_COMMAND_FDT_MANUAL,
                            request, sizeof request, TRUE, FALSE,
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
  goodix5503_command_start (self, GOODIX5503_COMMAND_FDT_MANUAL,
                            request, sizeof request, TRUE, FALSE,
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
  goodix5503_command_start (self, GOODIX5503_COMMAND_DRIVER_STATE,
                            state_payload, sizeof state_payload, FALSE, TRUE,
                            goodix5503_driver_state_done);
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
  goodix5503_command_start (self, GOODIX5503_COMMAND_CONFIG,
                            self->config, sizeof self->config, TRUE, TRUE,
                            goodix5503_config_done);
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
                                       payload->len, &error) ||
      !goodix5503_tls_is_established (self->tls))
    {
      if (error == NULL)
        error = g_error_new_literal (GOODIX5503_TLS_ERROR,
                                     GOODIX5503_TLS_ERROR_PROTOCOL,
                                     "Goodix TLS handshake did not finish");
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
                                     "Goodix TLS final server flight is empty");
      goodix5503_activation_fail (self, error);
      return;
    }
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
  if (body->len != sizeof expected_firmware ||
      memcmp (body->data, expected_firmware, sizeof expected_firmware) != 0)
    {
      goodix5503_pre_reset_fail (
        self, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                        "unsupported Goodix 5503 firmware"));
      return;
    }

  if (!goodix5503_load_host_psk (self->psk, &error) ||
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
  self->closing = FALSE;
  if (self->delay_source)
    {
      g_source_destroy (self->delay_source);
      self->delay_source = NULL;
    }
  goodix5503_command_clear (self);
  goodix5503_outer_clear (self);
  g_clear_pointer (&self->frame_buffer, goodix5503_frame_buffer_free);
  g_clear_pointer (&self->tls, goodix5503_tls_free);
  OPENSSL_cleanse (self->psk, sizeof self->psk);
  OPENSSL_cleanse (self->expected_verification,
                   sizeof self->expected_verification);
  OPENSSL_cleanse (self->otp, sizeof self->otp);
  OPENSSL_cleanse (self->dac, sizeof self->dac);
  OPENSSL_cleanse (self->config, sizeof self->config);
  OPENSSL_cleanse (self->fresh_raw, sizeof self->fresh_raw);
  OPENSSL_cleanse (self->fresh_transformed, sizeof self->fresh_transformed);
  OPENSSL_cleanse (self->fdt_base, sizeof self->fdt_base);
  OPENSSL_cleanse (self->background, sizeof self->background);
  OPENSSL_cleanse (self->finger, sizeof self->finger);
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

static void
goodix5503_activate (FpImageDevice *device)
{
  static const guint8 payload[] = { 0x00, 0x00, 0x00, 0x00 };

  goodix5503_command_start (FPI_DEVICE_GOODIX5503 (device),
                            GOODIX5503_COMMAND_NOP,
                            payload, sizeof payload, FALSE, TRUE,
                            goodix5503_nop_done);
}

static void
goodix5503_deactivate (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  self->deactivating = TRUE;
  if (self->delay_source)
    {
      g_source_destroy (self->delay_source);
      self->delay_source = NULL;
    }
  if (self->transaction_cancel)
    {
      g_cancellable_cancel (self->transaction_cancel);
      return;
    }
  if (self->reset_attempted)
    {
      goodix5503_activation_fail (
        self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "Goodix activation cancelled"));
      return;
    }
  self->deactivating = FALSE;
  fpi_image_device_deactivate_complete (device, NULL);
}

static void
goodix5503_runtime_error (FpiDeviceGoodix5503 *self, GError *error)
{
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
          g_clear_error (&error);
          fpi_image_device_retry_scan (FP_IMAGE_DEVICE (self),
                                       FP_DEVICE_RETRY_GENERAL);
          return;
        }
      goodix5503_runtime_error (self, error);
      return;
    }
  fpi_image_device_image_captured (FP_IMAGE_DEVICE (self),
                                   g_steal_pointer (&image));
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
  guint16 interrupt;
  guint16 touch_flag;

  if (error && g_error_matches (error, G_USB_DEVICE_ERROR,
                                G_USB_DEVICE_ERROR_TIMED_OUT) &&
      !self->deactivating)
    {
      g_clear_error (&error);
      goodix5503_outer_start (self, NULL, TRUE,
                              goodix5503_fdt_event_received);
      return;
    }
  if (error ||
      !goodix5503_packet_decode (frame ? frame->data : NULL,
                                 frame ? frame->len : 0,
                                 self->fdt_event_command, TRUE,
                                 &body, &error) ||
      !goodix5503_parse_fdt_response (
        body->data, body->len, &interrupt, &touch_flag, raw, transformed,
        &error))
    {
      if (frame)
        OPENSSL_cleanse (frame->data, frame->len);
      goodix5503_runtime_error (self, error);
      return;
    }
  OPENSSL_cleanse (frame->data, frame->len);
  OPENSSL_cleanse (body->data, body->len);
  OPENSSL_cleanse (raw, sizeof raw);
  OPENSSL_cleanse (transformed, sizeof transformed);

  if (self->fdt_event_command == 0x32)
    {
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), TRUE);
      goodix5503_capture_image (self, GOODIX5503_CAPTURE_FINGER,
                                goodix5503_finger_image_done);
    }
  else
    fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), FALSE);
}

static void
goodix5503_fdt_arm_done (FpiDeviceGoodix5503 *self,
                          GByteArray          *body,
                          GError              *error)
{
  g_clear_pointer (&body, g_byte_array_unref);
  if (error)
    {
      goodix5503_runtime_error (self, error);
      return;
    }
  goodix5503_outer_start (self, NULL, TRUE,
                          goodix5503_fdt_event_received);
}

static void
goodix5503_fdt_watch_start (FpiDeviceGoodix5503 *self, gboolean finger_on)
{
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE];
  g_autoptr(GError) error = NULL;
  guint8 command = finger_on ? 0x32 : 0x34;
  guint8 selector = finger_on ? 0x0c : 0x0e;

  if (!goodix5503_build_fdt_request (selector, self->dac, self->fdt_base,
                                     request, &error))
    {
      goodix5503_runtime_error (self, g_steal_pointer (&error));
      return;
    }
  self->fdt_event_command = command;
  goodix5503_command_start (self, command, request, sizeof request,
                            FALSE, TRUE, goodix5503_fdt_arm_done);
  OPENSSL_cleanse (request, sizeof request);
}

static void
goodix5503_change_state (FpImageDevice *device,
                          FpiImageDeviceState state)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);

  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    goodix5503_fdt_watch_start (self, TRUE);
  else if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF)
    goodix5503_fdt_watch_start (self, FALSE);
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
}

static void
fpi_device_goodix5503_class_init (FpiDeviceGoodix5503Class *klass)
{
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *image_class = FP_IMAGE_DEVICE_CLASS (klass);

  device_class->id = FP_COMPONENT;
  device_class->full_name = "Goodix GF3258 Milan 5503";
  device_class->type = FP_DEVICE_TYPE_USB;
  device_class->id_table = goodix5503_id_table;
  device_class->scan_type = FP_SCAN_TYPE_PRESS;

  image_class->img_width = GOODIX5503_IMAGE_WIDTH;
  image_class->img_height = GOODIX5503_IMAGE_HEIGHT;
  image_class->img_open = goodix5503_open;
  image_class->img_close = goodix5503_close;
  image_class->activate = goodix5503_activate;
  image_class->deactivate = goodix5503_deactivate;
  image_class->change_state = goodix5503_change_state;
}
