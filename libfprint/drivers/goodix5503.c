/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Goodix GF3258/Milan 5503 image-device integration. */

#define FP_COMPONENT "goodix5503"
#include "fpi-log.h"
#include "drivers_api.h"
#include "goodix5503-config.h"
#include "goodix5503-proto.h"
#include "goodix5503-security.h"

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
#define GOODIX5503_R_PSK_HASH_SELECTOR 0xbb020007
#define GOODIX5503_EXPECTED_CHIP_ID 0x220f

static const char expected_firmware[] = "GF3258_RTSEC_APP_10063";

typedef struct _FpiDeviceGoodix5503 FpiDeviceGoodix5503;
typedef void (*Goodix5503CommandCallback) (FpiDeviceGoodix5503 *self,
                                           GByteArray          *body,
                                           GError              *error);

struct _FpiDeviceGoodix5503
{
  FpImageDevice parent;
  GCancellable *transaction_cancel;
  Goodix5503FrameBuffer *frame_buffer;
  Goodix5503CommandState command_state;
  Goodix5503CommandCallback command_callback;
  GByteArray *command_response;
  GError *command_error;
  guint8 expected_command;
  gboolean expect_data;
  gboolean data_checksum;
  gboolean interface_claimed;
  gboolean out_done;
  gboolean read_active;
  gboolean deactivating;
  guint8 psk[GOODIX5503_SECURITY_PSK_SIZE];
  guint8 expected_verification[GOODIX5503_VERIFICATION_SIZE];
  guint8 otp[GOODIX5503_OTP_SIZE];
  guint8 dac[GOODIX5503_DAC_SIZE];
  guint8 config[GOODIX5503_CONFIG_SIZE];
  GError *primary_error;
  GSource *delay_source;
  gboolean reset_attempted;
  gboolean cleanup_active;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix5503, fpi_device_goodix5503,
                      FPI, DEVICE_GOODIX5503, FpImageDevice)
G_DEFINE_TYPE (FpiDeviceGoodix5503, fpi_device_goodix5503,
               FP_TYPE_IMAGE_DEVICE)

static void goodix5503_submit_read (FpiDeviceGoodix5503 *self);

static void
goodix5503_command_clear (FpiDeviceGoodix5503 *self)
{
  g_clear_object (&self->transaction_cancel);
  g_clear_pointer (&self->frame_buffer, goodix5503_frame_buffer_free);
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

  callback = self->command_callback;
  response = g_steal_pointer (&self->command_response);
  error = g_steal_pointer (&self->command_error);
  if (self->deactivating && error == NULL)
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                 "Goodix operation cancelled");
  goodix5503_command_clear (self);
  callback (self, response, error);
  if (self->deactivating && self->command_callback == NULL)
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
          if (goodix5503_frame_buffer_length (self->frame_buffer) != 0)
            g_set_error_literal (&self->command_error,
                                 GOODIX5503_PROTO_ERROR,
                                 GOODIX5503_PROTO_ERROR_INVALID,
                                 "excess Goodix command response data");
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

static void goodix5503_activation_fail (FpiDeviceGoodix5503 *self,
                                        GError              *error);

static void
goodix5503_cleanup_done (FpiDeviceGoodix5503 *self,
                          GByteArray          *body,
                          GError              *error)
{
  g_clear_pointer (&body, g_byte_array_unref);
  g_clear_error (&error);
  self->cleanup_active = FALSE;
  self->reset_attempted = FALSE;
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
      fpi_image_device_activate_complete (
        FP_IMAGE_DEVICE (self), g_steal_pointer (&self->primary_error));
      return;
    }

  self->cleanup_active = TRUE;
  goodix5503_command_start (self, GOODIX5503_COMMAND_RESET,
                            reset_payload, sizeof reset_payload, TRUE, TRUE,
                            goodix5503_cleanup_done);
}

static void
goodix5503_pov_done (FpiDeviceGoodix5503 *self,
                      GByteArray          *body,
                      GError              *error)
{
  g_autoptr(GByteArray) owned_body = body;

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

  goodix5503_activation_fail (
    self, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                    "Goodix TLS activation is not connected yet"));
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
  FpImageDevice *device = FP_IMAGE_DEVICE (self);
  g_autoptr(GByteArray) owned_body = body;
  gboolean valid;

  if (error)
    {
      fpi_image_device_activate_complete (device, error);
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
      fpi_image_device_activate_complete (
        device, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
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
  FpImageDevice *device = FP_IMAGE_DEVICE (self);
  g_autoptr(GByteArray) owned_body = body;

  if (error)
    {
      fpi_image_device_activate_complete (device, error);
      return;
    }
  if (body->len != sizeof expected_firmware ||
      memcmp (body->data, expected_firmware, sizeof expected_firmware) != 0)
    {
      fpi_image_device_activate_complete (
        device, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                          "unsupported Goodix 5503 firmware"));
      return;
    }

  if (!goodix5503_load_host_psk (self->psk, &error) ||
      !goodix5503_derive_verification_record (
        self->psk, self->expected_verification, &error))
    {
      fpi_image_device_activate_complete (device, error);
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
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (self), error);
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
goodix5503_close (FpImageDevice *device)
{
  FpiDeviceGoodix5503 *self = FPI_DEVICE_GOODIX5503 (device);
  g_autoptr(GError) error = NULL;

  if (self->transaction_cancel)
    g_cancellable_cancel (self->transaction_cancel);
  if (self->delay_source)
    {
      g_source_destroy (self->delay_source);
      self->delay_source = NULL;
    }
  goodix5503_command_clear (self);
  OPENSSL_cleanse (self->psk, sizeof self->psk);
  OPENSSL_cleanse (self->expected_verification,
                   sizeof self->expected_verification);
  OPENSSL_cleanse (self->otp, sizeof self->otp);
  OPENSSL_cleanse (self->dac, sizeof self->dac);
  OPENSSL_cleanse (self->config, sizeof self->config);
  g_clear_error (&self->primary_error);
  if (self->interface_claimed)
    {
      g_usb_device_release_interface (
        fpi_device_get_usb_device (FP_DEVICE (device)), 0, 0, &error);
      self->interface_claimed = FALSE;
    }
  fpi_image_device_close_complete (device, g_steal_pointer (&error));
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
goodix5503_change_state (FpImageDevice *device,
                          FpiImageDeviceState state)
{
  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    fpi_image_device_session_error (
      device, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                        "Goodix 5503 capture is not connected yet"));
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
