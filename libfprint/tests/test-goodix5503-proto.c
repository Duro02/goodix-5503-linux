/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <glib.h>
#include <string.h>

#include "goodix5503-proto.h"

static void
test_frame_buffer_split_and_coalesced (void)
{
  const guint8 first_payload[] = { 0x01, 0x02 };
  const guint8 second_payload[] = { 0x03, 0x04, 0x05 };
  const guint8 usb_padding[7] = { 0 };
  g_autoptr(GByteArray) first = NULL;
  g_autoptr(GByteArray) second = NULL;
  g_autoptr(GByteArray) joined = g_byte_array_new ();
  g_autoptr(GByteArray) frame = NULL;
  g_autoptr(Goodix5503FrameBuffer) buffer = goodix5503_frame_buffer_new ();
  g_autoptr(GError) error = NULL;

  first = goodix5503_packet_encode (0x20, first_payload,
                                    sizeof first_payload, TRUE, &error);
  g_assert_no_error (error);
  second = goodix5503_packet_encode (0x36, second_payload,
                                     sizeof second_payload, FALSE, &error);
  g_assert_no_error (error);
  g_byte_array_append (joined, first->data, first->len);
  g_byte_array_append (joined, second->data, second->len);
  g_byte_array_append (joined, usb_padding, sizeof usb_padding);

  g_assert_true (goodix5503_frame_buffer_append (buffer, joined->data, 3,
                                                 &error));
  g_assert_false (goodix5503_frame_buffer_take (buffer, &frame, &error));
  g_assert_no_error (error);
  g_assert_true (goodix5503_frame_buffer_append (
    buffer, joined->data + 3, joined->len - 3, &error));
  g_assert_true (goodix5503_frame_buffer_take (buffer, &frame, &error));
  g_assert_cmpmem (frame->data, frame->len, first->data, first->len);
  g_clear_pointer (&frame, g_byte_array_unref);
  g_assert_true (goodix5503_frame_buffer_take (buffer, &frame, &error));
  g_assert_cmpmem (frame->data, frame->len, second->data, second->len);
  g_clear_pointer (&frame, g_byte_array_unref);
  g_assert_false (goodix5503_frame_buffer_take (buffer, &frame, &error));
  g_assert_no_error (error);
}

static void
test_frame_buffer_rejects_bad_header (void)
{
  const guint8 invalid[] = { 0xa0, 0x04, 0x00, 0x00 };
  g_autoptr(Goodix5503FrameBuffer) buffer = goodix5503_frame_buffer_new ();
  g_autoptr(GByteArray) frame = NULL;
  g_autoptr(GError) error = NULL;

  g_assert_true (goodix5503_frame_buffer_append (buffer, invalid,
                                                 sizeof invalid, &error));
  g_assert_false (goodix5503_frame_buffer_take (buffer, &frame, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_CHECKSUM);
}

static void
test_packet_round_trip (void)
{
  const guint8 payload[] = { 0x01, 0x00, 0x8b, 0x00 };
  g_autoptr(GByteArray) packet = NULL;
  g_autoptr(GByteArray) body = NULL;
  g_autoptr(GError) error = NULL;

  packet = goodix5503_packet_encode (0x20, payload, sizeof payload, TRUE, &error);
  g_assert_no_error (error);
  g_assert_nonnull (packet);
  g_assert_true (goodix5503_packet_decode (packet->data, packet->len, 0x20,
                                           TRUE, &body, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (body->data, body->len, payload, sizeof payload);
}

static void
test_no_checksum_packet (void)
{
  const guint8 payload[] = { 0x82, 0x01, 0x3f, 0x00 };
  g_autoptr(GByteArray) packet = NULL;
  g_autoptr(GByteArray) body = NULL;
  g_autoptr(GError) error = NULL;

  packet = goodix5503_packet_encode (0x36, payload, sizeof payload, FALSE, &error);
  g_assert_no_error (error);
  g_assert_cmphex (packet->data[packet->len - 1], ==, 0x88);
  g_assert_true (goodix5503_packet_decode (packet->data, packet->len, 0x36,
                                           FALSE, &body, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (body->data, body->len, payload, sizeof payload);
}

static void
test_packet_rejects_mutations (void)
{
  g_autoptr(GByteArray) packet = NULL;
  g_autoptr(GByteArray) body = NULL;
  g_autoptr(GError) error = NULL;

  packet = goodix5503_packet_encode (0x20, NULL, 0, TRUE, &error);
  g_assert_no_error (error);

  packet->data[3] ^= 1;
  g_assert_false (goodix5503_packet_decode (packet->data, packet->len, 0x20,
                                            TRUE, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_CHECKSUM);
  g_clear_error (&error);
  packet->data[3] ^= 1;

  packet->data[packet->len - 1] ^= 1;
  g_assert_false (goodix5503_packet_decode (packet->data, packet->len, 0x20,
                                            TRUE, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_CHECKSUM);
  g_clear_error (&error);
  packet->data[packet->len - 1] ^= 1;

  g_assert_false (goodix5503_packet_decode (packet->data, packet->len - 1, 0x20,
                                            TRUE, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_LENGTH);
  g_clear_error (&error);

  g_assert_false (goodix5503_packet_decode (packet->data, packet->len, 0x21,
                                            TRUE, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
}

static void
test_capture_router_valid_and_reversed (void)
{
  const guint8 ack_payload[] = { 0x20, 0x01 };
  const guint8 prelude_payload[] = { 0x01 };
  const guint8 envelope_payload[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    23, 0x03, 0x03, 0x00, 0x01, 0xaa,
  };
  g_autoptr(GByteArray) ack = NULL;
  g_autoptr(GByteArray) delayed = NULL;
  g_autoptr(GByteArray) prelude = NULL;
  g_autoptr(GByteArray) encrypted = NULL;
  g_autoptr(GByteArray) envelope = NULL;
  g_autoptr(GError) error = NULL;
  Goodix5503CaptureState state = { 0 };

  ack = goodix5503_packet_encode (0xb0, ack_payload, sizeof ack_payload,
                                  TRUE, &error);
  delayed = goodix5503_packet_encode (0xd0, NULL, 0, TRUE, &error);
  prelude = goodix5503_packet_encode (0x20, prelude_payload,
                                      sizeof prelude_payload, TRUE, &error);
  encrypted = goodix5503_outer_encode (0xb2, envelope_payload,
                                        sizeof envelope_payload, &error);
  g_assert_no_error (error);

  g_assert_true (goodix5503_capture_consume_frame (
    &state, ack->data, ack->len, &envelope, &error));
  g_assert_true (goodix5503_capture_consume_frame (
    &state, prelude->data, prelude->len, &envelope, &error));
  g_assert_true (goodix5503_capture_consume_frame (
    &state, encrypted->data, encrypted->len, &envelope, &error));
  g_assert_true (state.done);
  g_assert_cmpmem (envelope->data, envelope->len, envelope_payload,
                   sizeof envelope_payload);
  g_clear_pointer (&envelope, g_byte_array_unref);

  memset (&state, 0, sizeof state);
  g_assert_true (goodix5503_capture_consume_frame (
    &state, ack->data, ack->len, &envelope, &error));
  g_assert_false (goodix5503_capture_consume_frame (
    &state, delayed->data, delayed->len, &envelope, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
}

static void
test_command_router_ordering (void)
{
  const guint8 response[] = { 0x82, 0x01, 0x3f, 0x00 };
  const guint8 ack_payload[] = { 0x36, 0x01 };
  g_autoptr(GByteArray) ack = NULL;
  g_autoptr(GByteArray) data = NULL;
  g_autoptr(GByteArray) body = NULL;
  g_autoptr(GError) error = NULL;
  Goodix5503CommandState state = GOODIX5503_COMMAND_WAIT_ACK;

  ack = goodix5503_packet_encode (0xb0, ack_payload, sizeof ack_payload,
                                  TRUE, &error);
  data = goodix5503_packet_encode (0x36, response, sizeof response,
                                   TRUE, &error);
  g_assert_no_error (error);
  g_assert_true (goodix5503_command_consume_frame (
    0x36, TRUE, TRUE, &state, ack->data, ack->len, &body, &error));
  g_assert_cmpint (state, ==, GOODIX5503_COMMAND_WAIT_DATA);
  g_assert_null (body);
  g_assert_true (goodix5503_command_consume_frame (
    0x36, TRUE, TRUE, &state, data->data, data->len, &body, &error));
  g_assert_cmpint (state, ==, GOODIX5503_COMMAND_DONE);
  g_assert_cmpmem (body->data, body->len, response, sizeof response);
  g_clear_pointer (&body, g_byte_array_unref);

  g_assert_false (goodix5503_command_consume_frame (
    0x36, TRUE, TRUE, &state, data->data, data->len, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
  g_clear_error (&error);

  state = GOODIX5503_COMMAND_WAIT_ACK;
  g_assert_false (goodix5503_command_consume_frame (
    0x36, TRUE, TRUE, &state, data->data, data->len, &body, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
}

static void
test_fdt_response_and_request (void)
{
  const guint8 response[GOODIX5503_FDT_RESPONSE_SIZE] = {
    0x82, 0x01, 0x3f, 0x00, 0x65, 0x01, 0x4b, 0x01,
    0x6b, 0x01, 0x50, 0x01, 0x6b, 0x01, 0x47, 0x01,
  };
  const guint8 dac[GOODIX5503_DAC_SIZE] =
    { 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00, 0x88, 0x00 };
  const guint8 zero_base[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  const guint8 expected_request[GOODIX5503_FDT_REQUEST_SIZE] = {
    0x0d, 0x01, 0x8b, 0x00, 0x84, 0x00, 0x8c, 0x00,
    0x88, 0x00, 0x80, 0x00, 0x80, 0x00, 0x80, 0x00,
    0x80, 0x00, 0x80, 0x00, 0x80, 0x00,
  };
  const guint8 expected_raw[GOODIX5503_FDT_BASE_SIZE] = {
    0x65, 0x01, 0x4b, 0x01, 0x6b, 0x01,
    0x50, 0x01, 0x6b, 0x01, 0x47, 0x01,
  };
  guint8 raw[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint8 transformed[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE] = { 0 };
  guint16 interrupt = 0;
  guint16 touch_flag = 0;
  g_autoptr(GError) error = NULL;

  g_assert_true (goodix5503_parse_fdt_response (
    response, sizeof response, &interrupt, &touch_flag, raw, transformed,
    &error));
  g_assert_no_error (error);
  g_assert_cmphex (interrupt, ==, 0x0182);
  g_assert_cmphex (touch_flag, ==, 0x003f);
  g_assert_cmpmem (raw, sizeof raw, expected_raw, sizeof expected_raw);
  g_assert_true (goodix5503_fdt_bases_within_delta (raw, raw, 0));

  g_assert_true (goodix5503_build_fdt_request (
    0x0d, dac, zero_base, request, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (request, sizeof request, expected_request,
                   sizeof expected_request);

  g_assert_false (goodix5503_build_fdt_request (
    0x0e, dac, zero_base, request, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
  g_clear_error (&error);

  g_assert_false (goodix5503_build_fdt_request (
    0x8d, dac, zero_base, request, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
  g_clear_error (&error);

  g_assert_false (goodix5503_parse_fdt_response (
    response, sizeof response - 1, &interrupt, &touch_flag, raw, transformed,
    &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_LENGTH);
}

static void
test_fdt_up_request (void)
{
  const guint8 dac[GOODIX5503_DAC_SIZE] =
    { 0x8b, 0x00, 0x83, 0x00, 0x8c, 0x00, 0x87, 0x00 };
  const guint8 base[GOODIX5503_FDT_BASE_SIZE] = {
    0x80, 0x29, 0x80, 0x13, 0x80, 0x3d,
    0x80, 0x13, 0x80, 0x13, 0x80, 0x13,
  };
  const guint8 expected_request[GOODIX5503_FDT_REQUEST_SIZE] = {
    0x0e, 0x01, 0x8b, 0x00, 0x83, 0x00, 0x8c, 0x00, 0x87, 0x00,
    0x80, 0x29, 0x80, 0x13, 0x80, 0x3d,
    0x80, 0x13, 0x80, 0x13, 0x80, 0x13,
  };
  const guint8 expected_frame[] = {
    0xa0, 0x1a, 0x00, 0xba, 0x34, 0x17, 0x00, 0x0e, 0x01,
    0x8b, 0x00, 0x83, 0x00, 0x8c, 0x00, 0x87, 0x00,
    0x80, 0x29, 0x80, 0x13, 0x80, 0x3d,
    0x80, 0x13, 0x80, 0x13, 0x80, 0x13, 0x7d,
  };
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE] = { 0 };
  g_autoptr(GByteArray) frame = NULL;
  g_autoptr(GError) error = NULL;

  g_assert_true (goodix5503_build_fdt_up_request (dac, base, request, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (request, sizeof request, expected_request,
                   sizeof expected_request);
  g_assert_cmpmem (base, sizeof base, expected_request + 10, sizeof base);

  frame = goodix5503_packet_encode (0x34, request, sizeof request, TRUE,
                                    &error);
  g_assert_no_error (error);
  g_assert_nonnull (frame);
  g_assert_cmpuint (frame->len, ==, sizeof expected_frame);
  g_assert_cmpmem (frame->data, frame->len, expected_frame,
                   sizeof expected_frame);

  g_assert_false (goodix5503_build_fdt_up_request (NULL, base, request,
                                                    &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
  g_clear_error (&error);
  g_assert_false (goodix5503_build_fdt_up_request (dac, NULL, request,
                                                    &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
  g_clear_error (&error);
  g_assert_false (goodix5503_build_fdt_up_request (dac, base, NULL, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
}

static void
test_fdt_stage_separation (void)
{
  const guint generation = 7;

  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_DOWN, 0x32, generation,
                     generation, 0x32, 1u << 3), ==,
                   GOODIX5503_FDT_EVENT_CAPTURE_DOWN);
  /* A read timeout does not mutate the armed generation; the same wait may
   * remain cancellable and accept a later exact event. */
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_DOWN, 0x32, generation,
                     generation, 0x32, 1u << 3), ==,
                   GOODIX5503_FDT_EVENT_CAPTURE_DOWN);

  /* The accepted down event must enter command-20 capture.  Only the generic
   * AWAIT_FINGER_OFF transition after image submission may start manual 0x36. */
  g_assert_cmpint (goodix5503_fdt_state_action (
                     GOODIX5503_FDT_PHASE_IDLE, TRUE), ==,
                   GOODIX5503_FDT_STATE_ARM_DOWN);
  g_assert_cmpint (goodix5503_fdt_state_action (
                     GOODIX5503_FDT_PHASE_CAPTURE, FALSE), ==,
                   GOODIX5503_FDT_STATE_PREPARE_UP_BASE);
  g_assert_cmpint (goodix5503_fdt_state_action (
                     GOODIX5503_FDT_PHASE_PREPARE_UP_BASE, FALSE), ==,
                   GOODIX5503_FDT_STATE_NOOP);
  g_assert_cmpint (goodix5503_fdt_state_action (
                     GOODIX5503_FDT_PHASE_ARM_UP, FALSE), ==,
                   GOODIX5503_FDT_STATE_NOOP);
  g_assert_cmpint (goodix5503_fdt_state_action (
                     GOODIX5503_FDT_PHASE_WAIT_UP, FALSE), ==,
                   GOODIX5503_FDT_STATE_NOOP);
  g_assert_cmpint (goodix5503_fdt_state_action (
                     GOODIX5503_FDT_PHASE_WAIT_DOWN, FALSE), ==,
                   GOODIX5503_FDT_STATE_REJECT);

  /* The pinned accepted-up path arms the next enrollment down watch before
   * reporting OFF.  A later AWAIT_ON notification must not arm it twice. */
  g_assert_cmpint (goodix5503_fdt_state_action (
                     GOODIX5503_FDT_PHASE_ARM_DOWN, TRUE), ==,
                   GOODIX5503_FDT_STATE_NOOP);
  g_assert_cmpint (goodix5503_fdt_state_action (
                     GOODIX5503_FDT_PHASE_WAIT_DOWN, TRUE), ==,
                   GOODIX5503_FDT_STATE_NOOP);

  /* No event is accepted while command-20 capture or later manual/up-base
   * preparation is in progress. */
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_PREPARE_UP_BASE, 0x32, generation,
                     generation, 0x32, 1u << 3), ==,
                   GOODIX5503_FDT_EVENT_REJECT);
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_CAPTURE, 0x32, generation,
                     generation, 0x32, 1u << 3), ==,
                   GOODIX5503_FDT_EVENT_REJECT);
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_CAPTURE, 0x34, generation,
                     generation, 0x34, 1u << 4), ==,
                   GOODIX5503_FDT_EVENT_REJECT);
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_DOWN, 0x32, generation + 1,
                     generation, 0x32, 1u << 3), ==,
                   GOODIX5503_FDT_EVENT_REJECT);

  /* Accepted down/up bits have priority over bit 5. */
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_DOWN, 0x32, generation,
                     generation, 0x32, (1u << 3) | (1u << 5)), ==,
                   GOODIX5503_FDT_EVENT_CAPTURE_DOWN);
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_UP, 0x34, generation,
                     generation, 0x34, (1u << 4) | (1u << 5)), ==,
                   GOODIX5503_FDT_EVENT_REPORT_UP);
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_DOWN, 0x32, generation,
                     generation, 0x32, 1u << 5), ==,
                   GOODIX5503_FDT_EVENT_UPDATE_MASK);

  /* Only the exact up command in the armed WAIT_UP generation may report OFF. */
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_UP, 0x34, generation,
                     generation, 0x32, 1u << 4), ==,
                   GOODIX5503_FDT_EVENT_REJECT);
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_UP, 0x32, generation,
                     generation, 0x34, 1u << 4), ==,
                   GOODIX5503_FDT_EVENT_REJECT);
  g_assert_cmpint (goodix5503_fdt_event_action (
                     GOODIX5503_FDT_PHASE_WAIT_UP, 0x34, generation,
                     generation, 0x34, 1u << 4), ==,
                   GOODIX5503_FDT_EVENT_REPORT_UP);
}

static void
test_fdt_up_base_generation (void)
{
  const guint8 manual[GOODIX5503_FDT_BASE_SIZE] = {
    40, 0, 70, 0, 80, 0, 110, 0, 120, 0, 150, 0,
  };
  const guint8 event[GOODIX5503_FDT_BASE_SIZE] = {
    50, 0, 60, 0, 90, 0, 100, 0, 130, 0, 140, 0,
  };
  const guint8 expected[GOODIX5503_FDT_BASE_SIZE] = {
    0x80, 0x29, 0x80, 0x13, 0x80, 0x3d,
    0x80, 0x13, 0x80, 0x13, 0x80, 0x13,
  };
  guint8 output[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  g_autoptr(GError) error = NULL;

  g_assert_true (goodix5503_generate_fdt_up_base (
    manual, event, 0x0001, 0x0004, 21, output, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (output, sizeof output, expected, sizeof expected);

  g_assert_cmphex (goodix5503_fdt_update_area_mask (0x0033, 0, 0x0004),
                   ==, 0x0033);
  g_assert_cmphex (goodix5503_fdt_update_area_mask (0x0033, 1u << 5, 0),
                   ==, 0);
  g_assert_cmphex (goodix5503_fdt_update_area_mask (0, 1u << 5, 0x003f),
                   ==, 0x003f);
  g_assert_cmphex (goodix5503_fdt_update_area_mask (
                     0x0033, (1u << 3) | (1u << 5), 0x0004), ==, 0x0033);
  g_assert_cmphex (goodix5503_fdt_update_area_mask (
                     0x0033, (1u << 4) | (1u << 5), 0x0004), ==, 0x0033);

  memset (output, 0, sizeof output);
  g_assert_false (goodix5503_generate_fdt_up_base (
    manual, event, 0, 1, 1, output, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
  g_clear_error (&error);
  g_assert_false (goodix5503_generate_fdt_up_base (
    manual, event, 0, 1, 0, output, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_INVALID);
}

static void
test_fdt_next_down_base (void)
{
  const guint8 accepted_up[GOODIX5503_FDT_BASE_SIZE] = {
    0x34, 0x12, 0xcd, 0xab, 0x01, 0x00,
    0xfe, 0xff, 0x80, 0x80, 0x00, 0x7f,
  };
  const guint8 expected[GOODIX5503_FDT_BASE_SIZE] = {
    0x80, 0x1a, 0x80, 0xe6, 0x80, 0x00,
    0x80, 0xff, 0x80, 0x40, 0x80, 0x80,
  };
  const guint8 dac[GOODIX5503_DAC_SIZE] = { 0 };
  guint8 output[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint8 request[GOODIX5503_FDT_REQUEST_SIZE] = { 0 };
  g_autoptr(GError) error = NULL;

  goodix5503_fdt_next_down_base (accepted_up, output);
  g_assert_cmpmem (output, sizeof output, expected, sizeof expected);

  /* The command-32 constructor must send the transformed next-down base
   * unchanged; it must not apply the accepted-up transform a second time. */
  g_assert_true (goodix5503_build_fdt_request (
    0x0c, dac, output, request, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (request + 2 + GOODIX5503_DAC_SIZE,
                   GOODIX5503_FDT_BASE_SIZE, expected, sizeof expected);
}

static void
test_fdt_up_base_truncation (void)
{
  guint8 manual[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint8 event[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  guint8 output[GOODIX5503_FDT_BASE_SIZE] = { 0 };
  g_autoptr(GError) error = NULL;

  manual[0] = event[0] = 0xff;
  manual[1] = event[1] = 0xff;
  g_assert_true (goodix5503_generate_fdt_up_base (
    manual, event, 0, 1, 21, output, &error));
  g_assert_no_error (error);
  g_assert_cmphex (output[0], ==, 0x80);
  g_assert_cmphex (output[1], ==, 0x14);
  for (gsize offset = 2; offset < sizeof output; offset += 2)
    {
      g_assert_cmphex (output[offset], ==, 0x80);
      g_assert_cmphex (output[offset + 1], ==, 0x13);
    }
}

static void
test_packed_decoder (void)
{
  const guint8 group[] = { 0xa5, 0x34, 0x67, 0x89, 0xbc, 0xd2 };
  g_autofree guint8 *packed = g_malloc (GOODIX5503_PACKED_IMAGE_SIZE);
  g_autofree guint16 *pixels = g_new0 (guint16, GOODIX5503_PIXEL_COUNT);
  g_autoptr(GError) error = NULL;

  for (gsize offset = 0; offset < GOODIX5503_PACKED_IMAGE_SIZE;
       offset += sizeof group)
    memcpy (packed + offset, group, sizeof group);

  g_assert_true (goodix5503_decode_packed_image (
    packed, GOODIX5503_PACKED_IMAGE_SIZE, pixels, GOODIX5503_PIXEL_COUNT,
    &error));
  g_assert_no_error (error);
  g_assert_cmphex (pixels[0], ==, 0x534);
  g_assert_cmphex (pixels[1], ==, 0x89a);
  g_assert_cmphex (pixels[2], ==, 0x267);
  g_assert_cmphex (pixels[3], ==, 0xbcd);

  g_assert_false (goodix5503_decode_packed_image (
    packed, GOODIX5503_PACKED_IMAGE_SIZE - 1, pixels,
    GOODIX5503_PIXEL_COUNT, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_LENGTH);
}

static void
test_difference_image (void)
{
  g_autofree guint16 *background = g_new0 (guint16, GOODIX5503_PIXEL_COUNT);
  g_autofree guint16 *finger = g_new0 (guint16, GOODIX5503_PIXEL_COUNT);
  g_autofree guint8 *output = g_malloc0 (GOODIX5503_PIXEL_COUNT);
  g_autoptr(GError) error = NULL;

  for (gsize index = 0; index < GOODIX5503_PIXEL_COUNT; index++)
    finger[index] = index % 4096;
  g_assert_true (goodix5503_build_difference_image (
    background, finger, GOODIX5503_PIXEL_COUNT, output, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (output[0], ==, 0);
  g_assert_cmpuint (output[4095], ==, 255);

  for (gsize index = 0; index < GOODIX5503_PIXEL_COUNT; index++)
    {
      background[index] = 1000;
      finger[index] = 1000 + index % 100;
    }
  finger[0] = 4095;
  g_assert_true (goodix5503_build_difference_image (
    background, finger, GOODIX5503_PIXEL_COUNT, output, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (output[0], ==, 255);
  g_assert_cmpuint (output[GOODIX5503_IMAGE_WIDTH + 1], <,
                    output[GOODIX5503_IMAGE_WIDTH + 10]);

  memset (background, 0, GOODIX5503_PIXEL_COUNT * sizeof *background);
  memset (finger, 0, GOODIX5503_PIXEL_COUNT * sizeof *finger);
  g_assert_false (goodix5503_build_difference_image (
    background, finger, GOODIX5503_PIXEL_COUNT, output, &error));
  g_assert_error (error, GOODIX5503_PROTO_ERROR,
                  GOODIX5503_PROTO_ERROR_NO_CONTRAST);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix5503/frame-buffer/split-coalesced",
                   test_frame_buffer_split_and_coalesced);
  g_test_add_func ("/goodix5503/frame-buffer/bad-header",
                   test_frame_buffer_rejects_bad_header);
  g_test_add_func ("/goodix5503/packet/round-trip", test_packet_round_trip);
  g_test_add_func ("/goodix5503/packet/no-checksum", test_no_checksum_packet);
  g_test_add_func ("/goodix5503/packet/reject-mutations",
                   test_packet_rejects_mutations);
  g_test_add_func ("/goodix5503/capture/ordering",
                   test_capture_router_valid_and_reversed);
  g_test_add_func ("/goodix5503/command/router-ordering",
                   test_command_router_ordering);
  g_test_add_func ("/goodix5503/fdt/response-request",
                   test_fdt_response_and_request);
  g_test_add_func ("/goodix5503/fdt/up-request", test_fdt_up_request);
  g_test_add_func ("/goodix5503/fdt/stage-separation",
                   test_fdt_stage_separation);
  g_test_add_func ("/goodix5503/fdt/up-base-generation",
                   test_fdt_up_base_generation);
  g_test_add_func ("/goodix5503/fdt/up-base-truncation",
                   test_fdt_up_base_truncation);
  g_test_add_func ("/goodix5503/fdt/next-down-base",
                   test_fdt_next_down_base);
  g_test_add_func ("/goodix5503/image/decode", test_packed_decoder);
  g_test_add_func ("/goodix5503/image/difference", test_difference_image);
  return g_test_run ();
}
