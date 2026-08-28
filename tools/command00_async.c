#include <errno.h>
#include <libusb-1.0/libusb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#define VID 0x27c6
#define PID 0x5503
#define EP_OUT 0x01
#define EP_IN 0x82
#define IN_CAPACITY 0x8000
#define ACK_TIMEOUT_MS 1500
#define CANCEL_TIMEOUT_MS 1500

static const unsigned char command00[64] = {
    0xa0,0x08,0x00,0xa8,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0xa5
};
static const unsigned char exact_ack[10] = {
    0xa0,0x06,0x00,0xa6,0xb0,0x03,0x00,0x00,0x01,0xf6
};

struct completion {
    volatile int done;
    enum libusb_transfer_status status;
    int length;
};

static double now_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1.0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static int sleep_ms(long ms) {
    struct timespec request = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    while (nanosleep(&request, &request) != 0) {
        if (errno != EINTR) return -1;
    }
    return 0;
}

static int same_ports(libusb_device *device, uint8_t bus,
                      const uint8_t *ports, int port_count) {
    uint8_t observed[8];
    int count;
    if (libusb_get_bus_number(device) != bus) return 0;
    count = libusb_get_port_numbers(device, observed, (int)sizeof(observed));
    return count == port_count && count > 0 &&
           memcmp(observed, ports, (size_t)count) == 0;
}

static libusb_device *find_unique(libusb_context *ctx, uint8_t bus,
                                  const uint8_t *ports, int port_count,
                                  int require_path) {
    libusb_device **list = NULL;
    libusb_device *match = NULL;
    ssize_t count = libusb_get_device_list(ctx, &list);
    int matches = 0;
    if (count < 0) return NULL;
    for (ssize_t i = 0; i < count; ++i) {
        struct libusb_device_descriptor descriptor;
        if (libusb_get_device_descriptor(list[i], &descriptor) != 0) continue;
        if (descriptor.idVendor != VID || descriptor.idProduct != PID) continue;
        ++matches;
        if (!require_path || same_ports(list[i], bus, ports, port_count)) match = list[i];
    }
    if (matches == 1 && match != NULL) libusb_ref_device(match);
    else match = NULL;
    libusb_free_device_list(list, 1);
    return match;
}

static int check_basic_layout(libusb_device *device) {
    struct libusb_config_descriptor *config = NULL;
    int found_out = 0, found_in = 0;
    int result = libusb_get_active_config_descriptor(device, &config);
    if (result != 0) return result;
    if (config->bNumInterfaces != 1) result = LIBUSB_ERROR_NOT_FOUND;
    for (uint8_t i = 0; result == 0 && i < config->bNumInterfaces; ++i) {
        const struct libusb_interface *interface = &config->interface[i];
        if (interface->num_altsetting != 1) { result = LIBUSB_ERROR_NOT_FOUND; break; }
        const struct libusb_interface_descriptor *setting = &interface->altsetting[0];
        if (setting->bInterfaceNumber != 0 || setting->bAlternateSetting != 0) {
            result = LIBUSB_ERROR_NOT_FOUND; break;
        }
        for (uint8_t e = 0; e < setting->bNumEndpoints; ++e) {
            const struct libusb_endpoint_descriptor *endpoint = &setting->endpoint[e];
            if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_TRANSFER_TYPE_BULK)
                continue;
            if (endpoint->bEndpointAddress == EP_OUT) found_out = 1;
            if (endpoint->bEndpointAddress == EP_IN) found_in = 1;
        }
    }
    if (result == 0 && (!found_out || !found_in)) result = LIBUSB_ERROR_NOT_FOUND;
    libusb_free_config_descriptor(config);
    return result;
}

static void transfer_done(struct libusb_transfer *transfer) {
    struct completion *completion = transfer->user_data;
    completion->status = transfer->status;
    completion->length = transfer->actual_length;
    completion->done = 1;
}

static int service_until(libusb_context *ctx, volatile int *done, double deadline) {
    while (!*done) {
        double remaining = deadline - now_seconds();
        struct timeval timeout;
        int result;
        if (remaining <= 0.0) return LIBUSB_ERROR_TIMEOUT;
        if (remaining > 0.05) remaining = 0.05;
        timeout.tv_sec = 0;
        timeout.tv_usec = (suseconds_t)(remaining * 1000000.0);
        result = libusb_handle_events_timeout(ctx, &timeout);
        if (result == LIBUSB_ERROR_INTERRUPTED) continue;
        if (result != 0) return result;
    }
    return 0;
}

static int drain_initial(libusb_device_handle *handle) {
    unsigned char buffer[512];
    for (int i = 0; i < 5; ++i) {
        int transferred = 0;
        int result = libusb_bulk_transfer(handle, EP_IN, buffer, sizeof(buffer),
                                          &transferred, 100);
        if (transferred > 0) memset(buffer, 0, (size_t)transferred);
        if (result == LIBUSB_ERROR_TIMEOUT) return 0;
        if (result != 0) return result;
        if (transferred <= 0) return LIBUSB_ERROR_IO;
    }
    return LIBUSB_ERROR_OVERFLOW;
}

static int self_test(void) {
    if (sizeof(command00) != 64 || sizeof(exact_ack) != 10) return 1;
    for (size_t i = 12; i < sizeof(command00); ++i) if (command00[i] != 0) return 1;
    puts("command00 async diagnostic self-test: OK");
    return 0;
}

static int observe(void) {
    libusb_context *ctx = NULL;
    libusb_device *device = NULL;
    libusb_device *observed = NULL;
    libusb_device_handle *handle = NULL;
    struct libusb_transfer *transfer = NULL;
    struct completion completion = {0};
    unsigned char *buffer = NULL;
    uint8_t ports[8];
    uint8_t bus;
    int port_count, claimed = 0, submitted = 0, result = 1;
    double reset_completed = 0.0, deadline;
    struct rlimit no_core = {0, 0};

    if (setrlimit(RLIMIT_CORE, &no_core) != 0) { perror("setrlimit"); return 1; }
    if (libusb_init(&ctx) != 0) { fputs("libusb init failed\n", stderr); return 1; }
    device = find_unique(ctx, 0, NULL, 0, 0);
    if (device == NULL) { fputs("expected exactly one 27c6:5503\n", stderr); goto cleanup; }
    bus = libusb_get_bus_number(device);
    port_count = libusb_get_port_numbers(device, ports, (int)sizeof(ports));
    if (port_count <= 0 || check_basic_layout(device) != 0) {
        fputs("device topology/layout mismatch\n", stderr); goto cleanup;
    }
    if (libusb_open(device, &handle) != 0) { fputs("device open failed\n", stderr); goto cleanup; }
    if (libusb_kernel_driver_active(handle, 0) != 0) {
        fputs("kernel driver owns interface 0\n", stderr); goto cleanup;
    }

    for (int i = 0; i < 3; ++i) {
        if (libusb_reset_device(handle) != 0) { fputs("USB reset failed\n", stderr); goto cleanup; }
        if (i == 0 && sleep_ms(42) != 0) goto cleanup;
        if (i == 1 && sleep_ms(3) != 0) goto cleanup;
        observed = find_unique(ctx, bus, ports, port_count, 1);
        if (observed == NULL || check_basic_layout(observed) != 0 ||
            libusb_kernel_driver_active(handle, 0) != 0) {
            fputs("device changed or became owned between resets\n", stderr); goto cleanup;
        }
        libusb_unref_device(observed); observed = NULL;
    }
    reset_completed = now_seconds();
    if (reset_completed < 0.0 || libusb_claim_interface(handle, 0) != 0) {
        fputs("interface claim failed\n", stderr); goto cleanup;
    }
    claimed = 1;
    if (drain_initial(handle) != 0) { fputs("initial drain failed\n", stderr); goto cleanup; }
    double remaining = 0.600 - (now_seconds() - reset_completed);
    if (remaining > 0.0 && sleep_ms((long)(remaining * 1000.0 + 1.0)) != 0) goto cleanup;
    observed = find_unique(ctx, bus, ports, port_count, 1);
    if (observed == NULL || check_basic_layout(observed) != 0 ||
        libusb_kernel_driver_active(handle, 0) != 0) {
        fputs("device changed before command00\n", stderr); goto cleanup;
    }
    libusb_unref_device(observed); observed = NULL;

    buffer = calloc(1, IN_CAPACITY);
    transfer = libusb_alloc_transfer(0);
    if (buffer == NULL || transfer == NULL) { fputs("allocation failed\n", stderr); goto cleanup; }
    libusb_fill_bulk_transfer(transfer, handle, EP_IN, buffer, IN_CAPACITY,
                              transfer_done, &completion, ACK_TIMEOUT_MS);
    if (libusb_submit_transfer(transfer) != 0) { fputs("IN submit failed\n", stderr); goto cleanup; }
    submitted = 1;
    deadline = now_seconds() + 1.500;
    int transferred = 0;
    int write_timeout = (int)((deadline - now_seconds()) * 1000.0);
    if (write_timeout < 1) { fputs("OUT deadline expired\n", stderr); goto cleanup; }
    if (libusb_bulk_transfer(handle, EP_OUT, (unsigned char *)command00,
                             sizeof(command00), &transferred,
                             (unsigned int)write_timeout) != 0 ||
        transferred != (int)sizeof(command00)) {
        fputs("command00 OUT failed\n", stderr); goto cleanup;
    }
    if (service_until(ctx, &completion.done, deadline) != 0) {
        fputs("command00 ACK timeout\n", stderr); goto cleanup;
    }
    submitted = 0;
    if (completion.status != LIBUSB_TRANSFER_COMPLETED ||
        completion.length != (int)sizeof(exact_ack) ||
        memcmp(buffer, exact_ack, sizeof(exact_ack)) != 0) {
        fputs("command00 ACK mismatch\n", stderr); goto cleanup;
    }
    puts("command00 async diagnostic: exact ACK");
    result = 0;

cleanup:
    if (observed != NULL) libusb_unref_device(observed);
    if (submitted && transfer != NULL) {
        completion.done = 0;
        (void)libusb_cancel_transfer(transfer);
        if (service_until(ctx, &completion.done, now_seconds() + 1.500) != 0) {
            fputs("fatal: pending IN could not be reclaimed\n", stderr);
            _Exit(2);
        }
    }
    if (buffer != NULL) { memset(buffer, 0, IN_CAPACITY); free(buffer); }
    if (transfer != NULL) libusb_free_transfer(transfer);
    if (claimed) (void)libusb_release_interface(handle, 0);
    if (handle != NULL) libusb_close(handle);
    if (device != NULL) libusb_unref_device(device);
    if (ctx != NULL) libusb_exit(ctx);
    return result;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    if (argc == 2 && strcmp(argv[1], "observe-command00") == 0) return observe();
    fprintf(stderr, "usage: %s --self-test | observe-command00\n", argv[0]);
    return 2;
}
