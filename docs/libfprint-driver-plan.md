# libfprint integration plan for Goodix 27c6:5503

## Driver class

The device delivers raw 80 by 64, 12-bit frames and performs host-side feature
processing in the official stack. A Linux implementation should therefore be an
`FpImageDevice`, not a match-on-chip `FpDevice` like `goodixmoc`. libfprint can
own enrollment, minutiae extraction, template storage and matching after the
transport produces a correctly oriented, quality-checked image.

The initial implementation must remain limited to USB ID `27c6:5503`, firmware
`GF3258_RTSEC_APP_10063` and IAP `MILAN_RTSEC_IAP_10027`. Dimensions, packed
format, TLS suite and command payloads are profile constants, not generic Goodix
properties.

## Asynchronous state machines

Use separate bounded `FpiSsm` machines for activation, capture and cleanup:

1. **Activation:** claim the existing bulk interface; NOP; exact firmware/IAP;
   read and compare the R-family PSK verification record; load the locally
   prepared config and PSK; runtime reset; TLS 1.2 PSK handshake; upload the
   exact config; apply the single pinned-default driver-state hook; initialize
   the bounded fresh-base path.
2. **Finger detection:** fixed FDT mode/down commands with cancellable bounded
   waits. Report finger status through `fpi_image_device_report_finger_status()`.
3. **Capture:** parse command-36 data through its dedicated FDT policy (two
   LE16 header fields followed by the exact profile-sized base), then send fixed
   `0x20`; route ACK/A0 command completions separately from B2 encrypted data;
   decrypt one exact application stream; validate
   9-byte opaque prefix, complete TLS records, 7,684-byte plaintext and 4-byte
   opaque trailer boundaries; decode 7,680 packed bytes.
4. **Cleanup/deactivation:** cancel outstanding USB transfer, wipe TLS/PSK,
   packed/plain/pixel and opaque buffers, attempt the fixed runtime reset even
   after an ambiguous earlier reset, release the interface, then report the
   original error.

The frame dispatcher must allow the proven delayed successful `0xd0` completion
at most once and only before an optional successful `0x20` completion. It must
then require B2. Unknown, failed, duplicate, reversed or excess frames are
protocol errors. No general command submission API belongs in the driver.

## Image conversion

The confirmed packing maps each six input bytes to four 12-bit pixels. Do not
copy the community PGM orientation: its writer swaps width and height. Before
setting `FpiImage` flags, one real clear/finger image must establish row order,
rotation, inversion and whether 12-bit values should be linearly reduced to
8-bit or normalized against the clear frames.

The 5,120-pixel area is small. Quality must be measured with libfprint's image
pipeline before assuming NBIS can enroll reliably. Clear/background frames may
need subtraction or gain correction. No raw image, image hash, opaque metadata
or pixel dump should be logged by default.

## Pairing and configuration deployment

The official DLL cannot be distributed or loaded by libfprint. Two stages are
needed:

- **Local prototype:** install the already derived 256-byte config and random PSK
  as root-owned `0600` state outside the source tree, with exact device identity,
  config SHA-256 and verification-record checks before every reset/upload. The
  free `build_local_runtime_config()` KAT already reproduces this unit's exact
  official-derived hash from tcode 224, FDT delta 21 and the reviewed checksum;
  the DLL is no longer needed to rebuild this unit's config.
- **Portable driver:** independently reimplement the reviewed OTP-to-config
  algorithm in free C code and validate it against offline official vectors.
  This removes the local DLL and per-machine pre-generated config requirement.

`fprintd` normally runs privileged, so the current user-owned pairing files are
not the final storage design. Installation must copy only the PSK and derived
config into a dedicated root-owned directory using atomic no-follow creation,
strict owner/mode/length checks and no command-line secret. Uninstall must not
change the device PSK; deleting the host copy would make the device unusable
until explicitly reprovisioned.

## TLS implementation

Use the system OpenSSL library in-process with TLS 1.2 only and cipher
`PSK-AES128-CBC-SHA256` only. The PSK callback/API may require an immutable
library-owned copy; document that limitation, disable core dumps for the daemon
path where practical, avoid network sockets, and cleanse all controllable
buffers with an optimizer-resistant primitive. TLS authentication already
protects the image stream; the nine prefix bytes and four plaintext trailer
bytes remain opaque boundaries, not claimed checksums or status fields.

## Testing gates

Before adding the USB ID to a production build:

- pure C packet framing/deframing and split/coalesced USB transfer tests;
- A0/B2 routing traces for direct B2, delayed D0, optional 0x20, and every invalid
  ordering;
- TLS record fragmentation, short/extra plaintext, alert and cancellation tests;
- packed decoder vectors and all exact-length failures;
- cleanup tests after every state, especially ambiguous reset/config/image waits;
- image orientation/quality tests using explicitly consented, owner-only local
  fixtures (never committed if they contain biometric data);
- repeated enroll/verify/cancel cycles through `fprintd` before PAM integration.

Password authentication must remain available throughout development and PAM
installation. Firmware flashing, downgrade, general register access and public
raw commands remain out of scope.
