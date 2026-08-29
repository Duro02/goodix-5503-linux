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
2. **Finger detection:** fixed FDT down/up commands with cancellable bounded
   waits and explicit arm generations. An exact `0x32` event stores its six raw
   words and area mask, reports ON once and enters command-20 capture first.
   Only after the captured image is submitted upward and libfprint enters
   `AWAIT_FINGER_OFF` does the pinned DN2 path perform one bounded manual `0x36`
   selector-`0x0d` read using the calibrated down base. The runtime takes the
   unsigned wordwise minima, combines the persistent and event area masks,
   generates the exact six-word GF3258 up base with the configured delta, then
   arms `0x34`. A bit-5 event flag replaces the persistent 16-bit area mask; it
   is not a finger-state predicate. Duplicate state notifications cannot repeat
   manual preparation or arming. Only an exact `0x34` event in the matching
   WAIT_UP generation reports OFF, and its transformed raw words become the
   dedicated next down base. The failed TX-off/delta qualification experiment
   is not retained, and no 12-area community arithmetic is used.
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
pipeline before assuming NBIS can enroll reliably. The prototype quality gate
initially used the real asynchronous NBIS path and returned categorical
`usable`, but repeated memory-only enrollment never produced a same-finger
match at the default threshold, at established small-sensor thresholds, after
the reference partial-image orientation, or after reference percentile
normalization. Those failed threshold/orientation experiments were removed.

The replacement uses the maintained Goodix SIGFM implementation:
directional TX-off subtraction, interior 3%..97% normalization, saturated-area
whitening, CLAHE, SIFT features, mutual nearest-neighbor filtering and pairwise
geometric verification. The initial bounded memory-only helper evaluated both
plausible linear interpretations because the protocol profile is 80x64 while
the exact 5503 PGM reference writes the stream as 64x80; it accepted eight
enrollment samples, matched the enrolled finger and rejected a different
finger.

The standard libfprint core strategy was then tested one orientation at a time.
With the protocol's 80x64 interpretation, eight-stage enrollment completed but
all three same-finger verification attempts failed. With the 64x80 linear
interpretation, standard eight-stage memory-only enrollment completed, the same
finger matched and a different finger was rejected. Results were categorical;
no template was serialized or persisted. This is a functional result, not a
statistical FAR/FRR claim.

SIGFM persistent format v1 is therefore bound to the 64x80 interpretation and
the current preprocessing, SIFT, 256-feature/32-correspondence limits,
mutual/geometric matcher and threshold 150. Any orientation, preprocessing,
descriptor, matcher or threshold change that alters feature/match semantics
requires a format-version bump. Persistence is implemented and malformed-input
tested; the first system enrollment exposed and then removed a template made
from repeated stages before physical release. Standard image, NBIS minutiae,
SIGFM feature and variant scratch copies are securely cleared. No raw image,
image hash, opaque metadata, match score or derived biometric statistic is
logged. The superseded dual-pipeline hardware helper was removed after the
standard 64x80 path succeeded; focused non-biometric algorithm tests remain.

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
