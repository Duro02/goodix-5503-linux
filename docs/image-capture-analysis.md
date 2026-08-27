# Image-capture and runtime configuration analysis

## Confirmed configuration origin

The 256-byte `DEVICE_CONFIG` base used by the community 5503 script is present
inside the pinned Lenovo Win11 `Wbdi.dll` 3.1.581.610 at VA `0x180257d70`.
Two official references identify its role:

- `GetFdtInitParam` references it at `0x18006bfe2`.
- `GetChipConfig` references it at `0x18006c2c0`, copies exactly `0x100` bytes,
  applies OTP-derived calibration values, and recomputes the final checksum.

`GetChipConfig` receives a device/context object, OTP bytes and OTP length, then
returns an allocated 256-byte runtime configuration. Static analysis shows it
parses at least tcode/diff and FDT-offset values from OTP. If parsing fails it
uses defaults, but still recalculates the configuration checksum.

The community constant is therefore not a universal opaque literal. Compared
with the official zero-OTP/default output, it differs at byte 200 (`0x16`
instead of `0x15`) and at checksum byte 254. This is consistent with calibration
for a different device. It must not be uploaded unchanged to this sensor.

## Local reproduction

`goodix5503.chip_config` maps the pinned DLL in Unicorn and invokes only official
`GetChipConfig` at `0x18006c020`. It hooks fixed allocation/logging/cookie
helpers, accepts exactly 64 mutable OTP bytes, requires status 1 and exactly 256
output bytes, validates the guest output pointer, and clears guest registers,
heap and stack. The all-zero OTP output is pinned as an offline regression
vector.

The reviewed fixed read-only opcode `0xa6` query returned exactly 64 OTP bytes.
The raw OTP remained in mutable non-dumpable memory, was not printed or saved,
and was cleared after official derivation. The resulting 256-byte configuration
has SHA-256 `54e6cd4c0d18b4472e7ec066a11aabcc55389779e426562a9c2bcfd2e188eba6`,
a valid independently checked official checksum, FDT delta `0x15`, and an
OTP-derived image tcode change from the default 256 to 224. It is stored owner-only at `artifacts/device-backup/runtime-config-5503.bin`. Its hash
differs from the zero-OTP regression output, confirming that real nonzero OTP
processing did not simply return the all-default vector. Static comparison shows
that this unit's final config changes only image tcode bytes `0xeb..0xec` from
256 to 224 and the resulting checksum; FDT delta remains the official default
21. `build_local_runtime_config()` now reproduces the exact pinned config hash
from the free template/field/checksum implementation without loading the DLL.

The first reviewed runtime-only clear-frame attempt uploaded this exact config,
completed TLS and reached the fixed image request. After its ACK, firmware 10063
returned a normal message-protocol (`0xa0`) frame where the community 10062 flow
expected the encrypted (`0xb2`) frame immediately. The fail-closed parser stopped
without decoding or saving image data, then attempted its cleanup reset. No
persistent write or firmware operation occurred, and the attempt was not retried.

On the single authorized retry, the intervening frame fully decoded as command
`0xd0`, not `0x20`. This is a delayed completion response for the earlier TLS
request. Static official-driver evidence agrees: `McuReqTlsConnection` at
`0x1800ac0b0` submits `0xd0` through `IoHubMcuSendCmd2`, whose ACK and later data
notifications are separate. The retry again stopped fail-closed, decoded/saved
no image, and attempted cleanup reset. No third attempt is authorized.

The offline state-machine revision permits at most one successful, fully
validated delayed `0xd0` completion before an optional successful `0x20`
prelude; `0xd0` must precede `0x20`. The following frame must still be a
structurally valid `0xb2` TLS image envelope. Unknown commands, failure status,
duplicates, reversed order, malformed packets, or more than two preludes remain
fatal. Further hardware use remains separately review- and user-gated.

## Community post-TLS sequence under review

The reference sequence performs runtime reset, chip-ID/OTP/POV reads, TLS,
configuration upload, two driver-state commands, POV initialization, FDT mode,
and encrypted image retrieval. The B2 outer payload contains nine opaque bytes
followed by complete TLS records; those bytes are not part of the four-byte
Goodix outer header. TLS decrypts to 7,684 bytes: 7,680 packed image bytes plus
four opaque trailing bytes. Neither opaque region's field semantics are proven,
so they must not be labelled as status, length or checksum. The parser retains
both in mutable buffers, enforces exact 9/4-byte boundaries, and wipes them
without printing or saving their content.

Official `_FpMcuGetImage` at `0x180058610` constructs a two-byte request beginning
with `1` and submits command `0x20` through `IoHubMcuSendCmd2` (`0x18007b930`).
Official IoHub strings distinguish ACK, data-in and data-processed callbacks,
supporting separate routing for A0 completions and B2 encrypted data. Clear and
finger images are 80 by 64 pixels; their packed 12-bit decoder consumes exactly
7,680 bytes.

No firmware operation from the community script is permitted. Runtime register,
configuration and sensor-mode writes will be represented only by fixed methods
with exact reviewed payloads; no raw command interface will be added.
