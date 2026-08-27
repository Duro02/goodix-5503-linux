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
processing did not simply return the all-default vector.

The first reviewed runtime-only clear-frame attempt uploaded this exact config,
completed TLS and reached the fixed image request. After its ACK, firmware 10063
returned a normal message-protocol (`0xa0`) frame where the community 10062 flow
expected the encrypted (`0xb2`) frame immediately. The fail-closed parser stopped
without decoding or saving image data, then attempted its cleanup reset. No
persistent write or firmware operation occurred, and the attempt was not retried.

The revised parser handles this observed 10063 ordering only if the intervening
frame fully decodes as a successful response for the exact image command `0x20`;
it then still requires the next frame to be a structurally valid `0xb2` TLS image
envelope. Other commands, failure status, or malformed packets remain fatal. A
second hardware attempt remains separately review- and user-gated.

## Community post-TLS sequence under review

The reference sequence performs runtime reset, chip-ID/OTP/POV reads, TLS,
configuration upload, two driver-state commands, POV initialization, FDT mode,
and encrypted image retrieval. Clear and finger images are 80 by 64 pixels. The
encrypted application stream is 7,684 bytes including a four-byte trailer; the
packed 12-bit image decoder consumes the remaining 7,680 bytes.

No firmware operation from the community script is permitted. Runtime register,
configuration and sensor-mode writes will be represented only by fixed methods
with exact reviewed payloads; no raw command interface will be added.
