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

The next hardware step is a fixed read-only opcode `0xa6` OTP query. Its 64-byte
response will remain in mutable non-dumpable memory and feed the official
configuration derivation. Only after the resulting configuration and exact
runtime command sequence pass review will any configuration upload or image
request be attempted.

## Community post-TLS sequence under review

The reference sequence performs runtime reset, chip-ID/OTP/POV reads, TLS,
configuration upload, two driver-state commands, POV initialization, FDT mode,
and encrypted image retrieval. Clear and finger images are 80 by 64 pixels. The
encrypted application stream is 7,684 bytes including a four-byte trailer; the
packed 12-bit image decoder consumes the remaining 7,680 bytes.

No firmware operation from the community script is permitted. Runtime register,
configuration and sensor-mode writes will be represented only by fixed methods
with exact reviewed payloads; no raw command interface will be added.
