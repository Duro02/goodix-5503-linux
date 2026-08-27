# Official 10063 Milan sequence evidence matrix

This document separates facts from the pinned Lenovo Win11 `Wbdi.dll`, shared
Windows log evidence, community 10062 behavior and local hardware observations.
It exists to prevent further step-at-a-time substitution of community commands.

## Source scope

- **Milan static evidence:** pinned `Wbdi.dll` SHA-256
  `567b5af3f2c51eca058172aaa0d0403d82680c75e77d2d073cfd403b1180fb8a`.
- **Shared log only:** `/tmp/WBDI.utf8.log` is PID `27c6:5110`, firmware
  `GF_ST411SEC_APP_12117`, and calls `ChicagoHU*`. It is not a 5503 trace. It can
  corroborate common IoHub framing/state concepts, but not Milan payloads,
  registers, calibration, geometry or full ordering.
- **Community candidate:** `goodix-fp-dump/driver_5503.py` targets firmware 10062.
  Its commands are not official 10063 evidence.
- **Local observations:** firmware/IAP identity, PSK/TLS, OTP-derived config, and
  the fail-closed clear-frame attempts recorded in `device-state.md`.

## Proven Milan facts

| Operation | Exact fact | Evidence |
|---|---|---|
| Identity | firmware `GF3258_RTSEC_APP_10063`, IAP `MILAN_RTSEC_IAP_10027` | official package/profile and local reads |
| Config | 256-byte template at `0x180257d70`; `GetChipConfig` at `0x18006c020`; local tcode 224, FDT delta 21, official checksum | pinned DLL, local read-only OTP derivation, free KAT |
| TLS request | D0 through `McuReqTlsConnection` at `0x1800ac0b0`; caller supplies null output pointer/length, so later A0/D0 data is opaque | pinned DLL call at `0x1800ac14f` |
| TLS finish | fixed D4/`0000` ACK-only after TLS state 16 | shared IoHub log; exact Milan caller VA still missing |
| Image wrapper | `MilanFSerMcuGetImage` at `0x180065c90`; validates output size and dispatches to generic or discriminator-10 path | pinned DLL |
| Generic image request | command 20, payload exactly `01 00`, length 2 | `_FpMcuGetImage` `0x180058610`, IoHub call `0x18005871a` |
| FDT constructor | selector-derived commands 30/32/34/36; payload is two-byte header plus optional dynamic bytes | `_FpMcuSwitchToFdtMode` `0x1800589b0` |
| Manual-base wrapper | selector 3 calls command 36 using a caller-provided dynamic word array | `MilanFSerMcuGetFdtManualBase`, call `0x180065b77` |
| Transport | ACK and later data use separate IoHub paths; B2 is encrypted TLS image data, not A0 command completion | IoHub functions/strings plus local observations |
| Image layout | profile 80x64; 7,680 packed 12-bit bytes decode to 5,120 pixels; TLS plaintext boundary currently 7,684 with four opaque bytes | profile/community/local parser evidence; opaque semantics unknown |

## Not yet proven for Milan 5503

The following must not be copied from the 5110 log or community 10062 script:

- complete cold-init command ordering;
- exact chip-ID register request and any required register writes;
- power-down scan-frequency command/payload;
- whether config 90 precedes or follows TLS on Milan;
- the exact post-D4 MCU-state query payload/parser for Milan;
- C4 twice and its official caller/count;
- D6 and D2 response success semantics;
- the 21 dynamic bytes supplied to command 36 for this unit;
- clear/base acquisition order and whether a stored base is required;
- field meanings of the B2 nine-byte prefix and plaintext four-byte trailer;
- full official failure cleanup and sensor restoration sequence.

Most importantly, the current command-36 literal is the community 10062 value.
The official constructor proves that these bytes are dynamic caller input; the
literal was not found in the pinned DLL. Another hardware run is blocked until
that dynamic Milan input and the surrounding call chain are recovered or the
command is removed from the first-frame path with official evidence.

## Current narrow candidate versus proof

The prototype currently performs identity/PSK checks, reset, D6, TLS D0 flights,
D4, config 90, C4 twice, D2, command 36, image 20 and cleanup reset. Only reset,
TLS, D4, config identity, image `20/0100`, packet/TLS validation and cleanup are
well supported. D6/C4/D2/36 and their ordering remain a community-derived block.
The prototype therefore remains useful as a fail-closed protocol harness but is
not yet an attested reproduction of the complete official 10063 capture state
machine.

## Offline work gate

Before another capture attempt:

1. close the Milan call graph above `MilanFSerMcuGetFdtManualBase` and
   `MilanFSerMcuGetImage`;
2. recover the source and derivation of command-36 optional words for a first
   clear/base frame;
3. recover Milan post-D4 state confirmation or prove it is unnecessary;
4. recover D6/D2/C4 caller semantics or remove them;
5. use a single operation deadline for USB/TLS/cancellation and test every
   partial-frame/failure edge;
6. independently review the resulting complete sequence.

No firmware, PSK or persistent operation is required for this work.
