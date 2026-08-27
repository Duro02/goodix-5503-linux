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
| TLS status | Milan operation table selects wire `92` with a dynamic one-byte request and two-byte output; no immediate D4 constructor exists in pinned Milan code | table `0x180259ce0`, `McuGetTlsStatus` `0x1800af210` |
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

The current command-36 literal is the community 10062 value. Corrected GF3258
analysis proves the official local payload is also 22 bytes, but its fields are
dynamic and the literal is not the official zero-base first request. Another
hardware run is blocked until those local values and the surrounding call chain
are implemented. The prior D4/`0000` step has also been removed: it came from
the 5110 log, while pinned Milan uses a dynamic wire-92 TLS-status operation and
exposes no immediate D4.

## Current narrow candidate versus proof

The former prototype candidate performed identity/PSK checks, reset, D6, TLS D0
flights, config 90, C4 twice, D2, command 36, image 20 and cleanup reset. Only
reset, TLS, config identity, image `20/0100`, packet/TLS validation and cleanup
are well supported. D6/C4/D2/36 and their ordering remain a community-derived
block. The hardware entry point is now explicitly disabled before USB even with
confirmation; it cannot be mistaken for an attested official sequence.

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

## Targeted profile-table findings

The correct local profile is `GF3258 DN2` at `0x180257a70`, with sensor ops at
`0x180257ac0`. The previously considered table `0x180258110` belongs to GF3288
and must not be used. Important GF3258 slots are:

- `+0x30` GetChipConfig `0x18006c020`;
- `+0x50` GetFdtInitParam `0x18006bf50`;
- `+0x60` MilanFSerMcuGetImage `0x180065c90`;
- `+0x78` GF3258 GetFdtManualBase `0x18006cdb0`;
- `+0x80` GF3258 GetNavBase `0x18006c6c0`;
- `+0x88` GetFdtDelta `0x180064570`.

`LogicMilanFSeries::Start` at `0x180087890` proves the high-level cold order:
D6-capable POV check, D0/TLS start, config generation/upload, one optional
post-config state hook, FDT/OTP host initialization, then `UpdateAllBase` at
`0x18008bdc0`. A fresh-base branch calls manual FDT base, nav base, manual FDT
base, delta validation, image base, then a third manual FDT base. A valid saved
base follows a different branch. It does not prove the community sequence
`C4,C4,D2,36,20`.

The pinned Milan MCU table selects generic D6/D2/C4 constructors but only proves
capability. D6 has a one-byte output whose content its constructor does not
interpret; D2 is output-bearing POV data, not a boolean; C4 is ACK-only and only
one shared direct state-1 caller was found. The community duplicate C4 and fixed
D2 invocation remain unsupported.

## Corrected GF3258 command 36 layout

The local `+0x78` target is `HUMilanFSerMcuGetFdtManualBase` at `0x18006cdb0`,
not the GF3288 function `0x180065810`. It calls the HU constructor
`0x18006dcc0`. For selector 3 and a 12-byte base, the exact layout is:

```text
(mode_nibble << 4 | 0x0d) 01
<four little-endian 16-bit live DAC values: 8 bytes>
<six transformed base words: 12 bytes>
```

The DAC values are initialized from four selected OTP bytes by
`milan_hu_series_update_dac_register_from_otp` at `0x18006f1c0` and may later
be updated from live registers. Each base word is transformed as
`(word & 0xff00) | 0x0080`. On the fresh calloc-zero branch, the suffix is
therefore six repetitions of wire bytes `80 00`. The exact official first
request is:

```text
0d 01 || <8 unit/runtime-specific DAC bytes> || (80 00) * 6
```

The community literal has the right 22-byte length, but embeds unverified DAC
values and nonzero saved/acquired-base high bytes. It is neither derivable from
the 256-byte config nor valid as the proven fresh zero-base request.
