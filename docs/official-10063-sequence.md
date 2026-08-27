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
| Local HU image request | discriminator 10 selects `_HUGetImage`; command 20 payload is `01 00` plus four live LE16 DAC words, length 10 | `_HUGetImage` `0x180065ef0`, IoHub call `0x180066127` |
| Generic image request | non-discriminator-10 profiles use command 20 payload `01 00`, length 2; this is not the local GF3258 branch | `_FpMcuGetImage` `0x180058610` |
| Local FDT constructor | command 36 payload is a two-byte header, the same 8-byte live DAC field, and 12 transformed base bytes | `HUFpMcuSwitchToFdtMode` `0x18006dcc0` |
| Local manual-base wrapper | selector 3 calls command 36 and returns raw and transformed forms of a bounded 12-byte response | `HUMilanFSerMcuGetFdtManualBase` `0x18006cdb0` |
| Transport | ACK and later data use separate IoHub paths; B2 is encrypted TLS image data, not A0 command completion | IoHub functions/strings plus local observations |
| Image layout | profile 80x64; 7,680 packed 12-bit bytes decode to 5,120 pixels; TLS plaintext boundary currently 7,684 with four opaque bytes | profile/community/local parser evidence; opaque semantics unknown |

## Not yet proven for Milan 5503

The following must not be copied from the 5110 log or community 10062 script:

- optional resume/sensor-check branches outside the normal fresh-base path;
- the callback semantics preceding the register-82 FDT-delta read;
- power-down scan-frequency command/payload, if any;
- D6 and wire-92 response-body semantics beyond transport completion;
- runtime high-nibble state used in command 36;
- exact transport capacities/timeouts for every command-20 branch;
- field meanings of the B2 nine-byte prefix and plaintext four-byte trailer;
- full official failure cleanup and sensor restoration sequence.

The fixed community command-36 literal has been removed from the runtime path.
Both command 20 and command 36 are now built from the unit's freshly read OTP;
the first command-36 base suffix is the proven zero-base value. The prior
D4/`0000` step has also been removed: it came from the 5110 log, while pinned
Milan exposes no immediate D4.

## Current narrow candidate versus proof

The dormant runtime implementation now begins with the Geneva raw wake byte
`e5` and 50 ms settle, performs identity/PSK checks, loader reset and chip-ID
selection, the mandatory post-command-00 `A6/0000` CheckSensor OTP snapshot,
TLS D0 flights, config 90, and the bounded official fresh-base coordinator. It
uses dynamic HU command-20/36 payloads, exact command-36 bodies, command
`70/1400`, register-82 delta reads, two consistency comparisons and at most
three complete attempts. Pinned image defaults additionally require cold
command `00/00000000`, one D6/`0000` discriminator, and exactly one post-config
C4/`0100`; D2 and duplicate C4 remain absent. The TLS bridge supports both
command-20 images on one TLS session.
The hardware entry point remains explicitly disabled before USB even with
confirmation until this new coordinator passes independent review.

## Offline work gate

Before another capture attempt:

1. independently review the bounded coordinator and multi-image TLS bridge;
2. verify all short/oversized command-36, delta, retry and cleanup tests;
3. retain a single operation deadline across USB and TLS;
4. confirm no optional resume-only command was accidentally made mandatory;
5. only then consider one runtime-only, memory-only validation.

No firmware, PSK or persistent operation is required for this work.

Pinned `Geneva::WakeUp @ 0x180099fe0` proves an exact one-byte synchronous raw
bulk-OUT write, a successful-transfer count check, and a 50 ms sleep while the
IoHub lock remains held. It performs no paired IN read, drain, flush, reset, or
parser call. Therefore the observed post-wake invalid outer frame does not
justify adding any of those operations. The Windows IoHub instead has a
persistent asynchronous receive dispatcher: `IoHubNotifyDataIn2 @ 0x18007be40`,
`IoHubNotifyDataProcessed @ 0x18007c0c0`, and `IoHubNotifyAck @ 0x18007bc30`
ignore notifications when no matching command is pending. The free synchronous
reader does not yet reproduce that transport-level filtering. The failed run
did not record the offending bytes, so their signature and length remain
unknown; blind draining or A8 retry is prohibited.

The free preflight is an explicit **functional PSK substitution**, not a
byte-for-byte replay of the paired Windows loader: it performs one bounded A8
APP identity read and the R verification read `E4/bb020007`, then compares the
owner-only local PSK-derived record. Windows additionally performs two A8 reads
and reads protected record `bb010002` before recovering the same paired secret.
Those omitted operations are read-only and have no proven sensor-state effect;
the local protected record was separately backed up and the PSK is independently
verified. Claims of exact ordering below apply from loader wake/reset and the
sensor cold path, not to this substituted host PSK recovery.

F6 is intentionally absent from the up-to-date APP branch. The previously
recorded `MILAN_RTSEC_IAP_10027` attestation in `docs/device-state.md` is accepted
for controlled runtime work, while the fresh A8 check prevents proceeding when
the device is currently in IAP mode.

## Targeted profile-table findings

The DLL selects between two GF3258 profiles solely from the shifted four-byte
MCU chip-ID register read (`82/0000000400`), not from PID, firmware or OTP:

- chip ID `0x220f`: `GF3258 DN2` at `0x180257a70`, ops `0x180257ac0`;
- chip ID `0x2503`: `GF3258 WN2` at `0x180256b80`, ops `0x180256bd0`.

A reviewed fixed read performed without reset returned zero and was discarded;
the pinned loader sequence was then reproduced as reset `A2/0514`, 10 ms delay,
and fixed register read `82/0000000400`. After per-word byte swapping and the
loader's `LE32 >> 8`, the local unit returned **`0x220f`**, conclusively selecting
DN2. The prepared DN2 config is now independently profile-attested rather than
being circular evidence. The table
`0x180258110` belongs to GF3288 and remains inapplicable. DN2-only slots used by
the dormant implementation are:

- `+0x30` GetChipConfig `0x18006c020`;
- `+0x50` GetFdtInitParam `0x18006bf50`;
- `+0x60` MilanFSerMcuGetImage `0x180065c90`;
- `+0x78` GetFdtManualBase `0x18006cdb0`;
- `+0x80` GetNavBase `0x18006c6c0`;
- `+0x88` GetFdtDelta `0x180064570`.

WN2 differs materially: its config template and profile-specific operations are
different, its navigation base is 80x16 rather than 80x12, and its expected
image sample is 10,564 rather than 7,684 bytes. A DN2 upload may be accepted at
the command layer without proving that the hardware is DN2.

Before `LogicMilanFSeries::Start`, pinned `McuDevLoader::Load` performs reset
`A2/0514`, waits 10 ms, reads and validates the chip ID, and constructs the
selected profile. The earlier loader begins with raw wake byte `e5` and a 50 ms
settle; it is not the framed command-00 NOP formerly used by the free preflight.
`Start` at `0x180087890` then proves the high-level cold order: cold command-00
precheck, CheckSensor `A6/0000` plus host OTP/DAC validation, one D6 POV
discriminator, D0/TLS start, validated config generation/upload, one
pinned-default post-config C4/state-1 hook, remaining host FDT initialization,
then `UpdateAllBase` at
`0x18008bdc0`. A fresh-base branch calls manual FDT base, nav base, manual FDT
base, delta validation, image base, then a third manual FDT base. A valid saved
base follows a different branch. It does not prove the community sequence
`C4,C4,D2,36,20`.

With pinned globals `0x180256808=1` and `0x180256810=1` and a calloc-zero fresh
logic object, the normal cold branch executes command `00/00000000`, then one
D6/`0000`, and later exactly one C4/`0100`. D6 advertises capacity one and
accepts decoded payload lengths 0..1; an empty payload retains the pre-zeroed
normal-cold discriminator `00`. `AA`, `DA`, and `DF` each call host-only
`McuStopTls` and then rejoin the same D0/config path. They emit no branch-local
USB packet and consume no saved one-key image. Because the free path has no
active TLS session, socket, thread or server at D6, it is already in the equivalent stopped state
and accepts these bounded discriminators before starting a fresh D0 session.
D2 and duplicate C4 remain unsupported.
The free DN2 config builder consumes that same validated post-reset OTP
snapshot. It derives selector byte `b3` from OTP offset 27, image tcode at
`eb:ec` and FDT word at `c7:c8` from offsets 42/43/45, then recomputes the
checksum; no prior fixed snapshot is uploaded.

Config 90 uses `McuParseChipConfig`, whose input length includes the trailing
wire checksum. It subtracts that checksum and copies the payload from its
unchanged start pointer. The free `_decode_packet()` already validates and
removes this checksum, so its returned payload must not be sliced again. Config
payload is bounded to one or two bytes and byte zero must equal `01`. The fourth
controlled validation exposed the former double-removal bug and stopped before
C4 or image acquisition.

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

## OTP-to-DAC derivation

The original 64-byte OTP is sufficient. `0x18006ef30` selects offsets
`0x32..0x35` when either its 23-byte CRC predicate or the four-byte CRC at
`otp[0x3e]` passes; otherwise it selects `0x2e..0x31` using the corresponding
right-side predicates. The CRC is complemented CRC-8/poly-0x07 with initial
zero. If neither family passes, at least three of the four paired bytes must
match; one mismatch is repaired to the floor-average of the other three left
bytes. Fewer than three matches fails closed in the free implementation.

`0x18006f1c0` zero-extends the four selected bytes to four LE16 words and writes
them to context `+0x70` and snapshot `+0x78`. The free implementation is in
`src/goodix5503/hu_runtime.py`; it requires a mutable exact 64-byte buffer. The
capture path retains only the derived eight-byte field and wipes OTP immediately.

The same live DAC field is consumed by two local commands:

```text
command 20: 01 00 || DAC_LE16[4]                         # 10 bytes
command 36: 0d 01 || DAC_LE16[4] || transformed_base[6] # 22 bytes
```

## Fresh-base coordinator and command-36 response

For no valid saved base, `UpdateAllBase` `0x18008bdc0` performs:

1. command 36 manual base0;
2. command 20 image followed by host-only nav-base conversion: decode the
   7,680 packed bytes to an 80x64 LE16 image, then retain complete rows
   8,12,...,52 as an 80x12 (1,920-byte) nav base;
3. command 36 manual base1;
4. command 70 payload `14 00`, then command 82 register-read payload
   `00 82 00 02 00`; parse its distinct Milan RegRw header, require read
   operation and exactly two data bytes, then interpret the returned LE16 value shifted right by eight
   as delta and compare base0/base1;
5. command 20 image base;
6. command 36 manual base2;
7. host comparison of base1/base2 and commit of transformed base2.

The host fallback nav conversion at `0x1800456d0`/`0x180059120` has no
content-dependent failure: it is a fixed row copy. The free coordinator performs
the same decode and crop and retains the result through the later acquisitions
before wiping it; no proprietary enclave implementation is required.

Each command-36 call requests a bounded 12-byte payload after its separate ACK.
`McuParseOther` at `0x1800a74e0` subtracts the trailing wire checksum represented
in its packet-object length and copies from the unchanged payload pointer; it
does **not** remove a leading result byte. The free `_decode_packet()` has
already removed that checksum, so the payload must pass unchanged to the HU
parser. Payloads 0..12 are right-zero-padded and anything over 12 remains an
error. The latest controlled run reported 15 only after the former one-byte
slice, proving the actual checksum-free device payload was 16 bytes and still
exceeds the official capacity. Output1 is the padded raw six-word response.
Output2 transforms each
raw LE16 word `x` to `((x >> 1) << 8) | 0x80`; accepted output2 becomes the base
for later requests. The DLL retries inconsistent pairs without a numeric bound;
the free implementation must instead use the existing operation deadline and a
small explicit retry cap.

The register-82 delta decode is unsigned high-byte extraction. The DLL executes
`movzx eax,word` before `sar eax,8`, so raw `00 ff` produces threshold 255;
base comparisons are `abs(u16_a-u16_b) <= zero_extended_delta`.

There is no C4, D6, D2, AE or wire-92 preparation *between* these acquisitions.
The pinned-default cold D6 occurs before TLS/config and the single C4 occurs
after validated config but before host FDT initialization. Duplicate C4 and D2
must not be introduced.
