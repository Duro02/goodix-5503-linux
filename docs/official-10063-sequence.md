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

## Current bounded runtime path

The active `goodix-5503-capture` entry point begins directly with the proven
command-00 transaction, performs identity/PSK checks, loader reset and chip-ID
selection, the mandatory post-command-00 `A6/0000` CheckSensor OTP snapshot,
TLS D0 flights, config 90, and the bounded official fresh-base coordinator. It
uses dynamic HU command-20/36 payloads, exact command-36 bodies, command
`70/1400`, register-82 delta reads, two consistency comparisons and at most
three complete attempts. Pinned image defaults additionally require cold
command `00/00000000`, one D6/`0000` discriminator, and exactly one post-config
C4/`0100`; D2 and duplicate C4 remain absent. The TLS bridge supports multiple
command-20 images on one session. Runtime validation has completed both the
memory-only clear-frame path and an FDT-down-triggered finger frame. The latter
received the unsolicited command-32 event and then a structurally valid
80x64 B2/TLS image without retaining image bytes or derived statistics. The
interactive validation remains bounded and non-persistent.

No firmware, PSK or persistent operation is required for this work.

Pinned `Geneva::WakeUp @ 0x180099fe0` proves an exact one-byte synchronous raw
bulk-OUT write, a successful-transfer count check, and a 50 ms sleep while the
IoHub lock remains held. It performs no paired IN read, drain, flush, reset, or
parser call. Therefore the observed post-wake invalid outer frame does not
justify adding any of those operations. The Windows IoHub instead has a
persistent asynchronous receive dispatcher: `IoHubNotifyDataIn2 @ 0x18007be40`,
`IoHubNotifyDataProcessed @ 0x18007c0c0`, and `IoHubNotifyAck @ 0x18007bc30`
ignore notifications when no matching command is pending. The free synchronous
reader does not yet reproduce that transport-level filtering. The failed run did not record the offending bytes. A later separately gated
`e5`-only observation saw zero bulk-IN completions for 500 ms after the settle,
so there is no independently queued wake response to drain. A second fixed
one-shot sent exactly one checksummed A8 and also saw zero bulk-IN completions
for 500 ms. Thus the prior invalid frame is not reproducible with a read first
submitted after A8. The Windows IoHub has a receive request pending continuously
through wake and command submission; reproducing that queue-before-OUT property
was then approximated by a third gated one-shot using one queued 32 KiB PyUSB
read, a 25 ms host barrier, `e5`, 50 ms and A8. It still observed zero
completions under a 600 ms absolute deadline. The queue-after-OUT gap is
therefore not the obvious cause, although PyUSB cannot acknowledge actual URB
submission and the official A8 wait budget still requires exact recovery. The
unknown bytes remain unobserved, and blind draining or A8 retry is prohibited.

Static recovery of the Geneva `DevIoParam` and `_IoHubExec` waits corrected the
observation budget: ACK and data each have a separate 1,500 ms timeout, applied
sequentially, so a legal A8 completion can approach 3,000 ms after submission.
The earlier 500/600 ms windows were therefore insufficient. The queued
one-off diagnostic used a 3,250 ms absolute envelope, rechecked the deadline and live
reader after wake and settle, caps the A8 OUT timeout to remaining time, and
records write/completion timing. The reviewed one-shot observed the **free
outer-A8** OUT complete at 528 ms, an exact ten-zero-byte IN completion at 531
ms, and the valid 31-byte A8 firmware frame at 533 ms. This explains the free
client's old `invalid outer frame length`. Final loader tracing proves outer A8
is legitimate firmware-version traffic from `McuGetFirmwareVersion @
0x1800a6060`, called by SelfCheck and ProcessPsk. The distinct
`McuGetCpuVersion @ 0x18009c830` F0/F1 SPI branch is runtime-flag gated and
skipped by the pinned USB configuration; its SPB sequence must not be translated
into libusb commands. Runtime USB selection does skip `_WriteSpi`, but a later no-hardware dynamic
trace through pinned QEMU, Windows, and the staged official driver corrected the
remaining byte-level conclusion. After enumeration and one queued 32 KiB IN
URB, its first application OUT was one padded 64-byte outer-A0 request:
`a00800a800050000000000a5 + 52*00`. No preceding `e5` appeared in that trace.
The byte `a8` at offset 3 is the outer-header checksum, not the command opcode;
the inner command is command `00` with four zero payload bytes and checksum
`a5`. The previously inferred direct-inner A8 packet
`0a0a0a0aa80300000001 + 54*00` and the 15-byte F0/SPB KAT are therefore not the
first pinned Windows USB request. Fail-closed hardware runs attested the exact
command-00 bytes and successful 64-byte completion on endpoint `01`.

A response-only guarded run then captured the full reply before denying the
second 64-byte OUT in the proxy:
`a00600a6b003000001f6`. This decodes normally as outer A0, command `B0`, payload
`00 01`: ACK for command `00`, success. usbmon frames 156/157/159/161 recorded
the prequeued 32 KiB IN, command-00 OUT, successful status-0 completion, and the
10-byte ACK respectively. The ACK arrived 3.411 ms after OUT submission. A new
IN was queued 40.649 ms later, but the next application OUT was denied before
hardware and that IN was cancelled. Thus the first official transaction closes
as ordinary command-00 ACK routing; it is not an A8 firmware response and does
not supply a separate data frame.

A separate owner-only loopback capture then identified that denied second OUT
without forwarding it to hardware:
`a00600a6a803000000ff + 54*00`. This is the ordinary outer-A0 command-A8
firmware-version request with payload `00 00`, padded to 64 bytes. Its complete
usbredir packet SHA-256 exactly matches the guard's denied-frame audit hash
`35e9cd3f285a2dc31c1d98c22ce1cdab2ce15ddf810967f7ba63245e5dd92e68`.
Concurrent usbmon contains only command 00 and its ACK, proving command A8 did
not reach the sensor in that run. Loopback capture SHA-256 is
`ebd77807a2615937d277d793b3443cc543119bad8798ebf2dbf980a2194e0665`;
usbmon SHA-256 is
`21e65fb9d708cad5eb094b3d06e78c21246353379b63f4e2a525c8aa5cfccb19`.

A reviewed two-OUT guard then completed the firmware-A8 transaction. usbmon
recorded exact response frames:

```text
A0 06 00 A6  B0 03 00 A8 01 4E
A0 1B 00 BB  A8 18 00 47 46 33 32 35 38 5F 52 54 53 45 43 5F 41 50 50 5F 31 30 30 36 33 00 12
```

The first decodes as ACK for command A8, success; the second is command-A8 data
`GF3258_RTSEC_APP_10063\0`. OUT completion preceded the ACK by 2.779 ms, and the
31-byte data frame followed 39.499 ms later. The next application OUT was denied
before hardware. Capture SHA-256 is
`21ffdc507804c6f2862512110c858b27e3ec6fb6c5ac17c93b757f36111faa22`;
guard audit SHA-256 is
`d7a6f91158d41fbe8f8ee466b925c64ab2624fcc558801a5d197ecdea12b945b`.
This dynamically proves ordinary separate ACK/data routing for firmware A8.
The Linux clear-frame preflight now mirrors the exact official wire payloads:
command `00/00000000` with ACK only, then two `A8/0000` identity reads with ACK
plus data; disagreement between the two firmware strings is fatal.

A subsequent owner-only loopback capture identified the denied third OUT as an
exact replay of the padded `A8/0000` request, not a new opcode. Its usbredir
packet hash matches the guard denied event, while concurrent usbmon proves it
was not forwarded. This dynamically confirms the static loader result that the
normal successful Windows path reads APP identity twice (SelfCheck, then
ProcessPsk). Loopback capture SHA-256 is
`042991ada67f905ad958fbd699f3605472b5c8db2b94b412d5d792f5a82a4b2f`;
usbmon SHA-256 is
`2b805509c0d2c839d7ed1d076a9fd0272fe17a2cc2a381f2e23e8a802063b36f`.
A reviewed three-OUT run then captured the second A8's exact same success ACK
and 31-byte firmware data before denying the fourth OUT. Thus both normal APP
identity reads have identical ACK/data routing.

The fourth denied-frame SHA-256 was matched offline against the small fixed
read-only candidate set, including the exact usbredir packet ID. It uniquely
matches padded command E4 with selector `bb010002` and zero length:
`a00c00ace40900020001bb00000000ff + 48*00`. The candidate packet hash is
exactly the guard audit hash
`a58048045dd2f77f13188e783ec28856f0e3f9f04bcac940a1806597b9135b64`.
It was denied before hardware in this run.

A later reviewed run allowed that exact read-only mode-0 request. Hardware
returned its normal E4 success ACK followed by a separate 10-byte command-E4
frame whose decoded payload is exactly `01 01`, not a 341-byte record envelope.
The guard's conservative backup-envelope hypothesis therefore failed closed
without forwarding the response to Windows. This dynamically reclassifies the
mode-0 transaction as a protected-record query/status operation; any actual
record recovery must be a later, separately gated transaction. No fifth OUT
reached hardware in that run.

After the exact `01 01` response was forwarded in a reviewed run, the fifth
OUT's complete audit hash was matched offline against the fixed candidate set.
It is an exact second `E4/bb010002/mode0` query, including padding and packet ID,
not a new command or write. It remained denied before hardware. Thus the pinned
Windows path performs this same status query at least twice. A subsequent
reviewed two-query run forwarded the second exact `01 01` response; the sixth
OUT hash again matches the identical mode-0 query. It was denied before hardware,
proving a third query without broadening the command family.

A reviewed three-query run forwarded the third exact `01 01` response and then
denied the seventh OUT before hardware. Its complete usbredir-frame audit hash is
`9578daa46925381e24024ce1bd3c723997557a8cfb1fe8df341791cab123215b`
(packet ID `4638055104`, frame length 74). Unlike the previous repeated queries,
it does not match the fixed read-only candidate set. Static control flow explains
why it must remain blocked: `ProcessPsk` performs exactly three validity attempts,
then the host-only IAP/app check falls through to `SetIap(..., 0x32)`; the next
code path logs `erase app failed, retry...`. `SetIap @ 0x1800a5900` constructs a
two-byte request and submits command `A4`. This is a firmware/IAP transition,
not a read-only loader observation. The dynamic frame was therefore not
forwarded, no loopback capture was enabled, and reconstruction intentionally
stops at this persistent-state boundary. Evidence hashes: usbmon capture
`3e717ae6a48da16816474e095733c3c941deb2bdb8f4bb76df8f4e1751f0dea6`;
owner-only guard audit
`5d16b52b123ce30f2c8811c8a0e47adfa105f49f66d7fe1d49f70e36b6ecb827`.

Pinned static analysis also closes the counterfactual valid branch. The three
observed `bb010002` transactions are three top-level `PresetPskIsValidR`
attempts, not three phases of one read. A successful attempt must recover a
32-byte PSK from a device-resident per-user DPAPI blob, then read the separate
32-byte R verification selector `bb020007` and compare it. Success returns from
`ProcessPsk` immediately; loader continuation is firmware A8, then runtime reset
A2/0514, then chip-ID 82/0000000400. This VM lacks the original Current User
DPAPI master-key state, while the current Linux pairing retained/replaced only
the white-box side. Reaching that official valid branch would therefore require
constructing and persistently writing a new `bb010002` DPAPI record matched to
the existing PSK (normally together with the matching `bb010003` TLV). That is a
new persistent operation and is not authorized by this trace work.

The first runtime attempt at reviewed commit `16750f5` still invoked the static
Geneva raw-wake helper before command 00. It failed closed at the first
command-00 ACK read with `ProtocolError: invalid outer frame length`; it did not
reach any A8, reset, TLS, configuration, FDT, or image operation and was not
retried. This is consistent with the already captured Windows USB evidence that
this selected runtime path has no preceding `e5`. The coordinator now follows
the dynamic transport trace and starts directly with command 00; diagnostic
the obsolete one-off wake tools were later removed from the active codebase.

The next separately reviewed no-wake observation at commit `c0db2a4` sent
command 00 first, as intended, but received no IN completion before its bounded
read expired with `USBTimeoutError`. It again reached no A8, sensor reset, TLS,
configuration, FDT, or image operation and was not retried. The Windows trace's
command-00 success occurred only after its attach/enumeration phase had issued
exactly three standard USB resets while retaining identity and topology. Linux
currently claims and drains the already-present device without any libusb reset.
That reset-only hypothesis was tested once at `d613c6d`: all three resets
completed and command 00 was sent first, but no IN completion arrived before the
bounded timeout. No later operation was reached. Because the experiment
falsified the hypothesis, its specialized reset/descriptor machinery was removed
rather than retained as dormant production complexity. The remaining concrete
transport difference was that Windows had a 32 KiB bulk-IN request queued before
command 00, whereas synchronous PyUSB submitted its first IN only after OUT. A
focused libusb async diagnostic proved this ordering by receiving the exact ACK;
a smaller PyUSB queued-read check then reproduced it. The experimental capture
path now uses that queued-read ordering for its fixed transactions without
changing the generic probe transport.

The free preflight is an explicit **functional PSK substitution**, not a
byte-for-byte replay of the paired Windows loader. It mirrors command 00 and the
SelfCheck and ProcessPsk A8 identity reads, substitutes a direct
`E4/bb020007` verification against the owner-only local PSK for Windows's
unavailable `bb010002` DPAPI recovery, then mirrors UpdateFirmware's third A8
identity read before reset. A normal successful Windows loader therefore has
three total A8 reads on this path, with `bb010002` recovery and `bb020007`
verification between the second and third. The omitted DPAPI-record read is
read-only and has no proven sensor-state effect; its prior contents were
separately backed up and the active PSK is independently verified. Claims of
exact ordering below apply from loader wake/reset and the sensor cold path,
while host secret recovery remains a functional substitution.

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
selected profile. Geneva contains a raw-wake implementation using `e5` and a
50 ms settle, but the pinned Windows USB run emitted no `e5` before its first
application command; its first OUT was command `00/00000000`. The Linux runtime
therefore does not invoke the dormant raw-wake method on this path.
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

Each command-36 call ultimately returns a bounded 12-byte HU base after its
separate ACK, but wire command 36 uses the dedicated `McuParseFdt` parser at
`0x1800a6650`, not `McuParseOther`. `McuParseFdt` consumes two LE16 header fields,
then copies the profile's exact base size from payload offset four. Its packet
length includes the trailing checksum, so for a six-word HU base the minimum
wire data is 4 + 12 + 1 checksum bytes; `_decode_packet()` removes that checksum
and presents an exact 16-byte body to the free parser. A raw usbmon capture at
commit `d6d7a4f` independently confirmed that body. Frames 191/193/195 contain
the exact 22-byte command-36 request, exact success ACK, and full A0 response:

```text
OUT: a01a00ba 361700 0d018b0083008c008700800080008000800080008000 2e
ACK: a00600a6 b00300 3601 c0
A0:  a01400b4 361100 82013f0065014b016b0150016b014701 7e
```

The A0 inner length `0x0011` is exactly 16 data bytes plus its checksum. The
response read was queued after the ACK under a distinct URB, command matching
was correct, and cleanup sent only A2 reset after the fatal result. No command
20 was sent. Capture SHA-256 is
`d20ac47a7f631b07203e03e05e9c2036911ce0fcb38536764a7a86aa0ddd1674`.
Public vendor logs from `tlambertz/goodix-fingerprint-reversing` independently
show the same parser contract on an older Milan profile: a successful raw body
starts with two LE16 fields, `McuParseFdt` logs the second as `fdt touch flag`,
and copies the remaining profile-sized base. The pinned parser proves the same
layout for HU: it reads the interrupt word, derives the touch flag from bytes
2..3, and copies 12 bytes starting at offset four. For manual operation it
selects the manual-base branch before that copy. The observed body therefore
parses losslessly as header `82 01 3f 00` followed by the six raw LE16 base
words; this is official field removal, not truncation or guessed normalization.
Bodies other than exactly 16 checksum-free bytes remain fatal in the free path.
The corrected parser was exercised on the real 10063 unit: all three bounded
fresh-base acquisitions completed, command 20 returned B2/TLS image data, TLS
decrypted to exactly 7,684 bytes, and the structural result was an 80x64 frame
with a 7,680-byte packed body plus the already-defined opaque 9-byte prefix and
4-byte plaintext trailer. No image bytes or biometric-derived statistics were
logged or retained.

A combined read-only 8051 image, formed from the low `0x2000` bytes of the
embedded `MILAN_RTSEC_IAP_10027` resident image and the 10063 APP at `0x2000`,
provides supporting but nonessential evidence: internal code writes `0x3f` to
XDATA `0xc0d0`. The host parser, rather than this unclosed MCU data flow, is the
authority for the four-byte header boundary.

Output1 is the exact six-word body after `McuParseFdt`. Output2 transforms each
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

## Embedded 10063 MCU package

The pinned DLL embeds two identical complete `MILAN_RTSEC_APP_10063` packages.
The descriptor-backed copy starts at file offset `0x1a1cd0`, has length `0xe01a`,
and SHA-256
`14e6effecbcbb5b20a5182c9f8941cd992f20b6ddb2e60a117fce424ab7e5eb5`.
Its 57,328-byte application payload is file range
`0x1a1ce6..0x1afcd6`, SHA-256
`3dcb1dc483ecdb4dadcd3d4d8447dae1d5099509e03f157289cab709b8453fbf`.
The second package at `0x20a520..0x21853a` is byte-identical. Package boundaries
were cross-checked against the official 10062 package and the community 10062
firmware image; no firmware was executed or written.

The payload is Intel 8051 code. `at51` ranks code base `0x2000` highest, which
also makes the `0xdff0` payload end exactly at `0xfff0`; calls into lower
addresses are consistent with ROM services. Radare2 recovers a candidate state-selector jump table with distinct cases
`0x0c`, `0x0d`, and `0x0e`; case `0x0d` reaches mapped address `0x49f2`.
Static evidence does not yet tie those selector values to wire commands 32, 34,
and 36, so they must not be labelled down, up, and manual solely from their
ordering. A nearby `0x3f` write and 16-byte copy are likewise not independent
evidence of the response layout: the copy source uses the 8051 generic-pointer
code-space tag and points into the lower resident image. MCU data flow to the
four leading response bytes remains unclosed; their parsing is instead justified
by the pinned host `McuParseFdt` implementation described above.
