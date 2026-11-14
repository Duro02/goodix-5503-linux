# GF3258 10062 / 10063 initialization: offline static comparison

## Scope and safety boundary

This note compares only these local PE files, without loading either DLL or
opening a USB device:

| Build | File | SHA-256 |
|---|---|---|
| 10062 | `artifacts/windows-driver/extracted/installed-win11/wbdi.dll` | `35891ece58fecc5f97d5b76bf7a56292e1a845692e218a98754ae505b229fdf1` |
| 10063 | `artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll` | `1f0b55106e637bb39485f29bf85740518a7f3ab21a621967d282ae7e9ea5dffd` |

All addresses below are PE virtual addresses with image base `0x180000000`.
Function boundaries come from `.pdata`; a function is called *normalized
equivalent* only when both ranges have the same size, instruction count,
instruction offsets and instruction lengths, and all changed instructions are
relocation-like code/data references or diagnostic line-number immediates.
That is strong evidence of matching compiled logic, not proof that a 10062
device accepts the same traffic.

No hardware command, including RESET, config, TLS, PSK, enrollment or firmware
operation, was sent for this investigation.  Nothing here enables 10062 or
changes its EXPERIMENTAL classification.

## Results in brief

- **Confirmed:** both DLLs contain the DN2 profile with chip ID `0x220f`; the
  profile callback-table layout relevant to configuration and FDT is unchanged.
- **Confirmed:** `Start`, firmware-version, R-family existing-PSK handling,
  TLS request/status, OTP selection/DAC conversion, configuration generation,
  and FDT parsing have normalized-equivalent 10062/10063 implementations.
- **Strong inference:** after a successfully selected 10062 DN2 profile, the
  pre-configuration ordering in `Start` is the same as the independently
  reconstructed 10063 ordering: `00`, `A6`, `D6`, `D0`, `90`, `C4`.
- **Confirmed exception:** `UpdateAllBase`, reached directly from `Start`, is
  not structurally equivalent.  It is 195 bytes shorter in 10062 and has a
  different final host-state calculation.  Therefore configuration/FDT helper
  equivalence does **not** establish an equivalent full initialization sequence.
- **Confirmed (later focused analysis):** `McuDevLoader::Load` and its static
  callback bindings normalize between the two DLLs.  The resolved loader order
  is wake, Realtek `ProcessPsk`, `UpdateFirmware`, reset, delay, and chip-ID
  lookup.  This establishes host-code correspondence, not a safe or verified
  10062 wire sequence; see `firmware-10062-mcu-loader-analysis.md` and
  `firmware-10062-callback-binding-analysis.md`.

## DN2 selection and callback mapping

The DN2 records have the same fixed fields: the ASCII profile name `GF3258
DN2`, chip ID at `profile+0x3c`, and a callback table at `profile+0x50`.

| Item | 10062 | 10063 | Evidence |
|---|---:|---:|---|
| DN2 profile | `0x180207a50` | `0x180257a70` | raw profile bytes |
| Chip ID (`profile+0x3c`) | `0x220f` | `0x220f` | raw LE32 |
| Callback table | `0x180207aa0` | `0x180257ac0` | `profile+0x50` |
| `ops+0x30` GetChipConfig | `0x18006bf30` | `0x18006c020` | table pointer and normalized pair |
| `ops+0x50` GetFdtInitParam | `0x18006be60` | `0x18006bf50` | table pointer and normalized pair |
| `ops+0x58` FDT-related callback | `0x180064630` | `0x180064720` | table pointer only |
| `ops+0x60` image-related callback | `0x180065ba0` | `0x180065c90` | table pointer only |
| `ops+0x78` manual-base callback | `0x18006ccc0` | `0x18006cdb0` | table pointer only |
| `ops+0x80` navigation-base callback | `0x18006c5d0` | `0x18006c6c0` | table pointer only |
| `ops+0x88` FDT-delta callback | `0x180064480` | `0x180064570` | table pointer and normalized pair family |

This corrects a potentially misleading interpretation of the raw table:
`+0x30` and `+0x50` are offsets from the callback table, not from the profile
header.  The corresponding profile-relative locations are `+0x80` and
`+0xa0`.  Thus the known GetChipConfig/GetFdtInitParam mappings occupy the same
logical slots in both builds.

Later loader/callback analysis resolves corresponding 10062 and 10063 reset
and chip-ID callback targets.  The static code constructs reset `A2/05 14`,
waits 10 ms, then uses a chip-ID helper associated with
`82/00 00 00 04 00`; a per-word byte swap followed by `LE32 >> 8` selects the
matching profile.  The table above confirms that a 10062 DN2 record also
represents `0x220f`.  This remains a static correspondence result only: it
does not establish live preconditions, accepted packets, or safe ordering for
any physical 10062 device.

## `.pdata` address map and normalized comparison

| Role | 10062 `.pdata` span | 10063 `.pdata` span | Result |
|---|---|---|---|
| `Start` | `1800877a0..180088da3` (5,635 B) | `180087890..180088e93` (5,635 B) | normalized equivalent |
| `McuGetFirmwareVersion` | `1800a5ea0..1800a6081` (481 B) | `1800a6060..1800a6241` (481 B) | normalized equivalent |
| `ProcessPsk` | `18009a410..18009af13` (2,819 B) | `18009a5d0..18009b0d3` (2,819 B) | normalized equivalent |
| `SetIap` | `1800a5740..1800a5939` (505 B) | `1800a5900..1800a5af9` (505 B) | normalized equivalent |
| `McuReqTlsConnection` | `1800abea0..1800ac021` (385 B) | `1800ac060..1800ac1e1` (385 B) | normalized equivalent |
| `McuGetTlsStatus` | `1800af050..1800af2ca` (634 B) | `1800af210..1800af48a` (634 B) | normalized equivalent |
| `PresetPskIsValidR` | `1800426c0..180042d22` (1,634 B) | same | normalized equivalent |
| `PresetPskReadSpecDataR` | `180043130..180043531` (1,025 B) | same | normalized equivalent |
| `McuParseFdt` | `1800a6490..1800a6de8` (2,392 B) | `1800a6650..1800a6fa8` (2,392 B) | normalized equivalent |
| `GetChipConfig` | `18006bf30..18006c2b9` (905 B) | `18006c020..18006c3a9` (905 B) | normalized equivalent |
| `GetFdtInitParam` | `18006be60..18006bf2a` (202 B) | `18006bf50..18006c01a` (202 B) | normalized equivalent |
| OTP selector container | `18006ee40..18006f0c1` (641 B) | `18006ef30..18006f1b1` (641 B) | normalized equivalent |
| OTP-to-DAC | `18006f0d0..18006f43e` (878 B) | `18006f1c0..18006f52e` (878 B) | normalized equivalent |
| `UpdateAllBase` | `18008bcd0..18008d04f` (4,991 B) | `18008bdc0..18008d202` (5,186 B) | **not equivalent** |

For `Start`, the only changed instruction categories are 229 RIP-relative
references, 52 direct code targets and 43 diagnostic line-number immediates;
there are no changed ordinary operands.  The same conclusion holds for the
other normalized rows.  The counts are a reproducibility aid, not a claim that
all indirect targets or external Windows APIs have identical semantics.

## Reconstructed call graph

Legend: **C** = confirmed by the paired disassembly or raw PE data; **I** =
strong inference from a normalized 10062 function plus the 10063 reconstruction;
**U** = unverified for 10062.

```text
McuDevLoader::Load [C: paired loader/callback code; later Start handoff U]
  -> wake -> Realtek ProcessPsk -> UpdateFirmware -> reset A2 / delay
     -> chip-ID helper / select DN2 0x220f [C static targets; live behavior U]
  -> Start [C function pair; loader-to-Start handoff U]
       -> command 00 precheck [I]
       -> CheckSensor: A6 OTP retrieval and host validation [I]
            -> OTP selector -> OTP-to-DAC -> GetChipConfig [C helpers]
       -> D6 discriminator [I]
       -> McuReqTlsConnection: D0 [C helper; ordering I]
       -> generated configuration: 90 [I]
       -> driver state: C4 / 01 00 [I]
       -> UpdateAllBase [C direct calls: 10062 0x1800888ae,
                          10063 0x18008899e]
            -> FDT/image/manual-base path [10063 C; 10062 U]

Generic SelfCheck / ProcessPsk [C normalized; not loader-selected]
  -> McuGetFirmwareVersion: A8 / 00 00 [C helper]
  -> R-family existing-record validation (three attempts in the 10063 path) [I]
       -> PresetPskReadSpecDataR: E4 selector bb010002 [C helper]
       -> verify selector bb020007 and cache 32-byte PSK [I]
  -> failure route: SetIap(argument 0x32) [C direct call in both builds]

Loader-selected Realtek ProcessPsk [C normalized]
  -> existing-PSK validation / write / recheck loops [C control flow]
  -> zero-result and non-IAP/test-IAP gate -> RTSMcuEraseApp(0x32)
     -> command A4, payload 00 32 [C; critical, never dispatch]
```

The graph deliberately leaves the loader-to-`Start` handoff and the
post-configuration `UpdateAllBase` behavior unresolved.  Those boundaries can
still yield a different wire sequence despite matching helper bodies.

## Initialization operation table

| Stage | Established command / structure | 10062 conclusion | Confidence and risk |
|---|---|---|---|
| Application identity | `A8`, payload `00 00`; firmware string response | matching version getter and `ProcessPsk` shape | C for helper logic; request is read-only in intent, but do not use it as authorization for hardware access |
| Loader reset | `A2`, payload `05 14`, then 10 ms | corresponding loader callback body selected in both DLLs | C for paired static target; live state-changing behavior and prerequisites U, high risk |
| Chip ID | `82`, payload `00 00 00 04 00`; decode yields profile key | 10062 DN2 table explicitly contains `0x220f`; corresponding static callback selected | C for table/target; physical response and reset-dependent transaction U, high risk |
| Precheck | `00`, payload `00 00 00 00` | inside normalized `Start` sequence by correspondence | I; low protocol semantic risk but no hardware action authorized |
| OTP | `A6`, payload `00 00`; post-reset snapshot feeds host validation | OTP selector and DAC conversion normalized | command placement I; raw OTP is sensitive device state, no acquisition performed |
| OTP-to-DAC | selector chooses validated OTP bytes; DAC is four LE16 words | same container and conversion code | C for host code; source OTP contents remain unknown |
| TLS start | `D0`; 10063 helper has null output pointer/length | `McuReqTlsConnection` and status helper normalized | C for helper correspondence, I for 10062 ordering; state/session transition, high risk |
| Config build | identical 256-byte template: old `0x180207d50`, new `0x180257d70` | generated config host logic normalized | C; template equality does not establish accepted 10062 config |
| Config apply | `90`; 10063 parser accepts a 1--2 byte successful response whose first byte is `01` | normalized config-generation path precedes non-equivalent continuation | I for 10062 dispatch; state-changing, high risk |
| Post-config state | `C4`, payload `01 00` in the normal 10063 cold path | represented by the normalized `Start` ordering | I; state-changing, high risk |
| FDT/manual base | command `36`: `0d 01 || DAC_LE16[4] || transformed 12-byte base` for 10063 DN2 | FDT parser and callback mapping normalize, but coordinator differs | C for parser/callback correspondence; 10062 ordering/payload U; image/base state risk high |
| Existing PSK | R read uses `E4` with selector `bb010002`; verification selector `bb020007` | R read/validation helpers and `ProcessPsk` normalize | C for helper correspondence; exact 10062 record format/live state U; secret-bearing operation, high risk |
| Loader PSK failure boundary | Realtek `ProcessPsk` can call `RTSMcuEraseApp(0x32)`, which dispatches `A4` / `00 32` | paired loader-selected callback; requires zero final result and a non-IAP/test-IAP mode string | C control flow; sensor effect U; **critical risk — never dispatch** |

The TLS response content, the precise `D0` payload, and the complete 10062
configuration outbound body are not asserted here.  The static evidence is
enough to identify their call paths; it is not a substitute for a separately
authorized protocol validation.

## OTP, FDT and configuration details

The existing helper comparison is materially stronger than matching strings:

- `GetChipConfig`, its reached children, the OTP selector container and the
  DAC conversion all preserve their instruction shapes after relocation
  normalization.
- The FDT prefix plus 256-byte template are byte-identical between the two
  DLLs.  The template SHA-256 is
  `db102741e72c88339a33a39af7ed75e2fce035a0354c5495fdd15d538df787e5`.
- The known DN2 command-36 constructor uses four DAC words and a six-word base;
  `McuParseFdt` is normalized, so the *parser* correspondence is confirmed.

This still does not make post-config FDT acquisition equivalent.  In the
10062 `UpdateAllBase` tail, two local status values at `[rsp+0x78]` and
`[rsp+0x7c]` must both equal `2` to store `1` in context field `+0xb8`; otherwise
it stores `0`.  The 10063 tail instead conditionally calls `0x18004ca20` or
`0x180040400`, obtains a byte in `[rsp+0x5c]`, and writes that byte to the same
field.  The semantics of those helper calls, and whether either emits device
traffic, were not established in this work.  This is the primary static
difference and is why no 10062 FDT transaction should be derived from 10063.

## TLS, PSK and enrollment boundary

The generic `ProcessPsk`, `PresetPskIsValidR`, and
`PresetPskReadSpecDataR` normalize, including the generic direct
`SetIap(..., 0x32)` failure call.  Later callback binding establishes that the
loader instead selects Realtek `ProcessPsk`; its equivalent zero-result,
non-IAP/test-IAP fallback reaches `RTSMcuEraseApp(0x32)` and `A4 / 00 32`.
This supports only a narrow conclusion: both packages preserve a dangerous
existing-record failure boundary.  It does **not** prove that a 10062 device
has the same protected record, that its PSK can be recovered on this host, or
that any provisioning/enrollment path is safe.

The official Windows path uses a host-protected existing PSK record and a
separate MCU verification value before TLS.  A missing or invalid record can
reach a critical fallback, which is not a recovery mechanism to emulate.  PSK
creation, replacement, enrollment and TLS establishment remain out of scope.
In particular, the normalised `McuReqTlsConnection` function must not be taken
as permission to try `D0` on firmware 10062.

## Difference from the Linux tree

The current Linux implementation intentionally does **not** treat this static
comparison as support evidence:

- `src/goodix5503/firmware.py` keeps `GF3258_RTSEC_APP_10062` as
  `EXPERIMENTAL`; only `10063` is `SUPPORTED`.
- `libfprint/drivers/goodix5503.c` has an exact 10063 firmware identity guard
  and retains the expected DN2 chip ID `0x220f`.  This work made no change to
  that guard.
- `src/goodix5503/probe.py` permits only a small read-oriented command set and
  rejects reset, configuration upload and TLS before USB transport.  It was
  not changed.
- Linux's local PSK handling is not evidence of Windows DPAPI/enclave record
  compatibility.  Do not translate the normalized Windows PSK helpers into a
  10062 persistent operation.

## Reproduction

Run from the repository root:

```sh
python3 -B tools/report_wbdi_initialization_pairs.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll'
python3 -B tools/compare_wbdi_10062_10063.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll'
python3 -B tools/report_mcu_loader_callbacks.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll'
```

The new report verifies the input hashes, reads `.pdata`, prints DN2 callback
slots, and classifies only disassembly differences.  It uses local `objdump`
and never accesses USB.

## Unresolved questions and next static work

1. Recover the callback/virtual handoff after fingerprint-context creation and
   establish whether, and under which host-only predicates, it reaches
   `Start`.  Do not infer it from matching helper code.
2. Trace `UpdateAllBase` differences through `0x18004ca20` and `0x180040400`
   (and their 10062 counterparts), distinguishing host-only base validation
   from any command dispatch.
3. Resolve the full 10062 post-config indirect callback chain, especially the
   branches through manual FDT, image and navigation-base callbacks.
4. Trace the `UpdateFirmware` decision predicates and the optional adapter
   callbacks used by Realtek `ProcessPsk`; avoiding the A4 fallback alone is
   not a safety guarantee.
5. Locate the 10062-specific firmware/package selector and establish whether
   any condition gates `Start` before the shared-looking code runs.
6. Keep any future hardware question separate: it would require explicit
   authorization, a verified backup/rollback plan for Windows Hello and PSK,
   and a command-by-command guard.  This static result alone is not such
   authorization.
