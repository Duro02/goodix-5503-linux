# `McuDevLoader::Load`: offline 10062/10063 comparison

## Scope and safety boundary

This is an offline comparison of the two supplied official `Wbdi.dll` PE
images.  It reads PE metadata, embedded strings, `.pdata`, `.data`, and local
disassembly only.  It did **not** load either DLL, enumerate or open USB, send
a command, reset the sensor, read OTP, start TLS, alter PSK material, upload a
configuration, enroll, or update firmware.

The result identifies the Windows loader implementation and its static call
graph.  It is not authorization to reproduce any reachable device operation.
In particular, it does not change the 10063-only Linux guards or the
experimental status of firmware 10062.

### Status of callback identification

This document originally recorded the loader before its callback descriptor
was fully resolved.  `firmware-10062-callback-binding-analysis.md` supersedes
the earlier “opaque target” wording: the paired descriptor binds `+0xc0` to
`McuSendNop`, `+0x80` to Realtek `ProcessPsk`, `+0x78` to Realtek
`UpdateFirmware`, `+0x30` to `McuResetFingerPrint`, and `+0x40` to
`McuGetChipId`.  `firmware-10062-psk-fallback-safety.md` supersedes the
generic-`SetIap` characterization of the loader PSK callback.  The
loader-to-`Start` handoff and all live-device outcomes remain unresolved.

Inputs (SHA-256) are the reviewed files used by the existing comparison tools:

| DLL | SHA-256 |
| --- | --- |
| 10062 `artifacts/windows-driver/extracted/installed-win11/wbdi.dll` | `35891ece58fecc5f97d5b76bf7a56292e1a845692e218a98754ae505b229fdf1` |
| 10063 `artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll` | `1f0b55106e637bb39485f29bf85740518a7f3ab21a621967d282ae7e9ea5dffd` |

## Function identification and boundaries

The primary target is not inferred from a nearby string alone.  Three
independent static facts identify it:

1. Its entry logs the pair `McuDevLoader.c` / `Load` (10062 strings
   `0x18010e9c0` / `0x18010ea1c`; 10063 `0x1801559f0` / `0x180155a3c`).
2. Its address is the first entry in the selected MCU dispatcher pair.  The
   adjacent entry is its cleanup handler.  The adjacent *separate* pair is
   tagged by `SpiDevLoader.c` / `Load`, ruling out an accidental match to the
   SPI implementation.
3. The body contains the Mcu-loader-specific diagnostic sequence `WakeUp
   failed`, `psk process...`, `update firmware...`, `reset fingerprint failed`,
   `get chipid failed`, and the chip-profile lookup.

| Logical routine | 10062 `.pdata` range | 10063 `.pdata` range | Size / instructions | Identification evidence |
| --- | --- | --- | --- | --- |
| `McuDevLoader::Load` | `0x180053690..0x18005411d` | `0x1800536b0..0x18005413d` | 2,701 B / 444 | `McuDevLoader.c`, `Load`, MCU dispatcher entry |
| Mcu loader cleanup | `0x180053600..0x180053686` | `0x180053620..0x1800536a6` | 134 B | adjacent dispatcher entry; `_DevLoaderCleanUp` path |
| `SpiDevLoader::Load` (control) | `0x1800541b0..0x1800549c5` | `0x1800541d0..0x1800549e5` | 2,069 B / 342 | `SpiDevLoader.c`, `Load`, adjacent SPI dispatcher entry |
| `Start` (separate later stage) | `0x1800877a0..0x180088da3` | `0x180087890..0x180088e93` | 5,635 B | prior paired analysis |

The relevant `.data` dispatcher is likewise paired:

| Entry | 10062 | 10063 | Value |
| --- | --- | --- | --- |
| selected-loader pointer | `0x1802067d0` | `0x1802567d0` | points to Mcu or SPI pair |
| MCU `Load`, cleanup | `0x1802067d8`, `+0x8` | `0x1802567d8`, `+0x8` | `Load`, then cleanup |
| SPI `Load`, cleanup | `0x1802067e8`, `+0x8` | `0x1802567e8`, `+0x8` | separate SPI implementation |

The common DevLoader code at 10062 `0x180052515` (10063
`0x180052535`) takes entry zero from the selected pair and invokes it through
a type-erased function wrapper.  Its completion thunk is 10062
`0x180050b20` (10063 `0x180050b40`).  The corresponding cleanup path takes
entry `+0x8` (10062 `0x1800533b0`; 10063 `0x1800533d0`).  A global flag
(`0x180206808` / `0x180256808`) chooses the Mcu pair when nonzero and the SPI
pair when zero.  The origin and meaning of that flag are not resolved here;
the selection block has no firmware-version string or explicit comparison.

## Normalized comparison

`tools/compare_wbdi_10062_10063.py` reports:

```text
McuDevLoader::Load: .pdata 0x180053690-0x18005411d / 0x1800536b0-0x18005413d;
size=2701; instructions=444; raw-different-bytes=331;
address-only-instruction-deltas=142; non-address-deltas=0;
normalized-equivalent=True
```

Every changed instruction byte is part of either a RIP-relative address or a
direct-call displacement.  There are no changed immediates, conditional jump
opcodes, register/memory operand forms, field offsets, or control-flow shape.
The sibling SPI loader has the same result (102 address-only changes and zero
non-address changes).  This is strong evidence that the package-layout shift,
not a firmware-specific source change, accounts for the raw differences.

Important direct calls inside the paired Mcu body are also structurally the
same:

| Purpose recovered from surrounding code | 10062 | 10063 | Result |
| --- | --- | --- | --- |
| common argument/state check | `0x1800ca070` | same | unchanged target |
| profile lookup by decoded chip ID | `0x180055790` | `0x1800557b0` | paired target |
| create the selected fingerprint context | `0x180085de0` | `0x180085ed0` | paired target |
| loader cleanup on failed path | `0x180053600` | `0x180053620` | paired target |
| completion callback | indirect wrapper | indirect wrapper | same call sites and argument layout |

The remaining calls include indirect callbacks held in runtime objects.  Their
invocation sites, object-field offsets, branch predicates, and success/error
paths normalize.  The later descriptor analysis resolves the loader callback
targets named below, but does not prove their live-device outcomes.

## Reconstructed loader flow

The following graph distinguishes an established direct edge (`-->`) from a
descriptor-bound callback edge (`==>`).  “Potential USB” means that the target
can reach the Mcu/Io layer; no call was executed for this work.

```text
DevLoader common init worker
  --> selected dispatcher[0]
        ├─ Mcu pair: McuDevLoader::Load
        └─ SPI pair: SpiDevLoader::Load

McuDevLoader::Load
  --> host argument/state validation
  ==> McuSendNop wake callback         [potential device operation]
  ==> Realtek ProcessPsk callback      [host protected-record flow; may enter critical recovery]
  ==> Realtek UpdateFirmware callback  [potential firmware-state operation]
  ==> McuResetFingerPrint callback     [potential device-state operation]
  --> Sleep(10 ms)
  ==> McuGetChipId callback            [potential read transaction]
  --> chip_id = returned_u32 >> 8
  --> profile lookup(chip_id)
  --> construct/store fingerprint context
  ==> completion(success) or cleanup + completion(error)
```

The precise `Start` invocation is **not** a direct edge from this function:
neither loader contains a direct reference to either `Start` address.  The
loader makes a fingerprint context available through opaque wrapper objects;
an eventual `Start` handoff remains outside the recovered direct call chain.
The independently normalized `Start` pair is therefore relevant background,
not proof that this loader directly runs it.

`Start` itself is also callback-dispatched: its first-entry function pointer is
stored at `0x180208d50` (10062) / `0x180258d70` (10063), with the containing
ops-table reference at `0x180208de8` / `0x180258e08`.  This supports the
absence of a direct `call` from the loader, but it does not bridge the two
opaque object graphs.  The loader-to-`Start` edge therefore remains unknown.

### Detailed success and failure logic

The Mcu body performs the following ordered checks.  Each callback failure
takes the common failed completion path; no retry loop is visible in this
function.

| Order | Static evidence | Confirmed effect in the loader | Device reachability / risk |
| --- | --- | --- | --- |
| 1 | `WakeUp failed` branch preceding the `psk process...` branch | invokes descriptor-bound `McuSendNop` at `+0xc0` and fails closed | command construction known; device effect untested, high |
| 2 | `psk process...` diagnostic following a `+0x80` callback | invokes Realtek `ProcessPsk` before firmware and reset | its fallback can reach `RTSMcuEraseApp` / `A4 00 32`; critical; no write was attempted |
| 3 | `update firmware...` diagnostic following a `+0x78` callback | invokes Realtek `UpdateFirmware` before reset | decision predicates unresolved; potentially flashing, critical |
| 4 | `reset fingerprint failed`, then imported `Sleep(10)` | invokes descriptor-bound `McuResetFingerPrint`, then waits 10 ms only on that path | static command construction known; state-changing, high |
| 5 | `get chipid failed`, callback result stored as 32-bit value | invokes descriptor-bound `McuGetChipId` and decodes `value >> 8` | read in intent but occurs after reset; physical response untested, high |
| 6 | direct call to lookup, then `finger print module not found` error | lookup failure triggers cleanup/error completion | host-only, high confidence |
| 7 | direct fingerprint-context constructor and null check | stores new context/callback state; success completion only after creation | host-side construction; target-specific downstream behaviour unresolved |

The success state is set only after context creation.  All earlier failures run
the Mcu cleanup entry and complete with an error status; successful completion
uses status zero.  The observed `0xe0000001` error value is an error-completion
constant, not a sensor response code.

## Chip-ID and profile handling

The loader does not contain an immediate `0x220f` comparison.  Instead it
decodes the returned 32-bit value with `shr eax, 8` and passes the result to
the profile lookup.  The supplied DN2 records are the matching profile-table
evidence:

| Item | 10062 | 10063 | Finding |
| --- | --- | --- | --- |
| DN2 profile | `0x180207a50` | `0x180257a70` | corresponding record |
| chip field, `profile+0x3c` | `0x220f` | `0x220f` | identical |
| profile operation table | `0x180207aa0` | `0x180257ac0` | corresponding table |
| Mcu loader profile lookup | `0x180055790` | `0x1800557b0` | normalized direct edge |

Thus **confirmed**: if the decoded result is `0x220f`, the table supplies the
DN2 profile in both DLLs.  **Not confirmed**: that a particular physical
10062 unit returns that value, or that the runtime callback uses an identical
wire request in the two packages.

There is no firmware-string comparison or firmware-version branch inside either
`McuDevLoader::Load`.  Firmware-dependent behaviour, if any, must be inside
the invoked PSK/firmware callback targets or a later context stage.  The
normalization result rules out an added or removed branch in the loader body
itself.

## USB command reachability

`McuDevLoader::Load` contains no immediate Goodix command byte or direct
`IoSendCmd` call.  It delegates command work through function-object fields,
so it cannot by itself prove a complete packet or transport outcome.  The
following assessment deliberately limits claims to the evidence available.

| Operation | Static link from Mcu loader | Additional named-helper evidence | Assessment |
| --- | --- | --- | --- |
| wake | descriptor-bound `McuSendNop`, before PSK | static helper constructs NOP-style command `00` | device-reaching; live effect untested, high |
| PSK processing | descriptor-bound Realtek `ProcessPsk`, before update/reset | fallback can call `RTSMcuEraseApp(0x32)` -> `A4 / 00 32` | can cross into persistent app/IAP handling; **critical risk** |
| firmware update | descriptor-bound Realtek `UpdateFirmware`, after PSK | update decision predicates remain unresolved | potentially flashing; **critical risk** |
| reset fingerprint | descriptor-bound `McuResetFingerPrint`, followed by 10 ms sleep | helper constructs command `A2` with `05 14` in both packages | static binding/packet construction confirmed; **high risk** |
| chip ID | descriptor-bound `McuGetChipId`, after reset | static helper associated with `82 / 00 00 00 04 00` | static binding confirmed; response/live semantics untested; **high risk** |
| config, TLS, enrollment | no direct call or command constant in this loader | they occur only in later/helper analyses | no direct reachability established from `Load`; downstream context handoff remains unknown |

The `A2/05 14` and `82` rows are intentionally not promoted to an execution
recipe.  They show why static discovery of the loader increases, rather than
reduces, the reason to retain transport guards.

## Relation to PSK/TLS, configuration, and enrollment

The important new fact is ordering, not a new 10062-specific implementation:
the loader invokes the PSK and firmware callbacks before reset and chip-ID
profile selection.  It then only creates a fingerprint context.  The matching
body does not directly call configuration generation/application, TLS setup,
or enrollment code.

Prior paired work established normalized equivalence of `ProcessPsk`,
firmware/version helpers, TLS helpers, OTP-to-DAC, config generation, FDT
parsing, and `Start`.  Combining that with this result supports only the
following bounded conclusion:

- **Confirmed:** the Mcu loader's callback ordering and error handling are the
  same in 10062 and 10063.
- **Strong inference:** the established 10062/10063 reset and chip-ID helper
  sequences are selected through the same corresponding Mcu callback layout.
- **Unknown:** whether a 10062 device has an acceptable existing Windows
  protected PSK record, whether the firmware-update callback decides to act,
  and whether the later context handoff reaches config/TLS/enrollment in the
  same live-device circumstances.

Nothing here establishes Windows Hello enrollment compatibility or preservation
of PSK state.  In fact, the reachable Realtek `ProcessPsk -> RTSMcuEraseApp`
failure boundary and firmware callback make any live validation particularly
unsuitable without separate authorization and a recovery plan.

## Comparison with the Linux tree

No Linux code was changed.  The current repository remains deliberately safer
than the Windows loader:

| Linux component | Current behaviour | Consequence |
| --- | --- | --- |
| `src/goodix5503/firmware.py` | classifies `GF3258_RTSEC_APP_10062` as `EXPERIMENTAL` | this analysis does not enable it |
| `libfprint/drivers/goodix5503.c` | retains exact `GF3258_RTSEC_APP_10063` guard and expected chip ID `0x220f` | 10062 remains rejected by the production driver |
| `src/goodix5503/probe.py` | allowlist excludes reset, configuration, TLS, firmware and PSK-writing commands before USB transport | none of the loader-reachable state changes can be dispatched by the conservative probe |

Linux therefore has no equivalent to the Windows DevLoader callback chain in
the currently authorized 10062 path.  It also must not add one merely because
the Windows Mcu loader normalizes: the callback targets can be state-changing
and their live preconditions are unresolved.

## Remaining unknowns and recommended next work

1. Recover the callback/virtual handoff after fingerprint-context creation and
   establish whether, and under which host-only predicates, it reaches
   `Start`.  Do not assume it from matching helper code.
2. Trace the Realtek `UpdateFirmware` decision predicates and the optional
   adapter callbacks used by Realtek `ProcessPsk`; neither path is shown safe.
3. Identify the source and meaning of the dispatcher flag
   `0x180206808` / `0x180256808`.  It selects Mcu versus SPI but is not shown
   to be a firmware selector.
4. Maintain strictly offline analysis until explicit authority, preservation
   procedures, and a verified recovery/rollback plan exist.  No 10062 support,
   USB operation, or guard relaxation follows from this document.

## Reproduction

Run from the repository root; both commands only read the two PE files and run
the local disassembler:

```sh
python3 -B tools/compare_wbdi_10062_10063.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll'

python3 -B tools/report_wbdi_initialization_pairs.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll'
```

The two scripts now include both `McuDevLoader::Load` and its adjacent
`SpiDevLoader::Load` control pair, verify the pinned DLL digests, recover the
`.pdata` ranges, and reject non-address instruction differences.
