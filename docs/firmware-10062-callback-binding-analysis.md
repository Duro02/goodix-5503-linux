# `McuDevLoader::Load` callback bindings: offline 10062/10063 analysis

## Scope and safety boundary

This document is static analysis of the two reviewed local `Wbdi.dll` PE
images. It reads PE `.data`, `.pdata`, code, strings and local disassembly.
Neither DLL was loaded; no USB interface was enumerated or opened; and no
RESET, NOP, PSK, IAP, TLS, configuration, enrollment, firmware, or other
device operation was sent. It makes no change to Linux firmware support,
the 10063-only identity guard, or the experimental classification of 10062.

| DLL | SHA-256 |
| --- | --- |
| 10062 `artifacts/windows-driver/extracted/installed-win11/wbdi.dll` | `35891ece58fecc5f97d5b76bf7a56292e1a845692e218a98754ae505b229fdf1` |
| 10063 `artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll` | `1f0b55106e637bb39485f29bf85740518a7f3ab21a621967d282ae7e9ea5dffd` |

Addresses are image-base VAs (`0x180000000`). Function extents are taken from
the PE exception table (`.pdata`). “Normalized equivalent” means the paired
functions have matching instruction offsets and lengths and all differing
operands are direct-code/RIP-relative addresses; it is evidence of matching
host code, not permission to reproduce a device action.

## Result in brief

The five callbacks used by `McuDevLoader::Load` are not dynamically chosen
from an unknown C++ object. They are direct pointers in a statically initialized
descriptor table in each PE image. The corresponding 10062 and 10063 entries
select paired implementations, and every selected implementation below is
normalized equivalent.

The important correction to the previous “opaque callbacks” statement is:

```text
McuDevLoader::Load
  static root -> root+0x38 -> Mcu callback table
  +0xc0  McuSendNop trampoline
  +0x80  Realtek ProcessPsk
  +0x78  Realtek UpdateFirmware
  +0x30  McuResetFingerPrint
  +0x40  McuGetChipId wrapper
```

This confirms that the loader can reach command construction and transport in
both builds. It does not establish a safe device precondition, successful I/O,
or compatibility of a 10062 unit's persistent state.

## Identification and static binding

The loader identities remain independently established by their
`McuDevLoader.c`/`Load` diagnostic arguments, the Mcu dispatcher entry, and
the adjacent separate SPI loader.

| Routine | 10062 `.pdata` | 10063 `.pdata` | Finding |
| --- | --- | --- | --- |
| `McuDevLoader::Load` | `0x180053690..0x18005411d` | `0x1800536b0..0x18005413d` | 2,701 B / 444 instructions each; normalized equivalent |
| descriptor `CreateContext` factory | `0x1800ac300..0x1800ac3a8` | `0x1800ac4c0..0x1800ac568` | normalized equivalent; allocates a `0xf8`-byte host object |
| common indirect-call thunk | `0x1801085b0` | `0x18014f520` | CFG/IAT dispatch target, not a device transport routine |

The `.data` binding chain is concrete:

| Item | 10062 | 10063 | Evidence |
| --- | --- | --- | --- |
| loader root-pointer cell | `0x180206840` | `0x180256840` | read at loader `+0x117` (`0x1800537a7` / `0x1800537c7`) |
| static root descriptor | `0x180209de0` | `0x180259e00` | raw qword in each pointer cell |
| `root+0x00` factory | `0x1800ac300` | `0x1800ac4c0` | loader invokes it first and keeps its returned host object |
| `root+0x38` callback table | `0x180209d00` | `0x180259d20` | raw qword; copied to `0x18023fd70` / `0x18026bad0` |
| returned factory object | `0x18023fd78` | `0x18026bad8` | loader passes it as callback `RCX` |

The root's `+0x10` and `+0x18` handlers are invoked after factory creation to
register/configure that object. The exact semantic names of those two handlers
are not recovered. The callback table itself is a raw static function-pointer
array, not a demonstrated MSVC C++ vtable: this analysis found no RTTI
complete-object locator evidence for it. A whole-`.text` xref scan found the
root pointer cells read by the loader but no executable writer that repopulates
them. Thus PE initialization/relocation is the established binding mechanism;
there is no evidence here of a firmware-dependent runtime substitution.

## Callback layout and paired targets

`McuDevLoader::Load` reads each listed slot from the global callback-table copy
and invokes it through the CFG dispatcher. The load/call locations below are
the 10062 sites; 10063 is the corresponding `+0x20` shifted body.

| Slot | Loader evidence | 10062 target / `.pdata` | 10063 target / `.pdata` | Normalized result |
| --- | --- | --- | --- | --- |
| `+0xc0` wake | read/call `0x18005393b/0x180053959` | `0x1800a9730..0x1800a9748` | `0x1800a98f0..0x1800a9908` | equal 6-instruction trampoline |
| `+0x80` PSK | `0x180053a79/0x180053a97` | `0x1800ad900..0x1800ae51e` | `0x1800adac0..0x1800ae6de` | equal 548-instruction Realtek `ProcessPsk` |
| `+0x78` firmware update | `0x180053b2c/0x180053b4c` | `0x1800ae520..0x1800aedd1` | `0x1800ae6e0..0x1800aef91` | equal 386-instruction Realtek `UpdateFirmware` |
| `+0x30` reset | `0x180053bea/0x180053c05` | `0x1800a7b00..0x1800a7d15` | `0x1800a7cc0..0x1800a7ed5` | equal 100-instruction `McuResetFingerPrint` |
| `+0x40` chip ID | `0x180053c64/0x180053c84` | `0x1800a5b30..0x1800a5cb4` | `0x1800a5cf0..0x1800a5e74` | equal 71-instruction `McuGetChipId` wrapper |

The order is therefore confirmed as NOP-style wake, Realtek PSK handling,
Realtek update decision/action, reset, imported `Sleep(10)`, then chip-ID
read. Each callback's zero result takes the loader's common failure path.
There is no firmware-version branch in the loader body or in the binding
selection itself.

The source-name evidence is direct: each target logs the respective embedded
name (`McuSendNop`, `ProcessPsk`, `UpdateFirmware`, `McuResetFingerPrint`, or
`McuGetChipId`) along its source path. In particular, the wake trampoline
directly calls `McuSendNop` at `0x1800a8090` / `0x1800a8250`; it is not an
unresolved generic “wake” implementation merely because the loader error text
says `WakeUp failed`.

## Transport reachability and observed command construction

The shared dispatch helper is `0x18007b840` in 10062 (paired address in 10063).
The following are static code facts, not commands issued in this work.

| Loader branch | Established descendant | Code-level packet evidence | Confidence / risk |
| --- | --- | --- | --- |
| wake | `McuSendNop` | passes command `0x00`, a zero-filled 4-byte local payload, and length 4 to the common dispatcher | confirmed reachability; device I/O potential, high |
| reset | `McuResetFingerPrint` | passes `0xa2` and local bytes `05 14`, length 2, to the dispatcher | confirmed reachability and construction; state-changing, critical |
| chip ID | wrapper -> `_McuGetChipId` (`0x1800abcb0..0x1800abe9d` / `0x1800abe70..0x1800ac05d`) | wrapper fixes selector zero and read length 4; helper builds `00 00 00 04 00` and dispatches `0x82` | confirmed reachability and construction; read intent but follows reset, high |
| PSK | Realtek `ProcessPsk` | selected target contains protected-record checks and state-dependent calls; its recovery branch can dispatch through `RTSMcuEraseApp` | confirmed loader reachability; persistent-state risk, critical |
| firmware | Realtek `UpdateFirmware` | selected target is explicitly named and contains firmware/IAP comparison/update paths | confirmed loader reachability; flashing risk, critical |

The command builder's return value only shows local success/failure handling;
static analysis cannot show that a USB transaction was accepted or completed.

## PSK, `SetIap`, and firmware safety boundary

There are two different `ProcessPsk` implementations in these binaries. This
distinction matters.

1. **The loader-selected callback is Realtek `ProcessPsk`** at
   `0x1800ad900` / `0x1800adac0`. It is the static `+0x80` target and is
   normalized equivalent. Its local fallback executes only after its prior
   processing result is zero and its two-attempt helper at
   `0x1800af370` / `0x1800af530` also returns zero. The branch logs “Not in
   IAP/TESTIAP mode”, calls `RTSMcuEraseApp` with literal `0x32`, and retries
   once if the first return is zero. `RTSMcuEraseApp` builds command `0xa4`
   with bytes `00 32`. This is an established potentially destructive route.

2. The previously found direct `SetIap` calls are in a **different** generic
   `ProcessPsk` body at `0x18009a410` / `0x18009a5d0`, not in the loader's
   `+0x80` callback. There, `SetIap` (`0x1800a5740` / `0x1800a5900`) is reached
   after the mode-check helper at `0x18009c590` returns zero; it is called with
   `0x32` and retried once on a zero return. That body is itself paired, but
   this analysis has not recovered a path selecting it for `McuDevLoader::Load`.

Consequently, it would be wrong either to say “the Mcu loader calls SetIap” or
to dismiss the loader's PSK branch as harmless because it does not call that
exact function. The selected Realtek path has its own IAP/app-recovery route.
Neither fallback's real-world trigger semantics, return-code convention, or
effect on an existing Windows Hello credential has been established.

`UpdateFirmware` is also selected before reset. Its paired body includes
firmware-version checks and named `UpdateFirmware`/IAP paths. Its exact
runtime predicates, image selection, and whether it can write on the target
device remain unknown; the static reachability alone warrants retaining the
current conservative guard.

## DN2 handling and later fingerprint context

After chip-ID callback success, the loader shifts the returned `DWORD` right
by 8 and calls profile lookup `0x180055790` / `0x1800557b0`. The matching DN2
profile record contains `profile+0x3c == 0x220f` in both DLLs. Thus the loader
uses the same profile-lookup mechanism for the known DN2 ID; it does not embed
an immediate `0x220f` comparison or a 10062-specific version branch.

On a profile match, it registers additional Mcu/profile handlers and calls
the fingerprint-context selector `0x180085de0` / `0x180085ed0`. That selector
chooses a static context descriptor by a profile-derived type value and stores
the result in `0x18023fd50` / `0x18026bab0`. These are host-side construction
and registration steps as far as the recovered code proves.

No direct call to `Start` (`0x1800877a0` / `0x180087890`) occurs in either
loader. Whole-image direct-call xrefs also do not reveal a direct caller for
those addresses: `Start` is separately represented in profile operation data.
The eventual scheduling/virtual handoff from the stored fingerprint context to
that operation remains **unknown**. Matching `Start` code therefore does not
prove that loader completion runs configuration, TLS, or enrollment.

## 10062 versus 10063 conclusion

The root descriptor, relevant field offsets, concrete callback targets, branch
order, and selected callback implementations pair one-for-one. The comparison
script reports only address-target differences for every resolved callback:

| Pair | Instructions | Address-only deltas | Other operand/control deltas |
| --- | ---: | ---: | ---: |
| `McuSendNop` | 74 | 24 | 0 |
| reset | 100 | 30 | 0 |
| chip-ID wrapper | 71 | 24 | 0 |
| chip-ID helper | 101 | 15 | 0 |
| Realtek `ProcessPsk` | 548 | 176 | 0 |
| Realtek `UpdateFirmware` | 386 | 126 | 0 |

This is strong evidence against a callback-binding or transport-implementation
change being the source of the firmware-10062 question. It does **not** prove
that the two firmware images have equal runtime state, provisioning records,
IAP/application mode, or Windows Hello enrollment behaviour.

## Linux comparison and risk assessment

No Linux source was changed. The existing safety posture remains appropriate:

| Linux component | Current boundary | Relation to this result |
| --- | --- | --- |
| `src/goodix5503/firmware.py` | `GF3258_RTSEC_APP_10062` is `EXPERIMENTAL`; only 10063 is supported | unchanged |
| `libfprint/drivers/goodix5503.c` | exact 10063 firmware guard; DN2 ID `0x220f` | unchanged; static Windows similarity is insufficient to relax it |
| `src/goodix5503/probe.py` | rejects reset, configuration, TLS, PSK and firmware-changing paths before transport | protects against all high/critical branches recovered here |

The worst unresolved risk is persistent credential state: Realtek `ProcessPsk`
and `UpdateFirmware` are both confirmed loader-reachable before reset/profile
selection, but their state predicates are not known. No conclusion about
preservation of an existing Windows Hello enrollment or PSK can safely be drawn.

## Reproduction and remaining questions

Run only from the repository root:

```sh
python3 -B tools/report_mcu_loader_callbacks.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll'
```

Recommended next offline work:

1. Recover the asynchronous scheduler/virtual edge from stored fingerprint
   context to the profile `Start` entry, or explicitly prove it is external.
2. Trace the predicates and return values feeding the loader-selected Realtek
   `ProcessPsk` and `UpdateFirmware` branches, including the helper behind its
   two-attempt IAP/app fallback.
3. Identify the source and semantics of the factory registration handlers at
   root `+0x10/+0x18`; do not infer them from nearby profile strings.
4. Keep all work offline until a separately authorized preservation and
   recovery design exists. No device command or support-guard change follows
   from this analysis.
