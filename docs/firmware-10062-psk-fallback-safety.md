# Realtek `ProcessPsk` fallback safety: offline 10062/10063 analysis

## Scope and safety boundary

This is a static analysis of the two local official `Wbdi.dll` images. It uses
their PE data, `.pdata`, embedded strings and local disassembly only. Neither
DLL was loaded. No USB interface was enumerated or opened, and no firmware,
PSK, TLS, reset, enrollment, configuration, or other device operation was
performed.

Nothing here enables firmware 10062, changes the exact 10063 Linux guard, or
authorizes a hardware compatibility check. Firmware 10062 remains
`EXPERIMENTAL`.

| Input | SHA-256 |
| --- | --- |
| 10062 `artifacts/windows-driver/extracted/installed-win11/wbdi.dll` | `35891ece58fecc5f97d5b76bf7a56292e1a845692e218a98754ae505b229fdf1` |
| 10063 `artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll` | `1f0b55106e637bb39485f29bf85740518a7f3ab21a621967d282ae7e9ea5dffd` |

All addresses are PE virtual addresses with base `0x180000000`. “Success” and
“failure” below describe the surrounding branch relation only where that is
unambiguous; numeric return-code semantics from external adapters are not
invented.

## Conclusion

The `McuDevLoader::Load` PSK callback is the Realtek implementation, not the
previously known generic `SetIap` implementation:

| Item | 10062 | 10063 | Evidence |
| --- | --- | --- | --- |
| callback-table slot | `0x180209d00+0x80` | `0x180259d20+0x80` | static loader descriptor |
| target | `0x1800ad900..0x1800ae51e` | `0x1800adac0..0x1800ae6de` | `.pdata` |
| normalized comparison | 548 instructions | 548 instructions | 176 address-only deltas, zero other operand/control-flow deltas |

`RTSMcuEraseApp` is reachable from that callback only when both of the
following are true:

1. The callback's accumulated final result is zero. A valid PSK verification
   makes the result one and bypasses the fallback. Several earlier failures,
   or exhaustion of the PSK write/recheck flow, can leave it zero.
2. The mode-check input, reached as `+0xc0` from the local structure passed to
   its helper, matches neither embedded case-insensitive marker `IAP` nor
   `TESTIAP`.

When those conditions hold, the code calls `RTSMcuEraseApp` with `0x32`, then
retries once only when its first return is zero. `RTSMcuEraseApp` constructs
the common-dispatch command `0xa4` and two bytes `00 32`. The callback result
is not changed by either erase attempt, so the callback returns its preexisting
zero value. In `McuDevLoader::Load`, zero from the PSK callback takes the
common failure completion; the subsequent firmware-update, reset and chip-ID
callbacks in that loader invocation are not reached.

That is a confirmed control-flow result. It does **not** prove precisely what
the sensor does upon receiving `0xa4`, whether a particular unit would accept
it, or whether its effects are recoverable. The name `RTSMcuEraseApp`, the
IAP-mode log text, and its position on a recovery path justify treating it as
critical risk.

## Callback reachability and comparison

`McuDevLoader::Load` calls its statically bound `+0x80` entry at:

| Event | 10062 | 10063 |
| --- | --- | --- |
| load callback table | `0x180053a79` | `0x180053a99` |
| indirect callback dispatch | `0x180053a97` | `0x180053ab7` |
| zero-result path | `0x180053aa1..0x180053ae4` | `0x180053ac1..0x180053b04` |
| nonzero-result continuation to `UpdateFirmware` | `0x180053ae9..0x180053b4c` | `0x180053b09..0x180053b6c` |

The loader does not select an implementation based on the firmware string.
The callback descriptor and the Realtek function body are paired between the
two packages; there is no static evidence that 10062 uses another PSK transport
or fallback implementation.

The older generic `ProcessPsk` at `0x18009a410` / `0x18009a5d0` does call
`SetIap` at `0x1800a5740` / `0x1800a5900`. It is a distinct function and is
not the `McuDevLoader::Load` `+0x80` target. Its behavior must not be used to
describe the Realtek callback.

## Reconstructed control flow

The graph covers the loader-selected 10062 function. The 10063 graph has the
same shape at the paired addresses.

```text
Realtek ProcessPsk(context)
  |
  +-- context is null ------------------------------------> final_result = 0
  |
  +-- if context+0xd8 == 1: clear host PSK cache buffers
  |
  +-- McuGetFirmwareVersion (A8, read-oriented) ----------> result == 0 -> final_result = 0
  |       |
  |       +-- ExtractFirmwareVersion ---------------------> result == 0 -> final_result = 0
  |
  +-- obtain host protected PSK material / length --------> failure -> final_result = 0
  |
  +-- up to 3x existing-PSK verification
  |       |
  |       +-- one verification returns 0 -----------------> final_result = 1; return
  |       |
  |       +-- all fail -----------------------------------> continue to write stage
  |
  +-- up to 3x PSK-write attempt
  |       |
  |       +-- failed attempts ----------------------------> continue/retry
  |       |
  |       +-- one attempt returns 0 ----------------------> recheck stage
  |
  +-- up to 3x existing-PSK recheck
  |       |
  |       +-- one verification returns 0 -----------------> final_result = 1; return
  |       |
  |       +-- all fail -----------------------------------> final_result = 0
  |
  +-- final_result != 0 ----------------------------------> return
  |
  +-- _stricmp(context+0xc0, "IAP" or "TESTIAP") != 0 --> return 0
  |
  +-- otherwise: RTSMcuEraseApp(0x32)
          |
          +-- first return == 0 -> log and retry once
          +-- otherwise / after retry -> Sleep(100 ms), return 0
```

The shorthand “verification returns 0” is a direct description of the branch
tests (`cmp local_result, 0; je success-block`), not a claimed universal ABI
rule for all helpers. The success block explicitly writes `final_result = 1`.
All non-success paths reaching the final fallback retain or explicitly write
zero.

## Branch-by-branch safety table

| Branch / evidence (10062) | Result / operation | Reachability conclusion | Confidence and risk |
| --- | --- | --- | --- |
| `0x1800ad9ab`: input context is null | writes final result zero and jumps to fallback gate | statically reachable for a null caller; whether loader supplies null is not established | confirmed branch; critical if fallback gate is passed |
| `0x1800ada89`: `McuGetFirmwareVersion` returns zero | logs failure, writes zero | a firmware-version read failure reaches gate | confirmed; high/critical boundary |
| `0x1800adaf2`: `ExtractFirmwareVersion` returns zero | writes zero | malformed/unparseable version result reaches gate | confirmed; high/critical boundary |
| protected-record preparation ending `0x1800add77` | a nonzero helper result writes zero | host protected-record/material preparation failure reaches gate | confirmed control flow; exact helper semantics partly unresolved |
| first verification loop `0x1800ade63..0x1800ae007` | up to three tries; a zero verification result writes final one at `0x1800adff5` | a valid check on any try skips fallback; three failures continue | confirmed loop/branching; critical distinction |
| PSK write loop `0x1800ae01b..0x1800ae19a` | up to three attempts; zero return enters recheck; failures leave zero | exhaustion reaches the gate; a write route can still reach it if all rechecks fail | confirmed loop/branching; writing is state-changing and forbidden |
| recheck loop `0x1800ae1db..0x1800ae323` | up to three tries; a zero check writes final one at `0x1800ae319` | a successful recheck skips fallback; exhaustion leaves zero | confirmed loop/branching; critical distinction |
| fallback gate `0x1800ae328` | only zero enters version-mode helper | every listed zero-result path converges here | confirmed |
| mode helper `0x1800af370..0x1800af3da` | compares `context+0xc0` to `IAP`, then `TESTIAP` with `_stricmp` | either marker returns one and bypasses erase; no match returns zero and reaches erase | confirmed; host-only comparison |
| `0x1800ae3cd` / `0x1800ae42a` | first / optional second `RTSMcuEraseApp(0x32)` | executed only after zero result and neither version marker | confirmed command reachability; **critical** |
| final block `0x1800ae4bd` | returns preserved final result | erase does not convert zero to success; loader aborts current init | confirmed |

## Data flow: status, PSK, firmware and IAP/app state

### Final callback result

The local `DWORD` at `rsp+0x50` is the callback's final result.

- It is initialized to `0xff000001` but later overwritten by the first
  meaningful stage.
- `McuGetFirmwareVersion` stores its return there at `0x1800ada8e`.
- The `ProcessPsk` success blocks explicitly store `1` at
  `0x1800adff5` (first verification) and `0x1800ae319` (post-write recheck).
- Failure branches explicitly store `0` before reaching the gate. The final
  erase block uses a different local (`rsp+0x68`) and never assigns its result
  back to `rsp+0x50`.

This proves that a successful erase attempt is not represented to this caller
as a successful PSK callback. The surrounding loader treats the callback's
zero return as failure and does not advance to its update/reset/chip-ID steps.

### Firmware and mode data

`McuGetFirmwareVersion` is called at `0x1800ada89`; its direct helper builds
command `0xa8` and is described by the embedded `McuGetFirmwareVersion` label.
`ExtractFirmwareVersion` at `0x1800adaf2` parses the returned local version
buffer. The branch gate uses the parsed text at `context+0xc0`, not a sensor
response buffer field inferred from the `0xa4` transport.

The mode helper loads two raw pointers from `0x180210e40` and compares the
`+0xc0` member of its local-structure argument to literal strings `IAP` and
`TESTIAP` through the imported `_stricmp`. It makes no USB call. The inference
that those strings designate IAP/test-IAP mode is strongly supported by the
literal text and adjacent log; the exact structure type, complete
firmware-version grammar, and its relation to a particular sensor state remain
unverified.

### Existing PSK handling

When the optional adapter global `0x180242208` is null, the function uses
direct Realtek helpers, including `PresetPskIsValidR` at `0x1800426c0` for
verification. When the global is non-null, the paired adapter calls at
`0x18004cb00`, `0x18004d810`, and `0x18004d870` replace portions of the same
host protected-record/read/write flow. Their external implementation is not
resolved, so no claim is made that it is side-effect-free.

The embedded strings identify the stages as obtaining sealed/encrypted PSK
material, checking whether a PSK is valid, writing a PSK, and checking again.
The code makes three attempts in each verification/write/recheck loop. Static
analysis establishes retry counts and branch outcomes, but does not expose the
protected material or establish Windows credential availability.

### Destructive branch

`RTSMcuEraseApp` is `0x1800ac130` in 10062. It builds a two-byte buffer whose
first byte is zero and whose second byte is its low-byte argument, then calls
the common command dispatcher with command `0xa4`. Both fallback calls pass
`0x32`, so the observed payload is `00 32`.

At `0x1800ae3d6`, a zero first return takes the retry block and calls it once
again at `0x1800ae42a`; a nonzero first return skips that second call. The
source text calls the zero path “erase app failed, retry”, but this report does
not generalize that return-code convention beyond this branch.

## Existing enrollment and read-only safety assessment

**Confirmed:** if the first verification loop or the post-write recheck gets a
zero result on any of its three tries, `ProcessPsk` stores one and does not run
the mode/erase fallback. This is the only statically established no-fallback
route tied to existing PSK verification.

**Strong inference:** a usable existing host-protected PSK record plus a
matching MCU-side record would lead the direct `PresetPskIsValidR` path to one
of those successful verification branches. The code logs “psk is valid!” on
that route.

**Unknown:** Windows Hello enrollment alone does not prove either condition.
The binary also depends on host protected-record material, adapter behavior,
firmware parsing, MCU responses and power/cache state. The static evidence
cannot determine the result for a particular enrolled sensor.

A read-only compatibility check cannot establish this fallback is safe before
state-changing work. At most, a firmware-version read could classify the
`IAP`/`TESTIAP` string gate. It cannot prove that all protected-record
preparation, existing-PSK verification, optional adapter calls, and rechecks
will yield the no-fallback result. In addition, the official loader calls this
PSK path only after its NOP-style wake callback, and its own read result is
not a substitute for the full host credential state. No live check is proposed
or authorized by this conclusion.

## 10062/10063 comparison

The static descriptor fields select the corresponding Realtek callbacks in
both DLLs. The function boundaries, all final-result field offsets, branch
opcodes, retry limits, `0x32` literal, IAP/test-IAP table, and direct command
path normalize. The raw differences are RIP-relative references and direct
call displacements only; no firmware-specific branch was found.

The following corresponding targets are especially relevant:

| Role | 10062 | 10063 | Result |
| --- | --- | --- | --- |
| Realtek `ProcessPsk` | `0x1800ad900..0x1800ae51e` | `0x1800adac0..0x1800ae6de` | normalized equivalent |
| mode helper | `0x1800af370..0x1800af3da` | `0x1800af530..0x1800af59a` | paired code/data references |
| `RTSMcuEraseApp` | `0x1800ac130..0x1800ac2f5` | `0x1800ac2f0..0x1800ac4b5` | paired construction/transport path |
| `PresetPskIsValidR` | `0x1800426c0..0x180042d22` | same range | normalized equivalent |

Thus the fallback is not a 10062-only addition. It is an equivalent critical
path in both packages; device runtime state, not a demonstrated host-code
difference, decides whether it is taken.

## Linux boundary and remaining questions

No Linux code changed. The repository continues to classify 10062 as
experimental, retains the exact 10063 firmware guard in the libfprint driver,
and rejects reset, configuration, TLS, PSK and firmware-changing paths in the
conservative probe before transport.

The remaining safety-critical questions require more offline work, not a
device test:

1. Recover exact semantics and implementation of optional adapter global
   `0x180242208` and its three callbacks.
2. Trace the direct `PresetPskIsValidR` and write helper data formats far
   enough to label their status values without extracting sensitive material.
3. Recover the callback caller that can supply a null context and determine
   whether this is a realistic loader failure path.
4. Trace `UpdateFirmware` separately; a successful `ProcessPsk` allows the
   loader to reach it, so avoiding the `A4` fallback alone is not a safety
   guarantee.

## Reproduction

The existing offline callback report verifies the selected function and its
normalized 10062/10063 counterpart:

```sh
python3 -B tools/report_mcu_loader_callbacks.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll'
```

The remaining control-flow evidence is reproducible with local `objdump` over
the function span and its named direct descendants. Those reads do not load
the DLL or access hardware.
