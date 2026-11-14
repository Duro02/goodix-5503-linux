# `UpdateAllBase` 10062 vs 10063: offline control-flow and `+0xb8` analysis

## Scope and conclusion

This is static analysis of the two local official `Wbdi.dll` files only.  The
DLLs were not loaded and no USB device was opened.  No reset, configuration,
TLS, PSK, enrollment, firmware or other device operation occurred.

The material difference is now established precisely:

```text
10062: context->field_b8 = (status_a == 2 && status_b == 2)

10063: context->field_b8 = adapter_or_state_machine(status_a, status_b,
                                                     process_global_state)
```

In the local fallback used by 10063, `field_b8` becomes one only when the
combined result is `2` *and* the preceding process-global result is `0`, `2`,
or `3`.  Otherwise the global is updated and the field becomes zero.  Thus a
pair of local `2` values is necessary but no longer sufficient.

`+0xb8` is confirmed to be a host-context `DWORD` flag.  It is not a USB frame
field, a sensor configuration byte, or an FDT response field.  Its descriptive
name and the meaning of result code `2` remain unknown; this document calls it
`field_b8` rather than inventing a name.

The difference is in host-side FDT/base coordination.  It has no established
direct path to PSK or enrollment, and the changed fallback contains no local
USB command construction or known transport call.  An optional 10063 adapter
ends in an unresolved imported call, so it cannot be claimed side-effect-free.

## Inputs and method

| Build | File SHA-256 |
|---|---|
| 10062 | `35891ece58fecc5f97d5b76bf7a56292e1a845692e218a98754ae505b229fdf1` |
| 10063 | `1f0b55106e637bb39485f29bf85740518a7f3ab21a621967d282ae7e9ea5dffd` |

Addresses are PE VAs, image base `0x180000000`.  Function extents are read
from `.pdata`.  The comparison uses local `objdump`, direct branch targets and
instruction operands.  Basic-block counts below are *syntactic* CFG counts:
they include a block after an unconditional jump when executable bytes follow,
and do not claim reachability without runtime inputs.

## Function boundaries, callers and CFG shape

| Property | 10062 | 10063 |
|---|---:|---:|
| `UpdateAllBase` `.pdata` | `18008bcd0..18008d04f` | `18008bdc0..18008d202` |
| Bytes | 4,991 (`0x137f`) | 5,186 (`0x1442`) |
| Instructions | 887 | 920 |
| Syntactic basic blocks / edges | 104 / 154 | 108 / 160 |
| Conditional branches / call instructions | 51 / 74 | 53 / 77 |
| Direct caller in `Start` | `1800888ae` | `18008899e` |

The frame grows from `sub rsp, 0x158` to `sub rsp, 0x168`; local result slots
move as a consequence.  This alone is code-generation/layout noise, not a
semantic result.  The semantic delta is the final decision region below.

`Start` passes the same host context pointer as the first argument in both
builds.  In `UpdateAllBase` it is saved to `[rsp+0x50]`; every documented
`+0xb8` access below dereferences that saved pointer.  This establishes that
the field belongs to the in-process context passed by `Start`.

## Shared coordinator flow

Most of the coordinator remains counterpart-shaped.  Both builds perform the
same two-result pattern, with optional generic-adapter branches controlled by a
global pointer:

| Step | 10062 evidence | 10063 evidence | Finding |
|---|---|---|---|
| First status result | helper `180040440`, result stored at local `rsp+0x78` | same helper, stored at `rsp+0x78` | counterpart flow |
| Second status result | `180040590`, or `18004d330` when global `180242208` is set; local `rsp+0x7c` | `180040590`, or `18004d350` when global `18026e0a8` is set; local `rsp+0x74` | counterpart flow with shifted addresses/slots |
| Associated state | context lengths `+0x70/+0x74`, buffers `+0x108/+0x100` | same offsets and use | host context, not a raw response object |
| Final flag | literal two-value conjunction | adapter or fallback state machine | **semantic change** |

The table does not label the statuses as FDT success, image validity, touch, or
calibration values: their numeric protocol meaning is not recovered.  The
surrounding call graph and buffers place them in the base/FDT coordinator, but
not enough evidence exists to assign a more specific name.

## Exact changed final decision

### 10062

At `18008cd90`, 10062 performs two direct local comparisons:

```text
18008cd90  cmp DWORD PTR [rsp+0x78], 2
18008cd95  jne 18008cdaf
18008cd97  cmp DWORD PTR [rsp+0x7c], 2
18008cd9c  jne 18008cdaf
18008cda3  mov DWORD PTR [context+0xb8], 1
18008cdb4  mov DWORD PTR [context+0xb8], 0
```

This is an exact conjunction.  There is no intervening external call and no
state-history input in this decision block.

### 10063

At `18008ce97`, 10063 first clears a local output byte and selects one of two
host call paths.  It zero-extends the output byte and stores it to the context:

```text
18008ce97  if (global_18026e0a8 != 0)
              call 18004ca20(global, &local_status, &out_byte,
                               status_a, status_b)
18008cf40  else
              call 180040400(&out_byte, status_a, status_b)
18008cf61  movzx eax, BYTE PTR [out_byte]
18008cf6b  mov DWORD PTR [context+0xb8], eax
```

The adapter error result is handled locally (including logging); failure does
not cause a retry in this block.  The byte is initialized to zero, so an
adapter failure cannot leave an uninitialized flag.

## Fallback state-machine data flow

The fallback wrapper is present in both DLLs but is newly selected for the
final `UpdateAllBase` decision in 10063:

```text
10063 180040400 -> 180060080 -> 18005f030
10062 180040400 -> 180060000 -> 18005f300
```

The old/new versions of this helper family have the same instruction logic
after address normalization.  The final `UpdateAllBase` use differs; this
strongly suggests an integration/driver-version change rather than a change
introduced by the 10062 firmware helper pairs themselves.

`18005f030` combines two status values with the following observed precedence:

| Input condition | Combined result |
|---|---:|
| either input is `1` | `1` |
| otherwise either input is `4` | `4` |
| otherwise either input is `3` | `3` |
| otherwise either input is `0` | `0` |
| both inputs are `2` | `2` |
| remaining combination | `1` |

`180060080` then writes `out_byte = 1` only for combined result `2` while its
process-global state at `180256da0` is `0`, `2`, or `3`.  On every other path
it stores the combined result to that global and writes `out_byte = 0`.
The 10062 counterpart uses global `180206d88` with the same logic.

Consequently, the 10063 fallback can be expressed as:

```text
combined = combine(status_a, status_b)
if combined == 2 and previous_global in {0, 2, 3}:
    field_b8 = 1
else:
    previous_global = combined
    field_b8 = 0
```

This is a confirmed code-level description.  It does **not** prove what each
status means at the sensor or user-visible level.

## Optional adapter branch

When `18026e0a8` is non-null, 10063 calls `18004ca20..18004ca94`.  This wrapper
has a shifted 10062 counterpart (`18004ca00..18004ca74`), but the 10062 final
decision does not invoke it.  The wrapper forwards to `180040be0`, which ends
in an IAT-indirect call through `18014f520` with descriptor pointer
`180306610`.

No known Wbdi USB packet builder or transport routine is directly called in
`18004ca20` or the fallback.  The IAT target and the object behind
`18026e0a8` are not resolved, so static analysis cannot rule out external host
effects.  It would be incorrect to call this path USB-free; the supported
conclusion is narrower: no direct USB command dispatch is visible in the added
local code.

## `field_b8` lifecycle and uses

Only accesses proven to use the same `Start`/FDT host-context type are listed.
Other whole-DLL `+0xb8` offsets may belong to unrelated objects and are not
evidence about this field.

| Lifecycle point | 10062 | 10063 | Evidence and conclusion |
|---|---|---|---|
| Reset | `18008aed7` in `18008a6a0..18008b20f` writes zero | `18008afc7` in `18008a790..18008b2ff` writes zero | flag is explicitly reset in a paired host method |
| Read before coordinator call | `180088860` in `Start` | `180088950` in `Start` | zero/nonzero chooses a later host branch before `UpdateAllBase` |
| Derivation in `UpdateAllBase` | `18008cda3` / `18008cdb4` | `18008cf6b` | exact difference described above |
| Read in paired handlers | `18008b571`, `18008b5c8` | `18008b661`, `18008b6b8` | zero triggers recalculation path |
| Recalculation write | `18008dfaf` in `18008d840..18008e0f2` | `18008e16f` in `18008da00..18008e2b2` | same state-machine/adapter model writes the context field |
| Read after coordinator | `18008cea3` | `18008d056` | field value is consumed by subsequent host logic/logging |

The lifecycle is therefore **reset → derive/rederive → branch/gate**.  All
listed stores are `DWORD` stores of zero/one (or zero-extended byte in 10063).
That proves a host boolean-like state flag.  It does not prove whether a one
means “base valid”, “state stable”, “ready”, or another policy label.

## USB, FDT, PSK and enrollment impact

### Confirmed

- The changed decision occurs after the shared two-status base/FDT coordinator
  flow and controls later host branching through `field_b8`.
- The modified local code neither references PSK selectors nor calls the
  mapped TLS, enrollment, configuration-upload, reset or firmware routines.
- Its fallback has no direct visible command construction/transport call.

### Strong inference

- The difference can change whether a later FDT/base/image-related host branch
  is taken after the same two input statuses.  It is therefore relevant to
  calibration/acquisition coordination, not merely logging.
- Because the fallback state machine already exists in both packages and the
  profile/OTP/config/FDT helper pairs normalize, this use-site change is more
  consistent with a host driver-version integration change than proof of a
  firmware-10062 protocol difference.

### Unknown

- Meaning of the statuses and result code `2`.
- Identity and side effects of the optional adapter/IAT path.
- Whether an adapter result can eventually influence an asynchronous command
  scheduled elsewhere.
- Any actual 10062 device behavior.  No device inference follows from this
  static result.

There is no established direct effect on Windows Hello enrollment or persistent
PSK state.  The unresolved adapter means an absolute “no side effect” claim
would exceed the evidence, but no mapped call chain from this difference to a
PSK/enrollment writer was found.

## Comparison with current Linux implementation

Linux has no binary field corresponding to the unidentified Windows
`context+0xb8`.  The explicit cold coordinator in
`libfprint/drivers/goodix5503.c` keeps FDT bases in `fresh_raw`,
`fresh_transformed`, `fdt_runtime` and `warm`; it validates base pairs with
`goodix5503_fdt_bases_within_delta()` and retries on failure.  Its final fresh
completion promotes known bases into `warm` rather than reproducing this
Windows history-gated flag.

This is a behavior difference, not a reason to modify Linux: the runtime is
still exact-firmware guarded for 10063 and `src/goodix5503/firmware.py` keeps
10062 `EXPERIMENTAL`.  No guard or device-facing implementation was changed by
this analysis.

## Reproduction

```sh
python3 -B tools/compare_update_all_base.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll' \
  --verbose
```

The script verifies both input hashes, obtains `.pdata` boundaries, reports
syntactic CFG metrics, and prints the two final decision blocks.  It is
strictly offline.

## Risk assessment and next research

| Area | Assessment |
|---|---|
| Static conclusion | high confidence for the `+0xb8` predicate/state-machine difference |
| Host object ownership | high confidence for the `Start` context; no type name recovered |
| FDT/base coordinator relevance | medium-high confidence from adjacent buffers/callback flow |
| USB command consequences | unknown; no direct added dispatch, external adapter unresolved |
| Windows Hello / PSK persistence | no direct call path found; cannot assert absence of all indirect effects |
| Enabling 10062 | unjustified and out of scope |

Next, continue offline by resolving the IAT target used by `180040be0` and
mapping its descriptor/global initialization.  Separately compare the callers
that consume `field_b8` after `UpdateAllBase`.  Neither result authorizes a
device test, relaxation of the 10063-only guards, or a persistent operation.
