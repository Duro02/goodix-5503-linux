# Offline 10062/10063 Wbdi.dll static comparison

## Scope and safety boundary

This is an offline comparison of two official Windows driver DLLs.  It reads
the files listed below, their PE metadata, and local `objdump` output only.  It
does **not** load either DLL or access a USB device.  In particular, it performs
no reset, configuration upload, TLS/PSK action, enrollment, firmware update, or
other state-changing operation.

The result narrows a static-code question only.  It neither proves that a
physical firmware-10062 device is DN2 nor authorizes firmware-10062 in the
runtime driver.  `GF3258_RTSEC_APP_10062` remains `EXPERIMENTAL` and the
production runtime remains pinned to the reviewed 10063 path.

## Inputs

| DLL | SHA-256 |
|---|---|
| `artifacts/windows-driver/extracted/installed-win11/wbdi.dll` (10062) | `35891ece58fecc5f97d5b76bf7a56292e1a845692e218a98754ae505b229fdf1` |
| `artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll` (10063) | `1f0b55106e637bb39485f29bf85740518a7f3ab21a621967d282ae7e9ea5dffd` |

The supplied DN2 table association is chip ID `0x220f`.  This comparison uses
the corresponding function pairs, but does not make a device assertion.

## Reproduction

Run from the repository root with GNU `objdump` available:

```sh
python3 tools/compare_wbdi_10062_10063.py \
  artifacts/windows-driver/extracted/installed-win11/wbdi.dll \
  'artifacts/windows-driver/extracted/win11/code$GetExtractPath$/Goodix_3.1.581.610/Wbdi.dll'
```

The script finds function boundaries from the PE exception directory (`.pdata`),
instead of assuming that the next symbol or an arbitrary byte count is a
boundary.  It compares each matching instruction at the same offset in the two
functions.  A byte difference is normalized only when the instruction is a
direct-call target or a RIP-relative data reference; any other changed operand,
changed instruction count, changed instruction length, or changed `.pdata`
length makes the script fail.  Use `--verbose` to print every normalized pair.

This is a deliberately conservative structural test, not a proof of equivalent
external callees or runtime behavior.

## Exact `.pdata` bounds and normalized result

| Path | 10062 `.pdata` range | 10063 `.pdata` range | Size | Raw differing bytes | Result |
|---|---|---|---:|---:|---|
| `GetFdtInitParam` | `18006be60..18006bf2a` | `18006bf50..18006c01a` | 202 | 20 | address-only |
| `GetChipConfig` | `18006bf30..18006c2b9` | `18006c020..18006c3a9` | 905 | 88 | address-only |
| FDT template-field helper | `180064cb0..180064da5` | `180064da0..180064e95` | 245 | 28 | address-only |
| GetChipConfig children A--E | corresponding same-size pairs | corresponding same-size pairs | 860, 433, 260, 260, 427 | 28--59 | address-only |
| GetChipConfig leaf | `180055470..1800554dc` | `180055490..1800554fc` | 108 | 0 | byte-identical |
| OTP selector container | `18006ee40..18006f0c1` | `18006ef30..18006f1b1` | 641 | 14 | address-only |
| OTP-to-DAC helper | `18006f0d0..18006f43e` | `18006f1c0..18006f52e` | 878 | 40 | address-only |

The OTP selector's documented selection point lies at `0x18006ef30` in 10062
and `0x18006f020` in 10063; `.pdata` shows that both lie within the paired
641-byte container above.  The script records the container rather than
inventing a smaller function boundary.

For every listed non-identical routine, the instruction sequence has the same
count and byte length.  Every changed instruction is either a direct `call`
target or a RIP-relative reference to logging/string/config data.  No changed
opcode, branch condition, immediate, register/stack operand, or other
non-address operand was found.  One `GetChipConfig` leaf pair
(`0x180055470`/`0x180055490`) is byte-identical.

## FDT and configuration data

`GetFdtInitParam` copies 14 bytes beginning at `base - 0x10` before invoking
its template-field helper.  The 16-byte surrounding prefix and the following
256-byte configuration block are byte-identical between:

* 10062: `0x180207d40..0x180207e50`
* 10063: `0x180257d60..0x180257e70`

Their shared 256-byte configuration SHA-256 is
`db102741e72c88339a33a39af7ed75e2fce035a0354c5495fdd15d538df787e5`.

The original 20 FDT-function byte differences resolve to eight instructions:
two direct calls (the paired validator and logger) and six RIP-relative
references (three logging data references, a logger global, and the two static
FDT/config addresses).  They are therefore package-layout relocations, not an
observed FDT-control-flow or data-field change.

`GetChipConfig` and its reached OTP/configuration helpers have the same
structural result.  This supports carrying the existing offline understanding
of OTP selection, OTP-to-DAC derivation, default handling, and checksum
recalculation across these two DLL builds.  It does not validate OTP contents
from a device and must not be used to substitute a static configuration blob.

## Guard remains unchanged

The comparison found no static evidence that would justify relaxing the
10063-only runtime guards.  Keep all provisioning, TLS, configuration,
enrollment, reset, and firmware-flashing paths disabled for 10062 unless a
separate, explicitly authorized, device-safe validation plan establishes them.
