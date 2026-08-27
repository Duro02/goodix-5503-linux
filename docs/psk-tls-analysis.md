# PSK and TLS static analysis

## Conclusion

The existing device PSK is not returned by the MCU as plaintext. The Lenovo
Windows 11 driver (`Wbdi.dll` 3.1.581.610) reads an opaque protected record,
recovers a 32-byte plaintext PSK through one of two conditional host paths,
verifies a separate 32-byte MCU hash, and caches the plaintext for TLS.

The driver supports two conditional host mechanisms: Windows DPAPI and an
enclave proxy. A reviewed read-only backup of this device's 324-byte R-family
record proves that the stored object uses the standard Windows DPAPI provider
format (blob version 1 and master-key version 1), not the enclave-sealed format.
Static analysis of `GfSealData` shows `CryptProtectData` called with no optional
entropy, no prompt structure and `dwFlags=0`, making it per-user rather than
machine scope.

The original Windows installation has been replaced by an Omarchy installation
covering the full internal disk. No NTFS partition, `Windows.old`, registry hive
backup or DPAPI master-key directory was found. The MCU hash cannot be inverted
or brute-forced, and the signed enclave cannot independently unseal a standard
per-user DPAPI blob. Therefore the existing random PSK cannot currently be
recovered from the available state.

## Confirmed Windows-driver path

Addresses are virtual addresses in Win11 `Wbdi.dll` 3.1.581.610.

- `fcn.1800420f0`: G-family PSK validation/load path, associated with
  `PresetPskIsVaildG`.
- `fcn.180042d30`: `PresetPskReadG` protected-data read wrapper.
- `fcn.1800426c0`: R-family validation path, `PresetPskIsValidR`.
- `fcn.180043130`: `PresetPskReadSpecDataR`; it calls the R transport at
  `fcn.1800af930`.
- `fcn.180041ec0`: DPAPI fallback that calls `CryptUnprotectData`.
- `fcn.18004cb20` / `fcn.18004d7d0`: enclave-proxy calls selected when the
  enclave-library handle is present.
- `fcn.1800a9ea0`: `PresetPskPskSet`; caches recovered plaintext key in host
  process memory.
- `fcn.1800a9ce0`: `PresetPskPskGet`; copies the cached key to a caller.
- `fcn.180043540`: `PresetPskWriteKey`; persistent provisioning path.

Observed validation flow:

1. Derive the expected protected-record length through the selected sealing
   path.
2. Read that many bytes of selector `0xbb010002` from the MCU.
3. Recover a 32-byte plaintext through either the enclave path or the DPAPI
   fallback (`CryptUnprotectData`).
4. Calculate a 32-byte local digest.
5. Read exactly 32 bytes from the family-specific verification selector:
   `0xbb020001` for G or `0xbb020007` for R.
6. Compare the two 32-byte values.
7. Cache the recovered plaintext PSK for TLS.
8. Explicitly clear temporary buffers.

`ProcessPsk` proves that the protected-record length is runtime-derived rather
than a universal literal. With an enclave handle, the call at `0x18009a8a0`
(`GetSealEncryptLen`) returns sealing overhead and the caller adds the 32-byte
PSK at `0x18009a931`. Without the enclave handle, `GfSealData` at
`0x18009a957` performs `CryptProtectData` and writes its actual output length.
That value is later passed to `PresetPskIsVaildG` at `0x18009aaef` (and the
parallel call at `0x18009afb8`). Static analysis therefore cannot justify a
single fixed backup length across both paths.

For this device, the DPAPI scope and inputs are now mapped: per-user scope,
no optional entropy, no prompt structure and flags zero. The generic enclave
path remains present in the driver but is not the format of the backed-up local
record.

## Persistent provisioning path

The official driver generates key material and constructs records tagged:

- `0xbb010002`
- `0xbb010003`

It then chooses a device-family write path; RTSEC firmware uses a distinct
transport function. The community project writes the public white-box record
with tag `0xbb010003`, after which it knows the corresponding plaintext PSK.
That changes persistent MCU state.

## Ranked options

1. **Complete the readable evidence set:** back up `0xbb020007` and retain the
   proven-unavailable result for write-only `0xbb010003`; exact old-pairing
   rollback is not possible.
2. **Recover original per-user DPAPI state:** valid in theory but unavailable on
   this machine.
3. **Complete a no-firmware PSK reprovisioning tool with verified retry-based
   recovery:** technically practical, but intentionally persistent; it cannot
   restore the exact old pairing and requires a separate risk decision.

Not feasible:

- derive a random 256-bit key from its 32-byte hash;
- use the community development key without replacing current PSK state;
- establish the sensor TLS session using only firmware/IAP metadata.

## Current safety boundary

No PSK write, firmware write, reset, register write, TLS/image or configuration
upload command is authorized.

Static mapping has now confirmed two read transports under opcode `0xe4`:

- Both families use protected-record selector `0xbb010002`.
- **G family:** verification selector `0xbb020001`; request body is little-endian
  `chunk_length`, `offset`, `selector`, `0`; nominal chunk size is `0x100`.
  Opcode `0xe4` is visible at `0x18009ccd1` and `0x18009cd51`.
- **R family:** verification selector `0xbb020007`; wire request body is only
  `selector`, `0`. `PresetPskReadSpecDataR` calls `fcn.1800af930`, which sends
  opcode `0xe4` at `0x1800afb68` and `0x1800afbd9`. The response is status byte,
  echoed selector, little-endian value length, then value bytes.

A live read of G selector `0xbb020001` returned MCU status `0x01`, while the R
selector `0xbb020007` is present and contains a non-community hash. This proves
that the local `27c6:5503` uses the official R-family record path.

The fixed R-family verification-hash read is implemented with an exact payload
whitelist. Unlike G, the R wire request does not transmit a requested length;
the MCU returns the selected object's length.

A separate inspection path for selector `0xbb010002` is implemented but must not
be used on hardware until its independent review passes. It fails closed unless
`PR_SET_DUMPABLE=0` is set and verified, also sets `RLIMIT_CORE=0`, accepts at
most 4096 bytes, reports only length and SHA-256, and overwrites its mutable copy
after hashing. The protected selector is excluded from the public raw-response
`request()` whitelist and is reachable only through a scoped metadata method.
The rollback evidence backup reads the two records exposed by the R-family MCU:

- `0xbb010002`: DPAPI-protected host record;
- `0xbb020007`: 32-byte verification record.

A live read of `0xbb010003` returned MCU status `0x01`. Static analysis explains
the asymmetry: `PresetPskWriteKey` constructs `0xbb010002` and a white-box
`0xbb010003` TLV before invoking the RTSEC write transport, but R-family read
cache/validation supports `0xbb010002`, `0xbb020001` and `0xbb020007`, not
`0xbb010003`. The white-box TLV is a write-time provisioning input consumed by
the MCU rather than a readable rollback record.

Consequently, the old verification state can be preserved and checked, but the
original MCU-side PSK cannot be fully restored after reprovisioning without the
unavailable white-box input or plaintext PSK. Reprovisioning is recoverable by
retrying with a new known PSK, not by restoring the exact old pairing.

Backup files are written to Git-ignored `artifacts/device-backup/` using mode
`0600` temporary files, file and directory fsync, and exclusive hard-link commits.
An existing file is accepted only if owner, mode, length and every byte match the
live record; it is never overwritten. After all USB reads, the session is closed
and a sudo run permanently drops to the invoking UID/GID before filesystem work.
Because `setresuid` may reset Linux dumpability, the process immediately sets and
verifies `PR_SET_DUMPABLE=0` again after the drop. Filesystem access as root is
rejected. New child directories are durably committed by fsyncing each parent.
All mutable record copies are overwritten in `finally` blocks. The unavoidable
residual is a short-lived immutable USB response object in Python memory. No
reader may expose a general raw-command interface.
