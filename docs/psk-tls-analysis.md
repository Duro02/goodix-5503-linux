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

Each record has an eight-byte little-endian `selector, value_length` header.
`PresetPskWriteKey` concatenates the complete `0xbb010002` TLV and the complete
96-byte `0xbb010003` white-box TLV, then submits the combined buffer once. With
this device's observed 324-byte protected-record length, that official request
would be 436 bytes. It then chooses a device-family write path; RTSEC calls
`PresetPskWriteR` at `0x1800aff60`. That transport first submits opcode `0xe0`
and falls back to opcode `0xe4` only if the transport call itself reports
failure. A successful response must have status byte zero. There is no effective
retry loop in this routine.

The community project instead submits only the 104-byte `0xbb010003` TLV using
opcode `0xe0`, after which it knows the corresponding plaintext PSK. This avoids
replacing the opaque host-recovery record, but still changes persistent MCU PSK
state.

The official arbitrary-key white-box encoder is now reproducible without running
Windows. `PresetPskWriteKey` calls `SecWhiteEncrypt` at `Wbdi.dll`
`0x180001090`. A local Unicorn harness maps only the pinned Lenovo
`Wbdi.dll` 3.1.581.610 (SHA-256
`567b5af3f2c51eca058172aaa0d0403d82680c75e77d2d073cfd403b1180fb8a`),
hooks only allocation/free/logging/cookie helpers, and executes that function.
For a 32-byte zero PSK it produces the exact 96-byte community white-box vector.
That known-answer test validates the pinned entry point and emulation setup for
the zero input; by itself it is not an arbitrary-key proof. Static inspection
shows that `SecWhiteEncrypt` branches on pointers, fixed input/output lengths,
cipher status and fixed-size block state, not on the 32 input byte values. As a
corroborating test, zero, all-`ff`, and incrementing-byte inputs each execute the
same 127,592 guest instruction addresses (trace SHA-256
`baf436c5c0c979c9dee4f1f586e2a6d8713b75e54ac8547b36bf0c7c66476a2e`)
and the same helper-call sequence while producing distinct outputs. An
independent nonzero Windows-generated known-answer vector is still unavailable.
No proprietary binary is committed or redistributed.

The emulator marks its process non-dumpable, sets `RLIMIT_CORE=0`, accepts only
a caller-wipeable `bytearray`, avoids `bytes(psk)`, and clears/unmaps its entire
32 MiB guest heap and 2 MiB guest stack on both success and failure. The caller
must still wipe the returned mutable 96-byte record and its input PSK.

The R-family `0xbb020007` calculation is also mapped. `CalculatePmk` hashes the
68-byte value `BE16(32) || zero[32] || BE16(32) || PSK`, then pads that 32-byte
digest with 32 zero bytes to form a 64-byte HMAC key. The verification record is
`HMAC-SHA256(key, bytes(64, 63, ..., 1))`. Emulating the official
`CalculatePmk` with the incrementing PSK `00..1f` produced the same intermediate
PMK as this formula; the resulting verification record is pinned in tests. This
nonzero behavior differs from the community expression `(BE16(length) || PSK) *
2`, whose published test PSK is all zero and therefore cannot reveal the
difference.

An offline-only preparation command generates a random key directly into a
mutable buffer from `/dev/urandom`, runs the pinned white-box known-answer test,
encodes the key, computes the expected R verification record, and stores all
three values in Git-ignored files. It refuses root, disables dumps before key
generation, requires owner-only directory/file modes, never overwrites existing
material, supports idempotent recovery after a partial file commit, and wipes
mutable buffers. Python's digest APIs still create short-lived immutable objects
for the derived PMK digest and the readable verification record; no immutable
plaintext-PSK copy is created, and non-dumpable/core-limit hardening contains
this allocator-residue limitation. The reviewed command contains no USB
transport and has now generated and reverified this machine's local material.

The candidate hardware path is deliberately not exposed as a CLI or public
session mutator. It refuses zero or multiple matching devices, opens the sole
confirmed `27c6:5503`, checks exact firmware `10063` and IAP `10027`, reads
the live old R verification record, permanently drops sudo privileges while
retaining the claimed USB handle, and only then reads local secrets. It refuses
to continue unless the live record equals the preserved old backup and unless
freshly recomputed white-box and verification values equal all prepared files.
Its sole mutation is one opcode `0xe0` request containing exactly
`LE32(0xbb010003) || LE32(96) || whitebox[96]`; there is no raw command,
selector, payload, fallback, or retry parameter. It immediately reads
`0xbb020007` and requires an exact match with the prepared verification record.
If a write response or immediate readback is lost, the result is reported as
ambiguous and no automatic retry occurs. A later invocation performs the same
preflight and recognizes either the preserved old hash or the exact prepared
new hash; an already-matching new hash returns success without another write.
This path passed independent review and was executed once after explicit
hardware-write authorization. Firmware and IAP preflight matched, opcode `0xe0`
returned success, and immediate `0xbb020007` readback exactly matched the
prepared verification record. No firmware, register or configuration write was
performed.

## TLS handshake test path

The candidate non-persistent TLS test follows the 5503 community flight order
without running its firmware-changing driver: fixed runtime reset command
`0xa2` with payload `05 14`, fixed TLS request `0xd0` with payload `0000`, one
MCU ClientHello outer frame (`0xb0`), one server flight back to the MCU, three
MCU TLS frames to the server, then the final server flight back to the MCU. The
server is an in-process Python/OpenSSL TLS 1.2 PSK endpoint over `socketpair`, so
the PSK is never placed in a process command line or exposed on a network port.
The exact official-driver suite string
`TLS-PSK-WITH-AES-128-CBC-SHA256` maps to OpenSSL
`PSK-AES128-CBC-SHA256` and is the only enabled TLS 1.2 suite.

Before opening USB, the test feature-gates Python/OpenSSL PSK callback and exact
cipher support. Before reset, it repeats unique-device and firmware/IAP checks,
drops sudo before reading the owner-only PSK, recomputes the R verification
record from that PSK, and requires both the saved and live records to match.
Server-flight collection uses complete TLS record and handshake-message
boundaries with a five-second overall deadline, not timing-based idle grouping.
It performs no PSK, firmware, register or configuration write. After independent
review, one explicitly invoked hardware run completed successfully with cipher
`PSK-AES128-CBC-SHA256`; firmware remained `10063` and IAP remained `10027`.

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

One explicitly authorized fixed PSK reprovisioning completed with readback, and
separately reviewed runtime resets/TLS handshakes completed without persistent
writes. Firmware and registers have never been written. The fixed read-only OTP
query and offline official config derivation have also completed; the derived
configuration has not been uploaded. Clear-frame configuration upload, sensor
mode changes and image commands remain pending code review and a separate
explicit hardware authorization.

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
