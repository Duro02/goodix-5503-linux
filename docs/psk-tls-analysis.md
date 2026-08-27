# PSK and TLS static analysis

## Conclusion

The existing device PSK is not returned by the MCU as plaintext. The Lenovo
Windows 11 driver (`Wbdi.dll` 3.1.581.610) reads an opaque protected record,
recovers a 32-byte plaintext PSK through one of two conditional host paths,
verifies a separate 32-byte MCU hash, and caches the plaintext for TLS.

One fallback path calls Windows DPAPI (`CryptUnprotectData`). A second path is
selected when the driver's enclave-library handle is present and invokes enclave
proxy calls instead. Static analysis has not proved which path was active on the
former Windows installation, so it is too strong to conclude that recovery
strictly requires the lost DPAPI context.

The original Windows installation has nevertheless been replaced by an Omarchy
installation covering the full internal disk. No NTFS partition, `Windows.old`,
registry hive backup or DPAPI master-key directory was found. The MCU hash itself
cannot be inverted or brute-forced. Reuse may still be possible only if the
official signed enclave can unseal the MCU record independently in an isolated
Windows environment; this remains unproven and must be tested with USB writes
blocked.

## Confirmed Windows-driver path

Addresses are virtual addresses in Win11 `Wbdi.dll` 3.1.581.610.

- `fcn.1800420f0`: Goodix PSK validation/load path, associated with
  `PresetPskIsVaildG`.
- `fcn.180042d30`: `PresetPskReadG` protected-data read wrapper.
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
5. Read exactly 32 bytes from selector `0xbb020001`.
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

The exact DPAPI scope, optional entropy and master-key prerequisites still need
mapping. The enclave path is real, but whether its sealing identity is tied to
the CPU, Windows installation, TPM/VBS state, or signer remains unresolved.

## Persistent provisioning path

The official driver generates key material and constructs records tagged:

- `0xbb010002`
- `0xbb010003`

It then chooses a device-family write path; RTSEC firmware uses a distinct
transport function. The community project writes the public white-box record
with tag `0xbb010003`, after which it knows the corresponding plaintext PSK.
That changes persistent MCU state.

## Ranked options

1. **Map and back up all opaque MCU records read-only:** useful for rollback and
   format research, but does not reveal plaintext by itself.
2. **Run the official unseal path in an isolated Windows environment with USB
   writes blocked:** may determine whether the signed enclave can reuse the
   existing record without the former OS. Instrumentation can capture the
   transient plaintext only after successful unseal.
3. **Recover original DPAPI state:** valid in theory but unavailable on this
   machine.
4. **Complete a no-firmware PSK reprovisioning tool with verified backup and
   rollback:** technically practical, but intentionally persistent and requires
   a separate risk decision.

Not feasible:

- derive a random 256-bit key from its 32-byte hash;
- use the community development key without replacing current PSK state;
- establish the sensor TLS session using only firmware/IAP metadata.

## Current safety boundary

No PSK write, firmware write, reset, register write, TLS/image or configuration
upload command is authorized.

Static mapping has now confirmed:

- protected record selector: `0xbb010002`;
- verification hash selector: `0xbb020001` with length 32;
- Goodix lower read opcode: `0xe4` (confirmed at `Wbdi.dll` virtual addresses
  `0x18009ccd1` and `0x18009cd51`);
- request body: little-endian `chunk_length`, `offset`, `selector`, `0`;
- nominal chunk size: `0x100` bytes;
- returned data starts after a 9-byte status/header prefix.

The fixed 32-byte verification-hash read is implemented with an exact payload
whitelist. A protected-record backup remains blocked because its runtime-derived
length depends on the active sealing path; asking for an arbitrary first chunk
would not prove a complete or correctly bounded backup. Any future reader must
obtain that length through a trusted equivalent of the official path and must
never expose a general raw-command interface.
