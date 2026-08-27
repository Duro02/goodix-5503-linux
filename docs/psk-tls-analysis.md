# PSK and TLS static analysis

## Conclusion

The existing device PSK is not returned by the MCU as plaintext. The Lenovo
Windows 11 driver (`Wbdi.dll` 3.1.581.610) reads an opaque protected record,
unprotects it with Windows DPAPI, verifies a separate 32-byte MCU hash, and
then caches the recovered 32-byte plaintext PSK in host memory for TLS.

The original Windows installation has been replaced by an Omarchy installation
covering the full internal disk. No NTFS partition, `Windows.old`, registry hive
backup or DPAPI master-key directory was found. On an SSD that has since been
repartitioned, encrypted and used, recovery of the old DPAPI context is not a
credible plan.

Therefore the existing random PSK cannot currently be reused on Linux without
a missing Windows DPAPI secret. The MCU hash cannot be inverted or brute-forced.

## Confirmed Windows-driver path

Addresses are virtual addresses in Win11 `Wbdi.dll` 3.1.581.610.

- `fcn.1800420f0`: Goodix PSK validation/load path, associated with
  `PresetPskIsVaildG`.
- `fcn.180042d30`: `PresetPskReadG` protected-data read wrapper.
- `fcn.180041ec0`: directly calls `CRYPT32.dll!CryptUnprotectData`.
- `fcn.1800a9ea0`: `PresetPskPskSet`; caches recovered plaintext key in host
  process memory.
- `fcn.1800a9ce0`: `PresetPskPskGet`; copies the cached key to a caller.
- `fcn.180043540`: `PresetPskWriteKey`; persistent provisioning path.

Observed validation flow:

1. Read a variable-length opaque object from the MCU.
2. Allocate a 32-byte output buffer.
3. Call `CryptUnprotectData` on the object.
4. Calculate a 32-byte local digest.
5. Read a second MCU object containing verification material.
6. Compare the two 32-byte values.
7. Cache the recovered plaintext PSK for TLS.
8. Explicitly clear temporary buffers.

The exact DPAPI scope, optional entropy and master-key prerequisites still need
mapping, but all DPAPI variants require state from the original Windows context.
The `Sgx` source-path names and enclave DLLs do not prove that this active Goodix
path can be recovered through SGX independently.

## Persistent provisioning path

The official driver generates key material and constructs records tagged:

- `0xbb010002`
- `0xbb010003`

It then chooses a device-family write path; RTSEC firmware uses a distinct
transport function. The community project writes the public white-box record
with tag `0xbb010003`, after which it knows the corresponding plaintext PSK.
That changes persistent MCU state.

## Ranked options

1. **Recover original DPAPI state:** best in theory, unavailable on this machine.
2. **Map and back up all opaque MCU records read-only:** useful for rollback and
   format research, but does not reveal plaintext by itself.
3. **Complete a no-firmware PSK reprovisioning tool with verified backup and
   rollback:** technically practical, but intentionally persistent and requires
   a separate risk decision.
4. **Run an isolated instrumented Windows environment:** could capture a newly
   generated PSK before the official driver provisions it, but the official
   fallback may write automatically and is not suitable until USB write blocking
   and capture are proven.

Not feasible:

- derive a random 256-bit key from its 32-byte hash;
- use the community development key without replacing current PSK state;
- establish the sensor TLS session using only firmware/IAP metadata.

## Current safety boundary

No PSK write, firmware write, reset, register write, TLS/image or configuration
upload command is authorized. The next implementation work is limited to static
mapping and a reviewed, fixed-selector reader for opaque PSK record metadata and
local encrypted backup.
