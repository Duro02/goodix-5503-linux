# Local 27c6:5503 device state

Observed through the project's staged, reviewed fixed-command paths. Firmware
has never been written. The PSK was explicitly reprovisioned once as documented
below; subsequent TLS and OTP/config checks made no persistent writes.

```text
USB ID:    27c6:5503
Firmware:  GF3258_RTSEC_APP_10063
IAP:       MILAN_RTSEC_IAP_10027
PSK hash:  reprovisioned with the locally prepared random PSK; R-family
           selector 0xbb020007 exactly matches the prepared verification record
G selector: 0xbb020001 returned MCU status 0x01 (unavailable)
R recheck: succeeded through the reviewed official R-family parser
Protected record 0xbb010002: 324 bytes
Protected record SHA-256: 062cb94a5805bf27bc05d519eaaaaa5fdc20ac17063d352cda9a5a6b92d78b1c
Protected record backup: artifacts/device-backup/psk-record-bb010002.bin
Backup validation: owner duro:duro, directory 0700, file 0600, 324 bytes,
                   SHA-256 matches the live metadata read
White-box record 0xbb010003: MCU status 0x01; not readable/backed up
Verification record 0xbb020007: 32 bytes, backed up as
  artifacts/device-backup/psk-record-bb020007.bin
Verification backup SHA-256:
  8722cc96d28ae20251c81a853c33dd1f5097c7ddd2e7505b19f38ef33fbbc74d
Offline new-pairing material: generated and idempotently reverified; no USB used
  artifacts/device-backup/new-pairing-psk.bin                  32 bytes, 0600
  artifacts/device-backup/new-pairing-whitebox-bb010003.bin    96 bytes, 0600
  artifacts/device-backup/new-pairing-verification-bb020007.bin 32 bytes, 0600
Read-only OTP/config derivation:
  OTP response length: 64 bytes; raw OTP was neither printed nor saved
  artifacts/device-backup/runtime-config-5503.bin              256 bytes, 0600
  config SHA-256: 54e6cd4c0d18b4472e7ec066a11aabcc55389779e426562a9c2bcfd2e188eba6
  official checksum: valid; FDT delta: 21 (0x15); image tcode: 224 (0x00e0)
Runtime clear-frame attempts: both reached image command after TLS/config/init
  and stopped fail-closed before image data. The authorized retry identified the
  `0xa0` prelude as delayed command `0xd0` TLS completion. Neither attempt decoded
  or saved an image; both attempted cleanup reset. No third attempt is authorized.
```

## Interpretation

The firmware and IAP versions match the newer firmware family embedded in the
official Lenovo Windows driver. The device must not be downgraded or reflashed.

The selector results identify this device's active record format as the official
R-family path, not the G-family path. Static analysis confirms that Lenovo's
`PresetPskIsValidR` uses `0xbb020007`; it is not merely a community-specific
selector.

The PSK result does **not** mean that the device has a bad key. It most likely
means Windows provisioned a per-device/per-installation random PSK rather than
the public development PSK used by `goodix-fp-dump`.

The community `driver_5503.py` treats any different hash as invalid and calls
its persistent `preset_psk_write` path. Running that script would overwrite a
presumably valid Windows-provisioned key even though this device already has
compatible firmware. It must not be run unchanged.

The 324-byte protected record has the standard Windows DPAPI provider header:
blob version 1, master-key version 1, flags 0, and a 64-byte description field.
No GUID, description text, encrypted payload or authentication value is printed
or committed. Driver disassembly also shows `CryptProtectData` called with no
optional entropy, no prompt structure and `dwFlags=0`, so this is the per-user
DPAPI path rather than machine scope. The former Windows user's DPAPI master key
is therefore required to decrypt it; the enclave alternative is not the format
stored on this device.

Exact restoration of the former Windows pairing is impossible because
`0xbb010003` is not readable. This no longer blocks TLS image work: fresh random
pairing material was prepared locally with the independently reviewed
offline-only tool. After explicit authorization, the reviewed fixed
write path sent one `0xbb010003` white-box TLV without changing firmware. The
MCU returned success and the immediate `0xbb020007` readback exactly matched the
prepared verification record. The original pairing is no longer active; the
known new PSK and its white-box record remain in owner-only Git-ignored files so
the same pairing can be recognized or retried. A separately reviewed,
non-persistent runtime check then completed a TLS 1.2 handshake with cipher
`PSK-AES128-CBC-SHA256`; firmware and IAP remained unchanged.
