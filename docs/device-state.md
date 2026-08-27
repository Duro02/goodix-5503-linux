# Local 27c6:5503 device state

Observed using the project's allowlisted, non-persistent USB probe. No firmware
or PSK write, configuration upload, register write or reset command was issued.

```text
USB ID:    27c6:5503
Firmware:  GF3258_RTSEC_APP_10063
IAP:       MILAN_RTSEC_IAP_10027
PSK hash:  R-family selector 0xbb020007 is present, but differs from the
           public community-development hash
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

TLS image capture now depends on recovering the lost per-user DPAPI state or,
after preserving all readable evidence and an explicit risk decision,
reprovisioning PSK state without changing firmware. Exact restoration of the old
pairing is impossible because `0xbb010003` is not readable; failure recovery must
retry provisioning with a known new PSK. Fresh random pairing material has now
been prepared locally with the independently reviewed offline-only tool. This
does not authorize device provisioning: the exact write implementation,
post-write readback and TLS recovery sequence must still be tested and reviewed
before requesting explicit hardware-write approval.
