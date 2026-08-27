# Local 27c6:5503 device state

Observed using the project's allowlisted, non-persistent USB probe. No firmware,
PSK, configuration, register or reset command was issued.

```text
USB ID:    27c6:5503
Firmware:  GF3258_RTSEC_APP_10063
IAP:       MILAN_RTSEC_IAP_10027
PSK hash:  present, but different from the public community-development hash
```

## Interpretation

The firmware and IAP versions match the newer firmware family embedded in the
official Lenovo Windows driver. The device must not be downgraded or reflashed.

The PSK result does **not** mean that the device has a bad key. It most likely
means Windows provisioned a per-device/per-installation random PSK rather than
the public development PSK used by `goodix-fp-dump`.

The community `driver_5503.py` treats any different hash as invalid and calls
its persistent `preset_psk_write` path. Running that script would overwrite a
presumably valid Windows-provisioned key even though this device already has
compatible firmware. It must not be run unchanged.

TLS image capture now depends on finding a non-destructive way to use or recover
the existing key state. Until that is solved, this project will not write a new
PSK.
