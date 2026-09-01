# goodix-5503-linux

A Linux driver for the Goodix `27c6:5503` fingerprint sensor found in many Lenovo laptops. The project started as reverse engineering; the driver is now finished and in daily use on the developer's own machine.

[中文版](README_zh.md)

## Features

- **Instant unlock**: the first authentication after boot or suspend takes a few seconds to calibrate; after that, as long as the machine stays up, every unlock is immediate (about 100 ms to get ready, fingerprint image within 60 ms of touch).
- **Enrolment guidance**: 12 presses by default, vary position and angle between presses; bad presses are rejected and asked again; the final press waits until you lift your finger before showing "complete".
- **Safety**: fingerprint images are processed locally and templates stay on the machine; no false acceptance with a different finger has been observed so far (limited testing, see Limitations).

## Limitations

- **Recognition rate**: the same finger does not always pass on the first press — in practice about half of the presses need a second try, and a retry almost always works. The cause is press deformation (force, angle) exceeding the matcher's geometric tolerance; it is a matcher tuning problem, documented in `docs/libfprint-driver-plan.md`.
- **One device combination only**: sensor `27c6:5503` with official firmware `GF3258_RTSEC_APP_10063`. Other firmware versions are not supported.
- **No firmware writes, no PSK changes**: the probing tools are read-only; an existing Windows pairing key on the device is left untouched.

## Install

On Arch (needs `opencv`, `gobject-introspection`):

```bash
bash packaging/arch/build-package.sh
sudo pacman -U --noconfirm --overwrite "*" .tools/packages/libfprint-goodix5503-*.pkg.tar.zst
```

The driver is a libfprint plugin; `fprintd` picks up the device automatically after installation.

## Usage

Enrol a finger:

```bash
sudo fprintd-enroll $USER
```

Any login manager with fprintd configured in PAM can then unlock with a fingerprint. To keep the sensor "warm" (instant unlock) between unlocks, fprintd must stay running:

```bash
sudo systemctl edit fprintd.service
# add:
# [Service]
# ExecStart=
# ExecStart=/usr/lib/fprintd --no-timeout
```

## Safety and probing

The probe tool only allows a small set of read-only commands:

- `NOP`: wake/sync the device;
- `FIRMWARE_VERSION`: read the application firmware version;
- `GET_IAP_VERSION`: read the IAP version;
- `PRESET_PSK_READ`: optional, read-only. Reads the official R-family `0xbb020007` verification record and the `0xbb010002` DPAPI record. `0xbb010003` is a write-only MCU white-box input (hardware-tested unreadable) and is never read again; check mode reports metadata only, backup mode saves opaque raw records but never prints record contents or plaintext keys.

The probe CLI still blocks firmware, PSK, config, reset, register writes and image capture. The pairing and experimental runtime modules in this repo have fixed, bounded command sets; they do not expose a generic raw-command interface through the probe CLI. Firmware/IAP writes and arbitrary protected-record writes remain prohibited or separately approved persistent operations.

"Non-persistent" does not mean zero risk: the tools still send query commands over USB. If the firmware misbehaves the device may become unresponsive until a reboot or full shutdown. But nothing modifies Flash, PSK or IAP.

## Probing hardware

The following commands only use the fixed read-only command set:

```bash
sudo .venv/bin/goodix-5503-probe
sudo .venv/bin/goodix-5503-probe --check-psk-state
sudo .venv/bin/goodix-5503-probe --inspect-protected-record
sudo .venv/bin/goodix-5503-probe --backup-protected-record
sudo .venv/bin/goodix-5503-probe --backup-rollback-set
```

PSK state is not queried by default. Protected-record operations first set and verify `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`; any failure aborts before USB access. Check mode prints only length and SHA-256. Backup mode closes the USB session, permanently drops root, re-verifies non-dumpable state, then does filesystem work as the original user; root-owned file writes are refused. Records are committed via `0600` temp files, `fsync` and exclusive hard links; existing files are only byte-verified, never overwritten. Readable backups are `0xbb010002` and `0xbb020007`; `0xbb010003` returns status `0x01` on read (write-only MCU pairing input, cannot be backed up). The backup directory is `0700` and Git-ignored; all mutable memory copies are overwritten after use. Old state can be verified after reprovisioning, but the original PSK cannot be fully restored.

## Development

- `src/goodix5503/`: Python probing and experimentation tools (read-only, never touch firmware/PSK)
- `libfprint/`: the C driver, the SIGFM matcher, and the libfprint patch
- Tests (no hardware needed): `PYTHONPATH=src python -m unittest discover -s tests -v`

Matcher parameters and the template format are versioned: any change to feature extraction, match semantics or the decision threshold must bump the template format version, or old templates will be rejected. Details in `docs/libfprint-driver-plan.md`.

## Upstream references and license

This project stands on the shoulders of the following open-source work:

- [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) (LGPL-2.1-or-later): driver framework, state machine, enrolment/verification flow. Builds are pinned to upstream commit `80a4b5ec...`; this repo does not include libfprint code.
- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump) ([MIT](https://github.com/goodix-fp-linux-dev/goodix-fp-dump/blob/master/LICENSE), reference commit `cc43bb3b`, `718ee3c1`): the 5503 protocol frame format (`0xa0` outer frame, checksums, command set). Interface reference only; their code is not copied.
- [goodix-fp-linux-dev/libfprint SIGFM branch](https://github.com/goodix-fp-linux-dev/libfprint/tree/0x00002a/libfprint-sigfm) (LGPL-2.1-or-later, reference commit `7ebe0c80`): how SIFT + CLAHE + mutual/geometric matching plugs into libfprint; `sigfm.cpp/hpp` keep the upstream copyright headers (three authors, 2022) and are distributed under LGPL.
- [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint) (reference commit `309d4c69`): that repo has **no LICENSE file**; we only referenced how it wires SIGFM to a Goodix sensor, no code was copied. The driver, protocol, TLS, config and persistent format in this project are independent implementations.

This project is licensed under `LGPL-2.1-or-later`. The official Windows driver binaries, device credentials (PSK/backups/templates) and local fingerprint images are not distributed with this repo.