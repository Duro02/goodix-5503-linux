# goodix-5503-linux

A Linux driver for the Goodix `27c6:5503` fingerprint sensor found in many Lenovo laptops. The driver was developed through reverse engineering and is being tested in daily use on the developer's machine; recognition reliability is still being improved.

[中文版](README_zh.md)

## Features

- **Fast capture**: cold activation takes a few seconds to calibrate. With the sensor state retained, preparation usually takes about 100 ms and an image arrives about 55 ms after touch detection. Quick retries reuse the confirmed lift baseline and background to avoid recalibrating during the next press; a USB reset requires cold activation again.
- **Fresh enrolment**: collect 40 accepted presses in four guided groups, select 24 references, then require at least 6 matches in 8 new presses before completing. Those checks never enter the template. Near-identical samples are rejected, the enrolment quality gate is enabled by default, and completion waits for the final finger lift. See the [fresh-enrolment design and validation](docs/fresh-enrollment-2026-09-22.md).
- **Safety**: fingerprint images are processed locally and templates stay on the machine; no false acceptance with a different finger has been observed so far (limited testing, see Limitations).

## Limitations

- **Recognition rate**: controlled presses and rapid lock-screen retries can behave very differently. Version 1.94.100-41 fixes a retry calibration defect; switching between the old and fixed driver reproduced the improvement in real lock-screen tests with the same template. Subsequent tests also identified coverage lost when replacing a template. Some presses still fail. See the [controlled enrollment experiment](docs/recognition-experiment-2026-09-22.md) and [lock-screen investigation](docs/recognition-runtime-gap-2026-09-22.md); their small-sample results do not establish a long-term success rate.
- **One device combination only**: sensor `27c6:5503` with firmware `GF3258_RTSEC_APP_10063` and IAP `MILAN_RTSEC_IAP_10027`. Other firmware/IAP versions are not supported.
- **No firmware writes; no runtime PSK writes**: the driver and probe only read pairing state. A single fixed PSK write is available only through an explicitly invoked `goodix-5503-setup`, after warning that the existing Windows fingerprint pairing will stop working and requiring exact confirmation.

## Install

This assumes that fprintd and PAM are already installed/configured. On Arch, install the build and setup prerequisites, then build the custom libfprint:

```bash
sudo pacman -S --needed base-devel git meson ninja gobject-introspection \
  cairo opencv libgudev libgusb openssl pixman python python-pip curl innoextract
bash packaging/arch/build-package.sh
sudo pacman -U --noconfirm --overwrite "*" .tools/packages/libfprint-goodix5503-*.pkg.tar.zst
```

The package also installs the fprintd keep-alive/no-core drop-ins, the suspend/resume restart hook, and an optional user warm-up unit. It never silently generates or writes a PSK.

### PSK pairing (mandatory first-use check)

The host and sensor must share the same 32-byte PSK or TLS cannot start. Installing libfprint alone is insufficient. Setup first performs a read-only comparison with `/var/lib/fprint/goodix5503/psk.bin`; a match exits without writing. Otherwise it requires exact interactive confirmation, creates a random PSK, backs up the readable old records, performs one fixed provisioning write with immediate readback, and atomically installs a root-owned `0600` host key.

Install the setup tool and run its initial check as the desktop user. Do not prefix it with `sudo`; it invokes sudo only for a few fixed helpers:

```bash
python -m venv .venv
.venv/bin/pip install -e '.[whitebox]'
.venv/bin/goodix-5503-setup
```

If it reports `already-paired-no-write`, the existing PSK is ready and no other pairing command is needed. If it reports that the pinned official encoder is missing, run:

```bash
bash scripts/download-windows-drivers.sh
bash scripts/extract-windows-drivers.sh
.venv/bin/goodix-5503-setup
```

A clean Linux installation normally has no host PSK, so new users will usually follow the second path. Setup warns that Windows fingerprint pairing will stop working and requires the displayed confirmation text; without confirmation it does not generate a key, create a backup, or write the sensor.

Provisioning is never run by package install or upgrade. An ambiguous write is not retried automatically. Keep the owner-only files under `artifacts/device-backup/` and rerun setup; it preserves the original backup, validates the prepared key, and first checks whether the sensor already committed it.

## Usage

Use your existing system fingerprint settings to enrol a finger. Standard fprintd clients use the driver’s collection, selection and checks. An optional terminal guide adds placement and pacing prompts:

```bash
goodix5503-enroll --finger right-index-finger
```

Use the same finger throughout. Allow about 49 presses plus retries: one fprintd duplicate check, 40 training samples, followed by 8 checks using your natural unlocking motion. Keep your finger off the sensor until each ready prompt. Poor or duplicate training samples do not advance progress. Fewer than 6 successful checks means enrolment fails; repeat with more varied natural placement. Passing this short check is not a guarantee of a particular long-term unlock rate.

The `1.94.100-45` guide asks you to use your usual unlock pressure and return your whole hand to the keyboard or mouse between presses. Ready prompts wait at least 2.5 seconds between presses and 6 seconds after each group; allow about 3–5 minutes. These pauses delay prompts, not the sensor. After fresh enrolment on 2026-09-23, five independent lock-screen rounds each succeeded on the first press; nine wrong-finger presses were rejected. This small sample does not establish a long-term success rate. See the [full results](docs/fresh-enrollment-2026-09-22.md).

The helper uses the standard fprintd API and requests authorization through the desktop when needed. `--no-notify` uses terminal prompts only. It refuses to overwrite an existing finger unless you pass `--replace`: fprintd deletes that finger's previous template as soon as re-enrolment starts, and cancellation does not restore it. Standard `fprintd-enroll -f right-index-finger "$USER"` also uses the driver selection and checks, but lacks the helper's placement guidance and replacement guard. fprintd reports 49 stages including its initial duplicate check; the driver uses 48.

The optional guide defaults to concise English; use `--language zh` for Chinese. No standalone application or menu entry is installed. System settings retain their own interface and do not display the optional guide’s timed prompts.

Any login manager with fprintd configured in PAM can then unlock with a fingerprint. To keep the sensor "warm" between unlocks, fprintd must stay running. The Arch package installs the `--no-timeout` drop-in under `/usr/lib/systemd/system/fprintd.service.d/`; see `packaging/systemd/README.md` for manual source deployments.

## Safety and probing

The probe tool only allows a small set of read-only commands:

- `NOP`: wake/sync the device;
- `FIRMWARE_VERSION`: read the application firmware version;
- `GET_IAP_VERSION`: read the IAP version;
- `PRESET_PSK_READ`: optional, read-only. Reads the official R-family `0xbb020007` verification record and the `0xbb010002` DPAPI record. `0xbb010003` is a write-only MCU white-box input (hardware-tested unreadable) and is never read again; check mode reports metadata only, backup mode saves opaque raw records but never prints record contents or plaintext keys.

The probe CLI still blocks firmware, PSK, config, reset, register writes and image capture. The pairing and experimental runtime modules in this repo have fixed, bounded command sets; they do not expose a generic raw-command interface through the probe CLI. Firmware/IAP writes and arbitrary protected-record writes remain prohibited or separately approved persistent operations.

"Non-persistent" does not mean zero risk: the probe still sends query commands over USB. If the firmware misbehaves the device may become unresponsive until a reboot or full shutdown. The probe never modifies Flash, PSK or IAP; only the separately confirmed setup workflow can make its one bounded PSK write.

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

## Deploying the systemd helpers

The repo ships systemd configuration (`packaging/systemd/`): fprintd keep-alive, core-dump prevention, wake-up auto-restart (fixes the suspend/resume claim race, upstream libfprint #731), and optional login warm-up. The Arch package installs the first three plus the disabled warm-up unit. Debug logging, fingerprint-image dumps, and the experimental quality gate are never installed by default. See `packaging/systemd/README.md` for manual deployment.

## Development

- `src/goodix5503/`: the read-only probe and explicitly confirmed pairing setup CLIs
- `libfprint/`: the C driver, the SIGFM matcher, and the libfprint patch
- Offline Python regression suite (no PyUSB or hardware needed):
  `python3 tests/run_offline_tests.py`

The offline runner replaces PyUSB with an inert in-memory stub before importing
the package. Any unmocked attempt to enumerate, claim, transfer to, or release
a USB device fails the test immediately. It includes the firmware guard and
protocol tests with fake endpoints; optional Unicorn-based white-box tests are
skipped when Unicorn is absent. It never runs the command-line probe or opens a
physical device.

Matcher parameters and the template format are versioned: any change to feature extraction, match semantics or the decision threshold must bump the template format version, or old templates will be rejected. Details in `docs/libfprint-driver-plan.md`.

## Upstream references and license

This project stands on the shoulders of the following open-source work:

- [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) (LGPL-2.1-or-later): driver framework, state machine, enrolment/verification flow. Builds are pinned to upstream commit `80a4b5ec...`; this repo does not include libfprint code.
- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump) ([MIT](https://github.com/goodix-fp-linux-dev/goodix-fp-dump/blob/master/LICENSE), reference commit `cc43bb3b`, `718ee3c1`): the 5503 protocol frame format (`0xa0` outer frame, checksums, command set). Interface reference only; their code is not copied.
- [goodix-fp-linux-dev/libfprint SIGFM branch](https://github.com/goodix-fp-linux-dev/libfprint/tree/0x00002a/libfprint-sigfm) (LGPL-2.1-or-later, reference commit `7ebe0c80`): how SIFT + CLAHE + mutual/geometric matching plugs into libfprint; `sigfm.cpp/hpp` keep the upstream copyright headers (three authors, 2022) and are distributed under LGPL.
- [AndyHazz/goodix53x5-libfprint](https://github.com/AndyHazz/goodix53x5-libfprint) (reference commit `309d4c69`): that repo has **no LICENSE file**; we only referenced how it wires SIGFM to a Goodix sensor, no code was copied. The driver, protocol, TLS, config and persistent format in this project are independent implementations.

This project is licensed under `LGPL-2.1-or-later`. The official Windows driver binaries, device credentials (PSK/backups/templates) and local fingerprint images are not distributed with this repo.
