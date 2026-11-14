# Plan: compiled Goodix firmware-guard test in libfprint

## Status and safety boundary

This is an implementation plan, not a test harness.  No overlay-prepared
upstream source or runnable native build environment is present in this
checkout, and no USB device was opened, enumerated, or contacted while
preparing it.

The intended test must compile the production
`libfprint/drivers/goodix5503.c` into libfprint and drive it through the normal
activation state machine.  It must not copy
`goodix5503_firmware_done()`, fabricate private libfprint types, or expose the
static callback solely for a unit test.

Every candidate test run is confined to a disposable environment with no host
USB device nodes or host PSK path.  Its only USB endpoint is an emulated one;
an unexpected transfer is a test failure, never a fallback to hardware.

## Exact upstream integration target

The overlay's build script establishes the authoritative target:

| Item | Required value | Local evidence |
| --- | --- | --- |
| Upstream repository | `https://gitlab.freedesktop.org/libfprint/libfprint.git` | project build convention |
| Upstream revision | `80a4b5ec612892c5c056c48dddaa561452cf37ec` | `scripts/build-libfprint-driver.sh` |
| Version family | libfprint `1.94.100` | source-directory check in the same script |
| Goodix build option | `-Ddrivers=goodix5503` | script's `meson setup` |
| Overlay sources | `goodix5503.c`, proto, config, security, image and TLS helpers | script copy list |
| Core patch | `libfprint/patches/sigfm-core-v1.94.100.patch` | script patch step |
| Existing test configuration | `-Dintrospection=true -Ddoc=false -Dudev_rules=disabled -Dudev_hwdb=disabled` | script's `meson setup` |

The script must remain responsible for rejecting a dirty or wrong-revision
source tree.  The compiled guard test should be added to the *prepared upstream
worktree* in a later, separately reviewed change, not compiled against a
system-installed libfprint or this overlay alone.

## Existing upstream test seam

libfprint's driver-test infrastructure uses Meson plus `umockdev-run` and
`tests/umockdev-test.py` to present a synthetic USB device and replay
transcript to the compiled driver.  The internal API also documents the
test-emulation gate `FP_DEVICE_EMULATION=1`; see the [upstream internal
API](https://libfprint.pages.freedesktop.org/fprint.freedesktop.org/libfprint-dev/libfprint-2-Internal-FpDevice.html).

The intended seam is therefore a driver test, not `test-device-fake.c` alone.
The latter is useful for generic `FpDevice` behavior, but it does not inject
GUsb transfers into this hardware driver.  The guard test must instead use the
existing driver-test wrapper to instantiate a synthetic USB device with VID:PID
`27c6:5503`, load the compiled `goodix5503` driver, and exercise normal
activation.

### Pinned-source inspection result

The exact source was obtained separately at
`/tmp/libfprint-goodix5503-80a4b5ec` and verified clean at
`80a4b5ec612892c5c056c48dddaa561452cf37ec`.  No overlay was applied and no
native build or test was run.  Its actual test code establishes the following
integration details:

- `tests/meson.build` sets `FP_DEVICE_EMULATION=1`, creates the
  `fprint-test-emulation` helper, and registers hardware-driver fixtures from
  the `drivers_tests` map.
- For each fixture it sets `FP_DRIVERS_ALLOWLIST` to the fixture driver name,
  then executes `tests/umockdev-test.py <fixture> --test <type>`.
- `tests/umockdev-test.py` creates a temporary directory and invokes
  `umockdev-run -d <fixture/device> -p <fake-syspath>=<fixture/*.pcapng> --`
  before the fixture's Python test process.  A pcap transcript is therefore
  the concrete mechanism that rejects unrecorded USB traffic.
- Existing `tests/goodixmoc/` fixtures demonstrate the required layout:
  `device`, plus `custom.py` and/or `*.pcapng`.  The generated test process
  uses an `FPrint.Context` and normal `FPrint.Device` operations, rather than
  calling driver-static callbacks.

The exact test seam is now known.  What remains unavailable is a runnable,
hardware-isolated native environment; see **Current execution blocker** below.

## Required isolated environment

Minimum prerequisites for a future test environment are:

- the clean pinned libfprint checkout above and this Goodix overlay;
- a C compiler, Meson, Ninja, `pkg-config`;
- GLib, GObject and GIO development files;
- GUsb/libgudev development files and the libfprint build dependencies;
- OpenSSL development files;
- GObject introspection, Python and Python GI for upstream driver tests;
- `umockdev-run` plus a version supporting the replay format selected by the
  pinned upstream tree (pcapng replay commonly needs modern umockdev);
- Cairo/Python-Cairo where the upstream driver-test target requires them.

The repository's full developer build script also requires OpenCV because of
SIGFM.  A narrowly scoped driver test may avoid that only if the pinned Meson
dependency graph demonstrably permits it; do not relax or guess that condition.

The harness must run in a disposable container or mount namespace with no host
`/dev/bus/usb` or host USB sysfs exposed.  `umockdev-run` must be the only
device provider.  The test environment must set the same in-tree library and
emulation variables as existing upstream driver tests, including
`FP_DEVICE_EMULATION=1`.  A test setup failure that exposes no fake device must
be a failure or explicit skip, never a fallback to normal host discovery.

## Test design

### Test location and registration

Add a future driver-test fixture, for example
`tests/goodix5503-guard/`, to the prepared upstream source.  Register it with
the existing `drivers_tests`/`umockdev-test.py` mechanism and make it depend on
the compiled `goodix5503` driver.  The fixture should contain:

1. a synthetic USB descriptor for exactly `27c6:5503`;
2. an ordered transport transcript; and
3. a test driver that requests activation and observes libfprint completion.

The transcript must permit only the startup NOP and firmware-version exchange
needed to reach `goodix5503_firmware_done()`.  It must reject all other OUT
traffic by default.  Thus a new PSK read (`E4`), reset (`A2`), config (`90`),
or any unlisted command is a deterministic replay mismatch.  No real GUsb
device exists in this arrangement.

### Rejected identity cases

For each response below, replay the minimum startup exchange and then end the
transcript:

| Firmware response body | Expected compiled-driver result | Required transport assertion |
| --- | --- | --- |
| `GF3258_RTSEC_APP_10062\0` | activation fails with `FP_DEVICE_ERROR_NOT_SUPPORTED` | no transfer after the firmware response |
| a terminated unknown identity, such as `GF3258_RTSEC_APP_10064\0` | same failure | no transfer after the firmware response |
| malformed, missing-NUL, or nonzero-trailing identity | same failure | no transfer after the firmware response |

These tests execute the actual compiled static callback via its normal caller.
The bounded transcript makes the absence of follow-up dispatch observable:
any PSK, reset, config, or other later command is a hard test failure before it
can communicate with hardware.  The current C driver has no firmware-update
command dispatcher; the no-follow-up-transfer assertion is stronger and avoids
inventing one.

### Accepted identity boundary

Use `GF3258_RTSEC_APP_10063\0` (and separately the expected post-reset marker
`GF3208_RTSEC_APP_10063\0`) to prove that the compiled guard does **not** take
the unsupported-identity return.  The production function then loads the host
PSK and schedules an `E4` verification request.  This test has two additional
requirements:

1. provide a synthetic 32-byte test PSK only inside an isolated test root;
   never read `/var/lib/fprint/goodix5503/psk.bin` or any real credential; and
2. make the fake transport record the first `E4` attempt and abort there.  It
   must not supply a PSK response or allow TLS, reset, configuration, image,
   enrollment, or firmware-changing paths.

This proves only the compiled guard's accepted branch and first safe test
boundary.  It does not validate a PSK, TLS session, reset, configuration, or
any physical firmware behavior.

## IAP boundary

`goodix5503_firmware_done()` receives only the application-firmware response;
it has no IAP value or IAP comparison.  Invalid-IAP behavior therefore cannot
be a compiled test case for this callback.  Keep it in the existing pure-Python
`classify_firmware()` tests and state that boundary explicitly in any result.

## Minimal implementation sequence

1. Acquire the exact clean upstream revision in a separately prepared offline
   build environment; verify its commit before copying the overlay.
2. Inspect its `tests/meson.build`, `tests/umockdev-test.py`, and an existing
   hardware-driver fixture to use the pinned API rather than a hand-written
   substitute.
3. Add the synthetic `27c6:5503` fixture and rejection transcripts first.
   Run only the new Meson target under `umockdev-run` in an environment with no
   host USB nodes.
4. Add the accepted-boundary case only after an isolated-root solution for the
   hard-coded PSK path is reviewed.  Prefer a namespace-mounted synthetic path
   over a production environment override or test-only symbol replacement.
5. Make the overlay build script copy/register the test only after its exact
   upstream integration has passed review.  Do not add it to the Python runner:
   the compiled test has separate native dependencies and must fail closed when
   its isolated environment is unavailable.

## Current execution blocker

The pinned source is now available only for inspection in `/tmp`, but the
current environment still cannot satisfy Phase 2.  It has a C compiler, Ninja,
Bubblewrap and `unshare`, but lacks all of the following:

- `meson` and `umockdev-run`;
- GLib/GObject/GIO and GUsb development metadata (`pkg-config` cannot find
  them);
- the remaining native/GI dependencies needed to configure the pinned Meson
  test suite.

Because `umockdev-run` is absent, this environment cannot demonstrate that
`FPrint.Context.enumerate()` sees only the synthetic fixture and never falls
back to host USB.  Building a partial substitute, stubbing GUsb, or executing
the driver outside that wrapper would invalidate the hardware-isolation
requirement.  No native test fixture or build-script integration is therefore
added in this checkout.

The remaining implementation blockers, for a separately prepared native
environment, are:

1. The accepted path uses a hard-coded host PSK path; an isolated filesystem
   strategy is required before that case is safe to run.
2. The exact Goodix response frames and pcap transcript must be constructed
   and reviewed before committing a fixture; an omitted transfer must stay a
   fatal mismatch.
3. No compiled test can establish sensor acceptance, persistent state,
   Windows Hello enrollment preservation, or firmware-10062 compatibility.

Until those blockers are resolved, run the hardware-isolated Python suite:

```sh
python3 tests/run_offline_tests.py
```

It remains a source-level safety gate, not a substitute for the proposed native
test.
