# Production C firmware-guard test: compiled-code feasibility

## Result

No compiled-code harness is added in this checkout.  The current reproducible
offline gate is the source-level regression check run by:

```sh
python3 tests/run_offline_tests.py
```

It tests the production driver's actual source at
`libfprint/drivers/goodix5503.c`, not a copied firmware predicate.  It verifies
the two explicitly pinned 10063-era application identities
(`GF3258_RTSEC_APP_10063` and the expected post-reset
`GF3208_RTSEC_APP_10063`) and that no 10062 identity is accepted.  It also
verifies that the unsupported-identity branch calls the pre-reset failure path
and returns before any follow-up `goodix5503_command_start` dispatch.

The Python runner replaces PyUSB with an inert module before importing the
package.  Any unmocked Python USB enumeration, claim, transfer, or resource
release fails immediately.  It does not build or load the C driver and never
opens a physical USB device.

## Production guard and dependency boundary

The guarded callback is the static function
`goodix5503_firmware_done()` in `libfprint/drivers/goodix5503.c`.  It depends
on the real surrounding driver implementation, including:

- the private `FpiDeviceGoodix5503`/`FpImageDevice` object layout;
- `goodix5503_pre_reset_fail()` and `goodix5503_command_start()` in the same
  translation unit;
- libfprint internal headers and completion/error APIs (`drivers_api.h` and
  `fpi-log.h`);
- GLib/GObject/GIO, GUsb, and OpenSSL.

The guard is `static`, so an external test cannot call it without either
compiling the real translation unit in libfprint's build or changing the
production driver's visibility.  The latter would change production code for
testability only and is not justified here.

The C callback has no IAP argument or IAP comparison.  Invalid-IAP rejection is
therefore covered only by the pure-Python `classify_firmware()` regression test;
it must not be described as an executed property of this C callback.  Likewise,
the accepted C branch performs host-PSK loading and then schedules the PSK-read
command.  Without a real libfprint fake-transport test, this checkout cannot
claim compiled execution of either accepted branch or its later command path.

## Why this checkout cannot provide the compiled test

This repository intentionally stores the Goodix overlay rather than a complete
libfprint checkout.  It has no local `libfprint/meson.build`, `drivers_api.h`,
or `fpi-log.h`; `.tools/` has no cached upstream source.  The local environment
has a C compiler but no Meson or GLib development metadata (`pkg-config
glib-2.0` fails).  Building a standalone surrogate would require re-creating
private libfprint types and USB/completion APIs.  That would test a synthetic
framework contract rather than the production driver and could conceal the
very dispatch boundary this check is intended to protect.

## Correct future integration point

`scripts/build-libfprint-driver.sh` documents the appropriate upstream build
path.  A real compiled guard test belongs in the clean, pinned libfprint
v1.94.100 checkout at commit
`80a4b5ec612892c5c056c48dddaa561452cf37ec`, after the Goodix overlay and its
patch are applied.  It should be registered as a Meson test beside the existing
Goodix tests and use a fake GUsb transport that aborts on every transfer,
interface claim, or enumeration.

That environment requires, at minimum, a C compiler, Meson, Ninja, the pinned
clean libfprint source, and the development packages needed by that build
(GLib/GObject/GIO, GUsb, OpenSSL, and the script's OpenCV dependency).  The
current build script does **not** add or run a compiled firmware-guard test, so
it must not be presented as validation of this guard.

Until those prerequisites are supplied in a separately prepared offline build
environment, the source-level guard regression and static ordering checks are
the reproducible safety boundary.  They prove the source ordering for rejected
firmware, not ABI-level execution or device behaviour; no device operation is
authorized by them.
