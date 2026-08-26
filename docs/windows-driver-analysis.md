# Lenovo/Goodix Windows driver static analysis

## Scope

This analysis uses official Lenovo packages for the ThinkBook 14 G3 ACL machine
type `21A2` and hardware ID `USB\VID_27C6&PID_5503`. Proprietary files stay
under the Git-ignored `artifacts/windows-driver/` directory and must not be
redistributed.

No installer was executed and no fingerprint hardware was accessed.

## Official packages

| OS | Lenovo file | Goodix version | SHA-256 |
|---|---|---:|---|
| Windows 10 | `74ti05afkkxbyyb0.exe` | 3.1.581.520 | `c94d7c866b0fc0be4d62511b780294900eef972f6e8ec9db761b74cfdf1af4ea` |
| Windows 11 | `74ti04afkkxbyyb0.exe` | 3.1.581.610 | `27b211eee3f973b2e5b70823d6fb7c69394876839ab9e2e9a85f14b8ce1008ee` |

Lenovo catalog manifests:

- `https://download.lenovo.com/catalog/21A2_Win10.xml`
- `https://download.lenovo.com/catalog/21A2_Win11.xml`

The packages were extracted with `innoextract`; they contain Goodix, ELAN and
Synaptics payloads. Only the Goodix directory applies to `27c6:5503`.

## Driver architecture

`WbdiUsb.inf` binds the same Goodix UMDF/WinUSB stack to:

- `27c6:5503`
- `27c6:55a2`
- `27c6:55a4`
- `0bda:5811`

Relevant files:

- `Wbdi.dll`: UMDF device driver and USB/protocol implementation.
- `GoodixEngineAdapter.dll`: Windows Biometric Framework engine adapter.
- `AdapterEnclave.signed.dll`: protected image preprocessing and matching.
- `WbdiEnclave.signed.dll`: protected TLS, PSK and image-processing code.
- `SessionService.exe`: supporting Windows service.
- `sgx_white_list_cert.bin`: enclave authorization data.

The INF uses the Windows built-in sensor and storage adapters, but supplies a
Goodix engine adapter. It uses WinUSB as a lower filter and installs `Wbdi.dll`
as the UMDF service.

## Host-side image and matching evidence

The binaries provide direct evidence that `5503` is not a pure match-on-chip
sensor:

- `Wbdi.dll` contains USB image acquisition paths such as `FpMcuGetImage`,
  `FpParseImage`, `FpGetImageSampleSize`, `CaptureData` and
  `ConvertImageSample`.
- It contains calibration/FDT paths for base images, finger-down/up detection,
  image validation and raw image buffers.
- TLS/PSK code includes Mbed TLS client/server code and messages for decrypting
  image data.
- `GoodixEngineAdapter.dll` and the enclave export or reference
  `enrolAddImage`, `enrolGetTemplate`, `identifyImage`, `identifytemplate`,
  preprocessing, image quality and template pack/unpack operations.
- The engine binary includes host algorithm sources named `feature.c`,
  `preprocess.c`, `recognition.c`, `pack_finger_template.c` and
  `finger_goodix.c` in its build-path strings.
- The engine checks for Windows' `WINBIO_DATA_FLAG_RAW` and
  `WINBIO_ANSI_381_FORMAT_TYPE` capture format.

Conclusion: the sensor performs acquisition, FDT and some preprocessing, then
sends encrypted image data to the host. The host decrypts/preprocesses images,
extracts features and performs enrollment/identification. Raw or near-raw
images exist transiently in host memory even if Windows does not persist them.

## Protocol/firmware evidence

`Wbdi.dll` includes:

- Geneva MCU firmware version/check/update logic;
- application-vs-IAP detection and firmware CRC checks;
- MCU register read/write and FDT mode transitions;
- PSK generation, sealing, white-box encryption, MCU PSK/hash read/write and
  HMAC verification;
- Mbed TLS handshake and TLS image receive paths;
- source paths naming `FpMcuCmd.c`, `MilanFSerMcu.c`, `UpdateFirmware.c`,
  `Usb.c`, `Image.c`, `PskUnify.c` and `TlsModuleUnify.c`.

No standalone Goodix firmware file appears in this Lenovo package. Firmware
images/configuration may be embedded in `Wbdi.dll`, selected only for some
sensor interfaces, or omitted because this model ships with a suitable version.
Static strings list multiple GF32xx firmware families, so any embedded blob must
be associated with the exact `5503` device path before use.

## Comparison with the community implementation

The official binaries independently confirm the major design implemented by
`goodix-fp-linux-dev/goodix-fp-dump`:

- framed USB commands;
- MCU/IAP firmware queries;
- PSK metadata and provisioning;
- TLS-protected image transfer;
- FDT/calibration images;
- host-side image processing and matching.

This supports using the community `driver_5503.py` as a protocol reference, but
not running its firmware/PSK mutation path. The Linux implementation should
first support the device's existing firmware and PSK state without writes.

## Next static-analysis targets

1. Locate the exact `27c6:5503` device descriptor/config table in `Wbdi.dll`.
2. Map USB command constants and payload builders to the community protocol.
3. Identify the selected sensor geometry, frame format and image decoder.
4. Determine whether the PSK can be used without reprovisioning.
5. Identify suspend/resume and MCU-reset sequences separately from firmware
   update paths.
