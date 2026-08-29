# Local 27c6:5503 device state

Observed through the project's staged, reviewed fixed-command paths. Firmware
has never been written. The PSK was explicitly reprovisioned once as documented
below; subsequent TLS and OTP/config checks made no persistent writes.

```text
USB ID:    27c6:5503
Firmware:  GF3258_RTSEC_APP_10063
IAP:       MILAN_RTSEC_IAP_10027
MCU chip ID: 0x220f after pinned reset + 10 ms + register-read flow; selects
             GF3258 DN2 profile (the earlier no-reset zero read was invalid)
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
Runtime clear-frame attempts: no attempt decoded or saved an image, and each
  attempted cleanup reset. Early runs resolved delayed D0 completion and the
  ten-byte HU image request. Later pinned-parser/cold-state runs reached the
  first command 36 and consistently received a 16-byte body after protocol
  checksum validation and stripping,
  which exceeds the official DN2 12-byte output capacity and remains fatal.
  A raw usbmon capture at commit `d6d7a4f` closed the transport question. Its
  22-byte OUT body was exactly `0d01 || live DAC_LE16[4] || (8000)*6`; the
  device returned the exact success ACK and then a complete command-36 A0 frame
  whose inner length was 17 (16 data bytes plus checksum). The decoded body was
  `82013f0065014b016b0150016b014701`. The IN URBs and command IDs were ordered
  correctly, and cleanup sent only A2 reset after the fatal response; command
  20 was not sent. Capture SHA-256:
  `d20ac47a7f631b07203e03e05e9c2036911ce0fcb38536764a7a86aa0ddd1674`.
  The latest full diff found two still-missing mandatory prerequisites: raw
  loader wake `e5` plus 50 ms settle, and CheckSensor A6 OTP acquisition after
  reset/chip selection and command 00. A separately reviewed one-shot at commit
  `cb0d0c4` then wrote raw `e5`, waited 50 ms, and failed on the first A8 ACK
  read with `invalid outer frame length`. It did not reach firmware decoding,
  reset, OTP, TLS, config, command 36, or image acquisition. Because reset had
  not started, cleanup closed USB without issuing reset. The result is final
  under that one-shot authorization; there was no retry. Hardware capture
  remains disabled. Static follow-up proved the one-byte write and 50 ms settle
  are exact and that official WakeUp performs no read/drain/flush. The missing
  parity is the Windows IoHub asynchronous pending-command filter, which ignores
  no-pending and mismatched notifications; the synchronous free reader assumes
  the next IN bytes are the A8 ACK. Because the failed bytes were not recorded,
  their signature and length remain unknown and no safe filter is yet proven.
  A one-off source-gated diagnostic performed only `e5`, settle,
  and a 500 ms transfer-boundary observation; it drops root permanently after
  claiming USB. The separately reviewed one-shot completed with zero bulk-IN
  transfers during that window. This disproves an independently queued wake
  response as the cause of the earlier stale-frame hypothesis. It does not
  reveal the bytes returned only after the subsequent A8 request. A second
  separately reviewed one-shot sent exactly one checksummed A8 after the wake
  and likewise observed zero bulk-IN completions in the following 500 ms. No
  parser, retry, reset, or additional command was used. This means the earlier
  invalid frame cannot yet be reproduced by post-write synchronous reads. The
  remaining proven host difference was that Windows keeps one 32 KiB IN request
  pending through WakeUp/A8. A third reviewed one-shot approximated that model
  with one queued `read(0x8000)`, a 25 ms host barrier, then `e5`, 50 ms, and A8;
  it also observed zero completions under its 600 ms absolute deadline. This
  rules out the obvious post-write submission gap but not PyUSB's unobservable
  URB-submission race. Static follow-up proved that official Geneva waits 1,500
  ms for ACK and then separately 1,500 ms for data; all three observation
  windows were too short. That queued diagnostic was corrected to a 3,250
  ms absolute envelope with post-wake/post-settle deadline checks and timing
  output. The reviewed 3,250 ms one-shot then captured two complete IN
  transfers at 531/533 ms: first exactly ten zero bytes, then a valid 31-byte
  A8 frame containing `GF3258_RTSEC_APP_10063`. Wake completed at 26 ms and the
  free outer-A8 OUT ran from 76 to 528 ms. This reproduces the prior invalid-
  outer-length cause in the free client: its synchronous parser treated the
  leading zero transfer as an A0 outer header. Final pinned-Win11 loader tracing
  shows outer A8 is legitimate firmware-version traffic in SelfCheck and
  ProcessPsk. A separate optional `McuGetCpuVersion` F0/F1 SPI branch exists but
  is skipped by the pinned USB globals and is not a libusb protocol. The ten
  zeros remain an empirical completion, not a token to ignore. The reviewed
  15-byte F0/`_WriteSpi(0x3d00)` one-shot was the wrong SPB layer and correctly
  produced no USB IN. A later direct-inner 64-byte one-shot likewise produced
  no IN. Finally, a no-hardware usbredir trace from pinned QEMU/Windows and the
  staged official driver observed the actual first application OUT as outer-A0
  `a00800a800050000000000a5 + 52*00`; no preceding `e5` appeared. Hardware runs
  confirmed the exact bytes and successful 64-byte endpoint-`01` completion.
  Crucially, `a8` at offset 3 is the outer-header checksum, not an A8 opcode:
  the inner packet is command `00`, four zero payload bytes, checksum `a5`.
  A response-only guarded run captured endpoint-`82` reply
  `a00600a6b003000001f6`, which decodes as command-B0 payload `00 01`: ACK for
  command 00, success. The ACK arrived 3.411 ms after the OUT submission. The
  guard then denied the next 64-byte application OUT before forwarding it; no
  TLS, PSK, configuration payload, protected-record, or firmware write reached
  hardware. Final response capture SHA-256 is
  `3bc86861dfea11d5838e6e0fb406151b5a60c5ee87889b184a852a08a2f80a10`;
  guard audit SHA-256 is
  `f1908bb21fa3eb6d0589943c5adec1c36a0d4ed1edd49f7226e85befc436d998`.
  A later owner-only loopback capture identified the denied second OUT as
  `a00600a6a803000000ff + 54*00`: command A8 with payload `00 00`, padded to
  64 bytes. Its complete usbredir packet hash exactly matches the denied audit
  event. Concurrent usbmon proves this second OUT never reached hardware. A
  reviewed two-OUT run subsequently forwarded that exact read-only firmware-A8
  request and captured separate responses: ACK `a00600a6b00300a8014e`, then
  data frame `a01b00bba818004746333235385f52545345435f4150505f31303036330012`
  containing `GF3258_RTSEC_APP_10063\0`. The next OUT was denied before hardware.
  An owner-only loopback capture identified that denied third OUT as an exact
  second padded `A8/0000` request, confirming the two normal APP identity reads
  statically mapped to SelfCheck and ProcessPsk. A reviewed three-OUT run
  captured identical success ACK and firmware data for the second read. The
  fourth denied OUT hash uniquely matches fixed read-only command E4 selector
  `bb010002`, mode 0. A later reviewed run received ACK plus command-E4 payload
  `01 01`, not the protected record; this is a query/status transaction. The
  conservative record-envelope gate rejected and wiped it before Windows. A
  later reviewed runs forwarded the exact `01 01` results; successive denied
  OUT hashes identify exact second and third `E4/bb010002/mode0` queries. After
  the third exact response, the seventh OUT was denied before hardware. Static
  flow places it at `SetIap(..., 0x32)` / command A4, immediately before an app
  erase/retry path, so it is a persistent-state boundary and will not be
  whitelisted. This closes command-00 and both firmware-A8 response routes while
  leaving any later actual record recovery separately gated. Static analysis
  proves these are three failed `PresetPskIsValidR` attempts. Entering the valid
  official branch would require a new device-resident DPAPI `bb010002` record
  recoverable by this VM user and matched to the existing PSK; preparing it can
  be offline, but writing it is a separately authorized persistent operation.
  One reviewed Linux runtime attempt at commit `16750f5` still emitted raw `e5`
  before command 00 and failed closed on that command's first read with
  `invalid outer frame length`. It reached no A8, reset, TLS, config, FDT, or
  image operation and was not retried. The pinned Windows USB trace had already
  proved that the selected runtime emits no preceding `e5`; clear-frame capture
  now starts directly with command 00 while wake diagnostics remain isolated.
  The separately reviewed no-wake attempt at commit `c0db2a4` then sent command
  00 first but timed out waiting for any IN completion. It also reached no A8,
  sensor reset, TLS, config, FDT, or image operation and was not retried. In the
  successful Windows trace, command 00 followed three standard USB enumeration
  resets. A reviewed one-shot at `d613c6d` reproduced those resets but still
  timed out with no IN completion and reached no later operation. USB reset
  state alone is therefore insufficient, so the specialized reset/descriptor
  code was removed instead of becoming dormant production complexity. Unlike
  synchronous PyUSB, Windows had a 32 KiB IN request queued before command 00.
  A focused libusb asynchronous diagnostic then submitted a real 32 KiB IN
  before the fixed OUT and received the exact command-00 ACK. A smaller PyUSB
  queued-read check reproduced the same result. The experimental capture path
  now queues each bounded IN before its corresponding fixed OUT and queues the
  next response read immediately after each completion.
```

After a bounded C-runtime A2 cleanup, A8 reports the official embedded base
marker `GF3208_RTSEC_APP_10063`; a full power cycle restores the attested
`GF3258_RTSEC_APP_10063` identity. The initially observed command-36 failure was
later traced to the C decoder incorrectly selecting the no-checksum trailer mode,
not to incompatible base firmware. Runtime therefore accepts only these two
exact official 10063 identities and still requires fixed PSK, chip-ID and OTP
profile checks. No firmware write occurred.

The first end-to-end development `FpImageDevice` run then completed fresh-base,
finger-down, encrypted command-20 transfer, in-process TLS decryption, image
submission, and finger-up. The smoke helper reported only categorical success;
no image, minutiae, hash, or biometric statistics were saved or logged. The
critical ordering fix was to consume the optional post-final-flight A0/D0 as the
TLS request's completion before starting config/image work, while preserving the
25 ms queued-IN barrier used by the proven Python transport.

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
