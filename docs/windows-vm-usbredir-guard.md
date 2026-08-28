# Windows VM usbredir guard

Direct USB passthrough to a fresh Windows VM is prohibited: the pinned driver
can replace PSK/protected records and contains firmware-update paths. Disabling
`WbioSrvc` does not disable its PnP UMDF service.

`goodix-5503-usbredir-guard` is a deliberately single-use stream proxy. It
accepts only `27c6:5503`, safe standard enumeration, bounded 32 KiB bulk-IN
reads, and exactly six pinned bulk-OUT transfers on endpoint 1:

```text
a00800a800050000000000a5 + 52 zero bytes (command 00; 64 bytes)
a00600a6a803000000ff + 54 zero bytes (firmware-version A8; 64 bytes)
a00600a6a803000000ff + 54 zero bytes (second identity read; 64 bytes)
a00c00ace40900020001bb00000000ff + 48 zero bytes (protected query; 64 bytes)
a00c00ace40900020001bb00000000ff + 48 zero bytes (second query; 64 bytes)
a00c00ace40900020001bb00000000ff + 48 zero bytes (third query; 64 bytes)
```

This is a padded outer-A0 command-00 packet: `a8` is the outer-header checksum,
while the inner command byte is `00` with four zero payload bytes. It is the
first application OUT observed dynamically from the pinned Windows VM; no
preceding `e5` appeared. The guard correlates its request ID and forwards only
the successful command-00 OUT completion reporting the exact 64-byte
transferred length. It requires the exact command-B0 success ACK
`a00600a6b003000001f6` before allowing the first pinned read-only firmware A8.
The second identical A8 is allowed only after exact first response frames
`a00600a6b00300a8014e` and
`a01b00bba818004746333235385f52545345435f4150505f31303036330012`.
Three fixed read-only `E4/bb010002` mode-0 requests are then allowed. Each ACK and
observed 10-byte command-E4 payload `01 01` response must be exact. These are
query/status transactions, not the 324-byte protected record. Each response is
still handled conservatively with one mutable backing buffer, no packet
metadata/content hashing in the audit, and zeroing in a `finally` path.
Buffered-bulk responses are always denied. Afterward only already-audited
control-IN requests and bounded endpoint-`82` reads may pass. Any seventh bulk OUT
closes both streams before forwarding; so do a mismatched or failed completion,
a nonexact ACK/data response, and the bounded observation deadline.
At most three normal pre-command USB resets are allowed. They retain the
already pinned usbredir connection identity; any topology packet that does
recur must still match exactly. Unknown, malformed,
class/vendor control, stream, TLS, further reset, firmware-write/configuration, PSK,
and replay traffic closes both streams without
forwarding the denied frame or synthesizing a response.

The protocol profile pins usbredirhost's actual pre-connect order: interface 0
(`ff/00/00`), endpoint information, then high-speed `DEVICE_CONNECT` with device
class `ef/02/01` and `27c6:5503`. Endpoint-array
indices 1/18 must be bulk OUT `01` and bulk IN `82`, both with max packet 512. The
index mapping is usbredirhost 0.15 `EP2I(ep) = ((ep & 0x80) >> 3) | (ep & 0x0f)`.
Both HELLO packets are validated before either is forwarded. The guard clears
the bulk-streams capability in both forwarded HELLOs, preserves every other
known capability bit, and uses 64-bit IDs only when both peers offer them. The
guard is little-endian-only, buffers complete frames, caps each frame
at 64 KiB, and accepts one connection with no reconnect. Its JSONL audit path
must have an owner-only parent and is created `0600`; authorization is recorded
before send and forwarding afterward.

Threat model: pinned, trusted local QEMU 11.1 and usbredirect 0.15 peers, the
trusted official guest, and fixed physical `27c6:5503`. The guard prevents
accidental unintended control/OUT/persistence traffic; it is not a general USB
firewall or defense against a malicious local peer. It does not interpret TLS
and must never be used beyond the audited prefix.

## Loopback topology

Use new owner-only output paths. The guard itself strips usbredir bulk-stream
negotiation from both HELLOs:

```sh
pkexec usbredirect --device 27c6:5503 --as 127.0.0.1:40501

goodix-5503-usbredir-guard \
  --listen 127.0.0.1:40502 \
  --upstream 127.0.0.1:40501 \
  --audit /secure/capture/goodix-guard.jsonl \
  --accept-timeout 60
```

Configure QEMU/libvirt with a socket chardev connected to `127.0.0.1:40502` and:

```text
usb-redir,streams=off,filter=-1:0x27c6:0x5503:-1:1
```

Capture host `usbmon` and the loopback stream separately in an owner-only
directory. A real-device run still requires an independent gate review. VM
snapshots do not roll back sensor state.
