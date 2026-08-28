# Windows VM usbredir guard

Direct USB passthrough to a fresh Windows VM is prohibited: the pinned driver
can replace PSK/protected records and contains firmware-update paths. Disabling
`WbioSrvc` does not disable its PnP UMDF service.

`goodix-5503-usbredir-guard` is a deliberately single-use stream proxy. It
accepts only `27c6:5503`, safe standard enumeration, a bounded 32 KiB bulk-IN
reader, then exactly one bulk-OUT transfer on endpoint 1:

```text
a00800a800050000000000a5 + 52 zero bytes (64 bytes total)
```

This outer-A0 A8 packet is the first application OUT observed dynamically from
the pinned Windows VM; no preceding `e5` appeared. The guard correlates its
request ID and forwards the successful A8 OUT completion and immediately closes both streams; a mismatch, failed status,
or bounded completion timeout closes them without forwarding further traffic.
At most three normal pre-command USB enumeration resets are allowed; each
requires the exact topology to be announced again. Unknown, malformed,
class/vendor control, stream, TLS, further reset, firmware/configuration, PSK,
and replay traffic closes both streams without
forwarding the denied frame or synthesizing a response.

The protocol profile pins usbredirhost's actual pre-connect order: interface 0
(`ff/00/00`), endpoint information, then `DEVICE_CONNECT`. Endpoint-array
indices 1/18 must be bulk OUT `01` and bulk IN `82`, both with max packet 512. The
index mapping is usbredirhost 0.15 `EP2I(ep) = ((ep & 0x80) >> 3) | (ep & 0x0f)`.
Both HELLO packets are validated before either is forwarded; the single
capability word is preserved and 64-bit IDs are used only when both peers offer
them. The guard is little-endian-only, buffers complete frames, caps each frame
at 64 KiB, and accepts one connection with no reconnect. Its JSONL audit path
must have an owner-only parent and is created `0600`; authorization is recorded
before send and forwarding afterward.

Threat model: pinned, trusted local QEMU 11.1 and usbredirect 0.15 peers, the
trusted official guest, and fixed physical `27c6:5503`. The guard prevents
accidental unintended control/OUT/persistence traffic; it is not a general USB
firewall or defense against a malicious local peer. It does not interpret TLS
and must never be used beyond the audited prefix.

## Loopback topology

Use new owner-only output paths and disable usbredir streams:

```sh
sudo usbredirect --device 27c6:5503 --as 127.0.0.1:40501

goodix-5503-usbredir-guard \
  --listen 127.0.0.1:40502 \
  --upstream 127.0.0.1:40501 \
  --audit /secure/capture/goodix-guard.jsonl
```

Configure QEMU/libvirt with a socket chardev connected to `127.0.0.1:40502` and:

```text
usb-redir,streams=off,filter=-1:0x27c6:0x5503:-1:1
```

Capture host `usbmon` and the loopback stream separately in an owner-only
directory. A real-device run still requires an independent gate review. VM
snapshots do not roll back sensor state.
