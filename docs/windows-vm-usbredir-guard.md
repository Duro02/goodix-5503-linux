# Windows VM usbredir guard

Direct USB passthrough to a fresh Windows VM is prohibited: the pinned driver
can replace PSK/protected records and contains firmware-update paths. Disabling
`WbioSrvc` does not disable its PnP UMDF service.

`goodix-5503-usbredir-guard` is a deliberately single-use stream proxy. It
accepts only `27c6:5503`, safe standard enumeration, a bounded 32 KiB bulk-IN
reader, then exactly these bulk-OUT transfers on endpoint 1:

1. `e5`
2. `0a0a0a0aa80300000001` followed by 54 zero bytes (64 bytes total)

The guard correlates the two OUT completion IDs. It forwards the successful A8
OUT completion and immediately closes both streams; a mismatch, failed status,
or bounded completion timeout closes them without forwarding further traffic.
Unknown, malformed, class/vendor control, stream, TLS, reset,
firmware/configuration, PSK, and replay traffic closes both streams without
forwarding the denied frame or synthesizing a response.

The protocol profile pins interface 0 (`ff/00/00`) and usbredir endpoint-array
indices 1/18 to bulk OUT `01` and bulk IN `82`, both with max packet 512. The
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
sudo usbredirect --device 27c6:5503 --as 127.0.0.1:40501 --keepalive

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
