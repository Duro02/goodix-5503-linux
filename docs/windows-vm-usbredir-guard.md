# Windows VM usbredir guard

Direct USB passthrough to a fresh Windows VM is prohibited: the pinned driver
can replace PSK/protected records and contains firmware-update paths. Disabling
`WbioSrvc` does not disable its PnP UMDF service.

`goodix-5503-usbredir-guard` is a deliberately single-use stream proxy. It
accepts only `27c6:5503`, safe standard enumeration, a bounded 32 KiB bulk-IN
reader, then exactly these bulk-OUT transfers on endpoint 1:

1. `e5`
2. `0a0a0a0aa80300000001` followed by 54 zero bytes (64 bytes total)

After the A8 OUT, the next guest packet closes both streams. Unknown, malformed,
class/vendor control, stream, TLS, reset, firmware/configuration, PSK, and replay
traffic closes both streams without forwarding the denied frame or synthesizing
a response. The guard is little-endian-only, buffers complete frames, caps each
frame at 64 KiB, and accepts one connection with no reconnect. Its `0600` JSONL
audit records metadata and SHA-256 only.

This is not a general USB firewall. It does not interpret TLS and must never be
used to allow traffic beyond the audited prefix.

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
