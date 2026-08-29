# Engineering scope and proportionality

This project protects four hard boundaries:

1. never enter firmware/IAP/erase paths;
2. never write PSK or protected records without explicit persistent-write approval, backup and readback;
3. never log or persist plaintext PSKs or biometric images;
4. never expose a generic raw USB command interface.

Everything else is an engineering trade-off, not a security invariant.

## Runtime and diagnostic work

Fixed read-only or volatile-runtime operations do not require source-level
`False` gates, magic confirmation phrases, bespoke launchers, or complete USB
descriptor equality. They should use:

- unique `27c6:5503` selection and the expected physical port;
- interface/endpoint direction and type checks;
- refusal when a kernel driver or another process owns the device;
- fixed payloads, finite deadlines, bounded buffers and cleanup;
- clear labeling as experimental.

A diagnostic must answer one stated uncertainty. If it falsifies its hypothesis,
remove its specialized implementation instead of retaining dormant machinery.
Do not expand a one-command diagnostic into a general transport until its result
shows that the transport is needed.

## Reviews and tests

Independent review is mandatory for persistent writes and firmware boundaries.
For read-only/runtime work, one normal code review per coherent change is enough.
Fresh-context proportionality review runs approximately hourly and should report
at most three concrete simplifications; it is advisory rather than a new gate.

Tests should cover active behavior and hard boundaries. Delete tests that exist
only for removed experiments, review flags, transcript replay, or harmless USB
descriptor fields.

## Current direction

Windows tracing stopped at the driver's A4/IAP boundary and its trace-specific
proxy is archived in Git history. Raw-wake and three-reset hypotheses were tested
and falsified; their active implementations were removed. Pre-submitted bulk-IN
was confirmed and is now part of the fixed C transport, including 64-byte USB
chunking and bounded frame reassembly. Current work is limited to validating the
`FpImageDevice` capture/enroll/verify path and packaging it for `fprintd`.
