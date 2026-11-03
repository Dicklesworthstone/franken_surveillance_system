# Restarting source-once fusion

`fss-fusion::UniqueSourceEProcess` can export and restore its complete bounded derived
state. A restart retains every consumed source, including negative and zero observations
and sources from earlier numerical regimes. Replaying a source under another alias cannot
add likelihood again. Resetting a regime does not refund lifetime source capacity.

```rust
use fss_fusion::{EProcessConfig, UniqueSourceEProcess};

let process = UniqueSourceEProcess::new("event:entry", EProcessConfig::default(), 256)?;
let checkpoint = process.checkpoint()?;
// Persist checkpoint.bytes() and retain checkpoint.digest() independently.
let resumed = UniqueSourceEProcess::from_checkpoint(checkpoint.bytes(), checkpoint.digest())?;
assert_eq!(resumed.inventory_digest(), process.inventory_digest());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The owner does no filesystem or network I/O. The caller chooses and persists the bytes,
retains the expected SHA-256 independently, and verifies that the restored hypothesis,
configuration and source limit fit its intended operation. A damaged or incompatible
checkpoint returns a typed error, never a fresh process or a partially restored inventory.
`admitted_sources()` exposes canonical source, immutable item digest and first-admission
index for complete caller-owned provenance reconciliation.

## Frozen binary format

Version 1 is handwritten canonical binary. Its header is the eight bytes `FSSUSCP\0`,
a big-endian u32 version `1`, and a big-endian u64 payload byte length. The footer is
32 bytes of SHA-256 over the header and payload. The external checkpoint identity is
SHA-256 over the entire envelope, including the footer.

The payload stores, in order:

1. Source limit and source count as u32; strictly sorted source records, each containing
   the algorithm-tagged source digest, SHA-256 immutable item digest and u64 first step.
2. Optional source-receipt head, encoded as a Boolean followed by a digest when present.
3. Hypothesis text; numerical alert threshold, floor and ceiling as i128; minimum support
   count as u32; step index as u64; regime epoch as u32; accumulated lower and upper
   bounds and the active-regime lower-bound supremum as i128.
4. Last reset: tag 0 for absent, 1 for sensor health degradation with sensor/reason text,
   2 for clock discontinuity with sensor text/u64 gap, or 3 for operator reset with reason.
5. Optional numerical transcript head; u32 active supporting-component count; for each
   lexicographically sorted component, a u32 domain count and strictly sorted domain texts.

Text and digests use the existing `fss-core::CanonicalEncoder` representation. The reader
checks its complete byte bound and independent SHA-256 before interpreting the header.
Counts, text lengths, canonical ordering, unique/disjoint domain components, source indexes,
reset/step relations and numerical bounds are validated before returning an owner. Unknown
versions, invalid tags, duplicate rows, noncanonical ordering and trailing bytes refuse.

The complete envelope is at most 32 MiB. Lifetime source capacity is one through 4096.
Each admitted source permits at most 17 domain entries, including its intrinsic sensor
domain; domain text is at most 263 UTF-8 bytes. The last reset preserves the existing
in-memory API's text exactly, up to 64 KiB per string. An older in-memory state containing
larger reset text cannot be exported; its text is never silently truncated.

## What the checkpoint establishes

The checkpoint preserves continuation semantics and exact transcript ancestry. It does not
prove that a claimed history actually occurred. The independent pin detects substitution
relative to that pin; selecting an older valid pin still rolls back history. The caller must
retain and choose its latest accepted head, and provide its own authenticity and custody.

Source keys remain caller declarations. The checkpoint does not establish physical source
uniqueness, independent errors, field calibration quality, anytime-valid false-alarm rates,
current privacy/authority, continuous coverage or permission to publish events or effects.
Raw detector values discarded by an adapter before the numerical core remain that adapter's
responsibility and must be committed separately when exact raw-input continuity matters.

Historical `SequentialEProcess` constructors, numerical receipt bytes and existing report
formats remain unchanged. This API advances the restart/continuation part of `fss-x4a.16.9`;
the broader statistical and retained-source qualification work remains open.
