# Immutable native ONVIF analysis

The native `fss-onvif-metadata tracks`, `lifecycle` and `zones` commands use
`onvif::metadata::native_read::NativeOnvifRead`. They can inspect existing
retained metadata while a capture operation retains the exclusive publication
owner. They never open a publisher, acquire its writer lock, recover a journal,
initialize missing state, acquire camera data, publish derived roots or reconcile
external effects.

This completes a practical native read path already available in a narrower
canonical query projection. The native commands retain their complete result
sets, original source handles and explicit vendor-value disclosure. They do not
inherit the canonical query's 32-row synopsis ceiling.

## What is verified

The immutable owner validates the exact root, site, ordered XML/RTP source pins
and all limits before source access. Existing metadata-only native inspectors
replay deployment history and committed deletion proofs. An absent effect journal
or any uncommitted authority/effect journal tail is a complete refusal. The owner
does not repair or replace that history.

The same `read_view` reconstruction used by canonical ONVIF queries then opens
each exact flat publication closure. It verifies original XML or RTP/native
source evidence, recipes, frozen parser generations, manifests, direct children,
local deletion markers, publication records and committed deletion restrictions.
Every selected source, including empty and rejected sources, participates in
both complete reconstruction and projection passes. Full source receipts, native
reports and reference sets must agree. A later failure never releases an earlier
partial result.

After the last native admission checkpoint, bounded native metadata reconstruction
repeats under the original metadata allowance. Layout, authority head and roots,
effect history and deletion restrictions must still match; selected references
must remain undeleted. No caller callback follows this final authority observation.
Only pure result assembly and bounded rendering remain.

These are repeated observations, not an atomic filesystem snapshot or read lease.
A later operation must verify current custody again. Source custody authenticates
retained bytes and attribution; vendor observations remain vendor claims.

## Native Rust entry point

```rust
use fss_reference::onvif::metadata::native_read::{
    NativeOnvifRead, NativeOnvifReadLimits, OnvifAnalysis,
};

let result = NativeOnvifRead::open(
    root,
    site,
    &pins,
    &OnvifAnalysis::Tracks,
    NativeOnvifReadLimits::default(),
    &read_cx,
)?;
let complete_tracks = &result.native.tracks;
```

Select `OnvifAnalysis::Lifecycle` or `OnvifAnalysis::Zones(policy)` for additive
interpretations. `result.native.analysis` contains the complete typed report;
the original tracklet report and all source receipts remain available separately.
`open_with_io` accepts a source I/O capability for deterministic fault tests.

The explicit `ReplayCx` must name the exact deployment root. Its borrowed native
admission may be non-`Sync`, matching the synchronous `TaskCx` owner. Opening,
manifest/child reads, complete-root rereads and pure replay/projection work have
cooperative admission checkpoints. Individual filesystem syscalls are bounded
parts of an admitted read and are not preempted. Final metadata reconstruction is
one bounded finalization admitted at the last checkpoint. Native CLI delivery
checks the original cancellation/deadline again after rendering and drains before
returning successful stdout.

## Resource accounting

There are two independent nonrenewing read balances. Both must be explicitly
admitted; neither can borrow unused allowance from the other.

| Balance | Native CLI default | Native CLI maximum | Meaning |
|---|---:|---:|---|
| Source bytes | 64 MiB | 1 GiB | All selected flat-closure reads and revalidation |
| Source filesystem calls | 8192 | 65,536 | Includes metadata/open/read calls and absent-marker probes |
| Deployment metadata bytes | 128 MiB | 256 MiB | Opening and final metadata payloads, including deletion proofs |
| Deployment metadata attempts | 16,384 | 65,536 | Attempted payload reads; excludes stat/open syscalls |
| Tracklet shared work | 8,388,608 | 67,108,864 | Conservative source replay, projection and comparison reservations |
| Lifecycle/zones shared work | 33,554,432 | 67,108,864 | Includes both original grouping and selected additive interpretation |

Use `--max-read-bytes` and `--max-read-attempts` for the source balance.
In v2, `--max-read-attempts` explicitly counts all source filesystem calls, so a
previous indexed-read limit may need a deliberate increase for the same source.
Use `--max-deployment-read-bytes` and `--max-deployment-read-attempts` for the
separate metadata balance. A one-unit-short allowance refuses the complete read;
passes do not silently renew a budget.

The native Rust `OnvifReadLimits` source defaults remain 256 MiB and 131,072 calls,
with a hard maximum of 1,000,000 calls. `NativeOnvifReadLimits::from_tracks` carries
explicit tracklet ceilings into the new source accounting. CLI settings are
narrower defaults, not hidden extra authority.

Per-source closure shape, per-object size, native metadata snapshot and pure
projector ceilings remain explicit in the report. Work units are conservative
deterministic reservations, not CPU time or resident memory. Metadata payload
counts are not represented as filesystem-call counts. The native request byte
reservation includes both declared read balances; zones additionally reserves
65,537 policy-file bytes including its trailing probe.

## Versioned native JSON

The commands now emit:

- `fss.onvif_vendor_tracklets_report.v2`
- `fss.onvif_vendor_lifecycle_report.v2`
- `fss.onvif_vendor_zones_report.v2`

All original source receipts, frame/object/tracklet handles, row order, pure
projection digests, parser generations and disclosure rules remain unchanged.
Lifecycle and zones embed the complete v2 tracks envelope. Raw vendor module,
integer ObjectId and UTC values remain null unless `--include-values yes`;
UUIDs remain withheld. Operator zone policy remains visible as before.

The new custody snapshot uses `fss.onvif_native_immutable_read.v1`, binding the
complete source decision plus current authority, layout, ledger/effect roots,
metadata limits and actual metadata usage. Its digest deliberately differs from
a legacy mutable-owner snapshot. The top-level `read_owner`,
`source_request_digest` and `source_decision_digest` make that basis explicit.

The v2 `usage` object labels source bytes/calls separately from deployment payload
bytes/attempts. `publisher_opened` and `recovery_performed` are always false.
Legacy v1 schemas and `RetainedTracklets::open`, `RetainedLifecycle::open` and
`RetainedZones::open` retain their original types and exclusive-owner semantics.
No retained source format or original projection identity is migrated.

## Failure and qualification scope

Missing/torn history, wrong root/site, deleted or corrupt source custody, changed
authority/effects/deletion restrictions, invalid limits, exhausted allowance or
native admission refusal returns no successful JSON prefix. Retry requires a
fresh complete read with valid explicit authority. A read failure does not grant
repair permission or establish an empty source set.

The focused reference tests cover complete XML/RTP/empty-source parity across all
three interpretations with a writer held, more than 32 native frames, independent
resource exhaustion, missing/torn journals left untouched, final authority/effect
mutation, initial/final cancellation and a borrowed non-`Sync` native guard during
source I/O. Native process tests exercise command routing and the versioned
accounting/disclosure contract.

The implementation and tests were independently source-reviewed in the
2026-11-22 session. The execution environment disconnected before these changes
could be compiled or run. No executed-test, host qualification, live camera,
Profile M conformance or broader FSS-046 completion claim follows from this work.

When execution is available, run the existing pinned/offline owners:

```sh
cargo test --locked --offline -j1 -p fss-reference --test onvif_metadata_tracks_custody
cargo test --locked --offline -j1 -p fss-reference --test agent_onvif_contract
cargo test --locked --offline -j1 -p fss-cli --bin fss-onvif-metadata
cargo test --locked --offline -j1 -p fss-cli --test onvif_metadata_tracks_cli
cargo test --locked --offline -j1 -p fss-cli --test onvif_metadata_zones_cli
```

These focused commands do not replace `scripts/qualify.sh` or the applicable
native qualification gates.
