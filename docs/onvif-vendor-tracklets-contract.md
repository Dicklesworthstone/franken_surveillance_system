# Retained ONVIF vendor tracklets contract

`RetainedTracklets::open` and `fss-onvif-metadata tracks` answer a finite question over an explicitly ordered set of existing custody pins: which consecutive observations repeat the same vendor analytics module and integer ObjectId under compatible source, time and coordinate claims?

The derived association lives in the cognition plane. Original leaves retain `vendor_claimed` provenance; source custody authenticates retained bytes and attribution, not physical object identity or a camera's assertions. No detector runs, source acquisition, event creation, calibration, cross-camera identity, publication or external effect occurs.

## Exact inputs and output

Each source pin contains an owner kind (`xml` or `rtp`), a nonzero SHA-256 import identity and an exact nonzero SHA-256 publication root. One request accepts 1–32 distinct identities. XML accepts existing analytics-v2, frozen event-only v1 and native PullPoint roots. RTP accepts existing recorded packet imports and finite native RTSP metadata capture roots, including their original native observation closure. A missing expected root is an invalid request.

Source order is caller-declared context. Every new source pin starts a continuity segment. Device/profile changes, independently imported files and separate captures cannot manufacture one continuous track. Scope hashes bind site, sensor, device generation, profile generation/token and frozen parser generation; RTP scopes additionally bind replay generation, the complete 128-bit ingress, stream epoch, SSRC and payload type.

The closed JSON schema is [`onvif_vendor_tracklets_report.v1.json`](../schemas/onvif_vendor_tracklets_report.v1.json). `sources` preserves every selected pin and its processing counts, including rejected and zero-analytics documents. `frames` preserves exact source, document and frame locations, module/transform digests, all applicable barriers and occurrence ranges. `occurrences` preserves each original object position and its advisory group. `tracklets` lists occurrence indices in original order and explicit start/end reasons. These indices are report-local navigation, not physical identity.

The source receipt's `source_digest` names the complete original XML or complete RTP replay file. A frame's `source_digest` always names its exact original or reconstructed XML document. Native RTP's `native_source_digest` separately names original SDP, control and nanosecond packet observations; the replay-file digest does not replace it. Source/publication anchors and the current query anchor remain separate. Frame/object transformations and original classes/shapes remain hydratable at the exact original handles.

Both raw-field containers are `null` unless `vendor_values_included=true`. Explicit `--include-values yes` reveals original module, ObjectId and vendor UTC spellings. Nanosecond vendor-time interpretation is emitted as decimal text to retain full integer precision. Hashes and grouping are identical for private and disclosed views; disclosure never changes the source or policy. Private raw fields are also excluded from library `Debug` output.

## Grouping and barriers

A run requires a known, nonempty module, equal normalized XML integer ObjectId, strictly increasing vendor UTC, a positive gap within the selected maximum (default 5 seconds, maximum 60), and unchanged frame/object transformation claims. `+001` and `1` share a vendor key while both lexical values remain preserved. Equal timestamps, backwards timestamps and excessive gaps split runs. No timestamp sorting repairs original order. Different named modules may interleave independently; absence from the next frame of the same module ends the earlier run.

Unknown outer sections and unhandled event/lifecycle claims are global barriers. A missing module is also a global barrier; unknown modules are never coalesced into one implicit camera-wide module. Unsupported content inside a typed analytics frame isolates that module's frame. The implementation does not interpret ObjectTree deletion/merge semantics, biometric fields or unknown vendor extensions.

Within a clean retained RTP source, two document occurrences may continue only if their indices are adjacent and the prior document's final fragment agrees with the next document's preceding boundary on extended sequence, original record and exact source span. Empty analytics documents, rejected XML and opaque source-level content interrupt continuity even if the next document repeats an ObjectId. Any replay issue, unprocessed suffix or incomplete native acquisition disables cross-document linkage throughout that source. It does not discard supported frames inside a complete document.

End-of-input terminates every returned run without inventing an object departure or unseen final-frame duration. An empty report, empty frame, incomplete source or missing observation is never an absence or coverage certificate.

## Custody, cancellation and current authority

The owner opens a complete existing deployment with pending-effect reconciliation disabled. It never returns that mutable deployment. Standard opening still takes the publisher lock and can perform normal recovery/housekeeping; the API does not promise a forensic no-write mount. Missing/incomplete deployment history cannot trigger initialization.

The existing XML/RTP readers verify immutable recipe generations, exact roots and manifests, original bytes, derived projection/report bytes, packet provenance, publication ledger records and the durable deletion closure. The owner reconstructs every source and the full grouping twice, compares the ordered source receipts and deterministic report, admits completion, then verifies the durable authority head and current store before returning. A refusal returns no successful prefix. The CLI renders inside the original native request owner, which checks deadline/cancellation and drains before releasing complete stdout.

Current source custody must be checked again for any later operation; this snapshot grants no durable access or effect permission. Existing source recipe, parser, projection and RTP replay encodings remain unchanged. The new tracklet generation is `gen:fss1:onvif-vendor-tracklets-v1`.

## Cost and allocation boundaries

One nonrefillable spool allowance covers all indexed source/projection/provenance/deletion-plan reads across both passes. Reservations precede access, include declared stored-envelope bytes plus header and trailing probe, and never refund admitted failures. The default is 64 MiB and 8192 attempts; hard maxima are 1 GiB and 65,536. Opening recovery and filesystem metadata/open/directory operations are outside those counters and retain the existing deployment capacity limits: 64 MiB per object, 512 MiB retained spool, 65,536 objects and 128 roots under the standard deployment contract.

One outer work balance defaults to 8,388,608 units and cannot exceed 67,108,864. Before each source read, it reserves conservative full history passes covering deletion candidate/proof scans and publication lookup. RTP additionally reserves its bounded record/document traversal. Aggregate frame/object counts are checked after each source and before reading the next. Building source/frame handles also consumes work. Each of the two pure projections reserves its full selected `max_projection_work_units` from this same balance before running; the default per projection is 2,000,000 and hard maximum is 16,777,216. These conservative reservations are distinct from the pure report's exact deterministic work count and from CPU elapsed time.

Deletion-plan decoding/sorting remains constrained by its existing canonical format limits and the aggregate indexed byte allowance. XML parsing, original packet replay and native-source decoding retain their existing byte/count bounds. The new RTP frame projection hashes each XML/projection buffer once per document, then hashes small source-bound frame descriptors.

The complete source set admits at most 1024 frames, 4096 object occurrences and 4096 runs. The pure canonical report is at most 4 MiB; the complete CLI JSON is at most 16 MiB. JSON writes reserve capacity before append and fail without releasing a valid prefix. The native CLI deadline defaults to 30 seconds and permits at most 60 seconds; no retry or second pass renews it.

Finite synthetic fixtures cover the grouping and source-custody contracts. They are not physical-camera interoperability or ONVIF Profile M qualification. Broader FSS-046 metadata lifecycle and FSS-077 scene/event work remain open.
