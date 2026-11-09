# Read-only ONVIF analysis for canonical agent queries

The native `agent_onvif::query_onvif_in_deployment` API turns exact retained
ONVIF XML/RTP sources into a complete bounded, redacted semantic synopsis.
It supports the existing tracks, additive lifecycle and raw-coordinate zone
interpretations without opening the writable publisher. The frozen source
reconstruction, frame mapping and cognitive projectors are shared with the
standalone metadata commands.

This advances FSS-046 and the canonical AOP-005 query integration requirements.
It does not establish device/Profile M conformance, physical identity, trusted
capture time, calibrated occupancy or release qualification. The broader beads
remain open.

## Native API

```rust,ignore
use fss_core::PrincipalId;
use fss_object::HostSpoolIo;
use fss_reference::agent_onvif::{
    OnvifAnalysis, OnvifQueryLimits, OnvifQueryRequest,
    query_onvif_in_deployment,
};
use fss_reference::onvif::metadata::tracks::TrackSourcePin;

let request = OnvifQueryRequest {
    sources: vec![TrackSourcePin::Xml {
        identity: existing_import_identity,
        root: existing_publication_root,
    }],
    analysis: OnvifAnalysis::Lifecycle,
    max_entries: 32,
    principal: PrincipalId::parse("principal:operator")?,
    expected_anchor: None,
};
let query = query_onvif_in_deployment(
    &HostSpoolIo,
    absolute_existing_deployment_root,
    &request,
    OnvifQueryLimits::default(),
    &|| request_cancelled(),
)?;
let redacted_statements = query.epistemic(&request);
```

Use `TrackSourcePin::Rtp` for a retained RTP file or native finite RTP capture.
Use `OnvifAnalysis::Tracks` for grouping or `OnvifAnalysis::Zones(policy)` with
an explicit validated `ZonePolicy`. The [zone guide](onvif-vendor-zones.md)
explains how to obtain all four coordinate-domain pins. No source, module,
transform, parser generation or zone basis is inferred.

The principal is an audit label. The operator supplies the existing deployment
root and I/O capability; neither a principal string nor a result grants access,
source hydration, acquisition or effect authority. The selected source objects
come from that deployment's own verified layout. There is no separate caller
archive path in this query.

## Source ownership and verification

The operation reads current deployment history with the existing metadata-only
reader, including committed deletion proofs and effect history. It then uses one
real `PinnedClosureReader` for all exact source roots. Every selected manifest,
recipe, original source, retained projection, RTP document and native provenance
child is verified under its original frozen interpretation. The original
`local_root_reachability` batch, its exact child closure and declared receive
interval must agree.

Import-level, unit-level and object-level committed deletions are checked even
when the selected source contributes no analytic rows. Local tombstones, pending
root/deletion markers, missing objects, wrong roots, changed sites, corrupted
payloads and unverifiable source witnesses refuse the whole operation.

Each flat closure is rehashed before completion. The complete source reconstruction
and projection are performed again using the same reader and work balance. All
source receipts, original tracks, selected analysis and reference digests must
agree. A final deployment observation must match the original authority/effect
prefix, layout and deletion state. These are repeated bounded observations; they
do not create an atomic filesystem snapshot or a lease on future availability.

No publisher recovery, writer lock, source namespace enumeration, directory
creation, source repair, derived publication or effect reconciliation is used.
The query can run while a genuine deployment writer is open. The standalone
`fss-onvif-metadata tracks|lifecycle|zones` commands retain their original
publisher-opening contract and output identities.

## Complete semantic rows

The native API admits at most 32 semantic data rows. It computes the complete
selected result and refuses if that result exceeds `max_entries`; it never drops
unfavorable, unknown, empty-source or conflicting evidence to fit the response.

| Analysis | Rows charged to `max_entries` |
|---|---|
| All modes | Every source receipt, frame, object occurrence and original tracklet |
| Lifecycle | Additionally every document disposition, operation, endpoint, endpoint support reference, Behaviour observation and deletion/reuse conflict |
| Zones | Additionally every declared zone, occurrence/zone cell, frame/zone sample and observed transition |

Lifecycle frame barriers are included with the corresponding original frame.
Fixed scope, privacy and physical-uncertainty statements are additional protected
context. Thus a source with no analytic frames still consumes a source row;
frozen-v1, SOAP, rejected, empty and zero-document lifecycle inputs remain explicit.

The result retains exact source/frame/occurrence/tracklet handles. Original
ObjectId spellings, module labels, timestamps, UUID values, appearance values and
raw vendor coordinates are withheld by the semantic projection. Operator zone
IDs and declared coordinates remain visible. Unknown coordinate bases never
become outside/absence; boundary uncertainty and interrupted observations remain
visible. Known vendor declarations are not asserted to be known physical facts.

Recomputed analysis digests are proof pointers, not newly retained publications.
The source publication roots are existing verified metadata handles. The query
does not grant a higher hydration level or claim that original source bytes were
delivered to the agent.

## Limits and cancellation

Default source limits are 32 pins, 64 completed root observations across both
passes, 16,384 object admissions, 65,536 edges, 8 MiB per object, 256 MiB aggregate
source reads, 131,072 source filesystem calls and 32 Mi logical work units.
The frozen projector limits remain independent and explicit. Comparisons and
final commitments are charged before result release.

Both deployment observations share a separate 256 MiB/65,536 payload-read budget.
Deployment counters measure returned metadata payloads; source counters include
envelope framing and all metered filesystem calls. The source reader includes
initial reads and closure rehashes in both passes; it never resets between roots.
These counters are not CPU-time measurements, and deployment metadata/stat/open
calls are not represented as source filesystem calls.

Cancellation is checked between bounded phases and at source I/O boundaries.
The last checkpoint admits finalization: the existing synchronous metadata reader
reconstructs the final deployment prefix, followed only by pure comparison and
assembly. No caller callback then runs and invalidates the verified authority.
This final bounded phase is not interruptible. Direct library callers requiring
delivery suppression for a cancellation/deadline arriving during finalization
must apply their own delivery gate. A transport must also check its deadline after
rendering the complete response.

## Compatibility and validation

Frozen event-v1 and analytics-v2 recipes, retained projections, RTP source mapping,
original tracklet identities, lifecycle generations and zone generations are
unchanged. Shared reconstruction retains the old owners' original read/callback
ordering. The new read-only request/decision has separate digest domains because
its custody observations, budgets and output contract differ.

Focused genuine source and public API fixtures cover parity with existing owners,
writer-lock coexistence, pending-effect preservation, full-tree no-write behavior,
source deletion/tampering, cumulative bounds, complete-row refusal, final-admission
cancellation and callback-induced authority changes. See the current
[typed session handoff](SESSION_HANDOFF_2026-11-09_ONVIF_AGENT_QUERY.json) for exact
executed results and limitations. Developer memory settings, where used, are not
the release lane; `scripts/qualify.sh` remains the release authority.
