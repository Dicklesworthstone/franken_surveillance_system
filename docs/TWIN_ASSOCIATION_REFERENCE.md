# Source-driven multi-target association

`fss_twin::association::gate_contact_batch` connects existing active `ContactTrack`
snapshots to unassigned contact proposals from one camera exposure. This implements
the candidate-generation portion of FSS-099 / BTI-008 without assuming that an
upstream detector already knows which old track each new detection belongs to.

The function projects each incoming contact onto the imported property once, then
propagates every retained source-motion mode to the incoming capture interval.
Each track/detection pair retains all overlapping bounded support interpretations.
A pair may also have several orthogonal unresolved reasons: missing motion, unordered
capture, excessive gap, missing contact/support, unknown bounds or nominal occlusion
conflict. One reason cannot erase another. Unknown alternatives are not represented
as a zero-probability association or removed by nominal nearest-neighbor distance.

The source-pair propagation includes acceleration during the measured pair and the
forecast, reusing the existing average-velocity versus endpoint-velocity correction.
All lengths and acceleration assumptions remain in source-world units. No person,
bear, appearance, facial identity, hostile-intent or metric-scale prior is inferred.

The output is a complete Cartesian table, not a selected identity matching. A false
`possible()` means excluded only within the declared finite support search, same-
topology geometry error and motion assumptions. Missing real-world surfaces, incorrect
calibration bounds, target acceleration outside the supplied model or incomplete
input tracks are not ruled out by that result. An empty proposal batch is not observed
absence. No `CoverageWitness`, new canonical fact, alert or track mutation is issued.

## Input and source binding

One `AssociationFrame` names an exact camera snapshot, source-frame evidence,
exposure and capture interval. `UnassignedContact` has a detection-local ID and an
independent contact-record identity, but no assigned persistent track. The existing
contact projector internally needs a local label; that scratch label is not exposed
as a tracking assignment through the resulting `DetectionProjection` interface.

Every source snapshot must be active, bind the exact imported twin, share the capture
clock, and contain the identical admitted target camera. Duplicate track handles,
duplicate detection IDs/record hashes, reused source records and already-consumed
camera exposures are rejected. A malformed suffix cannot follow a published success.
Canonical ordering is by anonymous track ID and incoming detection ID.

The graph retains source receipts and actual source observations, incoming proposals,
projection alternatives, original camera/frame, all numeric policy, and overlap
witnesses. `check_current` rechecks the twin, admitted camera and active source
receipts before later consumption. Epoch uniqueness, canonical source custody,
authorization and privacy projection remain the owner's responsibilities. A checksum,
receipt or candidate overlap does not authenticate or adjudicate an association.

Limits are 32 source tracks, 32 detections, and at most 4096 retained overlap witnesses
per batch. Caller limits may narrow the witness ceiling. Overflow, allocation failure,
cancellation or exhausted work rejects the complete operation rather than dropping
the last processed target. All work is synchronous and in-memory; Asupersync may own
it but no competing runtime, file I/O, model service or new dependency is introduced.

## Tests and current boundary

```sh
cargo test --locked --offline -p fss-twin --test association_contract
python3 -B scripts/test_association_reference.py
```

Eleven Rust contracts exercise actual source-to-motion-to-association composition:
separated and crossing targets, unknown map errors, hidden contact, missing motion,
old/unordered capture, acceleration expansion, empty sets, replay conflicts,
malformed suffixes, stale source/camera generations, cancellation and witness limits.
The seven independent Python reference controls passed during authoring, including
10,000 shared-error/acceleration realizations. They check arithmetic and candidate
semantics, not execution of the Rust module. Rust compilation and native test
execution remain NOT_RUN because the authoring environment has no Rust compiler;
outbound DNS also failed. No field qualification or broad bead completion is claimed.

This increment deliberately does not select a one-to-one assignment, allocate new
persistent track identities, establish cross-camera identity, resolve merged detector
blobs, extract contacts from video or activate effects. Subsequent association logic
must retain unmatched and alternative assignments instead of choosing the nearest
person or treating a predicted handoff as its own confirmation.
