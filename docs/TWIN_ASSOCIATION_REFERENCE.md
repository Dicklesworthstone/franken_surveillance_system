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

## Coupled assignment hypotheses

`fss_twin::association_hypotheses::factorize_associations` now consumes the actual
candidate graph. The caller supplies a nonzero record for the conditional assumption
of at most one detection per target in this single exposure. The module does not
assert that arbitrary raw detector outputs, merged blobs or duplicate proposals
satisfy that assumption. Unsupported many-to-one phenomena remain outside it.

Every connected component retains ALL partial one-to-one matchings. Both source
tracks and detections may remain unmatched. For two crossing targets with two
compatible detections this means seven assignments: the two complete permutations,
four single-link assignments, and all unmatched. Keeping only maximum-cardinality
or nearest-neighbor assignments would erase legitimate miss/clutter alternatives.
No probability, rank, personal identity or threat label is assigned to these options.

Disconnected components are stored as separate factors, with their Cartesian
product defining the joint matching family. This is a combinatorial factorization,
not a claim of statistically independent map errors, evidence or identity beliefs.
Thirty-two independent candidate pairs retain 2^32 possible assignments using only
64 component assignments, rather than materializing billions of joint rows.

When a connected component exceeds its explicit-list ceiling (at most 1024) or the
complete result exceeds its materialization allowance (at most 4096), its entire
family is retained implicitly: every partial one-to-one matching over the stored
complete component edge set, including unmatched inputs. The attempted enumeration
prefix is discarded. `joint_count` becomes unknown, not zero, when a factor is not
enumerated or the exact product would overflow. The original graph, unresolved
conditions and source receipts remain attached. This representation fallback does
not convert actual work exhaustion or cancellation into success; those still error.

`check_assignment` accepts an explicitly proposed global matching and verifies its
membership even for implicit factors. It rejects repeated source tracks, repeated
detections, absent IDs and excluded edges. The resulting selection borrows the same
source graph. Its `observations` method prepares the original contact records with
the explicitly chosen anonymous track labels, without ingesting or changing any
track. The owner must retain/admit association evidence, revalidate `check_current`,
and perform witnessed updates separately. Matching membership never certifies
physical identity. The module does not overwrite history or activate effects.

```rust
let graph = gate_contact_batch(&twin, frame, &snapshots, &detections, gate_policy, &mut budget)?;
let hypotheses = factorize_associations(&graph, assignment_policy, &mut budget)?;
// proposed_links are an explicit external proposal, not the enumerator's first row.
let selection = hypotheses.check_assignment(&proposed_links, &mut budget)?;
selection.graph().check_current(&twin, current_camera, &current_snapshots, &mut budget)?;
let prepared_observations = selection.observations(&mut budget)?;
```

The API is synchronous derived cognition. It does not introduce an Asupersync
adapter, canonical durable matching format, detector, native video decoder, automatic
birth/death policy or multi-track atomic authority transaction. Existing owner
capability, privacy, source custody and publication boundaries remain unchanged.

## Assignment verification

```sh
cargo test --locked --offline -p fss-twin association_hypotheses
cargo test --locked --offline -p fss-twin --test association_hypotheses_contract
python3 -B scripts/test_association_hypotheses_reference.py
```

Five additional Rust unit contracts test every 3x3 candidate graph against an
independent edge-subset oracle, exact enumeration ceilings, 32-way factorization,
isolated unmatched nodes and actual work exhaustion. Six additional integration
contracts exercise source-motion graphs, crossing and separated targets, complete
implicit families, explicit selected-observation preparation, current-source
revalidation, one-to-one violations and cancellation. Together with the first
increment there are 22 newly authored Rust tests; none was executed here.

The six Python combinatorial reference controls passed, including all 512 3x3
bipartite graphs, exact product reconstruction, the seven-way crossing, monotonic
unknown-edge restoration, and the 2^32 factorized case. The seven prior arithmetic
controls also passed again. Delimiter and uploaded-byte checks do not substitute
for Rust compilation or testing. Native execution, recorded-video accuracy and
full FSS-099/BTI-008 qualification remain outstanding.
