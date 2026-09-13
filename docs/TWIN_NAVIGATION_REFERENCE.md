# Imported support topology and route extraction

Reference implementation for BTI-001/006 and FSS-099, not closure of those tasks.

`SupportNetwork::compile` derives a bounded graph from the evaluated triangles in
an actual `PropertyTwin`. Only explicitly declared support faces participate.
Complete shared edges connect across distinct object/vertex identities when their
coordinates are exactly equal. Nearby edges, point contacts, T-junctions and
vertically separated decks do not connect. Duplicated faces and edges incident to
more than two support faces fail rather than silently inventing a portal.

`route_to_feature` starts at a revision-bound barycentric contact and finds a
minimum-cost corridor to an admitted support face of a nominated semantic feature.
A caller supplies destinations, not waypoint paths. The polyline runs through
triangle centroids and shared-edge midpoints; each segment stays in its selected
convex support face. It cannot shortcut a hole by drawing a straight line between
non-adjacent centroids. A destination already containing the start retains that
position rather than moving it to the triangle center.

This is a shortest path in the discrete graph, not a globally optimal continuous
geodesic or all possible paths. Explicit alternatives and the existing propagated
reachable bounds must remain available to security policy. A route cannot establish
identity, physical intent, observed movement, or a witnessed absence.

## Movement assumptions

`NavigationProfile` requires explicit class, slope-cosine threshold, shared-edge
width floor and pedestrian cost divisor. A person may receive a soft preference
for declared pedestrian surfaces. Bear, other-animal and unknown profiles reject
a pedestrian divisor other than one. Grass is not forbidden by a path preference.
`without_preference` supplies a geometry-only counterfactual with the same slope
and width assumptions. Travel time uses geometric polyline length, never weighted
route cost. All lengths remain in imported source units; relative scale stays relative.

`NoModeledConnection`, `NoAdmissibleDestination`, and `StartExcludedByProfile`
are distinct outcomes. They describe this exact topology and supplied assumptions,
not physical impossibility. Disconnected stair treads, unmodeled ramps, gaps in
reconstruction, and absent door-state information require additional evidence.

Support topology is not a swept-body collision certificate. Edge width alone
cannot prove usable clearance inside every triangle or overhead. The importer’s
support and optical-opaque roles are intentionally separate: opaque geometry is
not silently treated as a movement barrier. In particular, a coarse ground plane
extending beneath a building is not a certified walkable free-space mesh. Movement
barriers, door states, body clearance and uncertainty-aware free-space compilation
remain requirements before physical traversability claims.

## Identity, resources and evidence

Every query checks both owner-resolved property/revision and exact package hash.
Returned routes retain both, original triangle ordinals, selected profile,
weighted cost and actual length. A changed remesh cannot reuse old triangle IDs.
The caller must capability-project the twin before compilation; this numerical
kernel does not perform authentication or establish new authority.

The reference ceiling is 65,536 source triangles and 256 output points. A bounded
binary heap implements Dijkstra with deterministic cost/node tie order. Compilation
uses ordered exact-coordinate edge/face tables. Compile/search/reconstruction poll
and charge the existing `WorkBudget`; over-budget or over-size work rejects the
whole operation. No top-k pruning or partial route is mislabeled complete.

## Verification boundary

`navigation_contract` loads real checksummed `FSSTWIN1` bytes before exercising
corridors, per-object vertex duplication, holes, separate layers, point contacts,
duplicate/non-manifold support, winding, class priors, slope/width exclusions,
stale basis/hash, size limits and cancellation. The hole test samples each returned
segment rather than trusting its waypoint labels.

```sh
cargo test --locked --offline -p fss-twin --test navigation_contract
```

The Rust tests have been authored but not executed in this authoring environment,
which has no Rust compiler. Independent Python graph/arithmetic experiments are
not execution of this Rust implementation. Real-property route validity, complete
free-space/body geometry, and GATE-070/080/115 qualification remain outstanding.
