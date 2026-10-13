# Original-frame native activity belief replay

`fss_reference::activity_replay` connects the existing retained-belief boundary to an actual
first-party computation, rather than to a fixture deriver or receipt checksum. It independently
executes the two native JPEG decodes and the pinned scalar activity model, then requires exact
reproduction of both the complete `ExecutorModelResult` and its `ModelInvocationReceipt` JSON.

This advances the concrete-derivation portion of `fss-s1gcl` / PROV-002. It does not close that bead,
activate a production model, migrate every legacy reader, or certify the physical scene.

## Native computation replay

`replay_activity_result` takes an independently selected `ActivityExecutorModel`, an
`ActivityReplayPlan`, eight exact input byte slices, explicit byte limits, a shared native JPEG
work budget and the scalar cancellation owner. The plan names the sensor, stream generation,
original job identity, component interpretation, threshold policy and original execution budget.
Those values never come from the offered result. The original budget matters because exact receipt
identity includes it; an exhausted run cannot be retried with more resources and called the same
computation.

Both source capsules must match the expected sensor and stream, their exact original byte lengths
and digests, and one-frame roles. The reference sequence must precede the evaluated sequence.
This is declared stream ordering, not a promotion of estimated capture time to synchronized time.
Native decode records are regenerated and compared in full. The committed model then reconstructs
the scalar operator trace, output and invocation. A changed score, receipt, source, native decoder,
model generation, job or execution configuration is not accepted by a score-only fallback.

Metadata lengths and the aggregate input length are checked before canonical decoding. The native
budget is shared across BOTH frames and retains consumed work on failure. The combined packed RGB
output ceiling covers the two decoded frames held for model execution; native decoder temporary
scratch, fixed preprocessing and scalar tensor allocation retain their separate existing bounds.
`ReplayedActivityResult` has private construction and returns no pixels. It proves computation
reproduction, not current custody or permission. Failed and abstaining invocations are deliberately
outside this successful-score profile and never become verified quietness.

## Concrete retained-evidence engine

`activity_replay::belief::ActivityBeliefEngine::load_committed` selects the committed digest-pinned
first-party package, with fixed algorithm identity `alg:fss-activity-replay:v1` and generation 1.
It implements the existing `RegisteredBeliefDeriver` trait; no dynamic code or model download is
introduced. This is a static reference registration, not deployment activation.

The verifier supplies an `ActivityEvidenceSet` containing the eight named role digests and each
role's expected current authority object and exact revision. The initial profile admits only
existing generation-1 authority-plane `local_root_reachability` records. The engine requires each
role to be directly bound or reachable through verified ancestry from that exact revision. It does
not assign an ancestor's family to its leaf. Native parsing and computation establish the leaf's
role separately. Shared bytes are deduplicated in the supporting set without dropping named roles.
Missing or extra supporting roots, any contradictions, a different proposition, or a substituted
authority revision refuse before native execution. This narrow computation check has no rule for
interpreting contradictory observations; it refuses them instead of silently ignoring them.

The belief ID binds the complete ordered role selection, authority revisions, native model and
semantic invocation configuration. `offer(result, anchor)` only constructs an UNVERIFIED candidate.
It is not a verified-type constructor: serialize that candidate and call the existing graph or
durable verifier with the independently selected engine. The engine reconstructs the statement
from the reproduced computation; the claimed statement and confidence are never engine inputs.
The uncertainty interval remains [0,1], because activity score is not calibrated presence
probability. Both activity and no-activity statements explicitly disclaim presence and absence.

One engine instance admits at most one native attempt, even on failure. Decode work remains
observable through `decode_work_used()`. A retry requires an explicit new request-owned engine and
new resource admission; it does not reuse a saved verification as current proof. Native failures
map to the core trait's existing `EvidenceRequired` refusal; the standalone replay has the detailed
error classification. Outer graph and durable work keep their own counters and allowances.

## Durable use and safety boundary

The existing `verify_durable_belief` entry point accepts this engine directly with an opened
`ReferenceDeployment`'s read-only ledger and publisher, explicitly authorized slots, I/O capability,
extra deny-set, budgets and cancellation condition. The application must authorize every raw source
and metadata role under current privacy policy BEFORE calling. The library is not a CLI access
policy and does not bypass masking, identity restrictions, retention rules or read authorization.

Durable verification still checks actual current slot records, full retained closures, journal
identity/head and exact reference replay. All deletion-bearing histories remain refused by that
profile; an empty extra deny-set is not an override. Events without local publication slots remain
unsupported. Copied inputs are not a lease on original source files. Returned knowledge cells stay
cognition and never become irreversible-effect premises or absence certificates.

The new integration contracts use the existing `retain_executor_result` writer, then close and
reopen a real deployment before capture and rederivation. They exercise valid/quiet computations,
hash-consistent altered scores, resealed conclusions/confidence, omitted/reclassified roles,
substituted revisions, stale/deletion-bearing authority, denied or removed publication roots,
no hidden mutations, cancellation, no implicit retry and malformed saved beliefs.

## Focused reproduction

```sh
bash scripts/test_belief_provenance.sh /tmp/fss-belief-provenance
```

The script retains logs, pins `nightly-2026-08-31`, and uses locked offline resolution. It includes
12 new standalone replay tests and 12 concrete durable-engine contracts, plus existing activity,
provenance and publication compatibility suites. New execution results must be checked in the
native run; source presence is not passing-test evidence. This focused lane does not replace full
repository formatting/clippy, target-matrix qualification, or local DSR release authority.
