# Acquisition continuity after a degraded window

Status: deterministic reference contract, not production or live-camera qualification.
Owning defect: `fss-jsiq8`; RTP consumers: `fss-2h5zq.29` and `fss-2h5zq.30`.

## Behavior

An acquisition can verify a clean sequence window after one or more explicitly recorded degraded
windows in the same stream generation. The damaged windows remain damaged. Recovery does not
fill missing packets, restore an earlier coverage witness, or imply an absence of activity.

Previously, `verify_continuity` required the new start to follow the last **verified** end. A
degraded interval consumed positions but carried no typed sequence bounds, so every subsequent
clean interval was refused. The new contract accounts for the unavailable interval explicitly.

For example, a verified window `100..109`, a degraded window `110..119`, and another degraded
window `120..129` allow verification of a clean window beginning at `130`. A start of `109`,
`119`, `129` or `131` is refused. The two degraded windows never become verified.

## Additive evidence and compatibility

`fss_core::WindowedDegradationEvidence` uses the new domain
`fss.acquisition.windowed_degradation.v1`. Its canonical field order is:

1. The new schema tag.
2. The digest of the complete `AcquisitionRequest`.
3. The digest of the immediately preceding first-frame, continuity, or windowed-degradation
   witness.
4. The inclusive start and end sequence positions.
5. The existing canonical `DegradationEvidence`, including its own v1 tag, lost dimensions and
   invalidated negative claims.

The existing request, first-frame, continuity, degradation and transition encodings and domains
are unchanged. The new wrapper does not reinterpret an old degradation record as sequence
evidence. The public in-memory `AcquisitionState::Degraded` variant has an additional optional
`last_windowed_degradation` field; exhaustive Rust constructors must supply that field.

The sequence range must be ordered, nonempty and representable as a `u64` inclusive count. Loss
cannot exceed its span. Bounds and the existing bounded degradation fields are checked during
canonical decoding. Binding to the actual request and current predecessor is checked at session
admission. Decoding alone does not authorize a transition.

## Session admission and recovery

Adapters obtain `continuity_predecessor_digest()`, construct the wrapper, and call
`degrade_window(evidence, now_ns)`. All fallible checks run before session mutation:

- The full request digest binds generation, source configuration and authority, in addition to
  the original source/device/adapter identity checks.
- The predecessor must match the session's current accepted witness.
- The degraded span must start immediately after that witness's end. The first window retains
  the existing convention that it may start at the first frame's sequence or the next position.
- Arithmetic never saturates or wraps at the end of the sequence space.

The transition history records the wrapper digest. The degraded state retains the wrapper and
the last verified continuity witness separately. Another degraded span chains to the wrapper;
a clean span must follow its end and must still pass every original continuity check. A new
window does not relax loss, reconstruction, jitter, completeness or first-frame requirements.

The current state retains one wrapper. Callers retaining a replayable session must also retain
the earlier wrapper objects referenced by transition digests; a digest alone cannot reconstruct
an unavailable interval. The added work per transition is bounded by the existing degradation
field limits, independent of the number of earlier windows. Existing transition history and
adapter report retention remain the callers' resource responsibility.

### Unscoped and indeterminate states

Legacy `degrade(DegradationEvidence, ...)` remains available for faults whose sequence bounds
cannot be established, including faults before first-frame custody. It does not invent a cursor.
After a windowed gap, a subsequent unscoped degradation cannot erase the gap and fall back to the
old verified end: recovery then needs an exact known-state reconciliation or a valid reconnect.

An indeterminate state retains its prior state. Direct continuity verification from that state
uses the same preceding-window checks. `reconcile` binds the entire original request and checks
a proposed clean or degraded state by rebuilding the allowed transition from the stored prior
state. Substituted authentication, acknowledgement, first-frame custody, request generations,
or nonadjacent windows are refused. Reinstating the exact stored prior state remains valid.

Reconnection clears the gap marker only after the new request is validated and its stream
generation is strictly newer. A refused reconnect leaves state, history and the marker intact.

## Absence remains scoped

The original `check_absence_claim_allowed()` returns an interval-free `CoverageWitness`. After
any windowed degradation it therefore remains refused for that generation, including after
successful recovery and later clean windows.

`check_absence_claim_allowed_in_window(generation, start_seq, end_seq, start_pts_ns, end_pts_ns)`
can return the **current `ContinuityWitness`**, with its scope intact, only when:

- The generation matches the current acquisition request.
- The session is currently continuity-verified.
- Both ordered query intervals lie wholly inside the current verified witness.
- The underlying coverage witness itself certifies absence.

The scope is conjunctive: the named generation **and** sequence interval **and** presentation-time
interval. It does not certify a time-only interval, establish clock continuity across a gap, or
prove an interior sequence-to-time mapping. A later sequence window with overlapping timestamps
cannot certify the earlier sequence window. Source time and physical observability still need
their own evidence.

Recorded RTP continues to use `CoverageStopReason::Unsupported` for its estimated recorder-clock
coverage, so even a recovered recorded window does not certify absence. This core API does not
upgrade recorded-file evidence into live coverage or detector accuracy.

## Verification and continuation

The independent core regression suite is
`crates/fss-core/tests/acquisition_recovery_contract.rs`; existing lifecycle contracts remain in
`crates/fss-core/tests/acquisition_lifecycle_contract.rs`. The RTP integration and generated-file
scenarios are in `crates/fss-reference/tests/rtp_continuity_contract.rs`, with the structured runner
`scripts/e2e/cap_ingest_rtp_continuity.sh`.

Native validation on `nightly-2026-08-31` passed all 1,230 `fss-core --all-targets` tests,
including the 15 new independent recovery cases, and all 22 core doctests. Core all-target
Clippy passed with `-D warnings`. The run used locked offline resolution, two build jobs,
disabled incremental compilation and debug symbols, and a temporary target directory to fit
the available filesystem. These are reference results, not a controlled DSR release receipt.

Implementation handoff:

| Field | Value |
| --- | --- |
| Mission | Restore honest same-generation acquisition recovery after accounted sequence gaps. |
| Authority | User-authorized changes to this repository's main branch; deterministic local reference inputs only. |
| Owning contract | `fss-jsiq8`, acquisition authority plane, additive windowed-degradation v1. |
| Durable evidence | Versioned wrapper, request and predecessor digests, original degradation, transition history; consumers retain referenced objects. |
| Invalidators | Changed request or predecessor, missing span, sequence overlap/skip/overflow, invalid continuity, unresolved unscoped degradation. |
| Unknowns | Live-device recovery, physical time accuracy, detector quality and site-wide observability are unqualified. |
| Next valid work | Integrate and inspect retained RTP recovery through a read-only operator command, retain the structured RTP results, and run repository qualification without relaxing its gates. |
| Separate open work | Within-tolerance RTP reordering still depends on the packet/depacketizer contract; event-threat fusion requires hypothesis-specific calibration before integration. |

The repository's `scripts/qualify.sh` and retained receipts determine qualification status.
Passing these focused contracts alone does not confer release qualification.
