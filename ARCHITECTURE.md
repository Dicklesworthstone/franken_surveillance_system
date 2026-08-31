# Architecture reference

This is the compact operational reference. The comprehensive plan owns the full normative detail.

## 1. System boundary

FSS runs primarily on an operator-owned edge node. It may supervise local camera/drone adapters,
codec processes, GPU model hosts, and encrypted object-store publication. Cloud services are
optional archives or vendor bridges, not the canonical cognition/control plane.

```text
camera VLAN / USB / owner cloud / drone app
                 │
       scoped adapter host processes
                 │  packet capsules + receipts
                 ▼
      acquisition and continuity regions
                 │
        source-object custody ledger
                 │
       ┌─────────┴──────────┐
       ▼                    ▼
 live proxy          analysis/event pipeline
       │                    │
 operator UI        geometry + model hosts
                            │
                    immutable event revisions
                            │
           ┌────────────────┼───────────────┐
           ▼                ▼               ▼
       alert policy      search/graph     archive root
           │                │               │
       effect receipts    agent views    B2/R2/local
```

## 2. Semantic planes

### Authority plane

Owns identities, generations, policies, receipts, original media manifests, redaction/retention,
calibration certificates, event revisions, and archive roots. It is the only plane allowed to
authorize an effect or declare canonical state.

### Cognition plane

Owns decoded surfaces, quality metrics, detections, tracks, embeddings, geometry estimates,
hypotheses, rankings, explanations, and memories. Its outputs are immutable, provenance-bearing,
versioned, and rebuildable. It can propose but not authorize.

### Effect plane

Owns alert delivery, PTZ, camera settings, exports, archive mutation, retention changes, and future
drone missions. It uses immutable intent, capability, lease fencing, idempotency, precondition
revalidation, commit, observation, and verification.

## 3. Trust domains

| Domain | May access | Must not access |
|---|---|---|
| safe semantic core | typed values and injected capabilities | ambient network/filesystem/time/secrets |
| acquisition adapter | one scoped device/account and bounded output channel | canonical DB, unrelated devices, model prompts |
| codec host | designated media descriptors/bytes and declared transforms | credentials, policy, archive keys |
| model host | authorized redacted inputs and immutable model files | effects, vendor credentials, arbitrary filesystem/network |
| archive host | encrypted chunks and scoped bucket credentials | plaintext media unless policy explicitly selects it |
| report renderer | typed redacted report model and provided assets | independent data fetch or secret lookup |
| agent/MCP server | bounded projections and explicitly granted effects | generic shell, raw secret, arbitrary vendor method |

## 4. Identity and generations

Every record that can affect interpretation names exact generations:

- `device_generation`: manufacturer/model/hardware revision/serial pseudonym/firmware/app/API;
- `stream_generation`: one start/reconnect/config epoch;
- `clock_generation`: synchronization model and uncertainty;
- `calibration_generation`: intrinsics/extrinsics/time alignment/coverage certificate;
- `privacy_generation`: masks, zones, redaction, retention;
- `model_generation`: code, weights, preprocessing, runtime, quantization, hardware policy;
- `index_generation`: producer model and canonical anchor;
- `policy_generation`: alert and effect rules;
- `build_generation`: FSS source/toolchain/features/dependencies.

A query’s version universe is complete or rejected. “Latest of each” is not a coherent snapshot.

## 5. Acquisition state machine

```text
Requested
  └─ Authenticated
       └─ AdapterAccepted
            └─ FirstFrameObserved
                 └─ ContinuityVerified
                      ├─ Degraded ↔ ContinuityVerified
                      ├─ Cancelled
                      ├─ Failed
                      └─ Indeterminate
```

No transition is inferred from time alone. It requires a typed witness. A reconnect starts a new
stream generation; sequence resets cannot silently continue the old one.

## 6. Event state machine

```text
Hypothesized → Witnessed → Corroborated → Adjudicated → AlertDelivered → Resolved
      │            │             │              │
      ├────────────┴─────────────┴──────────────┴→ Rejected
      └──────────────────────────────────────────→ Indeterminate
```

Each transition creates a new immutable event revision. Rejection does not delete earlier
hypotheses. Corroboration normally requires independent failure domains; registered urgent
single-sensor exceptions must be explicit and separately measured.

## 7. Time model

Each observation stores:

- device timestamp, when present;
- host receive monotonic time;
- disciplined UTC mapping, when available;
- earliest/latest capture time;
- delay/jitter model and evidence;
- clock generation;
- sequence and discontinuity markers.

Cross-camera association operates on overlapping time intervals, not exact timestamp equality.
Uncertainty expands under packet buffering, vendor relay, dropped metadata, clock steps, and
reconnect. Excess uncertainty degrades geometry and coverage rather than quietly widening gates.

## 8. Media path

FSS has three distinct media representations:

1. **Source evidence:** original packets/files whenever policy permits. Never silently transcoded.
2. **Live proxy:** low-latency, disposable, operator-oriented stream.
3. **Analysis surfaces:** decoded/color-converted/scaled/sampled frames with exact derivation
   receipts.

Where possible, source packets are remuxed rather than decoded/re-encoded. FFmpeg or an equivalent
is a pinned supervised subprocess. Commands are generated from typed plans, not concatenated user
strings. Output bounds, descriptors, environment, seccomp/sandbox, timeouts, and process groups are
part of qualification.

## 9. Cognition path

```text
continuity + image quality + tamper
          ↓
motion/change/audio candidate generation
          ↓
fast detector / segmenter
          ↓
within-camera tracks
          ↓
geometry-constrained cross-camera association
          ↓
open-vocabulary and temporal reasoning
          ↓
independent verifier
          ↓
calibration + sequential/conformal policy
          ↓
event revision, abstention, or request for evidence
```

Every stage can degrade independently. The policy receives both positive evidence and missing-
evidence reasons. Model hosts emit structured outputs only; free-form prose is an explanation
projection, not the decision contract.

## 10. Geometry path

The geometry core owns coordinate frames, transforms, uncertainty, lens/crop models, rolling
shutter, terrain/building geometry, semantic zones, visibility, occlusion, and expected transit
constraints. Learned 3D models generate proposals; robust optimization and geometric residuals
qualify them. NeRF/Gaussian splats are derived visualizations.

## 11. Storage and publication

Canonical ledger records are transactional. Large bytes live in content-addressed object storage.
Publication is:

```text
reserve identities
→ stage children
→ hash/encrypt/verify
→ commit child metadata
→ publish root last
→ verify reachability
→ schedule retrievability sample
```

Object-store success does not imply ledger publication; ledger commit does not imply remote
retrievability. Receipts preserve each boundary.

## 12. Agent query model

Queries are bounded projections at an anchor. They return:

- `schema` and anchor;
- selected entities/revisions;
- uncertainty and degradation;
- evidence handles, not necessarily bytes;
- score/explanation components;
- continuation or resnapshot requirement;
- allowed next commands.

Effects require separate capability and prepare/commit. MCP is an adapter over core contracts, not
the architecture’s owner.

## 13. Deployment profiles

| Profile | Intended hardware | Behavior |
|---|---|---|
| `edge-lite` | laptop/SBC/CPU-only | standards acquisition, source custody, cheap motion/detection, remote optional verifier |
| `edge-gpu` | desktop GPU/Apple Silicon/NVIDIA edge | full local detector/tracker, bounded VLM, geometry |
| `split-gpu` | edge node + trusted GPU worker | encrypted/authorized evidence capsules over ATP-style transport |
| `archive-only` | NAS/server | restore, scrub, search, report; no live acquisition |
| `lab` | isolated test network | proprietary adapters, packet capture, firmware matrix, aggressive faults |

Profiles change resource placement, not semantic contracts.
