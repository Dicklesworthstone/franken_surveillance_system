# Data formats and publication contracts

## 1. Format doctrine

- Every durable format has magic/schema identity and version.
- Durable identity is content-based where practical.
- Serde may encode versioned interchange JSON; it does not define an eternal binary format by
  accident.
- Unknown fields/versions have explicit behavior.
- Canonical records are immutable or superseded by a new revision.
- Derived artifacts name all producer generations.
- Original bytes and derivatives have different identities.
- Root-last publication prevents a visible root from referencing absent children.
- Every migration has deterministic fixtures and downgrade/read behavior.

## 2. Sensor capsule

`schemas/sensor_capsule.v1.json` describes one bounded media/metadata segment. The capsule binds:

- sensor and stream generation;
- sequence and capture-time interval;
- receive time and clock basis;
- codec/container/dimensions/frame count/source bytes;
- source and proxy object identities;
- continuity/decode/firmware evidence;
- privacy/redaction/retention state;
- publication root and ledger revision.

A capsule can represent intentionally omitted source bytes, but the omission reason and policy must
be explicit. A decoded frame without a source capsule is transient cognition, not canonical media
evidence.

## 3. Event hypothesis

`schemas/event_hypothesis.v1.json` is one immutable revision. It includes:

- state and semantic kind;
- time/zone/track scope;
- calibrated probability interval;
- evidence items and failure domains;
- model receipts;
- policy generation and decision fingerprint;
- abstention and reason.

An event ID has many revisions. Revisions are append-only. Resolution, rejection, or relabeling
creates a new revision and preserves the causal history.

## 4. Operation receipt

`schemas/operation_receipt.v1.json` captures effect truth:

```text
prepared
→ committed
→ adapter_accepted
→ observed
→ verified
```

Terminal branches are cancelled, failed, or indeterminate. The receipt binds principal,
capability, lease fence, idempotency key, request/precondition/result digests, timestamps, and
stable error identity.

A retry with the same idempotency key and same request returns the prior semantic result. The same
key with different content fails. An indeterminate operation is reconciled before any retry that
could duplicate effects.

## 5. Calibration certificate

`schemas/calibration_certificate.v1.json` binds:

- world coordinate frame;
- sensor intrinsics/extrinsics/time offset and uncertainty;
- protected-volume and blind-spot identities;
- lower-bound observed fraction;
- reprojection/time residuals;
- issue/expiry and invalidators;
- evidence root.

A rendering is not a certificate. The certificate can reference renderings as children.

## 6. Evidence bundle

`schemas/evidence_bundle.v1.json` is the support/replay envelope. It contains:

- event root;
- object inventory and retention state;
- build/config/device/model registry identities;
- replay command and expected decision fingerprint;
- optional seed.

A default support bundle omits private media and replaces it with hashes, structural metadata,
small explicitly approved crops, or synthetic reproductions. A forensic export is a separate
capability and retention event.

## 7. Object namespace

Target logical layout:

```text
objects/<algorithm>/<prefix>/<digest>
roots/sensor/<sensor-id>/<stream-generation>/<sequence>.json
roots/event/<event-id>/<revision>.json
roots/calibration/<generation>.json
roots/export/<export-id>.json
proofs/<gate>/<proof-root>.json
```

Object-store keys are hints, not identities. The digest and manifest define identity. Backends may
map keys differently without changing semantics.

## 8. Media derivatives

Each derivative receipt names:

- source capsule/object range;
- exact transformation plan;
- codec/runtime/build identity;
- color space, transfer function, range, rotation, crop, scale;
- frame sampling and timestamp mapping;
- output digest and byte/frame counts;
- warnings/concealment;
- resource measurements.

A thumbnail, VLM frame sequence, and operator proxy are separate derivatives even if generated in
one process.

## 9. Decision fingerprint

The decision fingerprint is a digest over the canonical ordered projection of:

- event revision inputs;
- evidence identities and classes;
- sensor health/coverage state;
- calibration/model/policy generations;
- calibrated score intervals;
- deterministic tie breaks and rule path;
- selected action/abstention.

It excludes incidental wall-clock logging, memory addresses, unordered map iteration, and prose.
Replay may regenerate different free-form wording while preserving the semantic fingerprint.

## 10. Deletion closure

Deletion is an effect over a reachability graph. A completion proof covers:

- canonical roots and child objects;
- local spool;
- remote backends;
- thumbnails/proxies/analysis caches;
- lexical/vector/graph indexes;
- model-host caches;
- reports and support bundles;
- memory items whose evidence no longer exists;
- backups subject to explicit retention/legal hold.

Where immediate physical deletion is impossible, the record states cryptographic erasure,
retention expiry, or blocked reason. “Row deleted” is not closure.
