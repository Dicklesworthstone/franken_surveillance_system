# Verify retained native activity from a cold deployment

`fss-evidence verify-activity` turns the existing native activity rederiver into an operator
workflow. It reads a result written by `retain_executor_result`, verifies its original source
custody and authority membership, and reproduces the computation in a fresh process. It does
not open a deployment writer, acquire deployment locks, repair files, or publish new cognition.

```sh
cargo run --locked --offline -p fss-cli --bin fss-evidence -- verify-activity \
  --root /path/to/deployment --site site:example \
  --result sha256:RESULT_OBJECT_HEX \
  --reference-capsule sha256:EARLIER_CAPSULE_OBJECT_HEX \
  --source-slot original-frame-publication \
  --sensor sensor:camera --stream stream:camera-generation --job job:original \
  --interpretation grayscale --execution-macs 10000000 --execution-bytes 16777216
```

Replace the symbolic digest placeholders with the exact retained identities. Repeat
`--source-slot` for distinct publications holding the eight roles, up to eight source slots.
The command independently selects the deterministic result/receipt publication; source roles
must belong to the explicitly selected source closures. It supports nested published manifests
and verifies every selected sibling, not just the objects named by the result. Identical earlier
and evaluated JPEGs may share source/decode object digests while keeping distinct capsule roles.

The sensor, stream, original job, component interpretation, threshold policy and original scalar
execution allowances are verifier inputs. They are never inferred from a claimed score. The
default is the reference threshold policy (generation 1, threshold `0.01f32`). Use
`--policy-generation` and `--threshold-bits` for a different independently selected policy;
the latter takes eight lowercase hexadecimal digits representing the exact finite nonnegative
`f32`. Both execution allowances must match the original invocation receipt, even if a different
allowance would happen to produce the same score.

## What a successful report establishes

The read-only owner replays committed deployment history and checks the complete canonical
deletion proof before reading selected source content. A committed deletion header revokes its
full planned closure even before cleanup completes. Slot retractions are checked independently
of shared object bytes, and an unrelated valid deletion does not disable an intact selection.

Native publication capture rehashes all selected objects and checks the exact slot records.
The original executor-result batch, its cognition revisions, its two-child manifest and its
retained invocation object must agree. The existing graph verifier then establishes each of
the eight roles' ancestry from current authority revisions. The pinned native JPEG decoder and
scalar model run again; the complete invocation receipt and result must reproduce byte for byte.
A final read must observe the same committed head, site, journal roots and source namespace.

The JSON report includes the exact ledger anchor and `ledger_root`, all named evidence roles,
the resulting derived belief and receipt, score bits, model/policy identities, and separate
custody, deletion, graph and native work counters. Pass that `ledger_root` back through
`--expected-ledger-root sha256:HEX` to refuse any changed authority history before source capture.
The report is deterministic for an unchanged deployment and request.

The belief remains **Estimated / Derived**, reference-only and uncalibrated, with uncertainty
`[0,1]`. `no_activity` cannot establish absence, coverage, person detection or corroboration.
No outcome authorizes an effect. These are sequential custody/head observations, not a lease
on future file availability. The report contains local operator metadata; it is not a privacy
transformed export or an agent-session response, and it never includes original media bytes.

## Bounds and failures

`--help` lists explicit custody read, per-object, object-count, captured-byte, deletion metadata,
journal, decode-work, output and timeout ceilings. Every allowance is independent; changing one
does not refill another. The underlying history reader keeps its per-journal byte bounds, and
the core replay additionally limits batches, delta/child entries, retained snapshot entries and
copied text. Journal I/O is not counted as custody I/O. Timeout checks are cooperative and do not
preempt an individual bounded filesystem call or the bounded native replay.

Missing, corrupt or revoked original evidence, an invalid deletion proof, a substituted slot,
stale pin, changed job/policy/budget, unreproducible score, exhausted allowance or cancellation
produces a nonzero exit and no partial JSON report. Missing deployments remain missing.

The fresh-process regression target is:

```sh
CARGO_BUILD_JOBS=1 cargo test --locked --offline -p fss-cli --test evidence_activity_contract
```

It uses real source JPEGs, native model receipts and the existing retention writer. The tests
cover active/quiet results, shared-byte roles, a canonically retained false score, stale and
incorrect independent inputs, read/work/output bounds, cancellation, source corruption, removed
publication records, real unrelated deletion and corrupt deletion metadata. This operator
integration advances the concrete retained-evidence portion of `fss-s1gcl`; it does not claim
production model activation, calibration, a remote authorization service or full release
qualification.
