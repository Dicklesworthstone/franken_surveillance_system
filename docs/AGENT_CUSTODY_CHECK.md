# Checked custody in event explanations

The `fss_cli::custody_review` adapter turns the existing publication-owner audit
into decision-relevant event metadata. It closes the gap between a structurally
valid support graph and the present availability of the event's declared object
closure. It is a read-only reference adapter, not authentication, evidence export,
event adjudication, or a production qualification.

## Verified scope and observations

The caller supplies its already authorized, verified `read_deployment` snapshot.
The adapter checks the selected current revision against its complete retained
chain, then uses `audit_authority_roots` on exactly that event publication root.
The actual publication walker enforces deletion denials and local tombstones,
verifies object envelopes, and expands only explicitly declared manifests.

A fresh deployment read must reproduce the same site, anchor, ledger/effect roots,
position, event record/root/revision, deletion denials and uncommitted-tail flags.
Observed drift or an unavailable recheck refuses the entire result. The walker
also compares publication/tombstone catalogues on both sides of its own reads.
No reader creates locks, repairs files or dispatches effects. These are sequential
observations, not an atomic snapshot or a guarantee against change-and-revert.

The projection preserves every discovered fault individually, including the exact
object and denial identities. Missing/corrupt manifests keep undiscovered children
unknown. Direct evidence, capsule, identity and model references outside the
observed closure are explicitly listed as unexamined, not silently certified.
Successful object states are represented by complete state counts; they are not
ranked samples. A combined ceiling of 32 fault/unexamined identities refuses a
larger complete projection rather than silently truncating it.

The existing `ExplainReceipt` binds the current event and the exact non-durable
JSON proposition bytes. That receipt is recomputable, not a newly persisted proof
object, hydration handle, or certificate for all embedded semantic provenance.
Physical event state, probability, counterevidence and alert eligibility do not
change. Historical support roots are not implicitly checked by this current-root
audit.

## Resource boundary

The publication stage retains one shared `CustodyAuditLimits` meter, including
both catalogue passes, successful reads and conservative failed-read reservations.
The subsequent deployment read uses the existing `OrientLimits`. Its *reported*
counters must also fit 128 MiB and 65,536 files before the review is admitted.
That admission check occurs after reading: it is not a preemptive syscall meter,
and the deployment doctor's preflight is outside those reported counters.
Cancellation is checked around that reader and at every custody I/O boundary;
blocking host calls cannot be preempted. No unmeasured CPU or allocator cost is
claimed as zero.

## Validation and qualification

Ten native library contracts use actual `publish_and_commit` and `publish_event`
fixtures, not manufactured event slots. They cover intact and damaged source and
counterevidence, missing manifests, tombstones, full lineage binding, observed
basis changes, cancellation, zero I/O allowance, failed revalidation and complete
context/accounting bounds.

```sh
cargo test -p fss-cli --lib custody_review::tests
```

These native tests, Rust compilation, rustfmt and Clippy remain unrun in the
authoring environment: no Rust toolchain is installed and network access to
obtain one is unavailable. Source inspection or supplementary semantic checks do
not replace native execution. No broad bead or release gate is closed.
