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

## Standard agent command

```sh
cargo run -p fss-cli --bin fss -- explain --json \
  --root /path/to/deployment --event-id event:your-event --custody yes
```

Omitting `--custody`, or explicitly passing `--custody no`, keeps the previous
structural-only execution, request identity and response bytes. The opt-in is
strictly `yes` or `no` and accepts the normal `--custody=yes` spelling. Rust
callers constructing `ExplainArgs` directly must initialize its new `custody`
field (`false` preserves the old behavior). The current MCP transport does not
expose this option; it still rejects undeclared client arguments.

With `yes`, the standard AOP-011 response keeps its registered cognitive payload,
all original event cells, counterevidence, protected worlds, physical knowledge
state, priced metadata handles and listed owner affordances. Additional
`claim:event-custody:...` propositions describe the current publication closure,
every discovered fault, and direct references outside the discoverable closure.
Graph-only availability statements are explicitly scoped to the graph stage.
No newly computed digest is represented as a retained or available source handle.
An existing `ExplainReceipt` composes the support and custody receipts; the
request identity records the opt-in, the decision identity includes observations,
and the ordinary payload digest binds the entire rendered cognitive payload.

A successful *explanation* can describe missing, corrupt or deleted objects and
returns the usual successful explanation exit. Its custody propositions and
warnings explicitly say that this is not intact-custody success. Physical event
judgments and stored probabilities remain unchanged. For an operator command
whose exit itself means every selected object verified, use `fss-custody audit`.

Observed authority drift or a failed recheck returns an AOP-011 refusal with
`resnapshotRequired=true` and refresh-before-retry guidance. Cancellation,
resource refusal or a complete context that does not fit also refuses; there is
no fallback to an unchecked answer and no discarded fault or protected world.
No effect is executed and no stored event is retracted by either outcome.

### Combined resource accounting

The two graph algorithms retain their existing shared operation/output allowance.
Custody adds the publication owner's default byte/call allowances, not per-object
refills. The response adds the completed custody charge and recheck's reported
bytes/files to the existing orientation counters; requested vectors include the
already admitted initial read and the additional custody/recheck allowances.
Both cognitive and outer budget vectors use those same totals. The recheck's
128 MiB/65,536-file limits are still **post-read counter admission**, not a claim
that its full doctor preflight was metered or preempted.

Additional semantic fields are charged as `ceil(UTF-8 bytes/4)` under the same
1,800-token `decision_diff` maximum. Replaced graph-scope text keeps its old paid
charge and pays additional length when it grows; shortening it never refills the
allowance. This is not full serialized-output tokenization. The existing 256 KiB
whole-success-response limit remains, including the final newline. Failure of
any complete projection does not return a shortened success.

The opt-in owns a 30-second checkpoint deadline beginning before the initial
read; ordinary unchecked explanations do not consult a clock. Checkpoints bracket
the custody/recheck phase and successful response delivery preparation. Individual
blocking syscalls and whole initial orientation/graph stages are not preempted.
CPU, latency consumption and allocator peaks remain unmeasured, never inferred
from these limits. Refusals preserve known completed-stage counters and explicitly
state that unreturned audit/recheck work is not accounted as zero.

### Integration validation

Two focused parser/accounting tests and seven native process tests were added.
The process contracts use the real publication fixture before launching `fss`;
they cover opt-in/default identity separation, unchanged original event reasoning,
matching budget vectors, deterministic read-only output, missing source, corrupt
counterevidence, unknown descendants, complete-fault overflow and argument errors.
The large unknown-descendant case may return its complete context or a registered
context-budget refusal, but never unchecked success or an unrelated runtime error.

```sh
cargo test -p fss-cli --lib orient_cmd::custody::tests
cargo test -p fss-cli --test explain_custody_cli
cargo test -p fss-cli --test explain_support_cli_contract
cargo test -p fss-cli --test orient_cli_contract
```

These new native targets are authored, not executed in the toolchain-less authoring
environment. The read-only principal remains the existing operator-local audit
label: the option does not authenticate another principal, widen a filesystem
capability, implement multi-tenant privacy projection, or authorize source export.
