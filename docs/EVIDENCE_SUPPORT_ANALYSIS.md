# Retained event support-path analysis

`fss-evidence` is a read-only operator diagnostic connecting the retained deployment
reader to the `EvidenceClaimGraph` active-support projection and registered
`ALG-DOM-001` dominator algorithm. It makes structural dependence on a shared
artifact visible without calling repeated references independent corroboration.
It is not an agent-session operation, an evidence-export approval, or an effect grant.

## Run

```sh
cargo run -p fss-cli --bin fss-evidence -- analyze \
  --root /path/to/deployment --site site:your-site
```

To require exactly the same anchored algorithm result as an earlier report, pass
that report's `witness_digest`:

```sh
cargo run -p fss-cli --bin fss-evidence -- analyze \
  --root /path/to/deployment --site site:your-site \
  --expected-witness sha256:REPLACE_WITH_64_HEX_DIGITS
```

The command parses all options before opening the deployment. Native filesystem
path bytes are preserved; the site must be an explicit valid UTF-8 lineage. No
files, journals, locks, repair records, sessions or effects are created. Successful
stdout is one complete JSON object followed by a newline. Argument refusals use
the existing CLI error/exit identities; graph refusals preserve the registered
graph error identity. Failures never emit a shortened successful report.

## What the result means

The reader rehashes committed event payloads and verifies their revision history.
The compiler selects exactly the latest retained revision of every event from
that one snapshot. A deployment beyond the declared bounds is refused rather
than silently filtered. Uncommitted ledger/effect tails remain visible as flags;
they are not admitted as committed event evidence.

Each selected revision and each referenced support artifact has an
`object:<digest>` vertex. An explicit Supports edge becomes a separate incidence
vertex: `support:<revision-digest>:<zero-based-edge-index>`, with a minimum of four
decimal digits in the index. Traversal is object -> support edge -> event revision.
The entire canonical revision digest binds every original field, not just the
traversed relations. The report includes the complete selected canonical event
records, preserving all evidence edges, identities, model receipts, policy
fingerprints, probability intervals, uncertainty and lifecycle state.

An artifact that lies on every declared path to an event is a structural
bottleneck. For example, two branches that reference the same recording can still
have that recording as their common dominator even when their failure-domain
labels differ. Conversely, distinct object references provide path diversity,
not proof of independent sensors or independent failures.

The synthetic entry root connects only supporting references not expanded as one
of the selected active event revisions. Such references are explicitly listed as
**unexpanded**. They are not hydrated or certified as source observations by this
command. A reference to an old revision is not redirected to its current successor.
A claim with no declared support remains `no_declared_support`; a support chain
with no route from the unexpanded-reference frontier remains `unrooted`. Neither
label means false, absent, rejected, or safe to ignore.

DerivedFrom, Contradicts, Invalidates, Supersedes, ObservedAfter, RequiredBy,
Explains, SensorTamper and SensorIntegrityRestoration are retained but never
traversed as positive support. Their exclusion from that traversal does not erase
their event semantics or resolve the underlying uncertainty. In particular, this
is not an AND/OR proof evaluator, calibrated probability estimator, current source
custody check, absence certificate, adjudication or effect authorization.

The algorithm witness binds its authority anchor, graph/query input, policy,
implementation, output and decision-path digests, and operation/output counters.
Its output digest covers the registered dominator output, not the entire wrapper
JSON or filesystem-read counters. The expected-witness pin is therefore an exact
anchored algorithm-result pin, not a current-availability or export certificate.
Source deletion or availability can change independently of this diagnostic.

## Resource and privacy boundaries

The default graph operation budget is 2,000,000, with a hard ceiling of 50,000,000.
The algorithm output-entry limit defaults to 65,536. Both are configurable downward
with `--max-operations` and `--max-output-entries`. The compiler separately admits at
most 128 active revisions, 8,192 total evidence edges (including non-supports), and
8 MiB of canonical event bytes. The source reader retains its existing separate
`OrientLimits`: 64 MiB per journal, 16 MiB per object and at most 64 revisions per
event. Reported algorithm costs do not pretend to account for source I/O, compiler
allocation or JSON rendering.

`--max-report-bytes` accepts 1,024 through 2,097,152 bytes, including the final
newline. Oversized reports fail before stdout; no counterevidence or warning is
removed to make them fit. `--timeout-ms` defaults to 30,000 and accepts 1 through
3,600,000. Deadline checks bracket reading, compilation, analysis and rendering;
they do not preempt an individual filesystem call or an algorithm step. Algorithm
work is independently bounded. Broken output streams return a failure exit code;
short writes are completed and repeated EINTR is bounded.

This is an operator-local metadata report with **no redaction transform**. It
contains no media hydration, but event identifiers and metadata can be sensitive.
Use the approved evidence-export path for sharing, not this diagnostic as a way
to bypass privacy/capability projections.

## Validation status and remaining scope

This increment is an **authored, unqualified reference candidate**. Rust
compilation, native tests, rustfmt and Clippy were not run in the authoring session
because no Rust toolchain was available. No hosted workflow or release gate was
weakened. Run the native qualification on a controlled host before release:

```sh
cargo test -p fss-graph-algorithms --test evidence_projection
cargo test -p fss-cli --bin fss-evidence
```

The graph test target includes ten tests, including 512 seeded record projections
against the existing independent node-removal oracle and insertion-order checks.
The operator target adds thirteen tests for grammar, native paths, record
preservation, byte boundaries, exact pins, source-site mismatch, cancellation,
algorithm exhaustion, uncommitted-tail visibility and bounded output delivery.
An independent Python semantic model, not the Rust implementation, was executed
in the authoring session: 2,048 projections, 130,449 node-removal comparisons and
two focused shared-artifact/ungrounded cases passed.

Historical provenance hydration, source custody verification, failure-domain
independence, graph-query integration into the universal agent envelope, and the
other retained graph-family builders remain outside this increment. No broad
bead or production qualification claim is closed by the existence of this code.

Contract references: `EvidenceClaimGraph`, `ALG-DOM-001`, `GRAPH-INV-001`,
`GRAPH-INV-004`, `GRAPH-INV-008`; follow-on to `fss-x4a.23.31`.
