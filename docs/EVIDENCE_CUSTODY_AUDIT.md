# Targeted retained-object custody audit

`fss_publication::custody_audit::audit_local_roots` verifies the local publication
closure of up to 128 explicitly selected roots without reopening a writer,
creating holds, scanning unrelated payloads, or repairing evidence. This closes a
read-side gap between a retained reference and a fresh check of its actual bytes.
It implements the existing bottom-up publication semantics; it is not an alternate
source ledger, graph truth model, or authority grant.

The additive `audit_authority_roots` uses the same walker for exact manifest roots
selected from separately verified canonical authority. It is the entry point the
operator command uses for committed events, which need not have local root slots.
See [the authority-root contract](AUTHORITY_CUSTODY.md).

## Closure and fault semantics

The first metadata pass reads bounded canonical publication and local tombstone
records. Each record is checked against the existing canonical record encoder.
The complete publication catalogue, not a guess based on payload bytes, determines
which objects are manifests. The payload walk follows only those declared
manifests. A leaf that happens to contain a well-formed manifest is still opaque.
Each unique digest is read once across the union of selected roots; every manifest
edge is charged, including repeated references to shared objects.

A report keeps each discoverable object as `verified`, `missing`, `corrupt`,
`invalid_manifest`, `object_over_limit`, `unreadable`, `deleted`, or
`locally_tombstoned`. A caller-supplied verified deletion index and local tombstones
deny payload reads even while an interrupted deletion leaves bytes on disk.
The denial's plan or tombstone-record digest remains visible. Missing/denied/invalid
manifests do not become opaque leaves: `manifest_expansion_complete` is false and
the undiscovered descendants remain unknown. Other discoverable branches are
still checked. No object bytes appear in the report.

A second bounded metadata pass must reproduce the first catalogue exactly. A
changed catalogue, foreign or corrupt metadata, pending publication, cancellation,
or exhausted aggregate allowance returns a typed refusal, never a shortened
successful audit. In `audit_local_roots`, a selected root without a local root
record is also refused. `audit_authority_roots` instead uses the caller-verified
selection to declare only those selected roots as manifests. It still checks any
existing local record and never infers manifest roles for opaque descendants.
There is no automatic repair/retry.

## Resource and authority boundaries

One request-owned read-only `SpoolIo` wrapper counts every filesystem call and
reserves each bounded file read before it executes. Both catalogue passes, spool
headers, bounded trailing-byte probes, successful reads and failed attempts share
the same allowances. Successful reads refund their unused allowance; failed reads
keep the entire reservation because their partial transfer size is unknown.
`charged_read_bytes` is therefore a conservative charge, not always actual I/O.
`peak_reserved_read_bytes` exposes the reservation envelope required by the run;
it is not resident memory. Cancellation is checked at every I/O boundary and graph
expansion, not only between whole stages. A blocking host syscall is not preempted.
The wrapper refuses all mutating and locking operations before forwarding them.

Defaults: 8,192 entries per metadata directory; 16,384 unique closure objects;
65,536 manifest edges; 16 MiB per object; 512 MiB aggregate charged reads; one
million filesystem calls. Hard ceilings are 65,536 metadata entries, 65,536 objects,
262,144 edges, the existing 64 MiB object limit, 4 GiB charged reads and four million
calls. Callers can narrow limits, not exceed them. Metadata, pending sets and results
are cardinality-bounded; no measured allocator-peak claim is made.

The caller owns filesystem authority, the selected root scope, cancellation and
upstream deletion verification. Supplying a denial can only restrict access, not
authorize it. A deployment adapter must bind roots to the verified ledger and
recheck that authority/deletion basis after the audit. The generic publication
owner does not authenticate an operator or invent a ledger anchor.

These are sequential read observations, not an atomic snapshot, filesystem lease,
proof against a malicious filesystem racing path substitution, remote-retrieval
certificate, or promise that bytes will remain present after the read. Equality of
two metadata observations cannot exclude an undetected change-and-revert. No fsync
is observed and no durability rung is upgraded. The result proves only the declared
publication closure, not all semantic references embedded inside opaque artifacts,
physical truth, independent corroboration, detection quality, or absence.

The result is a non-durable typed diagnostic, like the existing `LocalInspection`.
No new canonical event encoding, digest domain, effect, dependency or authority
schema is introduced.

## Validation

Native contracts use real canonical root/tombstone records and spool envelopes,
not a second fixture storage format. They cover shared and nested graphs, ignored
unrelated corruption, opaque manifest-shaped payloads, missing and corrupt sources,
invalid manifests, deletion precedence, per-object and aggregate budget boundaries,
cancellation, catalogue changes, symlinks and strictly read-only behavior.

```sh
cargo test -p fss-publication --test custody_audit_contract
cargo test -p fss-publication custody_audit::io::tests
```

Rust compilation, execution, rustfmt and Clippy have not run in the authoring
environment: no Rust toolchain or network route to one was available. Independent
semantic/encoding checks do not replace native tests. This is a reference candidate,
not a production qualification or closure of a broad work package.

## Operator workflow

```sh
cargo run -p fss-cli --bin fss-custody -- audit \
  --root /path/to/deployment --site site:your-site --event-id event:your-event
```

The command selects exactly the requested event's CURRENT publication root from
`read_deployment`, which replays committed authority and rehashes event manifests
and canonical records. The command additionally verifies the complete selected
revision chain. The event must be present, and its selected record must match both
the retained chain tail and committed revision digest. A different
site, missing event or unreadable canonical history is refused. An arbitrary
staged artifact cannot be used in place of an authoritative event root.

`publish_event` stages an event manifest and commits it to the ledger without also
creating a local `.root` record. The command therefore calls `audit_authority_roots`,
not the local-slot-only entry point. The report's additive `root_basis` is
`caller_verified_authority`, grounded in the event selection above. No local slot
is created or implied. Descendant manifests still require local publication
records. This corrects the initial command's `RootNotPublished` refusal on ordinary
committed event roots without changing those roots or any publication encoding.

`--expected-root sha256:HEX` optionally pins the event root from a prior report.
This prevents auditing a silently changed revision; it does not pin or guarantee
current byte availability. The custody walk receives only that event root and
object-to-plan denials derived from the verified committed deletion index. The
original event, including uncertainty and counterevidence, is rendered by its
canonical core renderer and remains unchanged by custody findings.

The command then reads the deployment again. Site, ledger/effect roots and
positions, current event root, revision, canonical event record, deletion denials
and uncommitted-tail flags must match. Any observed drift refuses the whole report;
there is no stale-root fallback, retry or repair. This bracket is separate from the
audit's two publication/tombstone catalogue reads. None of the comparisons creates
an atomic filesystem snapshot or detects every possible change-and-revert.

Complete reports include every discoverable object's typed state, known child
edges, verification lengths and denial references. No source payload is printed.
A nonzero runtime-failure exit accompanies a complete `custody_faults` report;
exit zero requires all selected publication-closure bytes to verify. Errors,
cancellation and report overflow emit no successful report. Operator metadata has
no redaction transform and must not be treated as an approved evidence export.

The following options configure custody allowances (not the entire command's I/O):
`--max-read-bytes`, `--max-io-calls`, `--max-objects`, `--max-edges`,
`--max-object-bytes`, and `--max-catalogue-entries`. Their ceilings and defaults are
those of the library above. `--max-report-bytes` permits 1,024 through 2,097,152
bytes including the newline. `--timeout-ms` permits 1 through 3,600,000 (default
30,000). The parser accepts at most 25 arguments of at most 4,096 bytes, preserves
native filesystem path bytes and rejects duplicate or unknown options before I/O.

Two separately bounded deployment reads use the existing `OrientLimits` defaults
and doctor inspection. They can inspect unrelated objects; their reported counters
are kept separate and are NOT charged to the new audit byte/call allowance. The
new nonrefillable meter covers the custody stage, including both of its publication
catalogue passes. Deadlines bracket deployment reads and are checked at every
custody I/O boundary; individual blocking syscalls are not preempted.

Twelve additional operator contracts cover grammar, root/identity pins, real
publication-envelope traversal, complete canonical metadata, missing/corrupt and
deleted payloads, authority drift, output boundaries, cancellation and bounded
output delivery. Their verified-snapshot seam is explicitly injected: these are
not an end-to-end proof of canonical ledger publication. A publication-only tree
is also checked to be insufficient for the actual deployment reader. Native
compilation/tests remain unrun in the authoring environment.

```sh
cargo test -p fss-cli --bin fss-custody
```


Six additional process contracts in `custody_authority_cli` create a deployment,
retain a source/provenance root through `publish_and_commit`, commit an actual
event through `publish_event`, then invoke the `fss-custody` binary. They do not
inject a snapshot or invent an event slot. They check successful traversal to both
support and counterevidence, byte-identical read-only retries, missing/corrupt
sources, incomplete provenance expansion, local tombstones while bytes remain,
current-revision pins, exhausted allowances and damaged authority. These native
contracts remain unrun in the authoring environment.

```sh
cargo test -p fss-cli --test custody_authority_cli
```
