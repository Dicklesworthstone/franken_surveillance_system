# Targeted retained-object custody audit

`fss_publication::custody_audit::audit_local_roots` verifies the local publication
closure of up to 128 explicitly selected roots without reopening a writer,
creating holds, scanning unrelated payloads, or repairing evidence. This closes a
read-side gap between a retained reference and a fresh check of its actual bytes.
It implements the existing bottom-up publication semantics; it is not an alternate
source ledger, graph truth model, or authority grant.

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
changed catalogue, foreign or corrupt metadata, pending publication, an unpublished
selected root, cancellation, or exhausted aggregate allowance returns a typed
refusal, never a shortened successful audit. There is no automatic repair/retry.

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
