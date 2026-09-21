# Durable original HTTP camera bytes

`fss_reference::ingest::http_archive::HttpWireArchive` retains the original
`HttpWireRead` before it can leave the native acquisition owner. It uses the
existing `LocalRootPublisher` and `StagingSpool`: no parallel media journal,
mutable file head, alternate object store, network request or foreign dependency.
This is source-custody integration toward plan sections 12–13, not a completed
production service, storage qualification or canonical event publication.

## Exact records and recovery

Each immutable `http_camera_wire_v1` manifest directly roots the unchanged raw
read and its bounded canonical metadata. Metadata includes original stream and
generation, byte range, raw hash, read-admission time, source/retention scope and
exact predecessor commitment. Source reads may contain sensitive HTTP headers
as well as pixels. `HttpWireScope` requires an explicit receive-clock identity
and retention-policy/authority evidence. Neither that evidence hash nor a stream
ID grants permission: pass an independently authorized storage owner and a
`PublishCancellation` probe enforcing its live cancellation, deadline and scope.
No encryption, automatic deletion or privacy-policy relaxation is introduced.

The namespace binds the original stream/generation. Changing retention or clock
assumptions cannot evade an existing source slot. Individual read roots avoid
recursive descent through an ever-growing historical chain. A predecessor hash
is an ordering commitment, NOT a claim that the last read root structurally roots
all earlier media. Every read root must remain retained separately. `reads()`
exposes the exact ordered pins and source receipts for custody accounting.

`prepare` borrows an actual opaque socket read and returns its expected post-write
`HttpWirePin` and slot before I/O. Keep that pin independently before publication.
`publish` stages and verifies the bytes and metadata, then uses the existing
root-last publisher. Only a `Durable` result advances the in-memory prefix. There
is no fallible work after that advancement. Exact retries use the same slot/root;
changed bytes, receive time or source basis cannot become duplicate credit.

On an error, the source stays caller-owned and the prefix stays unchanged. Some
storage work may already exist. A poisoned publisher must be reopened/reconciled
using its existing recovery protocol. A crash after root visibility can be resolved
against the independently retained expected pin; it is never inferred from a hash
or a successful earlier stage. Orphan temporary roots are surfaced, not silently
removed by the archive. The existing publisher owns any explicit repair.

`load` requires an exact independently retained pin, not a mutable name or an
implicit latest head. It checks the entire bounded namespace, then re-reads and
rehashes each manifest, its exact child set, metadata and original payload. It
checks contiguous offsets, predecessor identity and nondecreasing receive time.
Missing/broken/conflicting roots, later unaccounted roots, changed retention or
clock scope, tombstones, corrupt bytes and narrowed runtime bounds are refused.
An empty declaration does not claim that an existing namespace is empty.

## Source-linked retrieval

`read_range` reconstructs a bounded original-wire range across read boundaries,
revalidating its required current roots, metadata and payloads. `verify_frame`
uses every native `HttpJpegFrame::source_spans()` entry to compare the complete
JPEG payload with those durable raw bytes. It can bridge HTTP chunk boundaries
and arbitrary socket read fragmentation without treating dechunked bytes as a
new source. A successful check concerns JPEG payload custody at that read; it
is not a fresh verification of unrelated response overhead or whole-response
termination. The raw overhead itself is retained in the same read records.

A durable prefix is not successful HTTP/MIME EOF, continuous camera coverage,
authenticated camera identity, physical absence, a calibrated detection or alert
authority. Receive time is never converted into camera capture time. The API does
not reconstruct an active TCP connection after restart or resubmit its GET.

Bounds cover 4,096 read records, 256 MiB of original input, 64 KiB per socket read,
16 MiB per returned range, root scanning, source maps and the existing spool's
maximum allocating read. Owner-selected lower ceilings apply. Deterministic
`WorkBudget` charges include configured worst-case spool reads and namespace
checks; cancellation is checked between storage operations. Per-read root writes
and full cold verification are correctness-first and need deployment throughput
measurement. At capacity, rotate explicitly; never drop source or refill budgets.

## Executable contracts

```sh
cargo test -p fss-reference ingest::http_archive::tests
```

Ten contracts exercise real filesystem publication and cold recovery, original
cross-read ranges, idempotent and lost acknowledgements, all four existing root
crash cuts, cancellation and budget refusal, rollback/gaps/later roots, corruption,
clock/retention drift, runtime bounds, wrong families and extra children. These
are source-custody contracts, not physical-camera interoperability tests.

The authoring sandbox has no Rust toolchain. Compilation, these Rust tests,
rustfmt, Clippy and production qualification remain unrun; lexical/hash checks
and independent state-model checks do not substitute for executing Rust.
