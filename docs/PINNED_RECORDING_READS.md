# Exact-pin native recording retrieval

Native AVC and HEVC recording windows can be retrieved through a request-owned read-only
capability without opening the archive's `LocalRootPublisher`. This removes the source
writer-lock requirement and archive-wide recovery scan from this retrieval path. The writer's
recovery, publication and deletion rules are unchanged.

The caller must supply an exact archive path, recording slot, immutable root, codec, source
scope and current read/retention authority. No source discovery, inferred codec, capture-time
interpretation or disclosure grant is added by the reader.

## Retrieval contract

`fss_publication::custody_audit::pinned_closure::PinnedClosureReader` admits one exact slot
and its canonical manifest at a time. Only direct children of that admitted manifest can be
read. Manifest-shaped child bytes remain opaque; the reader cannot use them to traverse an
unapproved object graph. It never enumerates directories, acquires a writer lock, creates
missing paths, stages objects, repairs state or removes data.

The recording entrypoints are
`recording::pinned::load_pinned_recording` and
`recording::hevc::local::load_pinned_hevc_recording`. They require the native four-child
recording closure, verify exact source scope and role identities, and run the existing full
AVC or HEVC packet replay and remux comparison. Correct object checksums alone cannot make a
forged source-to-media relationship valid.

Before returning a recording, the reader rehashes its manifest and all four children and
rechecks exact root-record identity, child count and every selected deletion marker. Pending
or indeterminate selected root/tombstone markers refuse the request. Dynamic native authority
is checked around each selected object and revalidation stage; request cancellation separately
gates every filesystem call. An unrelated corrupt or pending object is not inspected and does
not block the selected closure.

These are bounded observations, not an atomic filesystem snapshot, a durability certificate,
a read lease, or a guarantee of future availability. Protected deployment/ledger/privacy checks
remain the responsibility of the existing import owner. Successfully reading an archive does
not authorize publishing or disclosing its bytes.

## Shared bounds and cost

A single reader can retrieve a bounded sequence of windows. Its read-byte and filesystem-call
allowances never reset. Object, edge and root allowances also accumulate across windows:
each complete native window accounts for five object admissions, four edges and one pinned
root. Shared object identities in separate windows remain charged to each window's observation.
Every window retains the existing 32 MiB combined native-recording payload ceiling.

`finish_root` revalidates only the current selected closure, then drops its observation state.
Earlier completed payloads are not reread while processing later windows. Thus selected payload
read/hash work is linear in the selected windows' total bytes, independently of the number and
size of unrelated archive objects. Each payload is read on both admission and revalidation.
Spool envelopes, root records and temporary bounded-read reservations are charged separately;
reported retained-source bytes are not a total I/O quote.

`usage()` reports cumulative bytes, calls, peak read reservation, object/edge counts and completed
roots. `finalize()` checks remaining layout/cancellation state and closes the request against
further reads. It preserves completed accounting on a late failure. Repeating successful
finalization adds no I/O. `finish()` consumes the reader and returns the same final accounting.

The additive `ingest::rtsp_import::import_rtsp_pinned` entrypoint feeds the verified recording
into the unchanged retained-import provenance and custody path. It reserves three maximum
native-window byte passes in the supplied cumulative `WorkBudget` before source access.
The existing writer-backed `import_rtsp` API, proof encodings and import identities are preserved.

## Executed evidence

The pinned nightly native component command is:

```sh
cargo test --locked --offline -p fss-container --test pinned_recording_contract -- --test-threads=1
```

It passes 50 tests: 17 new closure/recording cases plus existing metadata, namespace, spool
capability and local-publication regressions. The test directly includes the production pure
object contracts, spool, publisher, custody readers and recording modules; it substitutes no
storage, custody or codec implementation. Native cases compare both AVC and HEVC with the
existing writer-backed loader while its writer lock is held, isolate unrelated corruption,
reject a checksummed source/index forgery through actual packet replay, enforce cumulative
quotas, and halt after a dynamic revocation during final rehash before reading another object.

The retained output is
[`2026-11-09-pinned-recording-native-tests.log`](validation/2026-11-09-pinned-recording-native-tests.log).
This proves these native components. It does not execute or qualify `ReferenceDeployment`,
the asynchronous runtime, the retained-import adapter or the CLI.
