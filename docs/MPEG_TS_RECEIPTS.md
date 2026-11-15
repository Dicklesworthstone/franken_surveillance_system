# Retained MPEG-TS extraction receipts

The finite AVC/HEVC transport parser in `fss-container` can now produce a compact
`TsExtractionReceipt`. It is the provenance primitive for connecting an extracted
elementary stream to its original transport recording.

## What the receipt binds

The versioned canonical payload binds:

- SHA-256 identities and exact lengths of the complete original transport file and
  the reconstructed elementary stream;
- automatic or explicit program/PID selection and every parser resource limit;
- declared codec, selected program, video PID and PCR PID;
- inspected packet/table counts, duplicate count, PES count and payload-span count;
- a canonical commitment to every PES boundary, its raw PTS/DTS values and every
  original-to-elementary byte mapping.

Original-byte identity includes unselected PIDs, transport/PES structure and exact
duplicate packets. Successful elementary extraction does not allow those original
bytes to be replaced, dropped or reconstructed from a derivative.

Mapping rows are hashed in native order with bounded incremental hashing. They are
not duplicated inside metadata. The receipt is at most 512 bytes regardless of
recording length; exact rows are reconstructed by the existing bounded parser.

## Construction, decoding and verification

`TsExtractionReceipt::from_extraction_with_checkpoint` uses the selection and
limits actually retained by `MpegTsVideo`. Callers cannot supply a different
historical policy when constructing the receipt. Hashing checks cancellation
between 64 KiB chunks and every mapping/PES row.

`to_bytes` writes explicit canonical field ordering and network byte order,
followed by a SHA-256 checksum. `from_bytes` refuses unknown schemas, malformed
values, unsupported digest algorithms, inconsistent counters, invalid limits,
truncation, trailing bytes and checksum changes. It makes no claim that the
declared extraction occurred.

`verify_bounded_with_checkpoint` intersects current limits with the recorded
limits, parses the complete original again, and compares all commitments.
Current policy can narrow every parser allowance. It cannot be widened by an
untrusted historical receipt. Only a successful final comparison returns the
reconstructed stream and source mappings. Source read authorization and aggregate
I/O accounting remain the caller's responsibility.

The convenience `verify_with_checkpoint` uses recorded parser limits; its caller
must first admit those limits under current authority. A receipt is data, never a
read grant, effect capability or release qualification.

## Interpretation limits

PES boundaries are not access-unit or frame boundaries. Raw 33-bit timestamps
remain wrapping 90 kHz media values. They are not converted into capture time or
used to establish camera continuity, absence evidence or decoded-picture support.
The existing parser's finite-file subset and explicit refusals remain unchanged.
Changes to the extraction/encoding semantics require a new receipt version.

## Native retained-import integration

`fss_reference::ingest::mpeg_ts_import::import_mpeg_ts_file` uses this receipt to
publish one bounded original transport recording through the existing native
retained-media owners. `MpegTsImportRequest` carries a `FileIngestRequest`, an
explicit or unambiguous `TsSelection`, and independent `TsLimits`. The caller also
supplies its existing `ReplayCx` and one cumulative `WorkBudget`.

The `ADP-MPEGTS-FILE-001` publication retains the complete original transport,
canonical origin proof, reconstructed elementary chunks, access-unit and omission
map, and sensor capsules together. Retained range reads first replay the original
under the admitted finite profile; full verification rereads originals. The
verified cursor cache holds at most one 64 MiB elementary stream and never claims
continuous health of stored bytes. Original transport and elementary output have
separate 64 MiB ceilings, with at most 65,536 native access units and original
chunks. Retry can complete an unpublished suffix but cannot repair corrupted
already-published originals from the loose input.

Five integration contracts in `mpeg_ts_import_contract.rs` exercise this path
using real native AVC/HEVC decoder fixtures. They are authored but unexecuted;
run `cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --test mpeg_ts_import_contract`
on the qualification host before claiming retained decode success.

## Validation status

Seven focused Rust contracts cover both retained AVC/HEVC transport fixtures,
exact reconstruction, nonvideo-byte corruption, selection/policy identity, current
limit narrowing, canonical corruption, forged claims and late cancellation.
They were authored during an execution-environment outage and have **not yet been
compiled or run**. The earlier 117 container and 50 packet passing tests are
unchanged-baseline evidence only.

Required focused command:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-container --lib mpeg_ts::
```

The repository-owned qualification entrypoint and native DSR receipts remain
required for promotion. No broad media or release gate is closed by this source
increment.
