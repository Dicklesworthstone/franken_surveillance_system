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

## Explicit M2TS framing

`MpegTsVideo::parse_framed` and `parse_framed_with_checkpoint` accept an explicit
`TsFraming::Ts188` or `TsFraming::M2ts192`. The existing `parse` and
`parse_with_checkpoint` entry points keep their 188-byte behavior. M2TS consists
of a four-byte opaque prefix followed by each 188-byte transport packet; the
parser does not guess framing, strip a loose header or resynchronize damaged
files. Source-size and packet-count limits apply to the selected physical framing.

The complete original digest includes every prefix and all unselected packets.
Payload spans refer to absolute offsets after each prefix in that original file.
Exact retransmission checks compare only the inner transport packet, so differing
prefixes on duplicate packets do not create a false continuity conflict. Prefix
bits are never promoted to capture time, synchronized clock evidence or health.

Standard TS receipts retain the exact `fss.mpeg_ts.extraction_receipt.v1`
encoding. M2TS uses `fss.mpeg_ts.extraction_receipt.v2` with explicit framing tag
`2`. V2 refuses any other tag, including an alternate encoding of standard TS.
Recorded source lengths and packet counts must agree with the selected stride.
Current-limit intersection and full original replay remain mandatory during
bounded verification; changing only an opaque prefix invalidates the source pin.

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

The container library compiled on the pinned compiler on 2026-11-23. An
independent harness compared the v1 receipt encoder from commit
`7286814285fa8c35912d6899f0605f035fcbfdba` with the current encoder and established
byte-for-byte equality for both AVC and HEVC fixtures (299 bytes each). The
fixed vectors are retained in `tests/fixtures/avc_i64.receipt-v1.hex` and
`tests/fixtures/hevc_i64.receipt-v1.hex` under `crates/fss-container`.

The focused library suite remains pending execution on the shared build host.
It includes the earlier source/selection/policy/corruption/cancellation contracts
plus explicit M2TS source mappings, prefix custody, continuity, malformed framing,
exact bounds, receipt version/tag refusals and legacy byte fixtures. Neither the
compiled library nor the independent encoder comparison substitutes for that
suite or the native retained-import tests.

Required focused command:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-container --lib mpeg_ts::
```

The repository-owned qualification entrypoint and native DSR receipts remain
required for promotion. No broad media or release gate is closed by this source
increment.
