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
