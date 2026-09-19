# Retained JPEG decode pipeline

This reference composition connects completed ADP-FILE imports to the canonical production
`fss-codec-mjpeg` decoder. It does not call the separate reference colour decoder, invoke a
foreign process, or pretend Annex-B H.264 is decoded. The output is complete, full-range Y
(luma), with the original encoded bytes and source capsule retained as provenance.

## Library execution

Use `fss_reference::ingest::recorded_decode::{RecordedDecodeRequest, RecordedFrame}`.
Select the exact import identity and segment index, explicitly supply `Grayscale` or `YCbCr`
component interpretation, and set independent source-read and codec ceilings. Pass a
`DecodeBudget` to `RecordedFrame::decode_and_publish`. One shared budget accumulates actual
codec work across multiple frames. Work units are deterministic operations, not milliseconds,
energy, or a fabricated full-resource measurement. A cancellable codec budget accepts an
owner-controlled cancellation flag; the deployment `ReplayCx` is checked at composition
boundaries, including after decode and before staging.

On success the graph retains raw compressed segment bytes, raw tightly packed Y samples,
the exact original capsule, import manifest/root and canonical decode receipt. The root is
published last through the existing local publisher and ledger bridge. A final `decode_receipt`
delta in the cognition plane establishes completion. The original capsule is never rewritten
or upgraded merely because decoding succeeded.

`RecordedFrame::open` reopens a completed derivative without the original source path or
another decode. It revalidates retained source, the exact receipt, final delta, publication
identity and luma checksum. `verify_by_replay` also reruns the canonical codec and compares
pixels, dimensions, codec accounting and work units without changing authority.

Capture intervals and clock basis are copied from the exact authority-held source capsule.
No EXIF orientation, ICC transform, lens correction, timestamp reconstruction, live coverage,
absence claim, person detection or alert authority is implied. The source interpretation is
explicit: ambiguous RGB/CMYK and unsupported JPEG coding processes fail in the canonical codec.

## Recovery and refusals

Successful retries reuse the same root and final batch; they do not append duplicate decode
claims or substitute a later global anchor. Decoder failure, exhausted work, bad source,
wrong interpretation or a pre-publication cancellation cannot publish partial pixels.

A failure after root publication but before the final decode delta may leave a durable root
whose decode operation is incomplete. `open` refuses it. Repeating `decode_and_publish` with
the same recipe resumes the final transition. An error may leave staged immutable objects;
this is not a claim of atomic rollback. Existing tombstones and publication conflicts are not
bypassed. Ordinary readers never truncate or repair journals.

## Binary receipt v1 (format owner: fss-reference retained-media composition)

This is internal reference evidence, not a replacement for the universal agent response
protocol. Its domain is `fss.recorded_luma_receipt.v1`; its current migration rule is exact-v1
or explicit refusal, never silent conversion. The receipt is capped at 4096 bytes. It uses
the existing checked canonical encoder in this exact field order:

1. Length-prefixed magic `FSSYREC1`, big-endian u32 version 1, domain text.
2. SHA-256 import identity, import root, import-manifest digest, canonical import-completion anchor.
3. u64 source segment index and file offset; capsule digest; complete canonical `SensorCapsule`.
4. u32 coded width and height; SHA-256 encoded source, luma and decoder identities.
5. u8 interpretation (0 grayscale, 1 YCbCr); u64 MCU count, entropy-block count, restart count,
   metadata-segment count, metadata-byte count and charged codec work units.

The content-addressed parent manifest authenticates the receipt's expected checksum within
local custody; a self-consistent checksum is not remote principal authentication. Dimensions
are bounded by the canonical codec: each axis <=4096, at most 4,194,304 pixels, encoded input
<=16 MiB. Unknown magic/version/interpretation, trailing bytes, truncated fields, altered
source binding and incompatible decoder identity are refused. Previous generation receipts
remain immutable; future readers must implement an explicit version/decoder migration policy.

The derived key binds the immutable import root, segment index, exact codec identity and
interpretation. Admission ceilings do not alter that key: a larger work allowance cannot
change the pixels or silently replace an existing result. The canonical object graph includes
both raw-pixel and compressed-source identities. PGM rendering is a separate export, with a
separate byte digest, and does not change the underlying evidence.

This implementation and its adversarial/restart/cancellation tests do not establish production
qualification. Run the repository's pinned-nightly Rust and local qualification lanes before
promoting a release claim.
