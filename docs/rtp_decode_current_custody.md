# Current-custody delivery for retained RTP decoding

The additive `recovery::checked_decode` API composes the existing retained RTP decoder with
point-in-time custody verification. It preserves frozen-snapshot decoding, source identities,
parameter selection, native IDR recovery, capture uncertainty and privacy transforms. No
canonical import bytes, active policies or authority rows are changed by decoding.

## Library use

After an independently authorized `inspect_rtp_import`, call
`retained.decode_h264_checked(request, limits, deployment, cx)`. The request is the existing
`RetainedRtpDecodeRequest`; limits are `RtpCustodyDecodeLimits`. The consumer returns the same
`RetainedRtpDecodeStep` and masked frame types as snapshot decoding. Inspect `stats()`,
`read_bytes()` and `steps()` for cumulative accounting. A failed attempt is terminal and
requires a fresh inspection; it never falls back to cached snapshot delivery.

The canonical `DeletionIndex` is verified at admission through the bounded read owner.
Committed denial wins before unlink; an unreadable denial record cannot mean no deletion.
The protected flat RTP graph contains the root, metadata, source chunks, reconstructed NALs,
source capsules and original envelopes, plus the applied privacy policy. Initial recovery
has already recomputed the exact manifest and report from the retained original source.

Before each frame leaves the boundary, every protected object is read and digest-checked
again. Checking only that frame's own packets would omit prediction and decode-ahead
references. This deliberately conservative reference mode checks the entire graph until
exact codec reference-dependency receipts permit narrowing. All served Y, Cb and Cr planes
are still masked by the existing owner; neither raw packets nor unmasked pictures are added
to this delivery API.

The authority anchor stays fixed. Policy changes, deletion commits, stale roots, cancellation,
custody failures and exhausted budgets retire the decoder and queued output. Failed delivery
is not counted as a served frame; earlier refusal and skipped-group counts survive recovery.

## Bounds and scope

Source bytes, record count, graph entries, object allocation, cumulative read bytes and progress
steps have independent limits. Reads reserve the spool object ceiling before I/O, refund unused
bytes only on success, and retain the reservation on failure. Native mask-owner reads are
reserved separately and conservatively charged. Initial recovery and checked delivery use
separate allowances; IDR recovery replenishes neither decode nor delivery budgets.

The default delivery allowance is 512 MiB. Cost is approximately graph payload bytes times
served frames, plus admission and deletion-proof reads. This is a bounded forensic/preview
profile, not a high-throughput scan. Readback is a point-in-time observation, not future
availability, physical durability, live coverage or evidence of absence.

## Validation

Thirteen integration tests cover cold pixel equivalence, all-plane masks, policy drift,
reinspection, queued source loss, cancellation, exact parameters, independent limits,
wrong mask dimensions, incomplete imports, recovered histories, malformed tails, unreadable
deletion authority, noncurrent dependency loss and cumulative delivery reads.

```sh
bash scripts/check_rtp_decode.sh tests
bash scripts/check_rtp_decode.sh format
```

The saved candidate was reviewed and its uploaded Git blob identities checked, but no local
Rust toolchain was available. Native execution and formatting results must be read from an
actual run; no broader bead or release qualification is claimed.
