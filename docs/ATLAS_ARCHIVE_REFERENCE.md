# Reloadable localization atlases

`fss_twin::atlas_archive` implements `encode_atlas` and `decode_atlas` over the
existing `LocalizationAtlas`, not a second matcher or camera database. This is
an implemented reference slice of BTI-002. It does not qualify property geometry,
activate calibration, retrieve private source images, or complete BTI-004/008.

An archive retains all landmarks (including unknown coordinate errors), original
reference exposures/image domains, descriptors, physical-point bindings, a source
manifest root, and each reference's source-recipe and complete allowed-mask hash.
The source manifest must retain map-to-property alignment, camera/PTS identities,
image conversion, exposure partition, selection, and associated evidence records.
Missing source bytes stay missing: hashes are not proof of retrievability or access.

The caller independently supplies the whole-file SHA-256, provenance root, admitted
descriptor identity, and exact imported `PropertyTwin`. Import verifies those,
checks the trailer, validates canonical ordering and numeric representation, then
runs `LocalizationAtlas::new` on the complete graph. The normalized semantic digest
must also match. Nothing is exposed from a valid prefix with a malformed suffix.
Local geometry handles are rebound from the caller's twin, not serialized to disk.

## FSATLAS1 wire format

Little-endian integers and IEEE-754 f64 bits; no padding, URLs, strings or scripts.
Nonfinite floats and negative zero are refused. All identities below are SHA-256.
Header: `FSATLAS1` (eight bytes), u64 payload length.
Payload:

1. Twin package, descriptor construction, normalized atlas, and provenance roots
   (four nonzero 32-byte digests).
2. Landmark, reference and binding counts (three u32 values).
3. Landmarks in strictly increasing ID order: ID u64, physical group u64, twin
   feature ordinal u32, world position 3*f64, evidence digest, error tag u8
   (0 unknown; 1 followed by three absolute-error f64 values).
4. References in ID order: ID u64; exposure, pixel and image-domain digests;
   width/height u32; source-record and allowed-mask digests; feature count u32.
   Features in ID order: ID u64, pixel-edge location 2*f64, descriptor 4*u64.
5. Bindings sorted strictly by (landmark, reference, image feature), each 3*u64.

Trailer: SHA-256 of header+payload. The caller's whole-file digest includes this
trailer. Normalized atlas identity is the existing reference fingerprint, not a
new assertion of durable fss/1 schema admission. No encryption/authentication is
implied by a checksum. Authorization, custody, publication, retention and deletion
remain with their existing owners; descriptors inherit source sensitivity.

Maximum whole-file size is 8 MiB, landmarks 4096, references 64, features/reference
512, bindings 32768. Count-derived byte lower bounds precede allocations. Shared
work is charged before hashing, and cancellation is polled during graph parsing.
Serialization returns bytes only; it cannot overwrite an accepted source or file.

## Verification

`cargo test --locked --offline -p fss-twin --test atlas_archive_contract` covers
round-trip identity, preserved matching, source/mask roots, unknown errors, every
fixture truncation and one-bit-per-byte mutation, resealed malformed numbers/counts,
stale twins, cancellation and insufficient work.

`python3 -B scripts/test_atlas_archive.py` independently constructs the source twin,
semantic fingerprint and wire golden. Its four tests passed during authoring,
including all 5,648 single-bit mutations and 706 truncated prefixes. The 706-byte
archive's whole digest is
`36764662860d5f075820570a1e42c4ff93d3a24763999ed58b3fb64e356812e3`.
This is a synthetic fixture, not a private property export. The Rust test compares
to this independent golden; no Rust compiler is available in the authoring runtime,
so compilation and Rust execution remain unverified. No release gate is closed.
