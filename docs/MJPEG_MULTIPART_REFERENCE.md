# Compressed camera-entity bytes to foreground analysis

This WP-060/WP-090 integration adds `fss_codec_mjpeg::multipart` and
`fss_twin::mjpeg`. These are bounded synchronous Rust operations over supplied
owner-authorized bytes. They do not connect a camera, authenticate a device,
read a clock, activate calibration, or introduce a foreign production runtime.

## Multipart entity framing

`MultipartStream::new` takes an exact admitted `Content-Type` field value and
source generation. `push` accepts arbitrary fragments at explicit consecutive
entity offsets and stops after one complete part. The caller retains the suffix.
Both JPEG parts with and without `Content-Length` are supported. Present lengths
must equal the actual payload bounded by the following MIME delimiter. A complete
JPEG end marker alone does not publish a part before its delimiter is validated.

Quoted boundaries, case-insensitive media/header names, bounded transport padding,
and a final closing delimiter without a trailing CRLF are supported. The CRLF
preceding the delimiter belongs to that delimiter, not to the JPEG. Boundary
values are not guessed, lowercased, or stripped of literal leading hyphens.
Duplicate headers, folded lines, bare-LF headers, ambiguous delimiter prefixes,
non-JPEG types and unsupported content/transfer encodings fail explicitly.
Vendor timestamp headers remain uninterpreted source text, never capture timing.

Each `MultipartFrame` retains the exact raw opening delimiter, headers, JPEG and
following delimiter with half-open source ranges and hashes. Adjacent parts share
the same boundary bytes by design. Preamble and epilogue are bounded and retained
in `MultipartEnd`. These are offsets in the **dechunked HTTP entity**, not original
TCP packets: upstream custody must preserve the transfer-decoding relationship.
The parser does not implement HTTP response/header parsing, chunked transfer,
compression, authentication, TLS, network access or reconnect policy.

Framing checks the JPEG envelope; `MultipartFrame::decode` performs the existing
complete entropy/decode validation. A later corrupt part never creates a whole-
entity completion. `finish` requires the explicit closing delimiter; a network
loss is not automatically clean EOF. Every failure latches. `abort` consumes the
parser and returns all unexposed source spans without allocation or spare budget.
Previously emitted frames stay owned by their caller.

Limits: 16 MiB per encoded image, 16 KiB per header block, 32 unique fields,
1024 bytes per header line, a 1-70 byte boundary, 64 bytes of delimiter padding,
and 64 KiB each for preamble/epilogue. Defaults narrow wrappers to 4096 bytes.
A 144-byte allowance bounds delimiter lookahead beyond the JPEG size. Caller
work is charged throughout; resource exhaustion is not permission to prune parts.
The grammar follows RFC 2046 section 5.1.1 with the explicit narrower subset above:
https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1 .

## Compressed-frame analysis integration

`mjpeg::decode_rectified` joins complete native JPEG luma decoding to the existing
lens correction and permission-mask projection. Source receipts retain compressed
bytes, decoded pixels, decoder identity, exposure, calibration and original mask.
The decoder generation is part of the image-domain identity. Full-range JPEG
cannot accidentally receive another video-range expansion. Unknown/private image
regions preserve the existing explicit mask semantics.

`JpegBackground::build` consumes selected reference images from that same path;
`JpegBackground::detect` processes a compressed query through rectification and
frozen-background comparison. It exposes the existing exact masked crops and
explicit external contact-proposal preparation, not invented feet, semantic target
classes, identity assignments or threats. The background never absorbs stopped
objects automatically. Original capture intervals remain separate owner inputs.

`mjpeg::stream::detect_framed` accepts the raw concatenated-JPEG framer's result;
`mjpeg::multipart::detect_multipart` accepts a MIME part. Both verify independently
expected stream/entity generations and frame hashes before decoding, preserving
source ranges alongside decode, rectification and foreground receipts. The two
entrypoints reuse the same decoder and analysis path, not parallel detectors.

## Reproduction and evidence boundary

```sh
cargo test --locked --offline -p fss-codec-mjpeg
cargo test --locked --offline -p fss-twin --test mjpeg_pipeline_contract
cargo run --locked --offline -p fss-codec-mjpeg --example decode_multipart -- ENTITY SHA256 'multipart/x-mixed-replace; boundary=frame' grayscale
python3 -B scripts/test_mjpeg_reference.py
python3 -B scripts/test_mjpeg_stream_reference.py
python3 -B scripts/test_mjpeg_multipart_reference.py
python3 -B scripts/test_mjpeg_native.py
python3 -B scripts/test_mjpeg_stream_native.py
python3 -B scripts/test_mjpeg_multipart_native.py
```

The file examples bound reads and verify independent input hashes. They are
owner-run integration harnesses, not a replacement registered `fss/1` API. Frames
are printed only after actual decode; final completion requires every requested
frame and entity termination to succeed.

The 21 independent Python reference tests passed: five codec, eight raw-stream,
and eight multipart controls. The multipart oracle uses separately formulated
whole-buffer framing and Python's MIME parser, including every fixture two-chunk
split, exact ranges, truncation, optional lengths, metadata and header conflicts.
These are independent controls, NOT execution of the Rust parser or decoder.

There are 60 authored Rust tests across this codec and its twin integration:
35 recovered codec/raw-stream tests, 16 multipart contracts and nine compressed-
image integration contracts. They include real encoded fixtures, all fragment
splits, malformed suffixes, cancellation, source mismatch, exact limits, and a
MIME-frame-to-foreground composition. Native compilation/tests have NOT executed:
Cargo is unavailable. All three native replay drivers return NOT_RUN (exit 3),
never a substituted passing transcript. Real camera/footage qualification, HTTP
transport ownership, H.264/HEVC, semantic detection/contact estimation, persistent
publication and the always-on Asupersync service remain open. No release gate or
broad bead is closed by this addition.
