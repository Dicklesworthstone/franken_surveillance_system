# Source-linked AVC receiver reference

Owning work: FSS-113, WP-050/WP-060. Implemented reference source and tests;
not production-qualified, a decoder, or a complete-picture certificate.

## Parameter-aware syntax

`fss_packet::avc` parses complete NAL bytes without Annex-B delimiters. SPS/PPS
parsing admits Baseline, Main, and High 8-bit 4:2:0 syntax with bounded dimensions,
reference counts, scaling lists, VUI/HRD, Exp-Golomb work and parameter bytes.
Coded dimensions are checked before cropping. Field/MBAFF and POC types 0/1/2
are retained. Timing metadata never becomes an invented capture clock.

Parsed PPS objects bind to exact immutable SPS bytes, not merely the reusable
numeric SPS id. Slice identity checks that binding again and applies use-time
limits. It reads a bounded prefix, not entropy-coded macroblocks. SPS/PPS suffixes
and trailing bits are validated. Slice bodies remain opaque.

`AvcSliceIdentity::starts_new_picture` implements the admitted primary-picture
identity comparison: frame number, PPS, field/bottom-field, reference-zero status,
POC fields and IDR identity. `first_mb_in_slice == 0` alone is not a boundary.
Data partitions, slice groups, SP/SI and extension-layer pictures fail explicitly.

## Assembly and failure propagation

`AvcAssembler` consumes owned complete NALs with original packet-source spans.
It admits only one exact SPS/PPS configuration per owner stream epoch; a parameter
change fences admission until a strictly newer epoch is validated. Byte, NAL-count
and age bounds are independent. Binding, time and source-order refusals do not
mutate pending state. Other failures return the rejected NAL intact and retire
affected derivative state with counts, bytes and source-sequence receipts.

Picture groups preserve their observed boundary class: next parsed picture,
next access-unit prefix, sender RTP marker, explicit sequence/stream end, or
unverified EOF tail. Observing macroblock zero and a marker is not proof that all
macroblocks arrived or can decode. Groups preserve discontinuity information.

Use `AvcReceiver` to compose `H264Receiver` and assembly. Ingest complete original
datagrams, then poll until Pending/Ended. Each source event owns its exact datagram
before separate bounded NAL-admission steps. Packet gaps, reconstruction errors,
fragment timeouts and restarts automatically invalidate affected pending pictures.
Rejected NALs remain owned in the output. No callback batches or ambient clocks
are introduced. Arrange the earliest returned wake even without network traffic.

Finish stops admission and drains accepted packets and queued NALs before picture
EOF. An incomplete FU at EOF retires its affected picture, rather than publishing
an apparently intact tail. Cancellation accounts separately for packet queues,
incomplete FU bytes, complete NAL queues and pending picture groups. Successful
restart returns old-state receipts; invalid new configurations leave it unchanged.

Source custody, capabilities, privacy, durable publication and RTSP transport remain
with their owners. The receiver opens no files/sockets, spawns no threads and grants
no authority. An emitted group does not certify decoding or physical continuity.

## Regression evidence

The three contract files contain 60 tests: 26 syntax, 19 assembly and 15 composed
receiver contracts. They include actual decodable synthetic baseline and cropped
High/B-picture bitstreams, exact configuration changes, malformed input, source
retention, reordered media timestamps, loss, deadlines, bounded pressure and restart.

```sh
cargo test --locked -p fss-packet --test avc_syntax_contract --test avc_assembly_contract --test avc_receiver_contract
cargo run --locked -p fss-packet --example avc_packet_replay
python scripts/check_avc_fixtures.py
bash scripts/qualify.sh --lane rust
```

The Rust replay emits source hashes, picture-group/NAL receipts and terminal buffer
accounting. The Python command is a laboratory-only independent syntax/FFprobe
fixture check against retained `expected.json`; it neither compiles nor executes
Rust. Fixture generation provenance is in `tests/fixtures/avc/README.md` under the
packet crate. Foreign encoders/decoders are laboratory oracles, never dependencies.

Authoring boundary: Python/FFprobe fixture checks passed for two clips and ten
pictures. Rust compilation, tests, Rustfmt and Clippy were unavailable in the
authoring container. Source presence does not advance FSS-113 or release gates to
qualified; full decoder/container/device integration and retained native receipts
remain separate work.
