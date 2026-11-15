# Retained MPEG-TS fixtures

These finite transport files remux existing, retained first-party codec test
inputs. They add independent MPEG-TS packetization and PSI/PES metadata without
re-encoding video. Neither FFmpeg nor any other external program is a production
or test runtime dependency; the files are checked in and unit tests read them.

| Fixture | Retained elementary input | Original bytes | SHA-256 |
| --- | --- | ---: | --- |
| `avc_i64.ts` | `crates/fss-codec-h264/tests/fixtures/baseline_i64.h264` | 4512 | `8fb304e88dc775c97806e9d3300e37ba68c4c66ade03ea6375e279ce6d934ff5` |
| `hevc_i64.ts` | `crates/fss-codec-h265/tests/fixtures/decode/i_64x64_ctu32_qp30.h265` | 4512 | `1b63cf8caeec3c5fc6d76c51606895df2abf8dd9f1d5363dc88c725c21fcc2f3` |

Generation used offline FFmpeg `7.1.5-0+deb13u1`, libavformat `61.7.103`:

```sh
ffmpeg -v error -threads 1 -fflags +genpts -r 25 \
  -i crates/fss-codec-h264/tests/fixtures/baseline_i64.h264 \
  -c:v copy -muxdelay 0 -muxpreload 0 -f mpegts \
  crates/fss-container/tests/fixtures/avc_i64.ts
ffmpeg -v error -threads 1 -fflags +genpts -r 25 \
  -i crates/fss-codec-h265/tests/fixtures/decode/i_64x64_ctu32_qp30.h265 \
  -c:v copy -muxdelay 0 -muxpreload 0 -f mpegts \
  crates/fss-container/tests/fixtures/hevc_i64.ts
```

Each fixture has 24 physical 188-byte packets, program 1, PMT PID 4096 and
video/PCR PID 256. The muxer inserts access-unit delimiters, so reassembled
Annex-B sizes are 3647 bytes for AVC and 3436 bytes for HEVC. Generated timestamps
are a fixture media cadence, never capture-time evidence. These fixtures contain
multiple pictures; the filenames identify their retained codec inputs, not a
promise of a single access unit.

## Admitted finite-file profile

The parser follows the transport, adaptation, PES and PSI grammars in
[ITU-T H.222.0](https://www.itu.int/rec/T-REC-H.222.0) sections 2.4.3 and 2.4.4,
and the 188-byte transport framing also described in
[RFC 2250 section 2](https://www.rfc-editor.org/rfc/rfc2250.html#section-2).

It requires a current, single-section PAT and PMT before selected video, stable
checked table bytes/CRCs, an unambiguous or explicitly selected program and
AVC/HEVC PID, legal selected-PID continuity, complete packet/PSI/declared-PES
lengths, and bounded reassembly. One exact duplicate packet is checked and
omitted from elementary copying; its original bytes remain in the source.
Optional PTS/DTS retain their raw wrapping 33-bit 90 kHz values. Unit builders
also split retained real AVC/HEVC bytes across PES and transport boundaries and
exercise pointer continuations, counter rollover, malformed input and limits.

M2TS/204-byte framing, encryption, indicated discontinuities, changed tables,
multi-section tables, adaptation extensions and optional PES grammars beyond
PTS/DTS are explicit refusals. A PES boundary is not a picture boundary. A
zero-length video PES is bounded by the next start or finite EOF; native codec
parsers must still validate access units and incomplete video tails. No fixture
or unit result grants live-camera coverage, time trust, or broader qualification.
