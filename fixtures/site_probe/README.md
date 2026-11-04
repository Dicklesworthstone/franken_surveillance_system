# Offline site probe media fixtures

These files exercise receipt production from a complete RTSP DESCRIBE response
and recorded RTP datagrams. They are deterministic laboratory inputs, not captured
camera sessions, authenticated server responses, or evidence of current liveness.
The one-source manifest uses a documentation-range IP address.

Both media streams preserve complete NAL bytes from existing, decodable codec
fixtures. They contain real picture syntax and entropy payloads, not synthetic
marker-only packets. The observer validates native picture assembly; these
fixtures do not imply that the probe performs pixel decoding.

| Fixture | Retained source | Pictures | RTP payload type | SSRC |
| --- | --- | ---: | ---: | ---: |
| `avc.rtpdump` | `crates/fss-packet/tests/fixtures/avc/baseline.264` | 4 | 96 | `0x11223344` |
| `hevc.rtpdump` | `crates/fss-codec-h265/tests/fixtures/decode/i_64x64_ctu32_qp30.h265` | 3 | 98 | `0x55667788` |

The source corpora document their synthetic-scene provenance and existing decode
oracles. No encoder, decoder, external executable, or network access is required
to regenerate these transport fixtures:

```sh
python3 fixtures/site_probe/generate.py
```

The generator verifies each source file's pinned SHA-256 before writing anything.
It copies the source parameter sets into the corresponding `.describe.rtsp` SDP,
packetizes the retained NALs as RFC 6184 single-NAL/FU-A or RFC 7798 single-NAL/FU
packets with at most 512 payload bytes, and writes standard rtptools rtpdump framing.

Packet sequence numbers start at 65534 and wrap. Picture timestamps start at
`0xfffff000`, advance by exactly 3600 ticks on the 90 kHz media clock, and wrap.
Recorded offsets are 0, 40, 80, and, for AVC, 120 milliseconds. Each stream starts
with an AUD packet for receiver probation. The final HEVC picture is closed by an
explicit EOS NAL with valid RBSP trailing bits; an RTP marker alone does not prove
that picture's boundary.

The response contains a deliberate `fixture-private-server-canary` Server header.
The CLI must expose only its digest, never the raw header value. Source/receipt
bindings still require the caller's exact manifest, response and dump byte pins.
CLI contract tests create malformed, incomplete, lossy, reordered, mixed-source
and variable-cadence variants in temporary directories; those variants are never
treated as successful observations.
