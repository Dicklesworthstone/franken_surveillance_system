# Bounded media probing

This is a reference implementation increment for **FSS-053** (`fss-x4a.12.2`). It extends the existing container-family probe with native AVC/HEVC configuration metadata. It does not close QL-MEDIA-001, TEST-MEDIA-MALFORMED-001 or GATE-040, and it does not establish camera or decoder support.

## Command

```sh
fss-probe < source-prefix
fss-probe --bytes 189 < source.ts
fss-probe --parameters < source.264
fss-probe --parameters --bytes 4096 --units 16 < source.265
```

The command reads only stdin and writes one diagnostic line. There is no network access, source retention, decoding, model execution or automatic fallback. The original family-only invocation remains available.

| Mode | Default byte allowance | Result |
| --- | --- | --- |
| Family | 189 | Container-family signature, payload domain and ISO-BMFF major brand when present |
| `--parameters` | 4096 | First complete admitted Annex-B configuration tuple, signalled dimensions/profile/level/depth, original parameter spans and inspection counts |

`--bytes` accepts 1 through 4096 for family mode and 12 through 4096 for parameter mode. `--units` is available only with `--parameters` and accepts 1 through 64. Invalid or repeated options refuse before reading stdin. Short reads are accumulated within the original allowance. Interrupted reads have a fixed retry ceiling, and output failures return an error status.

A successful AVC result has this shape:

```text
parameters container=annex-b codec=h264 scope=configuration-prefix coded_width=160 coded_height=128 display_width=160 display_height=128 bit_depth=8 profile=66 level=11 vps=none sps=START..END pps=START..END inspected_bytes=N inspected_units=N bytes=N
```

The numerical spans and counts come from the actual input. Spans are half-open byte offsets in that input, excluding Annex-B delimiters and trailing zero bytes. Source bytes are not printed. Non-alphanumeric ISO-BMFF brand bytes, except `.`, `_` and `-`, are percent-escaped so untrusted metadata cannot inject output lines or fields.

## Two different claims

Family recognition is allocation-free and examines at most the lesser of the supplied head, the caller's byte allowance and the hard 4096-byte ceiling. It reports the required prefix size when the allowance is insufficient. In particular, MPEG-TS recognition requires sync bytes at offsets 0 and 188; the second byte is never inspected outside the allowance. The default now includes both bytes. The first sync byte by itself cannot prove a transport stream.

ISO-BMFF recognition preserves the major brand from the appropriate ordinary or extended-size header. Impossible short `ftyp` sizes refuse. Independent overlapping signatures return `Contradictory`. The `00 00 00 01` extended-size word overlaps the Annex-B delimiter by construction; an explicit extended `ftyp` header resolves that particular ambiguity. A three-byte Annex-B prefix conflicting with an ordinary `ftyp` header remains contradictory.

Parameter recognition is a separate operation in `fss_container::probe::parameters`. It reuses `fss_packet::avc::{parse_sps, parse_pps}` and `fss_packet::hevc::HevcConfiguration` instead of duplicating codec syntax. Supported reference scope is:

- AVC Baseline/Main/High, 8-bit 4:2:0, with an SPS followed by a matching PPS.
- HEVC Main/Main10, single layer, 4:2:0, with a bound VPS/SPS/PPS tuple.

Only admitted base-layer HEVC parameter headers select HEVC. An ambiguous PPS-like header before an AVC SPS does not select AVC. Ordinary leading AVC slice and HEVC IRAP headers therefore cannot manufacture a mixed-codec contradiction. Repeated identical parameter sets before tuple completion retain the first source binding; distinct competing candidates or mixed codec declarations refuse. Once the first complete tuple is accepted, subsequent configuration changes are outside this result's scope.

HEVC parsing retains the native owner's **configuration-prefix** boundary: VPS profile/tier/level, SPS dimensions/crop/depth and PPS binding are interpreted, while the remaining parameter syntax is not certified. Neither AVC nor HEVC success certifies picture decoding, full profile/level conformance, sample timing, frame rate, source custody, live continuity, coverage or physical scene truth. Coded dimensions and cropped display dimensions remain separate fields.

## EOF, bounds and ownership

The native parameter API takes an explicit `end_of_source` observation. A caller may set it only after observing EOF; exhausting an allowance is not EOF. A final undelimited NAL is incomplete until either its next delimiter or actual EOF is observed. If an entire source is longer than the allowed prefix, its EOF cannot close the clipped prefix. The CLI never reads an extra byte just to decide whether EOF occurred. Consequently, an undelimited tuple ending exactly at `--bytes` needs a larger allowance to observe EOF, or a following delimiter within the allowance.

`ParameterLimits` independently limits head bytes, NAL count, coded width, coded height and coded luma samples. Defaults are 4096 bytes, 64 NAL units, 8192 by 8192 coded dimensions and 67,108,864 luma samples. Dimensions are metadata bounds; probing allocates no pixel buffers. Native parser allocations are confined to the bounded parameter bytes. Invalid limits fail closed rather than widening or clamping policy.

Delimiter scanning is linear in the inspected prefix. Cancellation is checked on entry, between units, every 128 delimiter-scan bytes and before/after native parsing; a final cancellation withholds the result. The caller supplies that cancellation observation. The stdin CLI does not install a separate cancellation runtime or signal handler.

`VideoParameters` borrows the exact parameter bytes through `ParameterSource`; Rust prevents those backing bytes being mutated or reused while the result is live. Debug output exposes ranges, not payloads. This lifetime binding is not a durable custody record: an ingest owner must still bind stream/configuration generations and retained source evidence before using metadata in its own publication protocol.

The cost boundary is the admitted source prefix plus at most 64 bounded native NAL inspections and one successful configuration parse. `inspected_bytes` is the highest inspected source offset, including a terminating delimiter; `inspected_units` counts complete units considered. These are inspection accounting, not measured CPU-time or decoding-cost claims.

## Exit statuses

| Exit | Meaning |
| --- | --- |
| 0 | The requested family or configuration-prefix metadata was identified |
| 2 | Invalid options/policy, I/O failure or bounded metadata allocation failure |
| 10 | The available prefix lacks enough information or a complete tuple |
| 11 | The requested container/codec/parameter syntax is unsupported |
| 12 | Conflicting signatures or parameter candidates prevent a coherent result |
| 13 | Native parameter parsing refused malformed/corrupt/mismatched input |
| 14 | Byte, unit, geometry or native syntax allowance was reached |
| 15 | Parameter cancellation, reserved in the CLI mapping for native cancellation outcomes |

Refusal of parameter extraction does not retract a separately established family signature. Neither result upgrades a source into a complete, retained or decodable stream.

## Focused verification

```sh
cargo test --locked --offline -p fss-container --lib probe::
cargo test --locked --offline -p fss-cli --bin fss-probe
```

The focused contracts cover retained AVC baseline/cropped fixtures, retained HEVC Main/Main10 metadata, exact source ranges, budget-tail noninterference, one-byte-short and one-unit-short refusals, geometry ceilings, EOF-versus-budget behavior, all cancellation checkpoints, contradictory candidates, cross-codec header aliases, native corruption/unsupported refusal, three-/four-byte Annex-B delimiters, trailing zero bytes, short/interrupted stdin reads, escaped brands and failed stdout writes. Native execution and broader qualification remain separately evidenced; the presence of these tests is not a passing qualification claim.
