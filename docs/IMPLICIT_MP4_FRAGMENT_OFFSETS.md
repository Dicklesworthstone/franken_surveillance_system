# Inherited offsets in multiplexed fragmented MP4

The native AVC/HEVC reader resolves selected video fragments whose byte base
depends on preceding track fragments. This advances FSS-115 / FSS-053
(`fss-x4a.12.14`, `fss-x4a.12.2`); both broad beads remain open. The existing
`AvcMp4::parse*` and `parse_inband*` entrypoints, tail recovery, and the file
adapter's `mp4avc` / `mp4hevc` selections receive the new profile.

## Addressing and source preservation

The addressing rules follow ISO/IEC 14496-12, sections 8.8.7 and 8.8.8:

- An explicit `tfhd.base_data_offset` wins, including when
  `default-base-is-moof` is also present.
- Otherwise that flag selects the enclosing `moof` start. Without either form,
  the first track fragment starts at the `moof`; a later one inherits the
  preceding track fragment's final data cursor.
- A signed `trun.data_offset` is relative to that base. Without it, runs
  continue from the preceding run, or from the base for the first run.
- Inheritance carries the final run end, even when an earlier run was placed
  farther forward in the file. Each `moof` establishes a fresh context.

The [MPEG ISO BMFF reference implementation](https://github.com/MPEGGroup/isobmff)
uses this final-cursor model in `MovieFragmentAtom.c::mergeFragments` and
`TrackFragmentAtom.c::calculateDataEnd`. FSS uses checked platform-sized and
signed offset arithmetic.

The reader traces only dependencies of selected video. Independently addressed
video does not cause unrelated audio payload tables to be interpreted. A required
predecessor must have a known track, unique same-track `trex`, one sample
description, and a self-contained data reference. Its sizes resolve from its own
run, fragment, then track defaults; video defaults cannot supply an audio extent.
A dependency chain stops when its predecessor has an independent base.

Every consumed sample must fit wholly inside one complete `mdat`. Consumed run
extents and any initial indexed samples share an overlap check. Selected video
retains original sample ranges, decode/composition ticks, durations, sync
assertions, and Annex-B source mappings. Other tracks contribute extent metadata;
they never advance the video clock. No audio decoder, audio output, production
dependency, custody encoding, UTC conversion or source-availability assertion is
introduced.

## Limits and refusals

Required sample descriptions and run entries consume the same
`maximum_table_entries` allowance as video metadata. `maximum_samples` remains
the selected-video limit. Track and box ceilings bound dependency metadata and
cached defaults. Cancellation is checked for each consumed sample and during
dependency traversal. Failures do not publish a partial index.

Missing or duplicate relevant defaults, unknown tracks, nonlocal references,
unsupported sample descriptions, malformed counts, out-of-file or overflowing
offsets, overlaps, and exhausted budgets refuse. Fragment-side encryption,
grouping and subsample tables remain unsupported when consumed.

A `duration-is-empty` fragment is explicitly unsupported: its separate empty-time
semantics are not treated as ordinary media. Supplying both first-sample flags
and per-sample flags is a layout error. A required predecessor with no samples
or any zero-count run refuses; the parser never invents a base from `mdat.end`.
Independently addressed selected empty fragments retain their no-sample behavior.

## Validation and reproduction

See `IMPLEMENTATION_STATUS.md` for the exact development and recovery scopes.
The original working implementation passed 87 native tests before an executor
outage: 13 new inherited-offset contracts, all 48 container unit tests and 26
selected AVC/HEVC regressions. The three malformed-media gauntlets exercised
58,000 mutants. Both frozen fragmented recordings preserved all ten video samples
and their timestamps and Annex-B bytes; the original new target also checked all
truncated prefixes, shared budgets and every parser cancellation checkpoint.

The recovered `implicit_fragment_contract` target retains five original tests:
audio-before-video source preservation, per-track default precedence, continued
and backward-positioned runs, dependency chains across movie fragments, and
explicit-base precedence with signed offsets. These test bodies passed within
the earlier full target; the reduced recovered target has not been rerun.

Production changes were recovered from recorded edits after the outage. The
published recovered source has been reviewed but has not been recompiled in a
native environment. The original 13-contract source could not be recovered in
full; pre-outage execution does not establish a pass for the exact recovered
tree. Re-run the retained tests and complete container suite before treating this
revision as natively verified:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-container
```

The packet/container production dependency closure contains only these two
crates and the standard library. Direct pinned-`rustc` execution of those real
libraries was the development fallback when Cargo's development dependency
closure was killed while compiling unchanged `fss-core`. That fallback does not
qualify codec execution, retained-store/file-adapter integration, the full
asynchronous runtime, `scripts/qualify.sh`, physical cameras or production use.
