# Native HEVC Main tiles

The native H.265 decoder admits uniform and explicit tile layouts for Main and
Main Still Picture, eight-bit 4:2:0 streams. This extends the existing real pixel
decoder: retained HEVC, MP4/MOV, Matroska and RTSP recording sources reach the same
native range decoder, RGB conversion and direct package-inference paths.

## Decoding contract

The implementation follows ITU-T H.265 (01/2026), particularly clauses 6.3.1 and
6.5.1, the PPS/slice syntax and semantics, and clauses 8.6, 8.7 and 9.3. Each
picture has bounded raster-to-tile and tile-to-raster maps; signaled segment
addresses remain raster addresses, while decoding progresses in tile-scan order.
The final partially occupied CTB counts at its full CTB extent when checking the
Main-profile minimum tile width/height.

Each slice **and each slice segment** must either stay inside one tile or contain
complete tiles. Dependent segments inherit their logical slice's header and
continue entropy/QP state inside a tile. A tile start initializes CABAC contexts
and QP even when it is also a dependent-segment start. Every segment still counts
against the existing picture segment limit.

Tile entry offsets count original escaped NAL bytes, including emulation
prevention. The decoder converts them to RBSP boundaries without allocating a
map per source byte. Each tile substream gets its own bounded bit reader. Its
terminating bin, zero alignment, consumed byte boundary, entry count and final
slice exhaustion must agree before any complete picture is returned.

Spatial prediction, entropy-neighbor contexts and SAO merge candidates cannot
cross tile boundaries. The separate `loop_filter_across_tiles_enabled_flag`
controls deblocking and edge SAO across those boundaries. It does not make a
spatial predictor available. Existing slice-boundary filter rules apply as well.

Main and Main Still Picture forbid simultaneous tiles and WPP. That combination
is refused. Main10, other chroma formats, field-coded sequences, extension
profiles and additional layers remain outside the admitted profile.

## Limits and recovery

All existing NAL, dimension, luma sample, picture, DPB and segment ceilings remain
active. Tile counts are bounded to at most 40 columns and 44 rows, the largest
Main-profile level bounds, and to the actual CTB grid. Columns must span at least
256 luma samples and rows at least 64, using the standard's padded CTB definition.
Explicit widths and heights cannot be zero, overlap, exceed the picture or leave
an empty inferred final tile.

The three CTB maps cost ten bytes per CTB, plus two small arrays per tile. They are
allocated fallibly only for tiled pictures after SPS and tile-geometry admission.
Untiled pictures allocate no tile maps. Entry offset storage is bounded by the
tile count. Existing owners retain their access-unit cancellation and work
boundaries; the pure codec retains its fixed per-NAL and per-picture ceilings.

A corrupt or incomplete tiled picture publishes no partial surface. Its inherited
segment state is discarded, prediction waits for a new IRAP, and already completed
pictures retain their existing output behavior.

## Decoder generations and retained history

`Decoder::new_v1` preserves the previous immediate `Unsupported(Tiles)` refusal
at the PPS flag. `Decoder::new` admits the new bounded tile profile. No production
dependency or foreign codec is introduced.

The retained owner exposes `RecordedH265Range` for current inputs and
`RecordedH265RangeV1` for fixed historical recipes. Both aliases share the same
implementation and budget accounting. Watch, tolerant recovery, whole-recording
dwell (including incremental reconstruction), detector cascade and fixed health
owners explicitly select v1, so previously recorded unsupported-tile breaks stay
reproducible.

Untiled input histories keep the exact existing decoder identity and canonical
frame receipt bytes. Once a decoder accepts any tiled PPS, its later completed
pictures bind the new tile generation, including subsequent untiled pictures:
their complete range input history could not have passed the old decoder.

The new identity label is:

```text
fss-codec-h265:main-420-8bit:scalar-reference:output-order:rasl-skip-at-range-start:tiles:v2
```

Frame publication validates both generations without changing its receipt or
manifest format. Pixel-change observations and `fss-file` reports use the actual
receipt identity. Current `fss-video` operator plans bind tile-capable admission;
an old HEVC approval digest does not authorize the expanded profile. Existing
untiled frame identities remain unchanged.

## Independent evidence

`scripts/generate_h265_tile_fixtures.py` authors actual CABAC substreams and invokes
FFmpeg only as an explicitly authorized offline oracle. The committed streams and
SHA-256 files are in `crates/fss-codec-h265/tests/fixtures/decode/`. Rust tests never
invoke FFmpeg.

The corpus covers uniform and unequal two-dimensional grids, nonzero residuals
and QP changes, dependent and independent slices, emulation-prevention bytes,
nonzero P motion, partial edge CTBs, and deblocking/band/edge SAO. Filter variants
prove the boundary flag changes actual samples. The P fixture additionally checks
every luma sample against an independent one-pixel reference translation; the
partial-edge fixture checks its PCM corner directly against the authored pattern.

`tiles_invalid_partial_segment.h265` is deliberately nonconforming despite being
accepted by FFmpeg: a segment crosses two partial tiles. It is retained only as a
normative refusal/recovery regression. Oracle acceptance alone is not a claim of
bitstream conformance.

Native verification commands are:

```sh
cargo test --offline --locked -j1 -p fss-codec-h265
cargo clippy --offline --locked -j1 -p fss-codec-h265 --all-targets -- -D warnings
```

The retained cold-publication/legacy-byte tests and operator-plan regression are
authored beside their existing owners. They require the reference/CLI dependency
closure and are distinct from the lightweight codec-native proof; no unexecuted
runtime test is represented as passing.
