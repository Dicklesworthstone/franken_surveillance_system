# Live AVC source and decoded-picture binding

An H.264 decoder can release a picture after accepting a later access unit, and can
release pictures in display order. The live RTSP adapter associates every released
picture with its original encoded access unit using the native decoder's
`decode_index`. It no longer assigns an earlier picture the bytes, digest, or timestamp
of the later packet group that happened to release it.

## Source identity and archive order

The adapter retains each admitted access unit's exact Annex-B bytes, SHA-256 digest,
RTP presentation timestamp, host receipt time, and discontinuity flag until its decoded
picture becomes available. Decoded pixels are joined to that source by decode index.
The resulting `CameraFrame` carries that original source metadata.

Frames leave the driver in decode order. Storage concatenates encoded frames in
driver order, so a recording remains independently decodable when B pictures depend
on references that appear later in display order. Presentation timestamps may remain
nonmonotonic; they are not rewritten to manufacture display or capture order.
Host receipt times retain source order for the supervisor's continuity checks.

SPS/PPS bytes are retained at initial admission and IDR boundaries. The binding does
not add a new `CameraFrame` field or change the stored media-chunk schema.

## EOF and source failure

A socket EOF begins draining accepted protocol input. Once the protocol reports a
clean end, the adapter verifies the final access unit, finishes the decoder, and emits
every validated delayed picture before reporting the disconnect. The disconnect still
reaches the supervisor's gap and reconnect handling.

Native decoding errors, incomplete multi-slice pictures, packet/fragment loss, invalid
assembly, unmapped or duplicate output indexes, and source time reversal close the
decoder generation with a driver error. The next connection starts fresh prediction
and continuity state.

An IDR that explicitly discards older output can leave retained sources without decoded
pictures. The adapter reports that gap instead of waiting forever for a missing index
or pairing a different picture with it. Parameter-only retirement does not consume a
picture index and is not classified as a lost picture.

## Bounded buffering

The source association is limited to 32 pending pictures, 32 MiB per encoded access
unit, and 128 MiB of combined pending encoded bytes and released decoded planes.
The native decoder retains its own declared limits. Exceeding an association limit
fails closed and requires a new generation.

The driver releases one ready frame at a time. A large IDR/EOF burst therefore does
not eagerly allocate RGB conversions for all delayed pictures. Encoded bytes move
into the emitted frame rather than being cloned for each decoder output.

## Regression coverage

The tests use the repository's real B-pyramid AVC fixture to verify pixel digests,
original encoded source, presentation times, receipt times, and independent decoding
of the concatenated archive. Other cases cover incomplete multi-slice input, IDR
output discard, EOF tails, parameter-only retirement, explicit loss, resource bounds,
and a local RTSP socket exchange through the actual network driver.

The tests are included in the existing daemon regression entrypoint:

```sh
bash scripts/check_daemon_contracts.sh
```

The session handoff records which tests actually ran. These source-level contracts do
not substitute for live-camera, platform, or release qualification.
