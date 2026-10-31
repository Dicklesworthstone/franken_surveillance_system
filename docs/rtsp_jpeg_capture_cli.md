# Native JPEG capture and cold source replay

`fss-capture-rtsp jpeg` connects the existing native RTSP/TCP, RFC 2435 JPEG,
datagram publication and pixel decoder owners. It captures original selected
RTP **and RTCP**, then stops after the requested number of fully validated native
luma pictures. `fss-capture-rtsp jpeg replay` reopens an independently pinned
prefix and reconstructs source-linked images without a camera connection.

This is a separate JPEG profile. The existing AVC/HEVC recording, timing,
catalogue and recovery contracts remain unchanged. JPEG uses the same original
datagram storage format; it does not introduce another archive history.

## Capture one bounded source prefix

Choose a **new** absolute source-directory path whose parent already exists,
the actual camera's literal IP/port and RTSP subtree, an exact selected JPEG
payload, and the source's ingress, generation and SSRC. The native owner does
not resolve DNS or discover an unknown SSRC. Supply nonzero SHA-256 identities
for owner authority, the receive clock and original RTP/RTCP retention approval.

```sh
fss-capture-rtsp jpeg \
  --root /owner/private/porch-jpeg-source \
  --peer 192.168.1.40:554 --authority 192.168.1.40:554 \
  --presentation /stream/jpeg --control-root /stream \
  --sensor-id sensor:porch --stream-id stream:porch-jpeg \
  --generation 1 --ingress 41 --ssrc 7 \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --retention-evidence "$RTP_RTCP_RETENTION" \
  --payload-type 26 --stop-after-pictures 1 \
  --owner-authorized yes --plaintext yes --retain-originals yes
```

The command first prints a pure plan. It performs no filesystem, network,
secret or clock access without `--approve`. Review the exact settings and repeat
the same command with `--approve` followed by its printed `approval` digest.
Argument order does not change the digest; every effective route, identity,
bound, authentication option and replay selection does. Dynamic JPEG payloads
96–127 require the selected SDP offer to match `JPEG/90000`; static payload 26
may omit `rtpmap`. `--media-index` selects a media section explicitly.

On Unix the new source directory is private, mode 0700. The command refuses an
existing capture destination and never resumes a failed connection implicitly.
Source data is unencrypted. Capture and replay both authorize the existing
publisher's lock, recovery-hold, temporary-metadata cleanup and synchronization
effects. Those recovery effects do not authorize deleting source observations.
Native blocking filesystem/connect calls are bounded by their existing owners
and checked at their boundaries; this is not a hard realtime preemption claim.

Each complete selected interleaved datagram is published through the actual
root-last store before another media poll. Probation packets, duplicates and
malformed RTCP remain original observations. A complete refused RTP frame is
retained when the current storage authority still admits that operation.
RTSP control/authentication messages, opaque TCP chunks and unprocessed wire
tails are excluded. Remaining queued packet/fragment and unretained-tail counts
are reported on termination.

Every complete image is reconstructed and decoded by the actual native JPEG
decoder; the requested stop counts successful complete pixel validations.
Malformed image refusals remain explicit and may be followed by later independent
images. Work exhaustion, lease loss, source failure or an unmet picture target
fails the command. Stopping closes the local connection and reports possible
remote-session persistence; it does not assert a successful remote TEARDOWN,
camera EOF, calibrated capture time or scene coverage.

## Save receipts independently

Output is bounded JSONL using `fss.rtsp_jpeg_capture_cli.v1`. Preserve complete
rows independently from the source directory. The key observations are:

| Kind | Meaning |
| --- | --- |
| `started` | The exact approved plan, including all effective ceilings |
| `configuration_accepted` | Hash of the actual accepted DESCRIBE response, selected payload and reduced-RTCP mode; original control bytes are not stored |
| `source_published` | Durable original prefix pin, payload digest/length, channel and original receive timestamp |
| `rtp_admitted` / `rtcp_validated` | Independent native transport interpretation of that original |
| `picture_validated` | Complete encoded/luma/decoder digests, dimensions, RTP sequence interval and decoder counts |
| `reconstruction_refused` / `decode_refused` | An explicit refusal, without partial pixels or a fabricated complete frame |
| `operation_finished` | Final result, latest durable pin, any uncertain candidate, remaining-source accounting and actual runtime closure |

A prefix pin has `scope`, `head`, `datagrams` and `payload_bytes`; all four matter.
If publication becomes uncertain, the last confirmed prefix and exact candidate
remain distinct. Never substitute a candidate for a durable receipt. An output
failure can leave committed source in the archive even if its newest receipt
could not be delivered. Preserve the directory and previously delivered rows;
the command does not delete data or retry an uncertain publication.

Capture's image row provides a prefix commitment and native reconstruction
interval, but its `source_provenance` is null. Cold replay supplies the stronger
source-map proof below. Pixel bytes are deliberately not retained or printed;
these commands produce verified source and reproducible image receipts, not an
MP4, image viewer, live detector or image-export directory.

## Reopen the exact source with no network or credentials

Use the same source scope, payload, limits and independently saved configuration
evidence. Select an exact saved prefix; later archive growth is verified separately
and cannot silently extend the selected input. Remove capture's
`--stop-after-pictures` and authentication options, and add:

```sh
fss-capture-rtsp jpeg replay \
  --root /owner/private/porch-jpeg-source \
  --peer 192.168.1.40:554 --authority 192.168.1.40:554 \
  --presentation /stream/jpeg --control-root /stream \
  --sensor-id sensor:porch --stream-id stream:porch-jpeg \
  --generation 1 --ingress 41 --ssrc 7 \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --retention-evidence "$RTP_RTCP_RETENTION" --payload-type 26 \
  --prefix-head "$SAVED_HEAD" --prefix-datagrams "$SAVED_DATAGRAMS" \
  --prefix-bytes "$SAVED_PAYLOAD_BYTES" \
  --configuration-evidence "$SAVED_CONFIGURATION" --reduced-rtcp no \
  --owner-authorized yes --plaintext yes --retain-originals yes
```

Set `--reduced-rtcp` to the actual reported mode. Review this replay's own plan
and repeat it with its own approval digest. Route fields now identify historical
source scope; the replay runtime has no network or secret grant. A missing source
root is an error and is never created. The saved source root and all source bytes
are verified using the original custody format and current finite allowances.

Replay begins at ordinal one. Earlier cached quantization-table definitions
cannot be skipped. Each complete replay picture includes an opaque provenance
digest and its actual source dependencies: extended sequence, original ordinal,
root, payload identity, channel and receive time. Equal retransmissions cannot
replace the originally admitted packet. The source-map identity also commits all
copied, interpreted-header and generated JPEG ranges in the actual reconstruction.
See [the reference API](jpeg_datagram_reconstruction.md) for access to those maps.

Historical receive timestamps drive the deterministic replay scheduler. Current
owner time drives storage deadlines. Neither is promoted to a physical capture
clock. Prefix exhaustion retires incomplete fragments without calling media EOF
or advancing a future timer. A completed replay means the selected original
observations were examined and the final custody check passed; consult picture,
refusal and discard counts for its actual decoding outcome.

## Authentication and independent bounds

Plain capture is the default. Linux Digest capture explicitly adds
`--credential-file /owner/private/camera-secret --auth-realm EXACT_REALM` and
reuses the existing [private credential-file contract](rtsp_capture_cli.md).
The lease is rechecked around socket operations, rotation revokes it, and fresh
native entropy supplies each cnonce. Legacy MD5 or no-qop behavior requires the
existing explicit opt-ins. There is no implicit credential fallback, authentication
upgrade, redirect or reconnect. Cold replay rejects credential options.

`jpeg --help` lists all finite controls. Source count/bytes, disk bytes, packet
queues, image/fragment/table dimensions, operation steps, native decode work,
source-verification work, report bytes and elapsed time have separate ceilings.
One source-work and one decode-work account span the complete operation; opening
or decoding another item cannot reset them. At least 16 KiB of report allowance
is required, including an 8 KiB terminal reserve. A refused/broken output sink
stops before initial filesystem or network effects. Runtime work uses the actual
Process → Property → Sensor owner, custody obligation and drain/finalization
barrier; uncertain source publication prevents a successful quiescence claim.
