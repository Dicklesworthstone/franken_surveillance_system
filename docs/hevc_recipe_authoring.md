# Authoring a portable HEVC recovery recipe

`fss-archive author-hevc-recipe` turns an explicitly supplied source interpretation
and per-picture timing schedule into the **existing** canonical HEVC recipe. No
custom Rust caller is required. The command replays pinned cold originals, matches
each expected RTP timestamp to an actual native picture request, and records the
full request identity and observation count. It never infers DTS, duration,
composition offset, missing parameter sets, or a picture boundary.

This is independent of camera acquisition: no camera, DNS resolution, credential
lookup, or new network connection occurs. The original route in the draft only
identifies the source. Digests name evidence and approvals; they do not authenticate
an external principal or grant access to another operator's store.

## Required inputs

Keep the original source-first capture scope and saved datagram prefix, original
VPS/SPS/PPS, recording scope, and independently established media timing. Supply a
regular UTF-8 JSON file matching `schemas/hevc_recipe_draft.v1.json`. Every field is
required and unknown or duplicate keys refuse. The following illustrates the shape;
replace the named strings with the **original** identities, parameter bytes and
complete schedule, not fresh values inferred from retained picture counts:

```json
{
  "schema": "fss.hevc_recipe_draft.v1",
  "source": {
    "ingress": "73", "generation": 1, "ssrc": 7,
    "peer": "127.0.0.1:554", "authority": "camera.local",
    "rtp_channel": 0, "rtcp_channel": 1,
    "receive_clock": "sha256:<original clock digest>",
    "retention_evidence": "sha256:<original retention decision digest>",
    "head": "sha256:<selected datagram prefix head>",
    "datagrams": 3, "payload_bytes": 2048
  },
  "recording": {
    "sensor": "sensor-owner-camera", "stream": "stream-owner-camera",
    "anchor": "sha256:<original recording anchor>", "time_scale": 90000,
    "timing_evidence": "sha256:<independent timing basis>",
    "configuration_evidence": "sha256:<original transport/configuration basis>",
    "payload_type": 98, "reduced_rtcp": false, "sprop_max_don_diff": 0,
    "vps_hex": "<original NAL bytes in lowercase hex>",
    "sps_hex": "<original NAL bytes in lowercase hex>",
    "pps_hex": "<original NAL bytes in lowercase hex>"
  },
  "timings": [
    {"rtp_timestamp": 9000, "decode_time": 0, "duration": 18000, "composition_offset": 0}
  ]
}
```

Parameter NALs exclude Annex-B start codes. Each accepts 1..32768 decoded bytes.
`ingress` is a canonical nonzero decimal string to preserve all 128 bits. Other
integers are JSON decimal integer tokens, not strings, fractions, or exponent
notation. Timing rows are in native decode-request order. Raw RTP timestamps are
matching guards and may wrap; their values never determine the supplied media
clock. Generation and receive clock in the recording scope are bound to the
explicit source scope. A late missing, extra or mismatched row refuses the whole
recipe even when earlier preview windows were valid.

The command uses a fixed, bounded native interpretation: current default packet,
reorder, no-DON, grouping and collector policies. Those complete values are saved
in the generated canonical recipe and covered by its approval. This does **not**
claim to recover the original live poll schedule. Nonzero DON and a schedule that
would require an unrecorded manual mid-prefix seal refuse. More specialized
policies remain available through the typed library.

## Preview, approve, publish

Hash the exact draft file bytes and retain that digest outside the file:

```sh
sha256sum draft.json
fss-archive author-hevc-recipe \
  --root /absolute/existing/source-store \
  --draft /absolute/draft.json --draft-id sha256:<file-digest>
```

The digest is checked before opening the source store. Preview uses its ordinary
exclusive lock and recovery synchronization, and performs native source reads.
It is **not** a no-I/O preview or a forensic read-only open. It publishes no recipe,
recording window, or completion root. Preview windows are discarded derivatives;
their original datagrams remain in the independently retained source archive.

Retain the returned `recipe` identity and `recipe_root`. Publication requires a
second invocation with the same draft digest and that exact recipe identity:

```sh
fss-archive author-hevc-recipe \
  --root /absolute/existing/source-store \
  --draft /absolute/draft.json --draft-id sha256:<file-digest> \
  --commit yes --approve-recipe sha256:<preview-recipe-identity>
```

All timing rows must execute successfully before publication becomes possible.
The existing source-closed recipe publisher verifies the originals, stages the
canonical recipe, and publishes its manifest root last. `recipe_status` is
`not_requested`, `published`, or `already_durable`. An exact approved retry is
idempotent. An altered draft, wrong approval, changed original or conflicting
publication refuses; no existing source is repaired, deleted, or overwritten.

The new command only **authors and publishes instructions**. Use the existing
operator to execute and publish the resulting recordings:

```text
fss-archive check-recipe --codec hevc ... --recipe-id <recipe> --recipe-root <recipe_root>
fss-archive reconstruct-recipe --codec hevc ... --recipe-id <recipe> --recipe-root <recipe_root> --commit yes
```

These commands additionally require the original source scope and independent
bounds described in `fss-archive help` and `docs/hevc_recording_recipes.md`.
No new recording or recipe format is introduced.

## Honest boundaries and bounds

`schemas/hevc_recipe_authoring.v1.json` defines the complete report. It preserves
selected and observed source heads, timing/preview counts, unread datagrams,
incomplete fragments and groups, queued NALs, and actual end-of-bitstream. Reaching
a saved prefix is never treated as TCP EOF. An empty or incomplete prefix may
produce an empty recipe with zero preview windows, not a fabricated picture.
`capture_complete` and `recording_published` are always false for this command.

A later valid source append does not change an older recipe's selected input. The
whole observed chain is verified and revalidated before publication, so the older
prefix does not conceal missing or corrupt later originals. No append is truncated
on disk. Source datagrams remain governed by the original retention decision;
metadata does not enable additional source retention or encryption.

Current timeout, total work, total steps, source inventory, draft size, timing
count, cumulative preview-window count/bytes and physical spool limits are finite
and independent. Preview output bounds count **all** windows even though only one
preview window is held at a time; new windows never replenish those allowances.
Use `help` for the exact bound options. Parser admission is at most one MiB and
4096 timing rows, with the existing JSON depth, node and string ceilings.

The draft-file backend is explicitly Linux x86_64/aarch64: nonblocking,
no-follow regular-file reads refuse symlinks and special files. Other targets
return a typed backend-unavailable error. The native authoring library remains
portable. A requested publication may have committed if its acknowledgement or
stdout delivery fails: reconcile or retry the exact approved identity, never
assume that an absent final report proves no write occurred.

Native library and process tests cover strict input, approvals, bounds, source
corruption, immutable older prefixes, cold canonical replay, exact publication
retry, cancellation and fragment accounting. A separate native test reopens the
authored recipe, reconstructs and publishes into another store, takes the original
source/recipe store offline, and pixel-decodes the resulting HEVC recording.
These are deterministic reference results, not physical-camera, power-loss,
throughput, storage-encryption, or release qualification.
