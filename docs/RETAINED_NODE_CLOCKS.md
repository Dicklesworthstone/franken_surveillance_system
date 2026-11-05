# Retained node clock observations and UTC candidate lookup

This bounded AVC/HEVC path connects an actual native capture's monotonic packet
admissions to a retained UTC interpretation. It advances VIT-019 and VIT-008;
it does not provide an always-on recorder, camera exposure time, or continuous
coverage. The implementation and its native contracts are present, but execution
qualification is pending under the resource limits recorded in
[implementation status](../IMPLEMENTATION_STATUS.md).

## Capture with an explicit local clock source

Add `--clock-ntp-peer 127.0.0.1:123`, or a canonical IPv6 loopback endpoint, to
an existing `fss-capture-rtsp` AVC/HEVC plan. Planning remains pure. Inspect its
`node_clock` policy and repeat the identical arguments with the returned
`--approve` digest. A pre-existing approval cannot enable this option.

The approved native owner makes one basic NTPv4 exchange before connecting to
the camera or creating the archive directories. It uses the capture's existing
`TaskClock`, with a separate approval-bound network resource. The local daemon
must already be configured by its owner to answer on that exact endpoint.
There is no DNS, discovery, clock adjustment, automatic retry or refresh.

| Bound | Admitted value |
| --- | --- |
| Clock-enabled capture lifetime | `--timeout-ms` at most 60000 |
| Recording windows per attempt | `--max-windows` at most 64 |
| Exchange | One request, at most one reply, at most one second |
| UDP payload reservation | 97 bytes: 48-byte request and 49-byte oversized-reply guard |
| Valid basic reply | Exactly 48 bytes; a successful exchange consumes 96 payload bytes |
| Receive polls | At most 1024, including polls with no reply |
| Host sample bracket | At most 25 milliseconds |
| Drift/slew assumption | At most 500 parts per million; this is an assumption, not measured precision |
| Correlation age | At most 60 seconds from the synchronization origin |
| Clock correction and per-instant uncertainty | At most 10 seconds each under the fixed profile |
| Retained read coordinates | At most 65536 unique admission keys |
| Clock index and manifest | At most 16 MiB together |
| Additional live/index memory reservation | 64 MiB |

Existing spool byte/object/root quotas still apply to the companion. This option
does not silently increase the archive's storage quota. The extra bounded
storage-operation allowance and all clock limits are included in approval.

Omitting the option preserves existing approval bytes, recording identities,
network grants, capture limits, and output shapes. In a finite reconnect campaign,
each child attempt retains the option but obtains a new exchange under its own
fresh generation and receive-clock identity. No witness moves between attempts.

## What the timestamps mean

The TCP owner supplies a monotonic `admitted_ns` before each native read. Source
packet packs retain that coordinate through framing, codec parsing and reordering.
Clock-enabled capture pairs the read's pre/post authority callbacks and saves a
bracketed host sample after successful reads. A poll without bytes cannot certify
a retained packet's completed read.

A window's UTC envelope starts at the earliest admission among **all** retained
packets and ends at the latest completed-read bracket needed by those packets.
Packets are stored in extended sequence order, which can differ from admission
order. Source-only parameter or boundary-lookahead packets are included. Neither
the first/last vector positions nor decode ticks provide the observation bounds.

These are node read-admission envelopes. A frame spanning reads may include
previously buffered bytes, and several windows may share a read coordinate. The
interval does not bound earlier camera encoding, NVR, network or kernel buffering.
Camera exposure remains `unknown`; the mapping is never passed to
`RtspCaptureOrigin` as a camera-time assumption.

The retained NTP source is an **unauthenticated local-daemon assertion**. Raw
request/reply bytes, four bracketed exchange samples, fixed policy, completed-read
samples and the terminal host sample allow independent consistency checking.
They do not establish trusted UTC, uninterrupted clock continuity, or a physical
synchronization source. Leap indications are refused until a separate mapping
policy is admitted. Intermediate checks refuse sampled wall steps, regression and
expiry; compatible samples do not narrow or renew the original correlation.

## Durable companion and failure behavior

The native owner collects exact source descriptors when a window is accepted and
admits them to the clock index only after its existing root is durable. It freezes
the terminal clock sample before storage-only drain. A later storage completion
cannot extend the source clock's lifetime.

After successful capture and archive drain, a `recording_clock_index_v1` manifest
is published through the existing root-last owner. Its closure contains the exact
original recording roots, all four original children of each window, and the
clock metadata. Original window and catalog formats remain unchanged. The new
routing slot is `fssrc1-<codec>-<scope digest>`; routing is not effect authority.

The `clock_index_published` progress record supplies the exact companion slot/root
and archive snapshot digest. Terminal `node_clock` reports actual UDP contact and
payload counts, plus one of these dispositions:

| State | Meaning |
| --- | --- |
| `available` | The exact companion has a durable receipt. It remains a bounded interpretation of original source. |
| `clock_unavailable` | No successful companion was acknowledged. Original recording custody remains separately reported. |
| `indeterminate` | Companion publication requires explicit recovery; an automatic successor is refused. |

A refused exchange never opens the RTSP connection. A later clock refusal cannot
delete, relabel, or roll back already durable originals. The existing source
custody drain remains available when terminal sampling fails. A source/storage
failure stays explicit even if its teardown also makes clock annotation
unavailable. Failed captures do not manufacture a successful timed index over a
partial prefix. A late output failure cannot retract a previously acknowledged
companion; its known identity remains in terminal custody facts when output is
still possible.

## Query exact retained footage by UTC

Use `fss-archive query-utc` with the existing archive's exact codec/source/decode
scope, `--expected-snapshot`, `--expected-clock-index`, `--start-utc-ns`, and
`--end-utc-ns`. Use the snapshot and companion roots from the same completed
capture. See [the archive operator command](ARCHIVE_OPERATOR.md) for a complete
argument example and its explicit recovery/open semantics.

The query is half-open `[start, end)`. Each stored UTC uncertainty envelope is
closed `[earliest, latest]`, so candidate overlap requires `latest >= start` and
`earliest < end`. Returned slots and roots name whole original windows; the query
does not crop or export media.

Every clock row must match a recording in the exact pinned snapshot, even if the
row would not overlap the requested interval. Cold loading replays each original
through its selected native codec verifier, compares all retained packet
coordinates, checks current root/tombstone bindings and the full closure, and
recomputes every UTC endpoint. A checksum alone does not admit a supplied time.
The report emits no media payload, but recovery and source verification perform
bounded original-source reads.

Snapshot recordings absent from the clock index remain explicit
`clock_unavailable` handles. Their UTC relationship is unknown, so they cannot be
silently excluded. Candidate and unknown handles both count toward atomic window
and whole-window hydration-byte limits. Overflow refuses the complete answer;
there is no truncated success. A missing, corrupt, tombstoned, wrong-scope or
wrong-root companion cannot yield a successful timed query. Legacy archives
remain usable through the existing decode-tick commands.

No result asserts UTC coverage, physical absence, or complete scene history.
No-overlap only means no timed candidate was found in those exact supplied roots
under the retained clock assumptions.

## Remaining functional work

This is one bounded clock epoch per successful capture. Standing recorder leases,
clock refresh across long-running epochs, start/end/heartbeat reporting for a
supervised site service, adaptive cadence, upstream historical camera retrieval,
and the canonical agent/MCP footage view remain separate work. These additions
leave VIT-005, VIT-008 and VIT-019 open pending their complete contracts and native
qualification.
