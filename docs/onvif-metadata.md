# Retained ONVIF vendor metadata

`fss-onvif-metadata` captures a finite live ONVIF PullPoint event session or imports one complete owner-supplied PullMessages SOAP response or MetadataStream XML document. It retains the exact source, a deterministic vendor-event/analytics projection and the explicit source binding in an immutable, ledgered publication. New imports interpret the supported `VideoAnalytics` frame, object, coarse shape, classification and transformation fields alongside event notifications.

This implements bounded native PullPoint acquisition with opt-in finite renewal, durable control recovery and the local import/replay subset of FSS-046. Continuous reconnect, RTP metadata transport, cross-frame tracking, calibrated scene interpretation and physical-device/Profile M qualification remain separate work.

## Capture live PullPoint events

Use a known event-service endpoint and independently approved literal peer, HTTP authority and service subtree. This command performs one finite subscription lifecycle: CreatePullPointSubscription, bounded PullMessages calls, optionally bounded Renew calls, then Unsubscribe. It never reconnects or creates another subscription after an ambiguous failure.

The native capture lane requires Linux, including its entropy backend even for anonymous endpoints. It uses explicit plaintext HTTP, optionally with HTTP Digest. It does not claim server identity or encryption. WS-Security UsernameToken, HTTPS and automatic service discovery are not part of this capture command. `--subscribe yes` explicitly approves creation and cleanup of the temporary subscription; read-only media approval does not grant that permission.

`RECEIVE_ORIGIN_NS` is an operator-declared epoch for the start of this request. The command adds its owned monotonic request/response times to that origin; it does not read or trust camera UtcTime for receive timestamps. Supply the same independent generation pins described below.

```sh
target/debug/fss-onvif-metadata capture \
  --root /srv/fss/site --site site:home --sensor sensor:front \
  --device-generation "$DEVICE_GENERATION" \
  --profile-generation "$PROFILE_GENERATION" --profile main \
  --peer 192.0.2.10:80 --authority 192.0.2.10 \
  --events-path /onvif/events_service --service-root /onvif \
  --owner-authorized yes --plaintext yes --subscribe yes \
  --receive-origin-ns "$RECEIVE_ORIGIN_NS" \
  --max-pulls 4 --poll-seconds 5 --timeout-ms 30000 \
  --lifetime-seconds 120 \
  --credential-file /srv/fss/private/camera-credentials \
  --auth-realm "$EXACT_REALM"
```

The example address is a documentation address; replace it with the explicitly authorized camera. Omit credential options only for an endpoint that permits unauthenticated event access. A Linux credential file must be a private regular file with one username line and one password line, including a final newline. Passwords are never command-line arguments, evidence fields or output. Rotation or replacement of the credential file revokes the current lease. Legacy MD5 or no-qop Digest requires separate explicit flags.

Capture defaults to at most four pulls of five seconds each, 128 notifications per response and a 30-second network/admission deadline (at most 60 seconds). The maximum is 32 pulls; SOAP bodies remain bounded to 256 KiB. The coordinator reserves time, steps and exchanges for cleanup and stops polling before the reserve or the camera-reported lease would be exceeded. A lease duration is only an unverified server claim anchored conservatively to local request start; it is never a trusted camera clock. Each logical operation receives a fresh entropy-derived WS-Addressing MessageID; its single optional HTTP 401 retry retains that same ID. Durable successful Create and Unsubscribe control receipts require an explicit namespace-correct matching RelatesTo. An omitted, spoofed, duplicated or mismatching relationship refuses those control receipts; missing correlation is never silently upgraded into an exact reply. Complete Renew responses also remain in custody when unusable, with their lease confirmation explicitly absent. The older optional live-wire parser remains available for its existing compatibility callers. Endpoint reference parameters support a bounded scalar subset; unsupported complex references are refused explicitly.

### Opt in to bounded renewal

Add `--max-renewals 1` to the capture command to permit at most one renewal when the current lease cannot safely accommodate another poll. The option accepts `0..4` and defaults to `0`, preserving the existing no-renewal behavior. Renew uses the same `--lifetime-seconds` request and the original scoped subscription endpoint; it does not obtain a new endpoint or create another subscription. Renewal never resets the original session deadline, pull count, step budget or cleanup reservation. A short camera lease can therefore be extended within the admitted session, but renewal cannot turn the command into an indefinite watcher.

The capture approval binds the explicit renewal option and its effective cap. Enabled renewal appends the separate `fss.onvif_metadata_capture_bounded_renewal.v1` domain and cap after the existing approval fields. Existing calls without the option retain their original approval bytes; no-renewal calls append no extension. This changes neither ONVIF wire semantics nor existing v1 custody encodings.

Before admitting a Renew network request, the retention sink commits a `renew-intent` record with the original Create closure, exact route and approval, fresh MessageID, attempt index and local admission time. A cold read or exact storage retry never authorizes another dispatch. The optional HTTP Digest challenge retry reuses the same logical request identity; transport loss or an ambiguous result does not permit a fresh Renew retry.

A complete final Renew response is retained under its own `renewed` identity, including a non-success HTTP status, wrong content type, malformed SOAP or missing/mismatching reply correlation. Retention proves the response bytes were observed; the record's name does not imply a successful renewal. `lease_confirmed=true` requires an observed monotonic completion time, HTTP 200, SOAP content type, an explicitly matching RelatesTo and a valid RenewResponse lease. A missing completion time remains explicit. Transport loss before a complete response leaves only the durable intent and an unknown result. The coordinator stops polling on an unusable response or custody refusal and attempts cleanup only while its independent current authority and reserved resources permit.

Capture reports `maximum_renewals`, `completed_renewals`, `retained_renewal_intents` and `retained_renewal_outcomes`, plus hash-only `renewal_intent.N` and `renewal_outcome.N` identities/roots. Confirmed lease responses remain historical vendor claims: they do not prove a subscription is active now, complete event coverage or physical absence. Known durable handles survive later refusal and output failure. Each metadata batch continues to retain its original Create source; renewal custody uses separate records without changing existing batch recipe bytes.

The result reports every definitely retained `batch.N.import_identity` and `batch.N.publication_root`, the stop reason and observed cleanup state. It also reports separate `create_intent`, `created_subscription`, `unsubscribe_intent`, `unsubscribe_outcome` and `unsubscribe` identities/roots when those publications commit. Before any Create connection admission, the command commits the intent; before the first poll, it commits the exact Create response, scoped endpoint reference and original intent closure. Before Unsubscribe, it commits an exact cleanup intent; every complete final cleanup response reaches raw custody before interpretation. A complete successful Unsubscribe response can additionally receive its existing terminal receipt. Each live metadata batch retains its original Create source as before, so existing recipe bytes stay compatible.

The command reports `subscription_source_received` and `subscription_source_retained` separately. A Create response can now be durable even when no polls succeed. A storage refusal after a commit preserves the receipt and stops additional polling; independently authorized network cleanup may still run. A genuine successful cleanup response remains an observation even if terminal storage later refuses, and the command reports incomplete custody with a nonzero exit. Missing cleanup correlation prevents a successful-cleanup observation. Late cancellation, deadline, request retirement and stdout failure preserve known hash-only handles.

Capture, import, inspection and control commands attach a borrowed live-owner admission gate to their replay I/O context. Cancellation, deadline, capability and budget refusals are checked at cooperative replay and publication boundaries, including direct I/O-authority validation. The first refusal is sticky; no later successful callback revives the context. Known durable receipts survive post-commit refusal, while optional private values are suppressed. This does not preempt an operating-system syscall already in progress or add a check inside every internal filesystem call.

An empty complete poll is retained, but proves no event coverage or physical absence. Device-wide notifications remain attributed to the independently selected sensor/device/profile pins; they are not proof that the camera filtered events to that profile. Vendor values are withheld from capture output and can be disclosed separately through explicit inspect.


## Recover after process, output or cleanup failure

The control catalog recovers identities even if the original process exited before stdout delivered them:

```sh
target/debug/fss-onvif-metadata control list \
  --root /srv/fss/site --site site:home --max-records 64

target/debug/fss-onvif-metadata control inspect \
  --root /srv/fss/site --site site:home \
  --kind created --control-id "$SUBSCRIPTION_ID" --expected-root "$SUBSCRIPTION_ROOT"
```

Select the `created` record's exact identity/root from the list, or use the original capture receipt. The catalog checks both visible roots and canonical ledger references, verifies complete custody, and preserves multiple observations separately. It returns the whole admitted catalog or refuses; increase the explicit bound up to 1024 if needed. Missing/corrupt/unledgered evidence never silently disappears. Records whose deletion is established by the native deletion owner are omitted; an empty catalog proves no absence of remote subscriptions.

| Retained record | What is known | Recovery meaning |
|---|---|---|
| `intent` | The original request was durably prepared before dispatch admission. | Dispatch and result can remain unknown after a crash. Never automatically replay Create from this record. |
| `created` | The exact scoped Create response and parent intent are in verified custody. | The subscription may have expired or been removed. Explicit cleanup can use its retained endpoint under fresh authority. |
| `unsubscribed` | A complete explicitly correlated Unsubscribe success and exact parent closure were retained. | This proves a historical response, not current device state or future absence. |
| `renew-intent` | A finite Renew request and original Create closure were committed before dispatch admission. | Dispatch and result can remain unknown after a crash. Never replay Renew automatically from this record. |
| `renewed` | A complete Renew response and exact parent intent were retained, even when the response was unusable. | Inspect `lease_confirmed`; a retained response never grants another Renew or proves current remote state. |
| `unsubscribe-intent` | The exact cleanup request and original Created closure were committed before dispatch. | A lost response leaves the attempt unresolved. Inspect current history and obtain fresh owner approval before another attempt. |
| `unsubscribe-outcome` | A complete final cleanup body and its intent were retained, including refused or malformed replies. | Inspect `success_observed`. A verified success prevents redispatch even if the separate `unsubscribed` marker was interrupted. |

Use `control inspect --kind renew-intent` or `control inspect --kind renewed` with the exact identity/root returned by capture or the catalog. Renewal outcomes name their original subscription and renewal intent separately. Inspection does not reconnect, renew or create a subscription. If a renewal result is unresolved, fresh explicitly approved `control unsubscribe` can still target the original retained Created record; the command never replays the unresolved renewal.

Inspect the selected `created` record first. Its `cleanup_control_witness` binds the verified cleanup history; its report names any latest attempt and successful terminal observation. Review unresolved attempts before deciding whether another request is appropriate. To perform cleanup, supply that exact witness as `EXPECTED_CONTROL`, a new explicit owner request with the independently known original pins, and a fresh receive-clock origin:

```sh
target/debug/fss-onvif-metadata control unsubscribe \
  --root /srv/fss/site --site site:home \
  --subscription-id "$SUBSCRIPTION_ID" --expected-root "$SUBSCRIPTION_ROOT" \
  --expected-control "$EXPECTED_CONTROL" \
  --sensor sensor:front --device-generation "$DEVICE_GENERATION" \
  --profile-generation "$PROFILE_GENERATION" --profile main \
  --peer 192.0.2.10:80 --authority 192.0.2.10 \
  --events-path /onvif/events_service --service-root /onvif --generation 1 \
  --owner-authorized yes --plaintext yes --unsubscribe yes \
  --receive-origin-ns "$CURRENT_RECEIVE_ORIGIN_NS" --timeout-ms 30000 \
  --credential-file /srv/fss/private/camera-credentials --auth-realm "$EXACT_REALM"
```

This command sends only Unsubscribe. It refuses Create/Pull/Renew options, checks every sensor/device/profile/peer/origin/event-path/subtree/generation pin before loading credentials or making network requests, and binds the selected identity/root and current cleanup witness into the fresh v2 cleanup approval. A stale witness refuses dispatch. A verified prior success returns `phase=already_unsubscribed` with zero HTTP exchanges before credentials or entropy are opened. The new receive origin must follow the retained Create interval. The stored approval is historical evidence and cannot grant another operation. Credential lease rotation, current cancellation/deadline and current network authority remain effective.

Every new cleanup intent pins the exact reconstructed SOAP request, including its fresh MessageID and original opaque endpoint-reference parameters. The intent must become durable before connection admission. Exact custody retries cannot resend it; a separately reviewed retry needs both a fresh request identity and a fresh approval. The current witness is rechecked at publication. There are at most 64 cleanup attempts per original Created record and 1024 catalog records per bounded scan. Created inspection and cleanup reserve a finite additional 512 MiB of cumulative read allowance for those verified histories; this is not a memory allocation or permission for additional network effects.

Complete HTTP errors, terminal authentication refusals, empty bodies, malformed SOAP and missing/mismatching correlation are retained as raw outcomes. They do not count as successful cleanup. `success_observed=true` requires HTTP 200, SOAP content type, an explicitly matching RelatesTo and a valid UnsubscribeResponse. Missing local completion time remains explicit and does not erase an otherwise verified acknowledgment. If cancellation or storage refusal follows a known commit, its hash-only handle survives in the report. If no complete reply was received, the intent remains unresolved. New attempt/outcome records participate in existing holds and deletion; deleted control evidence cannot be silently recreated by retry.

The response keeps `remote_unsubscribe_success_observed` separate from the durable terminal receipt. Any refused or incomplete cleanup exits nonzero while retaining known hashes for another cold inspection. A failed response never authorizes automatic Create. If only an unresolved intent exists, no safe endpoint can be reconstructed for cleanup; reconcile that uncertainty with the owner/device instead of dispatching again.

## Import

Build the binary with the repository's pinned Rust toolchain:

```sh
cargo build --locked -p fss-cli --bin fss-onvif-metadata
```

Supply independently known SHA-256 device and profile generation digests in `DEVICE_GENERATION` and `PROFILE_GENERATION`. A profile token alone does not identify its configuration. Set `RECEIVED_START_NS` and `RECEIVED_END_NS` from the explicit local receive interval; the command never substitutes the camera's UTC assertion.

```sh
target/debug/fss-onvif-metadata import \
  --root /srv/fss/site --site site:home \
  --input events.xml --sensor sensor:front \
  --device-generation "$DEVICE_GENERATION" \
  --profile-generation "$PROFILE_GENERATION" \
  --profile main \
  --received-start-ns "$RECEIVED_START_NS" \
  --received-end-ns "$RECEIVED_END_NS"
```

The source is bounded to 256 KiB. Optional `--source-sha256 sha256:HEX` checks an independently supplied input pin before destination work. The report includes `import_identity`, `publication_root`, source/projection digests, the retained `parser_generation` and the custody anchor. Keep the import identity and root for independent verification.

### Interpretation and compatibility

`import` accepts `--interpretation analytics-v2|events-v1`; the default is `analytics-v2`.

| Selection | Parser generation | Retained meaning |
|---|---|---|
| `analytics-v2` | `gen:fss1:onvif-vendor-analytics-v2` | Events and the bounded VideoAnalytics projection, using v2 recipe, projection and occurrence-identity domains. |
| `events-v1` | `gen:fss1:onvif-vendor-events-v1` | Frozen event-only interpretation. VideoAnalytics stays opaque, including interior fields that v2 would refuse. |

To retry a pre-v2 import exactly, add `--interpretation events-v1` to the original import command and retain its exact source and owner bindings, including receive endpoints. In the Rust API, `retain` defaults to `Interpretation::AnalyticsV2`; `retain_with_interpretation` accepts `Interpretation::EventsV1` for an explicit legacy retry.

Importing the same source under v2 creates a separate identity and publication; it does not change the v1 root. This also applies to event-only documents because the parser generation and digest domains are part of custody. Cold readers select the parser from the retained recipe. Unknown or mixed domain/generation combinations are refused, and a failed v2 interpretation never falls back to v1 automatically. The independent bytes and pins in `fixtures/onvif-metadata-v1/` exercise this compatibility boundary.

## Supported analytics projection

The parser resolves ONVIF namespaces and preserves source order. Its supported subset is:

- Each frame's asserted `UtcTime`, optional `Source`, optional frame transformation and ordered object occurrences. An empty frame remains an empty vendor assertion.
- Required object `ObjectId` in bounded signed-integer syntax. Original spelling is retained; numerically equivalent duplicate IDs in one frame are refused. IDs are not merged across frames.
- Optional appearance, with an optional object transformation, coarse shape and class group. A present shape requires both `BoundingBox` and `CenterOfGravity`.
- Legacy `ClassCandidate` elements with `Type` and `Likelihood`, and modern `Type` text with an optional `Likelihood` attribute. Candidate order, representation and missing likelihood are preserved; classes are not ranked, normalized or mapped to an FSS vocabulary.
- Explicit optional `Translate` and `Scale` components. Missing transformations stay missing; frame and object transformations are retained separately and are not applied to the coordinates.

Numeric values retain their accepted decimal/scientific spelling, including negative zero. Coordinates and transforms must be finite and have absolute value at most `1e9`; likelihoods must lie in `[0,1]`. Numeric spellings are bounded to 64 bytes, and nonzero values that underflow the parser's numeric representation are refused. Object IDs are bounded to 64 bytes; source and class labels to 256 bytes. One document permits at most 128 analytics frames, 128 objects per frame, 512 objects in total and 16 candidates per class group, subject to the existing XML and source-size limits. Exceeding a bound refuses the document rather than returning a prefix.

Unknown fields remain in the original XML with unsupported-content accounting. This includes polygons, object trees, PTZ/image fields and biometric or identity-bearing extensions such as face, body, plate, UUID, image and URL data. They are not activated as recognition, identity or tracking features. Class labels, likelihoods and coordinates remain uncalibrated vendor claims; bounding boxes acquire no inferred axis orientation, pixel grid or world units.

## Inspect and verify after restart

Both commands reopen the deployment, rehash the retained recipe/source/projection (and exact Create SOAP for live batches), reparse original XML with its stored generation, check the physical root record, and verify exact ledger linkage. They do not need the original input file and do not accept `--interpretation`.

```sh
target/debug/fss-onvif-metadata verify \
  --root /srv/fss/site --site site:home \
  --import-id "$IMPORT_ID" --expected-root "$PUBLICATION_ROOT"

target/debug/fss-onvif-metadata inspect \
  --root /srv/fss/site --site site:home \
  --import-id "$IMPORT_ID" --expected-root "$PUBLICATION_ROOT" \
  --include-values yes
```

SimpleItem values, analytics source labels, object IDs, class labels/likelihoods, shape coordinates and transformations are withheld by default. The report still includes digests, counts, presence markers, unsupported-content counts and untrusted vendor timestamps. The explicit local `--include-values yes` option reveals the supported values to stdout with escaped strings; it does not reveal opaque extension payloads or enable sensitive analysis. Raw source custody still retains the complete owner-supplied XML, so default report redaction is not source redaction.

Source/key/data absence remains distinct from a present empty group; notification order and duplicate occurrences are preserved. `Initialized`, `Changed` and `Deleted` remain vendor lifecycle assertions. Missing appearance, shape, class, likelihood or transformation likewise remains explicit.

Known notification digests permit conservative comparisons within the exact site/sensor/device/profile generation and profile token. V2 opaque-content detection includes nested analytics extensions: any such content additionally binds a notification identity to the complete original source and occurrence index. V1 keeps its original identity rules. Every v2 analytics-frame identity binds the complete original source and frame index as well as the owner generations and projection; it cannot establish cross-frame object identity. Retained occurrences are never coalesced.

## Custody and authority

### Holds and evidence deletion

Retained metadata and control receipts participate in the existing evidence-hold and deletion lifecycle. Use the
metadata receipt's `import_identity` or the control receipt's `identity` as the import target. Sensor-scoped deletion includes both file
metadata, native PullPoint imports and control receipts under their verified owner sensor binding. A ledger name
alone is insufficient: the metadata owner must verify the source, versioned interpretation,
projection, manifest and exact publication before admitting an import to a hold or deletion
closure. Damaged custody blocks planning instead of silently omitting the import.
The custody boundary returns only the verified owner sensor to the lifecycle owner;
vendor `Source` labels, topics and analytics claims cannot select a deletion scope or
grant approval.

Existing exact approval, active-hold, shared-object and recovery rules apply. A hold on metadata
also protects its derivative closure when another import's deletion would touch it. Shared
source, projection or subscription-response objects remain when another retained owner needs
them. Releasing a hold requires its own existing approval; deletion cannot release it implicitly.

Once the deletion record is durable, metadata reads and exact import retries refuse with
`ERR-EVIDENCE-DELETED-001`, even if an interrupted unlink has left bytes on disk. A different
sensor binding, interpretation or native poll identity cannot restore a deleted required object.
The check covers the recipe, source, projection, publication root and native PullPoint Create
response. Metadata deleted as another import's derivative is likewise denied and cannot be
rediscovered from its old publication batch. Deletion completion remains crash-resumable through
the existing owner.

The parent intent/Created/Renew-intent/Renewed/Unsubscribe closure follows the existing derivative rules: selecting an intent reaches its dependent observations; selecting a later observation does not absorb its ancestors. Renewal intents retain the original Create closure, and renewal outcomes additionally retain the exact renewal intent and complete response. Active holds and shared custody remain authoritative, and a different owner binding cannot resurrect tombstoned control bytes.

This uses local filesystem unlink and the existing deletion-plan scope; it does not send Unsubscribe or erase device-side subscriptions. Original input files,
external exports, device storage and unrecorded remote copies remain outside that scope.

### Versioned metadata custody

Live captures use the separate `fss.onvif_vendor_event_pullpoint.v1` custody domain and the frozen event-only projection; the analytics-v2 file-import default is unchanged. The live recipe additionally binds the capture approval, event/subscription route digests, poll occurrence, both request IDs and ordered monotonic Create/poll intervals. Cold verification validates reply correlations when present and the fourth source object's exact digest. The standalone successful Create/Unsubscribe receipts require explicit reply correlations. Renewal adds `fss.onvif_pullpoint_renew_intent.v1` and `fss.onvif_pullpoint_renewed.v1`; cold verification reproduces whether the retained response supports a lease without discarding unusable response bytes. Existing file, live-batch and Create/Unsubscribe encodings receive no new bytes.

Camera labels and timestamps always remain vendor-claimed cognition. Retention proves which bytes were supplied under the operator's attribution; it does not authenticate the camera or establish physical truth, coverage, absence, identity or permission to send alerts or move a camera.

Exact retries revalidate immutable custody. A valid durable root that was interrupted before ledger linkage may complete that linkage. Missing or corrupted previously published source, projection or root custody is refused rather than repaired by import. Inspect commands open the deployment's existing exclusive owner and may finish its normal recovery; they are not a forensic no-write mount.

A successful import receipt survives cancellation, deadline expiry or finalization failure observed after the durable operation completes. The CLI preserves `import_identity`, `publication_root` and `source_sha256`, reports `durable_publication=true`, and adds `post_commit_error` and/or `finalization_error` when present. It suppresses optional values on these late failures even when `--include-values yes` was requested. A presentation failure similarly falls back to the minimal custody receipt with `report_error`. Follow `safe_next=verify_exact_import` using the preserved identity and root; a late error does not mean the publication was rolled back.

If writing or flushing stdout fails after a durable import, the command emits a hash-only recovery receipt to stderr and exits nonzero. Optional values never appear in that stderr receipt. The preserved hashes support exact verification despite the output failure; if stderr also fails, receipt delivery cannot be guaranteed.

The library requires a valid replay I/O authority bound to the deployment root. Reader history is bounded to 65,536 batches and 1,048,576 deltas; writers reserve room before staging. This is a bounded reference path, not an unbounded event-history service.

## Scoped validation

With the repository's pinned Rust toolchain and locked crates.io dependencies, run:

```sh
cargo test --locked -p fss-reference \
  --test onvif_wire_contract \
  --test onvif_event_metadata_contract \
  --test onvif_analytics_metadata_contract \
  --test onvif_pullpoint_wire_contract \
  --test onvif_pullpoint_capture_contract \
  --test onvif_metadata_custody \
  --test onvif_control_custody \
  --test onvif_control_termination \
  --test onvif_control_deletion \
  --test replay_admission_contract
cargo test --locked -p fss-cli --bin fss-onvif-metadata
```

These suites cover namespace and numeric rejection, missing/opaque fields, frozen v1 bytes and roots, explicit v2 reinterpretation, generation rebinding, corrupt custody, disclosure controls and durable-receipt preservation. Renewal cases cover bounded attempts, unchanged deadlines, intent-before-dispatch, unusable complete replies, lost-response uncertainty, cold verification and hold/deletion closure. They use synthetic inputs and local reference deployments. Their execution status belongs in `IMPLEMENTATION_STATUS.md`; their existence alone establishes no camera interoperability, Profile M conformance, recognition quality or full release qualification.
