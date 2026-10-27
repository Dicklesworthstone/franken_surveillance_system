# Retained ONVIF vendor metadata

`fss-onvif-metadata` imports one complete owner-supplied ONVIF PullMessages SOAP response or MetadataStream XML document. It retains the exact source, a deterministic vendor-event/analytics projection and the explicit source binding in an immutable, ledgered publication. New imports interpret the supported `VideoAnalytics` frame, object, coarse shape, classification and transformation fields alongside event notifications.

This is the local import and replay subset of FSS-046. Live subscriptions, RTP metadata transport, cross-frame tracking, calibrated scene interpretation and physical-device/Profile M qualification remain separate work.

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

Both commands reopen the deployment, rehash the retained recipe/source/projection, reparse original XML with its stored generation, check the physical root record, and verify exact ledger linkage. They do not need the original input file and do not accept `--interpretation`.

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
  --test onvif_metadata_custody
cargo test --locked -p fss-cli --bin fss-onvif-metadata
```

These suites cover namespace and numeric rejection, missing/opaque fields, frozen v1 bytes and roots, explicit v2 reinterpretation, generation rebinding, corrupt custody, disclosure controls and durable-receipt preservation. They use synthetic inputs and local reference deployments. Their execution status belongs in `IMPLEMENTATION_STATUS.md`; their existence alone establishes no camera interoperability, Profile M conformance, recognition quality or full release qualification.
