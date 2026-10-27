# Retained ONVIF vendor metadata

`fss-onvif-metadata` imports one complete owner-supplied ONVIF PullMessages SOAP response or MetadataStream XML document. It retains the exact source, a deterministic vendor-event projection and the explicit source binding in an immutable, ledgered publication.

This is the local import and replay subset of FSS-046. Live subscriptions, RTP metadata transport, VideoAnalytics object geometry and physical-device/Profile M qualification remain separate work.

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

The source is bounded to 256 KiB. Optional `--source-sha256 sha256:HEX` checks an independently supplied input pin before destination work. The report includes `import_identity`, `publication_root`, source/projection digests and the custody anchor. Keep the import identity and root for independent verification.

## Inspect and verify after restart

Both commands reopen the deployment, rehash the retained recipe/source/projection, reparse original XML, check the physical root record, and verify exact ledger linkage. They do not need the original input file.

```sh
target/debug/fss-onvif-metadata verify \
  --root /srv/fss/site --site site:home \
  --import-id "$IMPORT_ID" --expected-root "$PUBLICATION_ROOT"

target/debug/fss-onvif-metadata inspect \
  --root /srv/fss/site --site site:home \
  --import-id "$IMPORT_ID" --expected-root "$PUBLICATION_ROOT" \
  --include-values yes
```

SimpleItem values are withheld by default. The explicit local `--include-values yes` option reveals them to stdout with escaped strings. Source/key/data absence remains distinct from a present empty group; notification order and duplicate occurrences are preserved. `Initialized`, `Changed` and `Deleted` remain vendor lifecycle assertions.

Complex element values and unknown sections stay in the retained XML and are counted as unsupported projection content. Known notification digests permit conservative comparisons within the exact sensor/device/profile generation. Opaque content additionally binds the original source and occurrence so it cannot be silently merged.

## Custody and authority

Camera labels and timestamps always remain vendor-claimed cognition. Retention proves which bytes were supplied under the operator's attribution; it does not authenticate the camera or establish physical truth, coverage, absence, identity or permission to send alerts or move a camera.

Exact retries revalidate immutable custody. A valid durable root that was interrupted before ledger linkage may complete that linkage. Missing or corrupted previously published source/root custody is refused rather than repaired by import. Cancellation after successful publication does not erase that result. Inspect commands open the deployment's existing exclusive owner and may finish its normal recovery; they are not a forensic no-write mount.

The library requires a valid replay I/O authority bound to the deployment root. Reader history is bounded to 65,536 batches and 1,048,576 deltas; writers reserve room before staging. This is a bounded reference path, not an unbounded event-history service.
