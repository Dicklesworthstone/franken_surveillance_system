# Import an HTTP camera archive into the recording pipeline

`fss-import-http` connects an existing raw HTTP/MJPEG archive to the retained recording
pipeline. Its output identity can be passed to the existing native decode, detector,
tracking and `fss-event watch` commands. It opens no camera connection and needs no new
dependency or media conversion process.

The importer replays the exact original HTTP response through the native HTTP and MIME
parsers, selects every complete JPEG in order, and publishes a retained MJPEG import.
Identical JPEGs remain separate frames and capsules. Bounds are whole-selection admission:
if there are more frames than the requested ceiling, the import refuses rather than
silently selecting the first few.

## Select and approve the exact import

Keep the source identity, generation, receive-clock identity, retention decision and final
wire pin from the capture report. The wire pin consists of `head`, `reads` and `bytes`.
Use that explicit pin; the importer neither searches for a newer camera nor follows later
archive history. The source archive and target deployment must be separate, non-nested
directories. An existing deployment keeps its retained sensor privacy policies.

Run a plan first, replacing the digest and identifier placeholders with the retained values:

```sh
fss-import-http \
  --archive /data/camera-http-archive \
  --root /data/surveillance-site --site site:home \
  --source sha256:SOURCE --generation 1 \
  --receive-clock sha256:CLOCK --retention-evidence sha256:RETENTION \
  --head sha256:HEAD --reads 27 --bytes 125000 \
  --sensor-id sensor:driveway --stream-id stream:driveway-recording \
  --receive-time-ns 1791504000000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes \
  --max-frames 128
```

The plan prints `approval_digest` and the full selection, destination, timing and resource
limits. It performs no filesystem, clock or network I/O. Repeat the same command with
`--approve sha256:APPROVAL` to execute it. Changing the source, pin, destination, site,
principal, sensor, stream, timing assumptions or resource ceilings invalidates the approval.

The acknowledgements have separate meanings: the owner authorizes the operation, permits
reading the original HTTP response, and permits retaining those originals in the target
deployment. A source digest or previous camera read does not confer those permissions.
The library API likewise requires an explicit `HttpImportAuthority`; it has no permissive
default. Existing publisher open obtains exclusive locks and performs its normal recovery
synchronization, so this is not a forensic read-only archive open.

A successful report contains `import_identity`, `import_root`, `manifest_digest`,
`origin_proof`, `frames`, `source_ending`, `capture_time_label` and `reused`. Pass the returned
`import_identity` to the existing recording tools. Source bytes, credentials, HTTP headers
and decoded pixels are not printed. The separately retained source archive is left in place.

## Original custody and reconstructed media

The ordered JPEG concatenation is explicitly labeled reconstructed media under adapter
`ADP-HTTP-MJPEG-ARCHIVE-001`. It is not presented as the original HTTP response. The existing
`FileImportManifest` encoding and publication format remain unchanged.

Every original read payload, wire metadata record and wire-root body is copied into the
import's own publication closure as an opaque leaf. That includes response headers, MIME
delimiters, chunk framing and a partial trailing frame. The canonical origin proof binds:

- The exact source scope and pinned read chain.
- The requested sensor, stream and receive timestamp.
- The complete ordered frame hashes, lengths and capture intervals.
- Each JPEG byte range to its original HTTP wire ranges and chunk identities.
- The verified native response ending and exact request digest.

The adapter generation names the proof digest; the import identity derives from that proof.
Changing a camera binding or timing assumption creates a different import identity even
when all JPEG bytes are identical. The proof, originals, reconstructed chunks, capsules and
custody manifest use the existing bounded part publication and root-last completion path.

Opening a retained HTTP import verifies the original metadata chain, proof membership and
exact capsule bindings. Segment readers also compare the JPEG bytes to their original wire
ranges before decoding. Full source verification additionally checks wrappers and the
partial tail. These checks work after the original archive is disconnected or removed,
because the target contains its own complete source closure. Original-object damage is a
refusal even when the reconstructed JPEG chunks remain intact.

The generic import deletion closure includes the copied originals and origin proof. Deleting
the target import does not delete the independent source archive. A flat standalone manifest
or the old context-free `fetch_segment_bytes` helper cannot resolve this origin authority;
use `RetainedFileImport::open` and its context-bound reads.

## Timing, privacy and incomplete captures

The explicit `--receive-time-ns` is the import's owner-declared receive timestamp. Raw camera
admission times are monotonic clock observations, and the importer never converts them into
wall-clock capture timestamps.

Without capture hints, every capsule has the conservative interval `[0, receive_time]`,
`ClockBasis::Estimated`, and `capture_time_label: unknown`. To supply an explicit assumption,
provide all three of `--capture-start-ns`, `--capture-uncertainty-ns` and `--fps`. Those hints
use the existing file-import interval calculation and retain the `operator_assumption`
label. A frame's latest possible capture after its receive timestamp is refused.

`explicit_framing_complete` means the original fixed-length or chunked HTTP response and
terminal MIME delimiter both completed. `pinned_prefix` means only the selected bytes were
available. This initial bridge does not adopt a separate socket-EOF witness, so an otherwise
valid close-delimited recording remains a prefix. Neither ending establishes physical scene
coverage, camera health, continuous acquisition, object absence or a detector result.

Import is a byte-custody operation. Existing retained decoders apply the target sensor's
current privacy mask before exposing derived luma or RGB. No historical mask, source hash or
timing hint substitutes for current privacy authority. Original HTTP bytes remain local,
unencrypted custody under the explicitly approved retention decision.

## Resource limits and recovery

The default selection allows 128 frames; the hard ceiling is 4096. Original wire bytes and
reconstructed media each have a separate 64 MiB ceiling. The original inventory is limited
to 4096 reads and the complete source map to 65536 spans. The proof is at most 16 MiB, and
retained reconstructed chunks are 1 MiB. Native HTTP/MIME framing keeps its own limits.
`--max-work` and `--max-framing-work` are shared across the whole operation; neither refills
per read or frame. The CLI also checks its declared timeout at source and publication
boundaries. These are bounded synchronous operations, not a hard real-time guarantee.

An interruption may leave staged bytes, capsule batches or a published part prefix. Repeat
the exact approved command to reconcile that same identity. The existing file-import retry
and journal-capacity checks apply before staging. Committed original custody is read back
before any retry may continue; fresh archive input never repairs missing or damaged data
behind an already visible root. Completed retries verify the retained result and append
nothing. A failed final output sink may follow a durable completion; an exact retry reports
that retained completion with `reused: true`.

## Focused verification

```sh
cargo test -p fss-reference --test http_wire_replay import::
cargo test -p fss-cli --bin fss-import-http
```

The native loopback fixtures cover fixed-length and chunked response parsing, duplicate
JPEGs, removal of the independent archive, current privacy masks, unknown timestamps,
close-delimited prefix honesty, timing-bound identities, denied authority, incorrect pins,
frame-ceiling refusal, original-byte damage, cancellation and exact retry, and generic
deletion closure. A composed 200-frame fixture acquires and imports a 96×48 recording,
then runs the native streaming watch pipeline against a target that first moves into the
owner's zone after the former 128-frame boundary. It checks exact event approval/retry,
unclassified and indeterminate results with `[0, 1]` uncertainty, and refusal after copied
originals are damaged while reconstructed JPEG chunks remain intact. These are reproducible
contract tests, not camera or detector-quality qualification.
