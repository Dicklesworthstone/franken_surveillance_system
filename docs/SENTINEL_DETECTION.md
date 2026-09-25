# Motion-independent sentinel detector bursts

The motion-first detector cascade can classify only a candidate its foreground gate
already found. A static or slowly changing object can therefore escape the trained
detector entirely. The sentinel path addresses this **routing blind spot** by running
short, deterministic detector bursts independently of foreground, tracks, or events.
It implements a bounded retained-recording slice of FSS-078 / RISK-007 / OPEN-006;
it does not establish a real-world recall improvement or a production monitoring service.

## Run

```sh
fss-infer package-detect \
  --root /path/to/deployment --site site:home \
  --import-id sha256:IMPORT_DIGEST \
  --first-segment 0 --frames 64 --interpretation ycbcr \
  --package models/yolox-nano/yolox_nano.fmpk \
  --package-digest sha256:PACKAGE_DIGEST \
  --sentinel-every-frames 16 --sentinel-burst-frames 3 \
  --sentinel-max-inferences 12
```

Replace the digest placeholders with exact retained-import and verified-package
identities. No file or model is downloaded. Existing kernel, thread, threshold,
per-frame execution, export, source-custody and privacy controls remain in force.
Without sentinel options, ordinary `package-detect` behavior and report bytes remain
unchanged. This option is not silently enabled on `watch` or `corroborate`.

`--frames` bounds the entire source range, at most 64 segments. The first burst starts
at `--first-segment`; subsequent starts are separated by the declared period, not a
wall-clock timer. Period is 1–64 segments, burst length is 1–8 (default 3) and cannot
exceed period or range. The explicit inference allowance must fit one full burst and
is at most 64 across the entire invocation. Only whole bursts are admitted in source
order. A short tail is unsampled; it is not silently shortened into a burst. Changing
the range, period, burst size or allowance changes the schedule digest even when the
same frames happen to be selected. Sparse observations cannot certify absence.

For a 20-frame range, period 8, burst 3 and allowance 6, segments 0–2 and 8–10 are
inferred. The full scheduled burst 16–18 is explicitly `budget_exhausted`. All fourteen
uninferred segments are enumerated in `unsampled_segments`.

## Native execution and provenance

MJPEG reads and decodes only admitted frames. H.264/H.265 decode the whole bounded
IDR/IRAP-led range once so inter-picture references remain valid; RGB conversion and
inference run only on selected pictures. Sentinel sampling saves model work but does
not claim proportional video-decode savings. One JPEG decode budget and one detector
head-work budget serve every burst; they are never renewed at each burst. Per-frame
preprocessing/execution limits retain their existing meaning. The aggregate output
has a 16 MiB ceiling.

The current sensor mask is applied before inference, screens the output detections,
and is carried by each child report. A missing selected picture, duplicate selected
picture, in-burst source gap, inconsistent burst identity/clock/dimensions, decode
refusal or cancellation refuses the computation rather than publishing a partial
burst as complete. Native display order is preserved inside each burst. A CRA range
whose skipped leading picture was selected is refused, not counted as completed.

The output is `fss.sentinel_detection_report.v1`. It binds the import and package,
model, privacy projection, decode range, schedule, all omissions, explicit budget
refusals and exact child-report digests. Each completed burst contains an ordinary
`fss.package_detection_report.v1`. That child's digest uses the unchanged canonical
JSON bytes including the final newline. For AVC/HEVC, a child beginning at a non-IDR
is an analysis interval produced by the outer range's decoder, **not** permission to
seek/decode it independently without its reference prefix.

## Retain and investigate candidates

Add `--retain yes` to retain completed child reports through the existing root-last
`package_detection_record` path. The retention receipt for each child goes to stderr;
stdout remains the computation report. Retention occurs independently per child:
a later failure does not undo earlier completed roots. An exact rerun under unchanged
source/model/privacy conditions reconciles existing children instead of republishing.
No successful invocation JSON is printed when a requested child retention fails.
An explicitly requested exported computation report can still exist; it is not a
retention acknowledgement. The aggregate report says `retention: not_asserted_by_computation`.

The child report digest, not the aggregate digest, is the existing workflow's input:

```sh
fss-event report --root /path/to/deployment --site site:home \
  --package-report sha256:CHILD_REPORT_DIGEST --label person \
  --confirmation-hits 3 --report-out burst-analysis.bin

fss-event prepare --root /path/to/deployment --site site:home \
  --report burst-analysis.bin --report-digest sha256:ANALYSIS_DIGEST \
  --track sha256:TRACK_DIGEST
```

Review the prepared candidate before the existing exact-digest `publish` step. Every
burst is tracked separately; sample gaps never become artificial continuous tracks.
The event stays unclassified, indeterminate, single-sensor and approval-gated. A
package label is uncalibrated supporting evidence, not identity, intent, corroboration
or alert authority. Existing package-evidence deletion closure remains applicable;
no second retention store or event publisher is introduced.

## Validation and remaining scope

The implementation session ran the independent scheduling model over **371,632**
configurations. It compares whole-burst budget admission with a separate arithmetic
membership oracle. That verifies the scheduling model, not Rust execution. Python
integration-fixture syntax was checked. **Rust compilation, native tests, rustfmt and
Clippy were not run: the session environment had no Rust toolchain or built binaries.**
No qualification gate, model-quality claim or production-readiness status is promoted.

The added native contract tests are:

```sh
python3 crates/fss-reference/tests/fixtures/sentinel_schedule_model.py
cargo test -p fss-reference --lib ingest::package_detect::sentinel::tests
cargo test -p fss-cli --bin fss-infer package_cli::tests
cargo test -p fss-cli --test package_detect_cli_contract
cargo test -p fss-cli --test sentinel_detection_cli_contract
```

The new real-binary test imports twenty identical color-bar JPEGs, checks that the
motion gate emits no candidate, samples independent detector bursts, compares a
child against ordinary package detection, retains and tracks the child reports,
prepares/publishes one candidate only with exact approval, checks idempotent retries,
and applies an approved privacy mask. The existing fixture's three `tie` predictions
are deliberately used to test wiring; color bars are not actual ties, and this is
**not** evidence of object accuracy or threat recall. Python serves only as the test
JSON/filesystem oracle; production execution remains Rust.

Still open: integration into an always-on owned live service, event-level evaluation
on a consented corpus, empirically justified time-based cadence, adaptive budget
allocation with protected floors, and tolerant recovery across refused video ranges.
This is a second candidate-acquisition route, not a guarantee that every incident
falls inside a sampled burst.
