# Check retained HTTP recordings from the command line

`fss-archive check-http` runs the native retained-wire replay and optional full
JPEG decoder over an exact original source prefix. It is a local operator utility,
not a new `fss/1` operation, and does not export media, contact a camera, invoke a
model, publish new evidence roots, or repair missing/corrupt originals.

The same typed operation is available as
`fss_reference::ingest::http_replay::check::check_http_recording`. The CLI only
parses an exact selection, opens the existing authorized publisher and renders the
bounded result. It does not implement its own HTTP, MIME, JPEG or source-map logic.

## Select the original source explicitly

Use the identities and counts independently retained during original publication:

```sh
fss-archive check-http \
  --root "$EXISTING_ARCHIVE" \
  --source "$SOURCE_SHA256" --generation "$SOURCE_GENERATION" \
  --receive-clock "$RECEIVE_CLOCK_SHA256" \
  --retention-evidence "$RETENTION_SHA256" \
  --head "$WIRE_HEAD_SHA256" --reads "$WIRE_READS" --bytes "$WIRE_BYTES" \
  --read-originals yes --decode grayscale
```

Every digest variable is a full `sha256:` identity. The clock is the original
receive-clock identity, NOT an invented capture time. The source/head/counts select
one exact `HttpWirePin`; they are not a request to follow the latest root or list
hidden source objects. `--read-originals yes` acknowledges local access to ORIGINAL
headers and imagery, not just derived results. Local filesystem permissions and
the existing storage owner remain the access boundary; it is not a remote grant.

Select `--decode ycbcr` for an independently known JPEG Y/Cb/Cr source or
`--decode grayscale` for grayscale. `--decode none` checks source custody and
HTTP/MIME framing only and makes no decoded-image claim. There is deliberately no
`auto` mode that silently guesses component semantics. YCbCr mode validates all
entropy blocks and reconstructs luma; it is not an RGB/ICC colour-fidelity claim.

For a capture with an independently retained native termination record, add:

```sh
  --completion-root "$HTTP_COMPLETION_ROOT_SHA256"
```

The record is loaded and reverified, never inferred from the directory or silently
ignored if it is invalid. This permits close-delimited EOF finalization, including
an EOF-terminated final MIME delimiter. Without it, stored close-delimited bytes
remain `prefix_exhausted`, even after valid images have been decoded. See
`HTTP_COMPLETION_WITNESSES.md` for how original acquisition records that witness.
Existing archives cannot retroactively fabricate it.

## Output and failure semantics

A complete JSON object uses the reference operator shape
`fss.local_http_check.v1`. It contains exact source and optional completion pins,
explicit decode mode and decoder generation, framing status/termination, typed
failure, progress/work counts, and EVERY successfully checked frame row. Rows
contain original ordinal, compressed digest/size, complete source-map identity and
run count, plus dimensions/luma digest only after successful full native decode.
No original pixels, header values, camera address, path or credentials are emitted.

`status=complete` returns exit zero. `prefix_exhausted` and `refused` return the
existing runtime-failure exit identity WITH a complete typed report. A late corrupt
JPEG or exhausted budget preserves all earlier fully checked frame rows as an
explicit verified prefix, with the failed original ordinal and exact error family.
An empty verified prefix is not an empty scene. `frame_chain` commits to that ordered
frame prefix and decode interpretation; it is not a full-report success certificate.

Invalid arguments, inability to open/verify the selected archive, invalid requested
completion, or output-cap exhaustion return nonzero without a partial JSON object.
Malformed inputs are not echoed in diagnostics. OS stdout failure can of course
interrupt delivery; a consumer must require complete JSON and inspect both exit
status and the report classification rather than treating received bytes as success.

## Whole-operation bounds

Use `fss-archive help` for all bound flags. In particular:

- `--max-source-work`, `--max-framing-work` and `--max-decode-work` are separate
  whole-request deterministic reference allowances, never replenished per frame.
- `--max-steps`, `--max-frames`, `--max-frame-bytes`, `--max-dimension` and
  `--max-pixels` bound native work and complete input/output, never top-k sampling.
- `--max-reads`, `--max-source-bytes`, publisher/object/scan bounds, `--read-bytes`
  and `--max-report-bytes` bound source access, allocation and report size.

The frame ceiling is a stop boundary, not evidence of EOF. Allow headroom for
termination; reaching the native replay cap must not be read as a successful end.
The elapsed timeout is checked at explicit I/O/parse/decode boundaries. Bounded
synchronous decode and host filesystem calls are not forcibly preempted mid-call;
this is not a hard-real-time execution deadline or measured performance SLO.

Both the command and original publisher are synchronous. Existing exclusive locks
and recovery synchronization apply when opening the archive; this is NOT a
forensic read-only open. The checker itself publishes no roots and invokes no
cleanup, replacement, retention change, or implicit repair operation.

## Validation and remaining boundary

Library tests in `http_check.rs` cover source-linked full decoding, stable identities
across read sizes, explicit framing-only mode, incomplete prefixes, late invalid
JPEGs, budgets, corrupt originals, invalid requested completion and denied access.
`http_completion.rs` additionally drives actual native capture/terminal publication
through cold operator checks. `http_check_process.rs` exercises the separate CLI
process, report/exit contracts, non-disclosure and all-or-nothing output caps.

Rust compilation, these test targets, rustfmt, Clippy and native qualification were
NOT RUN in this editing environment because no Rust toolchain is installed.
Lexical, formatting and independent framing-model checks are supplementary only.
The work advances the FSS-019/FSS-120/FSS-135 reference recovery path and the
WP-180 operator surface; it does not establish physical-camera compatibility,
continuous coverage, model quality, alert correctness or release qualification.
