# Operator HTTP/RGB history replay

Status: reference implementation, not production-qualified. `fss-replay` exposes the existing
`http_rgb_history_replay` engine; it does not replace its implementation or durable formats.
The previously supplied local replay patch is superseded by this integration with the
concurrent upstream driver. Do not apply that patch over the newer native driver.

## Inspect and execute separately

```sh
fss-replay inspect-http-rgb --root "$EVIDENCE_DEPLOYMENT" --site "$SITE" --session "$SESSION"
```

Inspection requires an existing deployment, runs no model, opens no original archive and
returns the committed recipe and any pending unledgered recipe separately. The response
includes the exact committed `tip` (session, root and revision). Unknown sessions report
`no_committed_history`; that is not a statement about physical scene absence.

Select the exact tip from that result:

```sh
fss-replay http-rgb --root "$EVIDENCE_DEPLOYMENT" --site "$SITE" --session "$SESSION" \
  --expected-root "$HISTORY_ROOT" --expected-revision "$HISTORY_REVISION" \
  --original-root "$ORIGINAL_ARCHIVE" --read-originals yes --execute-model yes
```

Original-header/JPEG/model disclosure and exact-model execution have separate mandatory
acknowledgements. The local operator boundary is filesystem access and explicit invocation;
`--principal` is attribution, not remote authentication. History authority cannot retain a
recipe, the evidence adapter can read only this recipe's exact evidence set and retention
scope, and the compute adapter permits only this session's model. A digest is not a grant.

The driver reconstructs every selected frame with the native HTTP/MIME, source-closed model,
JPEG, detector, tracker and zone implementations. Every saved stage fingerprint must match.
The sensor comes from committed configuration and its current policy is resolved in the
history deployment. No mask override or caller-supplied capture time exists. Changed latest
history is stale, not an instruction to follow it. Pending roots are not executed or repaired.

Results retain the native distinctions `configuration_only`, `prefix_verified`, and
`complete_verified`. An empty configuration executes no inference. A verified prefix does not
claim native stream completion. A complete result also verifies the original termination
witness and exact frame count. No outcome certifies detection quality, sensor authenticity,
clock alignment, physical coverage or absence. Source timestamps are decimal strings so
ordinary JSON consumers do not round them through binary64.

The original archive is selected by the pin retained in history. The paths must be absolute,
existing, non-symlink at their final components, and nonoverlapping after canonical resolution.
No replacement empty deployment/archive is created for a missing store. Existing exclusive
locks and recovery synchronization still apply; this is not a forensic no-sync open.
This first CLI surface selects the history deployment's privacy authority and the history's
original pin. External privacy authority or independently retained later original tips can
be supplied through the underlying library, not inferred by this command.

## Resource and effect boundaries

All allowances are operator inputs, never enlarged by saved metadata. `--max-work` is shared
by initial inspection, reconstruction and final history verification. Import, copy/hash,
framing, decode, detector, temporal, cursor and inference-attempt counters accumulate across
frames. `--stage-macs` and `--stage-bytes` bound each preprocessing/execution call; the sum of
the two operation ceilings is reserved before each attempt against `--max-execution-macs`.
Reservations are not reported as measured usage. Successful frame rows separately report
actual preprocessing and neural work. Per-attempt memory ceilings are not whole-process RSS
or cumulative-byte guarantees. `--max-attempts 0` admits metadata/configuration-only work but
not a numerical attempt. Use `--help` for all independent bounds.

The JSON `usage` includes initial metadata inspection. Native work already spent is not
refunded after failure. A refusal emits no partial successful JSON result. Neither success
nor failure publishes roots/events, repairs history, changes retention, contacts a camera,
downloads models or sends alerts. Output includes identities and counts, not media, weights,
model tensors, raw headers, addresses or secrets. Preserve private source identities accordingly.

A cooperative deadline is rechecked by metadata, source, evidence and compute adapters. A
kernel, filesystem operation or blocked stdout write is not preempted in hard real time.
Output size is bounded, writes use bounded chunks and consecutive EINTR retries are finite.
A broken output sink can prevent delivery even after successful read-only reconstruction.

## Checks

```sh
cargo test -p fss-cli --bin fss-replay
cargo test -p fss-cli --test http_rgb_replay_cli_contract
cargo test -p fss-reference --test http_rgb_history_replay_contract
```

Eight CLI unit tests and three real-binary metadata/configuration contracts accompany this
integration. Full numerical reconstruction is covered by the existing reference integration
suite. Source API compatibility, exact base/blob hashes, TOML, lexical delimiters and
whitespace were checked; Rust compilation, tests, rustfmt and Clippy could not run because the
authoring environment has no Rust toolchain. These checks are not production qualification.
This consumes existing RGB histories; it does not fabricate detector evidence from a
framing-only `fss-capture http` archive or start live monitoring.
