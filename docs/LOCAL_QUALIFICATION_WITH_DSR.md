# Local qualification and release with Doodlestein Self-Releaser

**Status:** normative release contract
**Revision:** 1
**Date:** 2026-08-31

FSS does not rely on GitHub-hosted Actions for build, test, qualification, or publication. Workflow YAML is retained as a portable executable job graph. The authoritative evidence is produced locally on controlled native machines and assembled by Doodlestein Self-Releaser (`dsr`).

## 1. Authority hierarchy

1. Stable semantic contracts and registries.
2. `scripts/qualify.sh` lane definitions.
3. Local lane receipts on controlled hosts.
4. DSR source/host/artifact/release manifests.
5. Optional hosted workflow observations.

A hosted success cannot override a failed local receipt. A hosted outage cannot block a release whose complete local contract passes.

## 2. Clean source identity

Strict qualification begins from:

- one clean FSS commit;
- no untracked source inputs;
- an isolated snapshot outside the mutable checkout;
- exact submodule/path/git sibling revisions;
- exact Cargo.lock and registry/source closure;
- exact toolchain and component identities;
- exact generated-file roots.

The source manifest records tree digests, not only branch names.

## 3. Franken sibling closure

For every live path or git dependency DSR records:

- repository and commit;
- clean/dirty status;
- tree digest;
- Cargo package/version/features;
- dependency edge and semantic import gate;
- license/security inventory root;
- whether it is production, oracle-only, or build-only.

A dirty sibling or unresolved branch reference blocks strict qualification.

## 4. Qualification lanes

### `QL-POLICY-001` — policy and registry

Parses JSON/TOML/YAML, validates schemas, stable IDs, registry cross-links, dependency allowlist, manifest, links, claims, and implementation-status consistency.

### `QL-REFERENCE-001` — reference semantics

Runs deterministic single-threaded ledger/object/graph/event oracles and golden traces.

### `QL-RUST-001` — Rust static and unit

Exact nightly; format; check all targets/features selected by matrix; Clippy `-D warnings`; tests; docs; no unsafe/forbidden dependencies.

### `QL-LAB-001` — deterministic schedules

LabRuntime replay, DPOR campaigns, cancellation injection, obligation leak oracle, trace canonicalization, and seed replay.

### `QL-MEDIA-001` — media fixtures

Packet/container/codec boundary fixtures, corruption/resource campaigns, source-to-decoded provenance, and cross-platform semantic digests.

### `QL-ADAPTER-001` — native device hardware

Runs only on hosts with exact registered camera/firmware/app/network fixtures. Produces compatibility certificates; no simulator result counts as live hardware proof.

### `QL-MODEL-001` — model quality

Pinned weights/runtime/hardware, event-level metrics, fixed operating points, calibration, shadow comparison, and held-out corpus identity.

### `QL-ARCHIVE-001` — archive recovery

Root-last publication, cloud emulator/live canary, interruption/resume, repair decode, retrievability, key recovery, and deletion closure.

### `QL-SECURITY-001` — security/privacy

Capability non-escalation, secret redaction, parser/resource bounds, sandboxing, mask-before-publication, retention, and deletion tests.

### `QL-PERF-001` — performance/energy

Same-binary A/A/B, semantic digests, percentile distributions, thermal/energy counters, workload manifest, regression thresholds.

### `QL-NATIVE-001` — native target builds

Linux x86_64/aarch64, macOS arm64/x86_64 where supported, Windows x86_64, and any appliance targets. Native behavior is tested on native hosts rather than inferred from cross-compilation.

### `QL-CUSTODY-001` — release custody

Checks exact assets, checksums, signatures, SBOMs, source archive, qualification roots, upload, download, and byte verification.

## 5. Workflow YAML

`.github/workflows/*.yml` calls the same scripts and lane names. It must not duplicate semantic check logic. DSR may run Linux jobs through `act` and dispatch native macOS/Windows lanes over SSH.

The workflow records required inputs explicitly and avoids GitHub-only state as a prerequisite. Secrets used for publication are DSR/local secrets, not required hosted secrets.

## 6. Host manifest

Each build/qualification host records:

- host ID and owner;
- OS/kernel/build number;
- CPU/GPU/accelerator and microcode/driver;
- memory/storage/filesystem;
- Rust and native toolchains;
- laboratory-oracle executable identities when a differential lane uses them, plus proof that
  they are absent from the production release closure;
- device fixtures physically connected;
- clock/NTP state where relevant;
- environment allowlist;
- isolation/container settings;
- last doctor result.

A host change creates a new manifest generation.

## 7. Build-root policy

Large snapshots, Cargo targets, models, media fixtures, and qualification artifacts use a disk-backed configured root. DSR must reject tmpfs/ramfs roots for strict runs. Every lane has byte/inode budgets and cleanup receipts.

## 8. Resume semantics

Each target/lane has an attempt directory and immutable result receipt. A resumed run:

- verifies prior source/host/contract identities;
- rehashes completed artifacts;
- retries only incomplete/invalid lanes;
- never combines receipts from incompatible source or policy roots;
- withholds the authoritative aggregate manifest until all required lanes pass.

Partial artifacts may be retained for diagnosis but are never published as a release.

## 9. Release root

The release root includes:

- source manifest and archive;
- sibling closure;
- toolchain/host manifests;
- primary assets;
- checksums and signatures;
- SBOM/license notices;
- per-lane qualification roots;
- compatibility/model/adapter certificates;
- known limitations and negative evidence;
- exact asset enumeration;
- verification instructions.

The root is published after children. Draft release creation does not count as publication.

## 10. Upload and independent verification

DSR uploads contracted assets, lists the remote release through a no-cache read, downloads every asset to a clean verification directory, checks byte identity/signatures/SBOM links, and only then promotes the release from draft. Missing, extra, renamed, or duplicate assets fail closed.

## 11. Version and tag rules

- version is read from one registered authoritative package;
- workspace version ambiguity fails closed;
- release tag is annotated and bound to the clean source commit;
- protected tag rules are verified where configured;
- an existing differing tag/release is a conflict, not overwritten;
- release notes are generated from the exact source range and negative-evidence ledger.

## 12. No aggregate readiness

A release manifest reports each readiness dimension separately. For example, a build may be qualified for replay/UVC but not Wyze firmware X, DJI live capture, or a particular model package/hardware tuple. Asset publication never rounds partial compatibility up to “FSS supports all cameras.”

## 13. Initial commands

The repository’s semantic entry points are:

```bash
./scripts/qualify.sh --lane policy
./scripts/qualify.sh --lane rust
./scripts/qualify.sh --lane full --receipt-dir "qualification-artifacts/local/full-$(date -u +%Y%m%dT%H%M%SZ)"

dsr build --repo franken_surveillance_system --version vX.Y.Z --resume
dsr release --repo franken_surveillance_system --version vX.Y.Z --draft
dsr release verify --repo franken_surveillance_system --version vX.Y.Z
```

Each run needs its own receipt directory: without `--receipt-dir` the qualifier creates a unique
`qualification-artifacts/local/<stamp>-<lane>-<pid>` directory, and an explicit directory that already
holds another run's `commands.jsonl` is refused (exit 4) rather than overwritten.

Exact DSR command forms may evolve; the invariants above do not.

## 14. Release blockers

- dirty or unresolved source/sibling closure;
- unpinned nightly or unregistered foreign executable;
- network-dependent build;
- missing Cargo.lock for a release candidate;
- failed/absent required lane;
- unverified device/model compatibility claim;
- incomplete target matrix;
- missing signature/SBOM/source archive;
- partial manifest accidentally marked authoritative;
- upload/download mismatch;
- known critical negative evidence without an explicit blocked claim.

## When the fleet refuses admission

`RCH` can refuse every worker with `no_admissible_workers: disk_headroom=1` even though
`allow_local_fallback = true` is configured, in which case the shim still prints "remote required" and
the build never runs. Neither `rustup run <toolchain> cargo` nor a plain `cargo` escapes it, because
both are wrapped. Invoke the toolchain binary directly for that build only:

```sh
~/.rustup/toolchains/<pinned>/bin/cargo build --target <host-triple> ...
```

A second, distinct refusal appears when the fleet is up but its build disks are tight:
`RCH-E330 remote_build_disk_budget_exceeded` — the worker reports plenty of free space yet the admission
check says "free space cannot cover active build reservations and protected floor". Retries land on
other workers and fail the same way. Neither `RCH_DISABLE=1` nor `RCH_ALLOW_LOCAL_FALLBACK=1` in front
of the toolchain cargo suppresses it; the practical route is to retry later or over SSH on a worker.

### Claim lanes that exist today

`confirm`-style claim lanes are resolved from `scripts/lanes/<lane>.sh`; a lane whose script is absent
fails closed. Present now: `media` (probe contract, six fixtures), `archive` (six cold archive process
suites), `agent` (effect and rehearsal contracts), `privacy` (masking contract) and `lab` (replay, crash matrix, decode, file activity, ingest, recovery) — the first two are proven (38 tests green). `lab` is proven too: 43 tests green across its seven suites, `geometry` is proven (16 tests) and `threat` is proven (35 tests) and `model` is proven (28 tests); fixing `inference_cli_contract` exposed a stale read-allowance assumption — the reported payload bytes are now the exact allowance, because the empty final journal probe no longer consumes one. Wiring it exposed three stale `lab_ingest_cli` assertions (they demanded `first_frame_observed`, which a file import deliberately never reaches, and zero Annex-B omissions, when delimiters are reported) — fixed. Media and archive also
run inside `full` and `release`. `adapter` is written but **not green**: 72 of its 77 capture tests pass; the remaining 5 are all `campaign::history::sentinel` / `::watch` cases, which now reach the run and fail with `ERR-CAPTURE-RTSP-HISTORY-AUTHORITY-001` (a capability refusal in the sentinel path). It stays out of the gates until those pass and are the next wiring targets, in that order of expected value.

### When admission is refused repeatedly

`RCH_SYNC_LIVE_CHECKOUT_REFUSED` and `RCH_TOPOLOGY_PATHS_PRESENT` can keep every worker refusing for
tens of minutes while the queue has free slots. For a single verification run it is faster to take the
shim out and put it back:

```sh
rch shim uninstall
cargo test -q -p <crate> --test <suite> -j6
rch shim install --allow-local-fallback
```

That is a two-second operation each way and a suite that took 25+ minutes through the queue ran in
118 seconds locally. Leave the shim installed and on `--allow-local-fallback` when you are done.

Resolved cause of the bulk of the adapter failures: a non-blocking listener hands `O_NONBLOCK` to the
accepted socket on macOS, so every fixture's first `read` returned EAGAIN immediately and the failure
was reported as the *fixture's* error instead of the child's. Clearing it on every accepted peer, plus
tolerating a poll miss until the accept deadline, took the lane from 13 passed / 64 failed to 64 passed
/ 13 failed. Four separate macOS-visible defects were found and fixed getting this far, all of them invisible on Linux:
the accepted peer inherited `O_NONBLOCK`; the canonicalised root was compared back to the configured
text; the root was recorded lexically while consumers resolved it (refused as `Denied`); and the fixture
pre-created the history root that the child creates exclusively. The last 5 are sentinel/watch capability
refusals (`ERR-CAPTURE-RTSP-HISTORY-AUTHORITY-001`, which is `CampaignHistoryError::Denied`).

That error has only two producers, both in `crates/fss-reference/src/rtsp/campaign_history.rs`: the guard
in `check` at 319-326 (checkpoint stage, io-authority validity and principal, `cx.root_dir() != root`,
`plan.history_path != root`, `authority.permit(operation, plan)`) and the `checkpoint(CAMPAIGN_APPEND)`
at 909-911. Both sides of the path comparison are canonical now, so the live candidates are the
checkpoint stage and `permit`.

Reproduced by hand: with a `nc` listener on 127.0.0.1 the child *does* connect in under a second and
sends an 83-byte DESCRIBE (then fails only because `nc` never answers), and a plan-only run returns a
valid approval digest. So the child and its two-phase approval are fine, and the suspect is the test's
own fixture: it binds a listener, sets it non-blocking, spawns `serve` on a scoped thread and then runs
the child — and that loop is what waits ten seconds. Next step is a blocking listener in `serve` (accept
with a small poll only as a fallback) and re-run one test.

The 13 are reproducible outside the harness, which matters: running
`fss-capture-rtsp reconnect … --approve <digest>` by hand against a `nc` listener fails in about a
second with `ERR-CAPTURE-RTSP-ROOT-001` and **creates neither `--root` nor `--pins`**, so it dies in
pre-flight path validation before any socket work. Planning succeeds and the approval digest is
accepted. The candidates are `Failure::Root` sites in `driver.rs` (1483–1492 and the `_ =>` at 1472),
and pre-creating or omitting `--history-root` makes no difference.

Progress on the 13: the ROOT refusal was a real macOS bug and is fixed. `campaign_history` compared the
*canonicalised* root back to the configured text; on macOS the temp root is itself a symlink
(`/var` -> `/private/var`), so an ordinary path never compares equal and every campaign run refused
before creating anything. The run now reaches `Recorder::new` and fails one step later with
`ERR-CAPTURE-RTSP-HISTORY-001`, having created the history directory and nothing inside it — so the
next site is `CampaignWriter::new` or the `LocalRootPublisher::open` beside it in
`campaign_history.rs::Recorder::new`.

Where the campaign failures stand after another pass: the recorder *constructs* successfully (the
history root is created and an `E`-stage marker prints), so the remaining failure is inside the capture
run itself, not in setup. `reconnect.rs` builds `NativeEffects` and enters `run_from`, and the history
error comes from the recording path (`campaign_history.rs` 460–520). Stage markers are left in the code
on the error paths; strip them once the lane is green.
