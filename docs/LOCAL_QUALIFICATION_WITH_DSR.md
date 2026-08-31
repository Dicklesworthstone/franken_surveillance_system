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
./scripts/qualify.sh --lane full --receipt-dir qualification-artifacts/local

dsr build --repo franken_surveillance_system --version vX.Y.Z --resume
dsr release --repo franken_surveillance_system --version vX.Y.Z --draft
dsr release verify --repo franken_surveillance_system --version vX.Y.Z
```

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
