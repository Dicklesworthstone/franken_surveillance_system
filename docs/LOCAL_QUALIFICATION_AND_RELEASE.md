# Local qualification and DSR-first release architecture

**Document class:** normative qualification, build, custody, and publication plan
**Revision:** 1
**Date:** 2026-08-31
**Primary source DNA:** Doodlestein Self-Releaser, Dwarf Fortress MCP, FrankenFS, FrankenNetworkX, FrankenTorch

---

## 0. Thesis

FSS depends on exact nightly behavior, exact sibling revisions, native media/device behavior,
physical camera/firmware tuples, model generations, CPU/accelerator features, archive providers,
and long deterministic/fault campaigns. A green GitHub-hosted workflow cannot be the trust root for
such a system, even when hosted capacity is available.

The release rule is:

> **The direct local qualifier and its DSR-orchestrated native lanes are the release authority.
> GitHub workflow YAML is a portable executable specification of those commands. Hosted workflow
> runs are optional reproduction evidence and can neither bless a failing local receipt nor block a
> complete locally qualified release.**

FSS keeps workflows because they are useful job graphs, documentation, and an input to `act`/DSR.
It does not depend on GitHub-hosted runners, queue availability, or hosted caches.

## 1. Release invariants

### `REL-INV-001` — one qualification contract

Local direct execution, DSR/act, native remote hosts, and optional hosted Actions all invoke the
same repository-owned qualification commands. They do not maintain separate shell logic or weaker
profiles.

### `REL-INV-002` — clean source identity

Qualification begins from a clean immutable source snapshot at an exact commit/tag. Uncommitted
files, ignored local artifacts, mutable generated files, and developer checkout state cannot enter
the release.

### `REL-INV-003` — exact sibling closure

Every Asupersync/Franken path dependency is copied into the release snapshot from an exact clean
revision and recorded. Cargo resolution is locked/offline. The main commit alone is not sufficient
identity.

### `REL-INV-004` — latest qualified nightly

The source pins a dated nightly. DSR verifies the exact `rustc -Vv`/Cargo/component identity on each
host. Updating the pin creates a new qualification generation. “Nightly” never means the moving
channel at release time.

### `REL-INV-005` — native behavior is tested natively

macOS/Apple Silicon, Linux ISA profiles, Windows, device adapters, accelerators, filesystems, and
network/media boundaries are qualified on the actual required hosts or hardware. Cross-compilation
can establish buildability, not native behavioral readiness.

### `REL-INV-006` — partial matrices are never blessed

Verified completed target artifacts may be retained across an interrupted/resumed DSR run. The
release root and authoritative manifest are withheld until every required lane and cross-lane
invariant succeeds. A partial result is explicit staged evidence, never “mostly released.”

### `REL-INV-007` — exact asset contract

Each target/profile maps to one exact primary asset name plus required checksum/signature siblings.
The release contains only the enumerated assets, source snapshot, SBOM, qualification receipts, and
registered supplemental artifacts. Discovery-based uploads are forbidden.

The checked-in DSR contract uses stable, version-independent basenames because the release tag is
the version namespace and DSR validates exact names before a run. Target-specific support assets
carry the native Rust triple. The Linux x86_64 lane is the sole common-asset publisher for the
deterministic source archive and source manifest; every other lane publishes only uniquely named
target evidence. DSR therefore never has to guess whether same-named files from different hosts are
duplicates, and any extra or missing basename remains a hard failure.

### `REL-INV-008` — publication is root-last

Draft/staged assets may exist. The signed release manifest/root publishes only after all assets are
uploaded, downloaded again, and verified against the locally qualified bytes. Publication is the
semantic commit point.

### `REL-INV-009` — claims come from receipts

README badges, release notes, compatibility matrices, model/adapter support, and performance claims
are generated or checked against retained proof bundles. A workflow status badge is not a readiness
claim.

### `REL-INV-010` — hosted CI is supplementary

Hosted GitHub failures may reveal a problem and must be investigated. Hosted success is not
required release evidence and cannot override a local/native failure. Queue/throttle state is
operational metadata, not product correctness.

## 2. Repository qualification entrypoints

The semantic entrypoint is `scripts/qualify.sh` during the bootstrap phase and later the Rust
`fss-qualify` binary. Workflow files and DSR invoke profiles:

```text
quick       policy/schema/docs + fmt/check + focused tests
full        workspace tests + deterministic replay + dependency/format gates
native      platform-specific filesystem/network/process/media behavior
model       model/operator/differential/quality profile
adapter     exact device/firmware/app tuple profile
soak        long-running continuity/cancellation/reconnect/resource profile
security    malformed inputs, capability noninterference, secret/taint checks
privacy     masks, retention, export, deletion closure
release     all required lanes + reproducibility + artifact custody/publication
```

Every invocation writes a versioned receipt to an explicit output directory. Human logs are
siblings, not the machine contract.

## 3. Source snapshot and sibling closure

### 3.1 Preflight

Release preflight verifies:

- branch/tag and exact commit;
- no tracked/untracked mutation permitted by policy;
- annotated release tag points to the source commit;
- version agreement across publishable crates/binaries;
- `Cargo.lock` current and unchanged by offline metadata;
- architecture/registry/schema consistency;
- no expired device/model/dependency qualifications;
- exact DSR repository configuration;
- signing/public-key/tag-protection contract;
- sufficient disk on a non-tmpfs staging root.

### 3.2 Snapshot

DSR creates an isolated disk-backed snapshot. It never builds from the mutable developer checkout.
The snapshot includes:

- FSS source;
- exact sibling source closure under stable relative paths;
- lockfile and toolchain file;
- machine registries and schemas;
- model/adaptor manifests required for the selected release profile;
- checked-in fixtures/reference corpora permitted in source;
- workflow/job specifications;
- source manifest with file digests and modes.

Large external model weights and proprietary fixtures are referenced by sealed lab/asset manifests,
not smuggled into the source tree.

### 3.3 Closure manifest

The closure manifest records for every repository:

```text
repository identity
commit and tree digest
clean status
relative snapshot location
license digest
Cargo packages/features exposed
expected dependency edge
local qualification receipt
```

A sibling that is dirty, missing, at the wrong commit, or resolves differently offline blocks the
release.

## 4. Workflow YAML as portable specification

`.github/workflows/ci.yml` and `release.yml` have three roles:

1. readable declaration of job/lane dependencies;
2. optional hosted reproduction;
3. input to DSR/`act` on controlled machines.

They do not duplicate semantic commands. Every step delegates to a versioned script/Rust command.
Workflow runner labels describe the intended environment; DSR may map Linux jobs to `act` and macOS/
Windows jobs to native SSH hosts.

The workflow includes an explicit notice that:

- local DSR/direct receipts are authoritative;
- hosted success is supplementary;
- release publication requires the root receipt, not workflow completion;
- no runtime network acquisition is permitted after preflight provisioning.

## 5. Lane topology

### 5.1 `L0-source-policy`

- repository/manifest/schema/registry consistency;
- stable ID uniqueness/tombstones;
- dependency constitution and transitive graph;
- license/security advisory inventory;
- formatting/lints/docs links;
- generated artifact freshness;
- no secrets/credential patterns;
- no forbidden runtime/dependency patterns.

### 5.2 `L1-safe-reference`

- pure semantic core;
- deterministic in-memory ledger/object/graph/model/adapter references;
- state-machine and property tests;
- TLA+/Lean proof checks where available;
- same-seed replay and cross-platform canonical fixtures.

### 5.3 `L2-linux-native`

Required Linux target/CPU profiles. Includes Asupersync region supervision, filesystem durability,
sockets, the pure-Rust media boundary, local spool, and long cancellation/resource tests. A
separate sealed oracle lane may compare against an exact FFmpeg identity, which is excluded from
the release closure. SIMD/ISA-specific
artifacts declare minimum CPU features; a portable baseline remains available.

### 5.4 `L3-macos-native`

Apple Silicon and, while supported, x86-64 macOS. Includes UVC/USB behavior, filesystem semantics,
Asupersync region shutdown, networking, portable SIMD, energy measurements, and future safe
first-party accelerator substrates. Sealed oracle-process behavior is tested only in its lab lane.

### 5.5 `L4-windows-native`

Windows x86-64 (and arm64 when declared). Includes admitted safe-Rust camera/media substrate
contracts, region cleanup, filesystem atomicity, sockets, installer, and service lifecycle. Foreign
helpers are not production fallbacks.

### 5.6 `L5-replay-fault`

- complete crash/cancellation cut-point campaigns;
- packet loss/reorder/duplication;
- clock discontinuity;
- ledger/object/journal corruption;
- transfer path and archive ambiguity;
- effect lost-ACK/reconciliation;
- deterministic failure bundles.

### 5.7 `L6-storage-archive`

- local spool crash/repair;
- root-last multi-object publication;
- B2/R2/S3-compatible exact provider profiles;
- multipart interruption/reconciliation;
- download-and-verify/restore;
- proof-of-retrievability/repair;
- retention/hold/deletion closure;
- dated pricing/cost receipt.

Provider outage cannot block the local safety path beyond declared spool limits.

### 5.8 `L7-model-cpu`

- pure-Rust import/operator differential;
- scalar/SIMD/fused/quantized arms;
- model execution receipts;
- memory/OOM/cancellation;
- held-out event metrics and calibration;
- cross-platform numeric policy;
- no Python/ONNX runtime in release closure.

### 5.9 `L8-model-accelerator`

One lane per exact accelerator/OS/driver/runtime tuple. It includes process isolation, CPU replay,
OOM/hang/reset, output/tolerance, tail latency, energy, and fallback. Absence of this lane prevents
only the accelerator support claim, not the CPU release.

### 5.10 `L9-standards-adapters`

- replay/file import;
- UVC/UAC tuple matrix;
- RTSP/RTP/RTCP servers/cameras;
- ONVIF Profile T/M conformance fixtures and devices;
- auth/reconnect/profile/timestamp/packet faults;
- exact continuity/latency/source-custody receipts.

### 5.11 `L10-proprietary-lab`

One isolated lane per device/firmware/app/account-region tuple. No production credential enters the
general test fleet. Promotion requires documented owner-authorized onboarding, drift detection,
lockout/rate-limit protection, fixture sanitization, and a reproducible read path. This lane can be
excluded from public release if no tuple is qualified.

### 5.12 `L11-geometry-property`

- synthetic/known-rig calibration;
- camera movement/drift;
- time uncertainty;
- visibility/coverage validation;
- graph resilience/placement certificates;
- privacy mask reprojection;
- drone recorded-media import and manual calibration mission.

### 5.13 `L12-security-privacy`

- capability noninterference;
- adapter/model/media hostile-input corpus;
- secret/log/trace scans;
- prompt/OCR taint;
- privacy-mask early application;
- audio-off proof;
- export custody;
- graph-complete deletion;
- denial of weapon/pursuit/autonomous-flight effects.

### 5.14 `L13-agent-cognitive-product`

This lane implements `QL-AGENT-001` over a sealed task, interruption, multi-agent, drifted-handoff,
and repeated-task corpus. It verifies:

- cold/warm orientation from one anchor into a coherent `SituationCapsule`/`SituationFrame`;
- exact `ContractBasis` and `AgentRequestEnvelope`/`AgentResponseEnvelope` equivalence across Rust
  API, CLI, MCP, TUI, reports, replay, and handoff resume;
- knowledge-state, provenance, hypothesis-disposition, coverage, contradiction, redaction, and
  indeterminacy fidelity across every presentation;
- `WorldEnvelope` reconstruction, certified-core/absence preservation, material-alternative and
  protected-adversarial-residual retention, and evidence-linked collapse witnesses;
- robust/conditional/probe/wait/blocked affordance classification plus plan revalidation when the
  protected world frontier expands, splits, or loses coverage;
- semantic-compression receipts and omission counterfactuals proving critical context was retained;
- meaningful-delta/silence semantics, critical interruption, continuation, disconnect, and resume;
- durable investigations, competing hypotheses, VOI probe selection, stop rules, and residual
  uncertainty;
- hard-clamped nondominated affordance frontiers with component/sensitivity explanations and no
  authority laundering;
- objective→plan→prepare→commit→wait/cancel→verify/reconcile closure under stale/crash/lost-ACK
  schedules;
- multi-agent work claims/findings, branch isolation, capability noninterference, and duplicate-work
  reduction;
- root-last handoff/rebase under anchor, schema, policy, model, calibration, alias, budget, and
  authority drift;
- execution episodes, feedback/learning proposals, trauma guard, harmful transfer, expiry/revival,
  and absence of silent activation;
- Rust API/CLI/MCP/TUI/report semantic equivalence, stable errors, robot docs, accessibility, and
  bounded output;
- task correctness/calibration/evidence use/unsafe-action rate together with tokens, bytes, graph
  and model work, latency, energy, privacy exposure, operator burden, obligation closure, and
  handoff/accretion metrics.

The lane compares compact progressive operation against exhaustive/reference task oracles. Lower
resource use is a win only when task quality, hard constraints, coverage, and terminal-effect truth
are preserved.

The sealed possible-world gauntlet includes deliberately deceptive scenarios in which the
highest-ranked explanation is benign but a low-ranked residual remains both physically consistent
and high loss. A passing implementation must preserve that residual through context shaping,
handoff, transfer, model reranking, and view changes; refuse or condition actions that are unsafe
in it; select a discriminating probe when worthwhile; and remove it only with a valid collapse
witness. A/A and presentation-equivalence runs must produce the same envelope digest and action
robustness class from the same contract basis.

### 5.15 `L14-soak-canary`

Long-duration multi-stream operation with resource ceilings, failures, reconnects, model/archive
backlog, clock drift, and operator alerts. Canary install/upgrade runs the published bytes—not the
build tree—on clean hosts and verifies rollback.

## 6. Qualification receipt model

Each lane receipt includes:

```text
schema/lane/profile/gate IDs
source commit/tree and closure manifest digest
toolchain/target/host/CPU/OS identity
feature/profile/config/model/adapter/provider generations
fixture and workload roots
commands and environment allowlist
start/end intervals and duration
pass/fail/partial/interrupted status
checks, measurements, confidence intervals
negative evidence and excluded dimensions
artifacts/logs/replay bundles
reproduction command
signatures
```

A root release qualification receipt references every required lane receipt and verifies cross-lane
invariants such as identical source/lock/sibling closure and expected asset digests. The schema is
`schemas/release_qualification_receipt.v1.json`.

## 7. Parallel and resumable execution

DSR may execute independent lanes/targets concurrently under configured limits. Each attempt owns:

- isolated snapshot/build/output directories;
- logs and structured result;
- host/toolchain receipt;
- cancellation/drain state;
- artifact staging namespace.

On interruption:

- valid completed lane receipts/artifacts are retained;
- incomplete lanes are terminal/interrupted, not silently retried in place;
- resume verifies prior source/closure/toolchain/artifacts before reuse;
- changed inputs create a new run identity;
- the release root remains absent until the complete matrix passes.

This mirrors FSS’s runtime publication doctrine: staged children can exist without a committed root.

## 8. Reproducibility

Two builds may be called reproducible only when the declared reproducibility domain matches:

- source/tree and sibling closure;
- toolchain/target/profile/features;
- environment allowlist;
- model/generated asset inputs;
- timestamps through `SOURCE_DATE_EPOCH` or equivalent;
- archive ordering/metadata;
- linker and native tool identities where relevant.

The release compares bytes where deterministic output is expected. Where platform toolchains embed
unavoidable signed metadata, it compares normalized semantic manifests and documents the variance.
“Built from the same tag” is not reproducibility evidence.

## 9. Artifact contract

Planned primary CLI/service assets are versioned exact names, for example:

```text
fss-v0.x.y-x86_64-unknown-linux-gnu.tar.xz
fss-v0.x.y-aarch64-unknown-linux-gnu.tar.xz
fss-v0.x.y-aarch64-apple-darwin.tar.xz
fss-v0.x.y-x86_64-pc-windows-msvc.zip
```

A production release may include several binaries (`fss`, `fssd`, `fss-mcp`, `fss-qualify`,
selected boundary hosts) in one target archive. Each primary has:

- `.sha256` sidecar;
- `.minisig` or registered signature;
- exact archive file manifest;
- target qualification receipt reference.

Frozen additional assets include:

- source snapshot;
- root qualification manifest/receipt;
- dependency/SBOM report;
- licenses/notices;
- public verification instructions;
- checksums/signatures;
- schema/format registry snapshot;
- supported model/adapter/provider tuples;
- release notes generated from claim evidence.

No arbitrary logs, secrets, lab credentials, unqualified model weights, or discovery-based extras are
uploaded.

## 10. Signing, provenance, and custody

- The private signing key remains outside repositories/build snapshots.
- The exact public key is a tracked source input pinned to the release tag.
- DSR verifies tag-protection/ruleset facts where configured; missing/redacted policy fields are not
  evidence.
- Signatures cover primary assets and the root manifest.
- SBOM/provenance identify source, closure, toolchain, commands, hosts, and artifacts.
- Publication begins as draft/staging.
- Every uploaded asset is downloaded through the user-visible release path and verified.
- Only then is the root manifest/release promoted/published.
- `fss release verify`/DSR can independently re-download and check the exact asset set.

## 11. Versioning and activation

Version detection is read-only and fail-closed. A Rust workspace must have an unambiguous main
package or common publishable version. Release tags are annotated and source-bound.

Operational model/adapter/calibration generations are independent from the software version. A
software release states which registry/format ranges it understands; activation remains a prepared
runtime effect with rollback.

## 12. Canary, upgrade, and rollback

The canary protocol:

1. install published artifact on a clean canary host;
2. verify checksum/signature/provenance;
3. run `fss doctor` and read-only fixture replay;
4. test config/schema migration on a copy;
5. run bounded live standards adapter/model/archive smoke where authorized;
6. verify resource ceilings, logs, and no secret leakage;
7. stop/drain and inspect obligations/processes;
8. upgrade from prior supported version;
9. roll back to prior version and verify data readability;
10. seal canary receipt.

Failure prevents promotion but preserves staged evidence. Rollback never uses destructive database
rewrites without a sealed migration/restore plan.

## 13. Local DSR configuration

A checked-in example lives at `docs/dsr/franken_surveillance_system.yaml`. It names:

- repository/local path;
- workflow;
- workspace binaries;
- targets and native/act mappings;
- checks/profile commands;
- exact artifact names;
- release contract and sibling crates;
- included docs/licenses;
- environment and build-root constraints.

Secrets, private hostnames, and absolute sibling revisions remain operator-local or generated into
the run manifest.

## 14. Hosted GitHub Actions policy

The repository may keep push/pull-request/workflow-dispatch triggers to provide convenient
supplementary feedback. The following are prohibited:

- blocking release solely because hosted capacity is unavailable;
- treating a hosted badge as aggregate readiness;
- downloading unpinned “latest” tools/models in a release job;
- maintaining commands that diverge from local qualifier;
- using hosted-only secrets as a required qualification input;
- publishing a release directly from a generic hosted job without the signed local root receipt;
- claiming native camera/accelerator/filesystem support from an emulated/hosted lane.

## 15. Initial DSR execution order

1. `L0-source-policy` and `L1-safe-reference` locally.
2. Build the clean closure snapshot and pin the run identity.
3. Fan out Linux/macOS/Windows native build/test lanes.
4. Run replay/fault and storage/archive lanes.
5. Run model CPU and any claimed accelerator lanes.
6. Run standards-device and proprietary-lab lanes for claimed tuples.
7. Run geometry/security/privacy/agent-product lanes.
8. Run soak/canary on the built artifacts.
9. Reconcile every lane and verify cross-lane source identity.
10. Package exact assets, checksum/sign, generate SBOM/provenance.
11. Stage draft release, upload, download-and-verify.
12. Publish root manifest/release.

## 16. Rejected release designs

- release authority delegated to GitHub-hosted runner status;
- a second local build script separate from workflow commands;
- building from a dirty checkout;
- path dependencies copied without exact clean revisions;
- “all targets” claim from cross-compilation only;
- reusing partial artifacts without reverification;
- publishing some targets and calling the version released;
- uploading every file found in an artifacts directory;
- checksums generated before final packaging or not verified after download;
- unsigned mutable manifest;
- source presence/counts as feature qualification;
- benchmark claims without exact workload/source/toolchain receipts;
- proprietary adapter support without exact device/firmware/app lane;
- model support without pure-Rust execution and held-out quality lane;
- deleting failed/intermediate evidence to make the release look clean.

A DSR-first release is not merely a workaround for throttled Actions. It is the natural release
architecture for a system whose strongest claims depend on controlled local hardware, exact sibling
closures, physical devices, and retained evidence.
