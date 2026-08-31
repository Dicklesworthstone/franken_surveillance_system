# Deep dive: `doodlestein_self_releaser` as FSS's qualification and release authority

**Document class:** normative import analysis
**Status:** constitutional release doctrine
**FSS semantic owner:** `scripts/qualify.sh`, `fss-release`, repository release contracts
**Primary source:** <https://github.com/Dicklesworthstone/doodlestein_self_releaser>

## 1. Why release is part of the architecture

FSS depends on an exact nightly compiler, a closed first-party dependency closure, platform-native media/device behavior, large model artifacts, device/firmware compatibility labs, and potentially long soak/replay campaigns. A green hosted workflow cannot establish that state, and GitHub-hosted capacity is neither reliable nor required.

The release authority is therefore local and receipt-bearing. GitHub workflow files remain useful as portable job-graph specifications and documentation, but Doodlestein Self-Releaser (`dsr`) and controlled native hosts execute the authoritative qualification.

## 2. Clean source identity

Every qualification/release starts from a clean immutable source snapshot. It records:

- FSS commit and tree identity;
- dirty-state refusal;
- submodule/vendor state if any;
- exact Cargo lock digest;
- accepted nightly toolchain identity;
- target/profile/features;
- environment allowlist and relevant values;
- architecture/registry roots;
- qualification script digest;
- model/fixture/device-lab manifest roots.

A developer checkout with uncommitted sibling edits is never the release source.

## 3. Closed sibling revision closure

Every Asupersync or Franken-suite dependency is copied or resolved at an exact clean revision. The release manifest names each sibling tree and Cargo package identity. Path dependencies may be used during development, but release attribution cannot silently incorporate mutable sibling state.

The dependency closure is validated offline. A build that needs a registry or git fetch after snapshot sealing fails.

## 4. Native host matrix

Each supported target maps to a controlled host or an explicitly qualified cross-build path. Host selection considers:

- OS/architecture compatibility;
- health and free capacity;
- disk-backed staging root rather than tmpfs;
- exact toolchain availability;
- required device/media fixtures;
- signing authority scope;
- current contamination/quarantine state.

Platform-specific behavior—especially UVC, filesystem durability, network interfaces, process cleanup, and accelerator backends—must be exercised on native hosts where cross-compilation cannot provide evidence.

## 5. One qualification contract

`scripts/qualify.sh` is the repository-local semantic source of truth. It performs or dispatches:

1. policy/registry/schema/link validation;
2. dependency closure and forbidden-dependency checks;
3. formatting, compilation, Clippy, and tests under the accepted nightly;
4. deterministic reference and LabRuntime suites;
5. conformance/fault/crash matrices appropriate to the lane;
6. same-binary performance checks for release-perf lanes;
7. packaging and installer smoke tests;
8. proof-bundle and claim validation.

Workflow YAML calls this script. It does not duplicate a second set of semantics.

## 6. Lane taxonomy

FSS qualification is separated into lanes so evidence remains honest:

| Lane | Purpose |
|---|---|
| `source-policy` | schemas, registries, docs, dependency constitution, generated artifacts |
| `rust-core` | fmt/check/Clippy/unit/property tests |
| `lab-determinism` | virtual time, schedule exploration, trace replay |
| `storage-crash` | publication cut points, spool/archive recovery, deletion closure |
| `atp-transfer` | corruption/loss/reorder/resume/repair/path races |
| `graph-gauntlet` | reference algorithms, adversarial families, complexity witnesses |
| `model-conformance` | operator/model differential and numeric policy |
| `media-conformance` | parser/codec differential, malformed corpora, timestamp truth |
| `device-lab` | exact device/firmware/app/account-region tuple |
| `privacy-security` | taint, redaction, capability noninterference, secret scanning |
| `performance` | same-binary A/A + A/B distributional evidence |
| `soak-canary` | long-running resource, drift, outage, and upgrade behavior |
| `package-install` | exact assets, checksums/signatures, clean install/upgrade/uninstall |

A release claim cites the lanes and dimensions it earned. Missing device-lab evidence does not invalidate a core-library release, but it forbids claiming that compatibility tuple.

## 7. Partial matrices are never blessed

Completed artifacts may be retained across interrupted runs. Resume verifies each retained artifact before reuse and reruns only missing/invalid targets. The authoritative release root is withheld until all required targets and cross-target invariants pass.

This is the same root-last rule used in FSS evidence publication:

```text
staged target artifacts ≠ release
verified complete target set + signed manifest root = release
```

## 8. Exact asset contract

Every target has one canonical primary asset name plus registered siblings:

- SHA-256 checksum;
- Ed25519/minisign signature;
- SBOM;
- SLSA-style provenance;
- source/dependency manifest;
- qualification receipt;
- license inventory;
- optional model/fixture package manifests.

Upload is followed by download-and-verify. Publication success means the bytes a user can retrieve match the locally qualified bytes.

## 9. Latest-nightly promotion without semantic drift

FSS targets the latest Rust nightly, but “latest” is a promotion workflow rather than an ambient moving input:

1. a probe lane records the candidate nightly identity;
2. the complete required qualification set runs against it;
3. compiler/lint/performance/byte-output drift is classified;
4. the toolchain file changes in a dedicated reviewed commit;
5. that exact nightly becomes the accepted release toolchain;
6. release builds never auto-upgrade it.

Failure to promote the newest candidate promptly is visible debt; silently building with an unrecorded nightly is forbidden.

## 10. Reproducibility and custody

Release receipts include enough information for independent rebuild comparison. Where absolute byte identity is not yet possible, the manifest identifies nondeterministic fields and the narrower semantic equivalence check. FSS uses `SOURCE_DATE_EPOCH` and canonical archives where supported.

Signing keys are capability-scoped and absent from ordinary build hosts. A build host produces unsigned staged artifacts; the publication authority verifies receipts before signing.

## 11. Workflow files as portable specifications

`.github/workflows/*.yml` may describe lanes and can be executed locally through `act`/DSR-compatible machinery. They must not:

- install an unpinned toolchain implicitly;
- fetch dependencies during sealed qualification;
- contain unique release logic absent from repository scripts;
- be cited as the sole authority for a release;
- require GitHub-hosted runners to exist or succeed.

Hosted execution, when available, is supplementary evidence and cannot override a failing local receipt.

## 12. Failure modes a superficial import would create

1. **Green badge as trust root.** Hosted CI passes on a different environment than shipped artifacts.
2. **Mutable sibling closure.** A binary includes uncommitted Asupersync/Franken code.
3. **Partial release.** Some targets upload before the matrix completes.
4. **Discovery-based assets.** Extra or stale files accidentally enter a release.
5. **Cross-compiled false evidence.** Platform behavior is claimed without native execution.
6. **tmpfs exhaustion.** Large Rust/model builds wedge a host.
7. **Upload equals publication.** Remote bytes are never downloaded and checked.
8. **Toolchain drift.** “Nightly” means different compilers on different hosts.
9. **Workflow semantic fork.** Local and hosted checks diverge.
10. **Signing on builder.** Compromised build worker can bless arbitrary bytes.

## 13. Admission evidence

The release system is admitted when:

1. clean/dirty snapshot behavior is tested;
2. every first-party sibling revision is captured and offline-resolvable;
3. host selection, capacity, failover, and quarantine have deterministic receipts;
4. staging refuses tmpfs/ramfs and enforces disk budgets;
5. interrupted/resumed matrices never publish a partial root;
6. every retained target artifact is reverified before reuse;
7. exact asset enumeration rejects extras and omissions;
8. signing is separated from building and signatures verify after download;
9. SBOM/provenance/source manifests agree with the binary closure;
10. installers pass clean install, upgrade, downgrade refusal, and uninstall canaries;
11. the candidate-nightly promotion lane detects semantic and performance regressions;
12. workflows contain no unique authority and can be executed locally;
13. GitHub-hosted runner absence has no effect on qualification or release;
14. public readiness claims are mechanically derivable from retained lane receipts.

## 14. Final import rule

FSS imports DSR's **clean-snapshot, exact-sibling, native-host, resumable-but-never-partial, signed-and-download-verified release discipline**. Local receipts are release authority. GitHub is a distribution and collaboration surface, not the system that decides whether FSS is correct.
