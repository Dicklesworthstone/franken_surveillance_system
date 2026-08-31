# Qualification lane registry

Machine source: `architecture/release_qualification.json`. Full doctrine: [`docs/LOCAL_QUALIFICATION_WITH_DSR.md`](../docs/LOCAL_QUALIFICATION_WITH_DSR.md). GitHub workflow YAML is a portable job-graph specification and optional supplementary execution path; local DSR receipts are release authority.

| ID | Lane | Scope | Required evidence | Authority |
|---|---|---|---|---|
| `QL-POLICY-001` | `policy` | `all` | Machine registries, schemas, docs, dependency constitution, links, manifest, stable IDs | `local` |
| `QL-RUST-001` | `rust` | `all` | Pinned nightly fmt/check/clippy/test with unsafe and forbidden-dependency scans | `local` |
| `QL-LAB-001` | `deterministic_lab` | `linux-x86_64` | Virtual-time replay, schedule exploration, cancellation, obligation, and fault campaigns | `local` |
| `QL-ADAPTER-001` | `adapter` | `device tuple` | Protocol fixtures plus owner-authorized live first-frame/continuity/control tests | `local` |
| `QL-MEDIA-001` | `media` | `platform+codec` | Pure-Rust probe/decode/remux/timestamp/malformed-media gauntlet plus pinned lab-oracle differential evidence | `local` |
| `QL-ARCHIVE-001` | `archive` | `provider+region` | Multipart interruption, root-last, restore, retrievability, deletion, and cost-manifest tests | `local` |
| `QL-MODEL-001` | `model` | `model+hardware` | Artifact identity, operator coverage, deterministic receipt, OOM/cancel, quality, and shadow gates | `local` |
| `QL-GEOMETRY-001` | `geometry` | `site+camera tuple` | Held-out reprojection, covariance, drift, coverage, mask, and rollback tests | `local` |
| `QL-THREAT-001` | `threat` | `sealed corpus` | Event-level hard-negative/threat AUPRC, fixed-alert-budget recall, calibration, and miss ledger | `local` |
| `QL-PRIVACY-001` | `privacy` | `deployment profile` | Mask-before-egress, retention, export, deletion closure, and capability noninterference | `local` |
| `QL-LINUX-001` | `native_release` | `linux-x86_64` | Clean snapshot native build, tests, package, SBOM, signatures, smoke, and receipt | `local` |
| `QL-MACOS-001` | `native_release` | `darwin-arm64` | Clean snapshot native build, tests, package, SBOM, signatures, smoke, and receipt | `local` |
| `QL-WINDOWS-001` | `native_release` | `windows-x86_64` | Clean snapshot native build, tests, package, SBOM, signatures, smoke, and receipt | `local` |
| `QL-RELEASE-001` | `aggregate_release` | `all required` | Verify source/sibling closure, all lane receipts, exact assets, upload, download, and aggregate root | `local` |
