# DSR assimilation admission status (DEEP-DSR-001 / bead fss-x4a.27.50)

Companion to `DOODLESTEIN_SELF_RELEASER.md` §13 ("the release system is
admitted when…"): the criterion-by-criterion record of where each admitted
mechanism landed, the retained evidence, and the honest gaps. Status
vocabulary: **admitted** (mechanically evidenced in-repo), **pending-gate**
(landed but its defining proof belongs to a named open bead).

| # | Admission criterion | Landing site | Evidence | Status |
|---|---|---|---|---|
| 1 | clean/dirty snapshot behavior tested | receipts carry `sourceCommit` + `sourceTree`; DSR's own fence refuses a moving tree | clean-snapshot receipt 20261010T190212Z PASSED (39/39); DSR caught a mid-run commit on 2026-10-10 and invalidated the run | admitted |
| 2 | every first-party sibling revision captured, offline-resolvable | `scripts/sibling_closure.py` (digest over imports/allowlist/toolchain pin) + `CARGO_NET_OFFLINE` + `--offline` on every cargo invocation | `tests/test_qualification_receipt.py::TestSiblingClosure` 4/4; receipts carry `siblingClosureDigest` | admitted |
| 3 | host capacity with deterministic receipts | `scripts/capacity_check.py` wired as `capacity-preflight` before every lane | `tests/test_capacity_check.py` 7/7 incl. lane-wiring assertion; live refusal under pressure 2026-10-11 (typed state, reclaim guidance) | admitted (host selection/failover are DSR-internal, not FSS-lane concerns) |
| 4 | staging refuses tmpfs/ramfs, enforces disk budgets | disk budgets = capacity preflight (above) | tmpfs staging refusal is not separately enforced — release staging always targets the receipt dir on the system volume; noted as a release-lane follow-up | pending-gate (disk budget admitted; tmpfs explicit refusal unenforced) |
| 5 | interrupted/resumed matrices never publish a partial root | `scripts/target_matrix.py` (atomic state; resume = exact worklist; complete = all-declared gate) | `tests/test_target_matrix.py` 8/8 (interrupted-never-blesses, extended-reopens) | admitted |
| 6 | retained target artifacts reverified before reuse | `scripts/release_artifacts.py verify` (local reuse) + `dsr release verify` (post-upload) | local: 9/9 green in the policy lane; post-download = criterion 8's rehearsal | pending-gate (FSS-192/26.20: download-and-verify proof is the owner's rehearsal) |
| 7 | exact asset enumeration rejects extras and omissions | `scripts/release_artifacts.py` (leftover temp files refused preflight; out-of-set never shipped) | `tests/test_release_artifacts.py` 9/9; lane step `release-artifact-tests` PASSED | admitted |
| 8 | signing separated from building; signatures verify after download | `scripts/signing_authority.py` (builder==signer refused; payload binds digest+builder+signer) | `tests/test_signing_authority.py` 6/6 (round-trip, separation, tamper, wrong-signer) | pending-gate (separation admitted; verify-after-download = the 26.20 rehearsal) |
| 9 | SBOM/provenance/source manifests agree with the binary closure | `scripts/sbom_crosscheck.py` (five agreement legs) | `tests/test_sbom_crosscheck.py` 8/8 with real-generator fixtures | admitted |
| 10 | installer clean/upgrade/downgrade-refusal/uninstall canaries | — | no installer lane exists yet (the release has no installer artifacts to canary at the current stage) | pending-gate (installer canaries are premature until release artifacts exist; tracked with the release lane) |
| 11 | candidate-nightly promotion detects regressions | `scripts/toolchain_probe.py` (typed candidacy; NEVER auto-promotes; evidence names the full-qualification gate) | `tests/test_toolchain_probe.py` 6/6 | admitted (candidacy probe; the promotion RUN is by design a separate owner-gated full qualification) |
| 12 | workflows contain no unique authority, executable locally | all three workflows are thin `scripts/` calls | `tests/test_workflow_yaml_portable.py` 4/4 | admitted |
| 13 | GitHub-runner absence has no effect on qualification/release | local qualification is the authority (DSR quality transport green with identical receipts) | DSR receipt 20261011T202226Z PASSED, command-set-identical to direct run | pending-gate (full no-GitHub release proof = 26.14/26.20) |
| 14 | public readiness claims mechanically derivable from retained receipts | `scripts/claim_proof_bundle_checker.py` + receipt discipline (failed runs leave `status:failed` receipts; no qualifying root behind failure) | 470-test suite green; empirical cascade-era failed receipts | admitted |

## Source provenance (the import record)

- **Primary source**: <https://github.com/Dicklesworthstone/doodlestein_self_releaser> (deep dive §0).
- **Role**: research/admission source — release discipline only; DSR remains a
  sealed external tool (invoked as a binary), never an FSS production runtime
  dependency. No IPC wrapper, no runtime download, no credential path from
  DSR into FSS semantics.
- **Behavioral oracle**: `dsr quality --tool franken_surveillance_system`
  executing `scripts/dsr-quality-check.sh` → `scripts/qualify.sh policy` —
  receipt equivalence proven against the direct-local run (2026-10-11).
- **Substitute prohibition**: the qualification entrypoint is
  `scripts/qualify.sh` alone; DSR/CI may transport it but no surface may
  replace it (`workflow_yaml_portable` pins the YAML side).
- **Failure boundary**: DSR-unavailable is a typed transport degradation, not
  a qualification failure — local receipts remain the release authority.

## Verdict

10 of 14 criteria mechanically admitted; 4 pending-gate items all reduce to
the DSR release rehearsal (26.20/26.14 — the owner's GitHub-publish decision)
and the future installer lane. The deep dive's final import rule — local
receipts are release authority — is the operative discipline in every landed
mechanism.
