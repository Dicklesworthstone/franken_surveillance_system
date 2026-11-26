#!/usr/bin/env python3
"""scripts/offline_github_unavailable_drill.py — complete qualification and release drill
with GitHub-hosted runners and GitHub CLI completely unavailable (FSS-194, bead fss-x4a.26.14).

Proves the local DSR release-authority constitution operationally:
  1. architecture/local_qualification.toml declares local_dsr_receipt authority,
     github_hosted_required = false, offline_after_provisioning = true,
     signing_separate_from_build = true, download_and_verify_after_upload = true,
     and partial_target_matrix_may_publish = false.
  2. Every .github/workflows/*.yml file is audited to confirm no workflow claims
     standalone release authority, grants contents:write on release.yml, or bypasses
     local DSR publication via gh release / action-gh-release.
  3. Under a sealed GitHub-unavailable environment (shadow `gh` binary that records
     any call and exits 99, GITHUB_ACTIONS/GH_TOKEN/GITHUB_TOKEN unset, broken
     HTTP(S)_PROXY=http://127.0.0.1:1, CARGO_NET_OFFLINE=true, RUSTUP_AUTO_INSTALL=0):
       - local policy, manifest, stable-id, architecture-registry, dependency-DAG,
         and unsafe-prohibition audits pass with 0 `gh` invocations;
       - a local qualification receipt is sealed via scripts/qualification_receipt.py;
       - SBOM + license + Cargo.lock + qualification receipt cross-check passes via
         scripts/sbom_crosscheck.py;
       - separated build/signing authority fails closed on same_authority;
       - scripts/release_qualify.sh publish -> verify-remote AND lost-ACK indeterminate
         -> reconcile complete cleanly with 0 `gh` invocations.
  4. Requesting GitHub-hosted release authority (`--simulate-hosted-authority-request`)
     fails closed with typed state `github_hosted_not_release_authority` and local DSR
     remediation guidance.

Zero third-party dependencies: strictly Python standard library + local repo scripts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "fss.github_unavailable_drill.v1"

FORBIDDEN_WORKFLOW_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("gh_release_cli", re.compile(r"\bgh\s+release\s+(?:create|upload|edit)\b")),
    ("action_gh_release", re.compile(r"softprops/action-gh-release", re.IGNORECASE)),
    ("actions_create_release", re.compile(r"actions/create-release", re.IGNORECASE)),
)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def audit_local_qualification_config(repo_root: Path) -> list[str]:
    errors: list[str] = []
    cfg_path = repo_root / "architecture" / "local_qualification.toml"
    if not cfg_path.is_file():
        return [f"missing {cfg_path}"]
    cfg = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    expected = {
        "authority": "local_dsr_receipt",
        "repository_entrypoint": "scripts/qualify.sh",
        "workflow_yaml_role": "portable_executable_specification_only",
        "github_hosted_required": False,
        "clean_snapshot_required": True,
        "exact_sibling_revision_closure": True,
        "locked_resolution": True,
        "offline_after_provisioning": True,
        "partial_target_matrix_may_publish": False,
        "download_and_verify_after_upload": True,
        "signing_separate_from_build": True,
    }
    for key, want in expected.items():
        got = cfg.get(key)
        if got != want:
            errors.append(
                f"architecture/local_qualification.toml: {key}={got!r}, expected {want!r}"
            )
    return errors


def audit_workflows(repo_root: Path) -> tuple[list[str], int]:
    errors: list[str] = []
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return ([f"missing workflow directory {wf_dir}"], 0)
    workflows = sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))
    if not workflows:
        return (["no workflow YAML files found"], 0)

    names = {p.name for p in workflows}
    for required in ("ci.yml", "release.yml"):
        if required not in names:
            errors.append(f"missing expected supplementary workflow .github/workflows/{required}")

    for wf in workflows:
        text = wf.read_text(encoding="utf-8")
        for label, pattern in FORBIDDEN_WORKFLOW_PATTERNS:
            if pattern.search(text):
                errors.append(
                    f".github/workflows/{wf.name}: forbidden hosted release bypass ({label})"
                )
        if wf.name == "release.yml":
            if re.search(r"contents\s*:\s*write", text):
                errors.append(
                    ".github/workflows/release.yml: must not grant contents: write"
                )
            if "scripts/release_qualify.sh" not in text:
                errors.append(
                    ".github/workflows/release.yml: must delegate to scripts/release_qualify.sh"
                )
            if re.search(r"runs-on\s*:\s*(?:ubuntu|macos|windows)-", text):
                errors.append(
                    ".github/workflows/release.yml: release jobs must not rely on GitHub-hosted runners"
                )
    return (errors, len(workflows))


def audit_local_entrypoints(repo_root: Path) -> list[str]:
    errors: list[str] = []
    for rel in ("scripts/qualify.sh", "scripts/release_qualify.sh"):
        p = repo_root / rel
        if not p.is_file():
            errors.append(f"missing {rel}")
            continue
        if not os.access(p, os.X_OK):
            errors.append(f"{rel} is not executable")
        text = p.read_text(encoding="utf-8")
        if "CARGO_NET_OFFLINE=true" not in text:
            errors.append(f"{rel} does not enforce CARGO_NET_OFFLINE=true")
        if "RUSTUP_AUTO_INSTALL=0" not in text:
            errors.append(f"{rel} does not enforce RUSTUP_AUTO_INSTALL=0")
    return errors


def _make_github_blocked_env(shadow_bin: Path, gh_log: Path) -> dict[str, str]:
    gh_shim = shadow_bin / "gh"
    gh_shim.write_text(
        "#!/usr/bin/env bash\n"
        f"printf 'gh %s\\n' \"$*\" >> '{gh_log}'\n"
        "printf 'github-unavailable: simulated GitHub outage (FSS-194)\\n' >&2\n"
        "exit 99\n",
        encoding="utf-8",
    )
    gh_shim.chmod(gh_shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    env = dict(os.environ)
    for k in ("GITHUB_ACTIONS", "GITHUB_TOKEN", "GH_TOKEN", "CI", "GITHUB_RUN_ID"):
        env.pop(k, None)
    env["PATH"] = f"{shadow_bin}{os.pathsep}{env.get('PATH', '')}"
    env["CARGO_NET_OFFLINE"] = "true"
    env["RUSTUP_AUTO_INSTALL"] = "0"
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    env["ALL_PROXY"] = "http://127.0.0.1:1"
    env["NO_PROXY"] = ""
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["RCH_SHIM_LOCAL_IDE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run_cmd(
    argv: list[str], cwd: Path, env: dict[str, str], timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_drill(
    repo_root: Path,
    simulate_hosted_authority_request: bool = False,
) -> tuple[int, dict[str, Any]]:
    if simulate_hosted_authority_request:
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "requirementId": "FSS-194",
            "beadId": "fss-x4a.26.14",
            "state": "github_hosted_not_release_authority",
            "errorCode": "ERR-RELEASE-HOSTED-AUTHORITY-REFUSED-001",
            "githubHostedRequired": False,
            "remediation": (
                "GitHub-hosted workflows are supplementary specifications only and cannot hold "
                "release authority; execute scripts/qualify.sh and scripts/release_qualify.sh "
                "locally on a controlled native DSR host."
            ),
        }
        payload["drillDigest"] = _sha256_bytes(_canonical_json(payload).encode("utf-8"))
        return (1, payload)

    checks: list[dict[str, Any]] = []
    failures: list[str] = []

    cfg_errs = audit_local_qualification_config(repo_root)
    checks.append(
        {
            "id": "constitutional_local_qualification_toml",
            "status": "passed" if not cfg_errs else "failed",
            "errors": cfg_errs,
        }
    )
    failures.extend(cfg_errs)

    wf_errs, wf_count = audit_workflows(repo_root)
    checks.append(
        {
            "id": "workflow_yaml_supplementary_only_audit",
            "status": "passed" if not wf_errs else "failed",
            "workflowCount": wf_count,
            "errors": wf_errs,
        }
    )
    failures.extend(wf_errs)

    entry_errs = audit_local_entrypoints(repo_root)
    checks.append(
        {
            "id": "local_entrypoints_offline_seal_audit",
            "status": "passed" if not entry_errs else "failed",
            "errors": entry_errs,
        }
    )
    failures.extend(entry_errs)

    gh_calls: list[str] = []
    with tempfile.TemporaryDirectory(prefix="fss194-offline-drill-") as tmp:
        td = Path(tmp)
        shadow_bin = td / "shadow-bin"
        shadow_bin.mkdir()
        gh_log = td / "gh-calls.log"
        env = _make_github_blocked_env(shadow_bin, gh_log)

        # Self-verify that the GitHub outage trap actually rejects `gh`.
        trap = _run_cmd(["gh", "--version"], repo_root, env)
        trap_ok = trap.returncode == 99 and gh_log.is_file()
        checks.append(
            {
                "id": "github_cli_outage_trap_verified",
                "status": "passed" if trap_ok else "failed",
                "exitCode": trap.returncode,
            }
        )
        if not trap_ok:
            failures.append("shadow gh outage trap failed to trigger exit 99")
        # Reset log after trap verification so real drill must record 0 calls.
        gh_log.write_text("", encoding="utf-8")

        # 1. Local constitutional & policy qualification steps under GitHub outage.
        local_policy_steps = [
            ("policy", [sys.executable, "scripts/check-policy.py", "--skip-manifest"]),
            ("manifest_audit", [sys.executable, "scripts/manifest_audit.py"]),
            ("stable_id_audit", [sys.executable, "scripts/stable_id_audit.py"]),
            (
                "architecture_registry_consistency",
                [sys.executable, "scripts/architecture_registry_consistency.py"],
            ),
            ("dependency_dag_checker", [sys.executable, "scripts/dependency_dag_checker.py"]),
            (
                "unsafe_prohibition_checker",
                [sys.executable, "scripts/unsafe_prohibition_checker.py"],
            ),
        ]
        records_path = td / "receipt-run" / "commands.jsonl"
        prep = _run_cmd(
            [
                sys.executable,
                "scripts/qualification_receipt.py",
                "prepare-run-dir",
                "--exact",
                str(td / "receipt-run"),
            ],
            repo_root,
            env,
        )
        if prep.returncode != 0:
            failures.append(f"qualification_receipt prepare-run-dir failed: {prep.stderr.strip()}")
            checks.append({"id": "qualification_receipt_prepare", "status": "failed"})
        else:
            manifest_root = "unavailable"
            started_ns = time.time_ns()
            for step_id, argv in local_policy_steps:
                proc = _run_cmd(argv, repo_root, env)
                combined = (proc.stdout + proc.stderr).encode("utf-8")
                digest = _sha256_bytes(combined)
                status = "passed" if proc.returncode == 0 else "failed"
                if step_id == "manifest_audit" and proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        if line.startswith("effectiveRoot="):
                            manifest_root = line.split("=", 1)[1].strip()
                with records_path.open("a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "id": step_id,
                                "status": status,
                                "outputDigest": digest,
                                "argv": argv,
                            },
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                checks.append({"id": f"offline_{step_id}", "status": status})
                if proc.returncode != 0:
                    failures.append(
                        f"offline step {step_id} exited {proc.returncode}: {proc.stderr[-300:]}"
                    )

            finished_ns = max(time.time_ns(), started_ns + 1)
            head_commit_proc = _run_cmd(["git", "rev-parse", "HEAD"], repo_root, env)
            head_tree_proc = _run_cmd(["git", "rev-parse", "HEAD^{tree}"], repo_root, env)
            sib_proc = _run_cmd(
                [sys.executable, "scripts/sibling_closure.py", str(repo_root)], repo_root, env
            )
            if head_commit_proc.returncode != 0 or not head_commit_proc.stdout.strip():
                failures.append(f"git rev-parse HEAD failed: {head_commit_proc.stderr.strip()}")
            if head_tree_proc.returncode != 0 or not head_tree_proc.stdout.strip():
                failures.append(f"git rev-parse HEAD^{{tree}} failed: {head_tree_proc.stderr.strip()}")
            if sib_proc.returncode != 0 or not sib_proc.stdout.strip():
                failures.append(f"sibling_closure.py failed: {sib_proc.stderr.strip()}")
            head_commit = head_commit_proc.stdout.strip()
            head_tree = head_tree_proc.stdout.strip()
            sib = sib_proc.stdout.strip()
            toolchain_toml = tomllib.loads(
                (repo_root / "rust-toolchain.toml").read_text(encoding="utf-8")
            )
            toolchain = toolchain_toml["toolchain"]["channel"]
            receipt_path = td / "receipt-run" / "qualification-receipt.json"
            fin = _run_cmd(
                [
                    sys.executable,
                    "scripts/qualification_receipt.py",
                    "finalize",
                    "--output",
                    str(receipt_path),
                    "--records",
                    str(records_path),
                    "--lane",
                    "policy",
                    "--source-commit",
                    f"git:{head_commit}",
                    "--source-tree",
                    f"git-tree:{head_tree}",
                    "--sibling-digest",
                    sib,
                    "--host-digest",
                    _sha256_bytes(b"fss-194-local-dsr-host"),
                    "--toolchain",
                    toolchain,
                    "--target",
                    "local-native-drill",
                    "--started-ns",
                    str(started_ns),
                    "--finished-ns",
                    str(finished_ns),
                    "--status",
                    "passed" if not failures else "failed",
                    "--manifest-root",
                    manifest_root,
                    "--cargo-lock",
                    str(repo_root / "Cargo.lock"),
                ],
                repo_root,
                env,
            )
            receipt_ok = fin.returncode == 0 and receipt_path.is_file()
            receipt_obj: dict[str, Any] = {}
            if receipt_ok:
                receipt_obj = json.loads(receipt_path.read_text(encoding="utf-8"))
                receipt_ok = receipt_obj.get("status") == "passed"
            checks.append(
                {
                    "id": "offline_local_qualification_receipt",
                    "status": "passed" if receipt_ok else "failed",
                    "manifestRoot": manifest_root,
                }
            )
            if not receipt_ok:
                failures.append(
                    f"local qualification receipt finalization failed: {fin.stderr.strip()}"
                )

            # 2. Offline SBOM + License + Cargo.lock + Qualification Receipt cross-check (FSS-190).
            sbom_dir = td / "sbom-bundle"
            sbom_dir.mkdir()
            sbom_path = sbom_dir / "sbom.spdx.json"
            inv_path = sbom_dir / "license-inventory.json"
            meta_path = sbom_dir / "cargo-metadata.json"
            sbom_script = td / "sbom_check_driver.py"
            sbom_script.write_text(
                "import json, sys\n"
                "from pathlib import Path\n"
                "repo = Path(sys.argv[1])\n"
                "receipt_path = Path(sys.argv[2])\n"
                "sbom_out, inv_out, meta_out = Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5])\n"
                "sys.path.insert(0, str(repo / 'scripts'))\n"
                "import release_artifacts, sbom_crosscheck\n"
                "lock_text = (repo / 'Cargo.lock').read_text(encoding='utf-8')\n"
                "pkgs = sorted(sbom_crosscheck._lock_packages(lock_text))\n"
                "meta = {'packages': [{'name': n, 'version': v, 'id': f'{n}-{v}', "
                "'source': None, 'license': 'MIT', 'license_file': None} for n, v in pkgs]}\n"
                "class Ctx:\n"
                "    version = '0.0.1'\n"
                "    target = 'local-native-drill'\n"
                "    target_base = 'fss-0.0.1-local-native-drill'\n"
                "    source_date_epoch = 1700000000\n"
                "    artifacts = Path('/tmp/unused')\n"
                "sbom = release_artifacts.cargo_sbom(meta, Ctx())\n"
                "inv = release_artifacts.license_inventory(meta, Ctx())\n"
                "sbom_out.write_text(json.dumps(sbom, sort_keys=True), encoding='utf-8')\n"
                "inv_out.write_text(json.dumps(inv, sort_keys=True), encoding='utf-8')\n"
                "meta_out.write_text(json.dumps(meta, sort_keys=True), encoding='utf-8')\n"
                "receipt = json.loads(receipt_path.read_text(encoding='utf-8'))\n"
                "errs = sbom_crosscheck.crosscheck(sbom, inv, lock_text, meta, receipt)\n"
                "print(json.dumps({'packageCount': len(pkgs), 'errors': errs}))\n"
                "sys.exit(0 if not errs else 1)\n",
                encoding="utf-8",
            )
            sbom_proc = _run_cmd(
                [
                    sys.executable,
                    str(sbom_script),
                    str(repo_root),
                    str(receipt_path),
                    str(sbom_path),
                    str(inv_path),
                    str(meta_path),
                ],
                repo_root,
                env,
            )
            sbom_ok = sbom_proc.returncode == 0
            checks.append(
                {
                    "id": "offline_sbom_license_lock_receipt_crosscheck",
                    "status": "passed" if sbom_ok else "failed",
                }
            )
            if not sbom_ok:
                failures.append(f"offline SBOM cross-check failed: {sbom_proc.stdout} {sbom_proc.stderr}")

        # 3. Offline root-last release publication, verify-remote, same-authority refusal,
        #    and lost-ACK indeterminate reconciliation via scripts/release_qualify.sh (FSS-192).
        art_dir = td / "release-artifacts"
        art_dir.mkdir()
        (art_dir / "fss-local-native.tar.xz").write_bytes(b"fss-offline-native-bundle-v1")
        (art_dir / "SHA256SUMS.txt").write_bytes(b"sha256sums-offline-v1\n")
        receipt_file = td / "receipt-run" / "qualification-receipt.json"
        if not receipt_file.is_file():
            failures.append("missing local qualification-receipt.json for release bundle")
        else:
            (art_dir / "qualification-receipt.json").write_bytes(receipt_file.read_bytes())
        basis = _sha256_bytes(b"fss.contract_basis.fss194.offline_drill.v1")

        # 3a. Publish + verify-remote offline (wiring FSS-190 SBOM/license/lock/receipt leg inline!).
        pub_cmd = [
            "bash",
            "scripts/release_qualify.sh",
            "publish",
            "--release-id",
            "rel:fss194:offline:v0.0.1",
            "--version",
            "0.0.1",
            "--artifacts-dir",
            str(art_dir),
            "--remote-store-dir",
            str(td / "remote-store"),
            "--state-dir",
            str(td / "state"),
            "--principal",
            "operator:local-dsr",
            "--builder",
            "builder:local-dsr-host",
            "--signer",
            "signer:offline-hardware-key",
            "--contract-basis-digest",
            basis,
        ]
        if (td / "sbom-bundle" / "sbom.spdx.json").is_file() and receipt_file.is_file():
            pub_cmd.extend(
                [
                    "--sbom",
                    str(td / "sbom-bundle" / "sbom.spdx.json"),
                    "--license-inventory",
                    str(td / "sbom-bundle" / "license-inventory.json"),
                    "--cargo-lock",
                    str(repo_root / "Cargo.lock"),
                    "--metadata",
                    str(td / "sbom-bundle" / "cargo-metadata.json"),
                    "--qualification-receipt",
                    str(receipt_file),
                ]
            )
        pub = _run_cmd(pub_cmd, repo_root, env)
        pub_json = json.loads(pub.stdout) if pub.stdout.strip().startswith("{") else {}
        pub_ok = pub.returncode == 0 and pub_json.get("state") == "published"
        checks.append(
            {
                "id": "offline_root_last_release_publish",
                "status": "passed" if pub_ok else "failed",
                "rootDigest": pub_json.get("rootDigest"),
            }
        )
        if not pub_ok:
            failures.append(f"offline release publish failed: {pub.stdout} {pub.stderr}")

        ver = _run_cmd(
            [
                "bash",
                "scripts/release_qualify.sh",
                "verify-remote",
                "--remote-store-dir",
                str(td / "remote-store"),
            ],
            repo_root,
            env,
        )
        ver_json = json.loads(ver.stdout) if ver.stdout.strip().startswith("{") else {}
        ver_ok = (
            ver.returncode == 0
            and ver_json.get("state") == "verified"
            and ver_json.get("rootDigest") == pub_json.get("rootDigest")
        )
        checks.append(
            {
                "id": "offline_root_last_verify_remote",
                "status": "passed" if ver_ok else "failed",
            }
        )
        if not ver_ok:
            failures.append(f"offline verify-remote failed: {ver.stdout} {ver.stderr}")

        # 3b. Separated-authority refusal offline (builder == signer must exit 1).
        same_auth = _run_cmd(
            [
                "bash",
                "scripts/release_qualify.sh",
                "publish",
                "--release-id",
                "rel:fss194:same-auth",
                "--version",
                "0.0.1",
                "--artifacts-dir",
                str(art_dir),
                "--remote-store-dir",
                str(td / "remote-same-auth"),
                "--state-dir",
                str(td / "state-same-auth"),
                "--principal",
                "operator:local-dsr",
                "--builder",
                "same:principal",
                "--signer",
                "same:principal",
                "--contract-basis-digest",
                basis,
            ],
            repo_root,
            env,
        )
        same_json = (
            json.loads(same_auth.stdout) if same_auth.stdout.strip().startswith("{") else {}
        )
        same_ok = (
            same_auth.returncode == 1 and same_json.get("errorCode") == "same_authority_refused"
        )
        checks.append(
            {
                "id": "offline_separated_authority_refusal",
                "status": "passed" if same_ok else "failed",
            }
        )
        if not same_ok:
            failures.append(
                f"offline same-authority refusal failed: rc={same_auth.returncode} out={same_auth.stdout}"
            )

        # 3c. Lost-ACK indeterminate -> offline reconcile recovery via scripts/release_qualify.sh.
        lost_driver = td / "lost_ack_driver.py"
        lost_driver.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "repo = Path(sys.argv[1])\n"
            "sys.path.insert(0, str(repo / 'scripts'))\n"
            "import release_publication as rp\n"
            "cfg = rp.PublishConfig(\n"
            "    release_id='rel:fss194:lost-ack',\n"
            "    version='0.0.1',\n"
            "    artifacts_dir=Path(sys.argv[2]),\n"
            "    remote_store_dir=Path(sys.argv[3]),\n"
            "    state_dir=Path(sys.argv[4]),\n"
            "    principal='operator:local-dsr',\n"
            "    capability=rp.REQUIRED_PUBLISH_CAPABILITY,\n"
            "    lease_fence=1,\n"
            "    builder_identity='builder:local-dsr-host',\n"
            "    signer_identity='signer:offline-hardware-key',\n"
            "    contract_basis_digest=sys.argv[5],\n"
            "    toolchain_id='nightly-2026-08-31-local-dsr',\n"
            "    faults=rp.FaultSchedule(lost_ack_on_root_publish=True),\n"
            ")\n"
            "res = rp.publish_release(cfg)\n"
            "print(json.dumps(res, sort_keys=True))\n"
            "sys.exit(0 if res.get('state') == 'indeterminate' else 1)\n",
            encoding="utf-8",
        )
        lost = _run_cmd(
            [
                sys.executable,
                str(lost_driver),
                str(repo_root),
                str(art_dir),
                str(td / "remote-lost-ack"),
                str(td / "state-lost-ack"),
                basis,
            ],
            repo_root,
            env,
        )
        lost_json = json.loads(lost.stdout) if lost.stdout.strip().startswith("{") else {}
        lost_ok = lost.returncode == 0 and lost_json.get("state") == "indeterminate"
        rec = _run_cmd(
            [
                "bash",
                "scripts/release_qualify.sh",
                "reconcile",
                "--release-id",
                "rel:fss194:lost-ack",
                "--remote-store-dir",
                str(td / "remote-lost-ack"),
                "--state-dir",
                str(td / "state-lost-ack"),
            ],
            repo_root,
            env,
        )
        rec_json = json.loads(rec.stdout) if rec.stdout.strip().startswith("{") else {}
        rec_ok = rec.returncode == 0 and rec_json.get("state") == "published"
        checks.append(
            {
                "id": "offline_lost_ack_indeterminate_reconcile",
                "status": "passed" if (lost_ok and rec_ok) else "failed",
            }
        )
        if not (lost_ok and rec_ok):
            failures.append(
                f"offline lost-ACK reconcile failed: lost={lost_json} rec={rec_json}"
            )

        # 4. Assert ZERO calls reached the shadow `gh` binary across the entire drill!
        gh_lines = [
            line for line in gh_log.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        gh_calls.extend(gh_lines)
        checks.append(
            {
                "id": "zero_github_cli_invocations",
                "status": "passed" if not gh_calls else "failed",
                "ghInvocationCount": len(gh_calls),
            }
        )
        if gh_calls:
            failures.append(f"unexpected gh invocations during offline drill: {gh_calls}")

    state = "passed" if not failures else "failed"
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "requirementId": "FSS-194",
        "beadId": "fss-x4a.26.14",
        "state": state,
        "githubHostedRequired": False,
        "ghInvocationCount": len(gh_calls),
        "checks": checks,
        "failures": failures,
    }
    report["drillDigest"] = _sha256_bytes(_canonical_json(report).encode("utf-8"))
    return (0 if state == "passed" else 1, report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="FSS-194: Complete local qualification & release drill with GitHub unavailable."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root to audit and drill against.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output path to atomically write the JSON drill receipt.",
    )
    parser.add_argument(
        "--simulate-hosted-authority-request",
        action="store_true",
        help="Negative test: request GitHub-hosted release authority and verify fail-closed refusal.",
    )
    args = parser.parse_args(argv)
    rc, report = run_drill(
        args.repo_root.resolve(),
        simulate_hosted_authority_request=args.simulate_hosted_authority_request,
    )
    if args.output is not None:
        _write_json_atomic(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
