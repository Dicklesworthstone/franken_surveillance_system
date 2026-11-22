#!/usr/bin/env bash
# FSS-192 (`fss-x4a.26.12`) E2E verification: upload then download-and-verify
# root-last release publication, fault/cancel/indeterminate reconciliation,
# authority separation, and independent post-publish verification.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_192_release_publication.sh"
e2e_init "fss_192_release_publication" "fss-x4a.26.12" "$@"

e2e_step "unit_and_fault_suite" -- python3 -m unittest -v tests/test_release_publication.py
e2e_expect_exit "unit_and_fault_suite" 0

e2e_step "prereq_sbom_and_signing_authority" -- python3 -m unittest tests/test_sbom_crosscheck.py tests/test_signing_authority.py
e2e_expect_exit "prereq_sbom_and_signing_authority" 0

e2e_step "cli_e2e_publish_verify_and_negative_refusal" -- python3 -B - "$_E2E_REPO_ROOT" <<'PY'
import hashlib, json, subprocess, sys, tempfile
from pathlib import Path

repo = Path(sys.argv[1])
script = repo / "scripts" / "release_publication.py"
basis = "sha256:" + hashlib.sha256(b"contract_basis:fss.e2e.release.v1").hexdigest()

with tempfile.TemporaryDirectory(prefix="fss192-e2e-") as t:
    td = Path(t)
    art = td / "artifacts"
    art.mkdir()
    (art / "fss-linux.tar.xz").write_bytes(b"e2e-binary-archive-v1")
    (art / "SHA256SUMS.txt").write_bytes(b"e2e-sums-v1\n")

    # 1. Success path: publish -> independent verify -> idempotent replay.
    pub = subprocess.run(
        [
            sys.executable, str(script), "publish",
            "--release-id", "rel:e2e:v0.1.0",
            "--version", "0.1.0",
            "--artifacts-dir", str(art),
            "--remote-store-dir", str(td / "remote"),
            "--state-dir", str(td / "state"),
            "--principal", "operator:e2e",
            "--builder", "builder:e2e-x86_64",
            "--signer", "signer:e2e-hsm",
            "--contract-basis-digest", basis,
        ],
        capture_output=True, text=True, check=True, timeout=30,
    )
    pub_json = json.loads(pub.stdout)
    assert pub_json["state"] == "published", pub_json

    ver = subprocess.run(
        [sys.executable, str(script), "verify", "--remote-store-dir", str(td / "remote")],
        capture_output=True, text=True, check=True, timeout=30,
    )
    ver_json = json.loads(ver.stdout)
    assert ver_json["state"] == "verified" and ver_json["rootDigest"] == pub_json["rootDigest"], ver_json

    # 2. Negative path: same builder==signer MUST exit 1 with same_authority_refused.
    neg = subprocess.run(
        [
            sys.executable, str(script), "publish",
            "--release-id", "rel:e2e:same-auth",
            "--version", "0.1.1",
            "--artifacts-dir", str(art),
            "--remote-store-dir", str(td / "remote_neg"),
            "--state-dir", str(td / "state_neg"),
            "--principal", "operator:e2e",
            "--builder", "same:principal",
            "--signer", "same:principal",
            "--contract-basis-digest", basis,
        ],
        capture_output=True, text=True, timeout=30,
    )
    assert neg.returncode == 1, neg.stdout
    neg_json = json.loads(neg.stdout)
    assert neg_json["errorCode"] == "same_authority_refused", neg_json

    print(json.dumps({
        "published_root_digest": pub_json["rootDigest"],
        "verified_state": ver_json["state"],
        "asset_count": ver_json["assetCount"],
        "negative_refusal": neg_json["errorCode"],
    }, sort_keys=True))
PY
e2e_expect_exit "cli_e2e_publish_verify_and_negative_refusal" 0

e2e_summary
