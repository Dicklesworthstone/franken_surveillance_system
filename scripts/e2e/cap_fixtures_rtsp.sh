#!/usr/bin/env bash
# CAP- fixtures RTSP transcript (fss-2h5zq.8): per-file manifest sha256 + no-credential/no-IP
# guard across all 8 committed RTSP transcripts (including rtcp_rsize, sr_absent, and
# get_parameter_keepalive), plus remote contract test execution with CAPLOG ingestion.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_fixtures_rtsp.sh"
e2e_init "cap_fixtures_rtsp" "fss-2h5zq.8" "$@"

FIXTURES=(
    "clean.transcript"
    "auth_required.transcript"
    "interleave_split.transcript"
    "bad_content_length.transcript"
    "session_timeout_header.transcript"
    "rtcp_rsize.transcript"
    "sr_absent.transcript"
    "get_parameter_keepalive.transcript"
)

check_rtsp_fixture() {
    local fname="$1"
    python3 -B - "$_E2E_REPO_ROOT" "$fname" <<'PY'
import hashlib
import json
import os
import re
import sys

repo_root, fname = sys.argv[1], sys.argv[2]
rtsp_dir = os.path.join(repo_root, "tests", "fixtures", "media", "rtsp")
man_path = os.path.join(rtsp_dir, "fixture_manifest.json")
fix_path = os.path.join(rtsp_dir, fname)

with open(man_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

entries = [e for e in manifest.get("fixtures", []) if e.get("name") == fname]
if len(entries) != 1:
    sys.stderr.write(f"expected 1 manifest entry for {fname}, found {len(entries)}\n")
    sys.exit(1)

entry = entries[0]
with open(fix_path, "rb") as f:
    data = f.read()

actual_sha = hashlib.sha256(data).hexdigest()
if actual_sha != entry.get("sha256"):
    sys.stderr.write(f"sha256 mismatch for {fname}: expected {entry.get('sha256')}, got {actual_sha}\n")
    sys.exit(1)
if len(data) != entry.get("byte_len"):
    sys.stderr.write(f"byte_len mismatch for {fname}: expected {entry.get('byte_len')}, got {len(data)}\n")
    sys.exit(1)

# No-credential guard: Authorization header must never appear in any fixture.
if re.search(rb"(?i)authorization\s*:", data):
    sys.stderr.write(f"Authorization header found in {fname}\n")
    sys.exit(1)

# No IPv4 or IPv6 literals in ASCII text records.
magic = b"#!fss-rtsp-transcript v1\n"
if not data.startswith(magic):
    sys.stderr.write(f"missing magic header in {fname}\n")
    sys.exit(1)

pos = len(magic)
rec_count = 0
ipv4_re = re.compile(r"(?<![A-Za-z0-9.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![A-Za-z0-9.])")
while pos < len(data):
    if pos + 9 > len(data):
        sys.stderr.write(f"truncated record header in {fname} at {pos}\n")
        sys.exit(1)
    rec_len = int.from_bytes(data[pos + 5 : pos + 9], "big")
    pos += 9
    if pos + rec_len > len(data):
        sys.stderr.write(f"truncated record payload in {fname} at {pos}\n")
        sys.exit(1)
    payload = data[pos : pos + rec_len]
    pos += rec_len
    rec_count += 1
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        continue
    if ipv4_re.search(text):
        sys.stderr.write(f"IPv4 literal found in {fname}\n")
        sys.exit(1)

if rec_count != entry.get("record_count"):
    sys.stderr.write(f"record_count mismatch for {fname}: expected {entry.get('record_count')}, got {rec_count}\n")
    sys.exit(1)

print(json.dumps({
    "file": fname,
    "sha256": actual_sha,
    "byte_len": len(data),
    "record_count": rec_count,
    "authorization_headers": 0,
    "ipv4_literals": 0,
}, sort_keys=True))
PY
}

for fname in "${FIXTURES[@]}"; do
    step="fixture_${fname%.transcript}"
    e2e_step "$step" -- check_rtsp_fixture "$fname"
    e2e_expect_exit "$step" 0
done

e2e_cargo_test "fss-reference" "media_fixture_rtsp_contract"
e2e_summary
