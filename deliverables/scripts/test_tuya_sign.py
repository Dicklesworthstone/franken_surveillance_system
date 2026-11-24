#!/usr/bin/env python3
"""Tuya signer golden-vector & negative-vector test runner — byte-exact verification.

Enforces every gate from fss-tuya-signer-ci-po1ve and the dual critique (codex + GLM 5.3):
  1. Verifies Docker image platform lock (`linux/arm64`) and pinned OCI labels.
  2. Consumes EVERY golden vector's canonical input (and validates `canonical(request_map)`
     round-trip with exact diverging-field diagnostics when present).
  3. Checks child process exit status == 0 and compares output BYTE-FOR-BYTE.
  4. Executes EVERY negative vector (ILLEGAL_CLIENT_ID vs SING_VALIDATE_FALED gateway
     classification, 1-byte canonical mutation divergence, and wrong-seed divergence).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent / "tuya_sign_vectors.json"
SIGNER = HERE / "tuya_thing_sign.py"

sys.path.insert(0, str(HERE))
import tuya_thing_sign as tts  # noqa: E402


def _diff_canon_fields(got: str, want: str) -> str:
    g_map = dict(item.split("=", 1) for item in got.split("||") if "=" in item)
    w_map = dict(item.split("=", 1) for item in want.split("||") if "=" in item)
    diffs = []
    for k in sorted(set(g_map) | set(w_map)):
        if g_map.get(k) != w_map.get(k):
            diffs.append(f"field {k!r}: got={g_map.get(k)!r} want={w_map.get(k)!r}")
    return "; ".join(diffs) or f"got={got!r} want={want!r}"


def _run_signer(args: list[str], env_extra: dict[str, str] | None = None) -> tuple[int, str, str]:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(
            [sys.executable, str(SIGNER), *args],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
            check=False,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"


def _extract_hex(out: str, length: int) -> str:
    for line in out.splitlines():
        s = line.strip()
        if len(s) == length and all(c in "0123456789abcdef" for c in s):
            return s
    return ""


def check_image_metadata(harness_spec: dict[str, Any]) -> tuple[bool, str]:
    image = os.environ.get("FSS_SIGN_IMAGE", harness_spec.get("image", "fss-jvm"))
    r = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if r.returncode != 0:
        return False, f"docker image {image!r} missing: {(r.stderr or r.stdout).strip()[:200]}"
    info = json.loads(r.stdout)[0]
    arch = f"{info.get('Os')}/{info.get('Architecture')}"
    labels = (info.get("Config") or {}).get("Labels") or {}
    want_plat = harness_spec.get("platform_lock", "linux/arm64")
    want_lib = harness_spec.get("native_lib", "libthing_security.so")
    want_digest = harness_spec.get("base_digest")
    errs = []
    if arch != want_plat:
        errs.append(f"arch={arch!r} want={want_plat!r}")
    if labels.get("fss.platform_lock") != want_plat:
        errs.append(f"label fss.platform_lock={labels.get('fss.platform_lock')!r} want={want_plat!r}")
    if labels.get("fss.native_lib") != want_lib:
        errs.append(f"label fss.native_lib={labels.get('fss.native_lib')!r} want={want_lib!r}")
    if want_digest and labels.get("fss.base_digest") != want_digest:
        errs.append(f"label fss.base_digest={labels.get('fss.base_digest')!r} want={want_digest!r}")
    if errs:
        return False, "; ".join(errs)
    return True, f"image={image} id={info.get('Id', '')[:19]} arch={arch} base={want_digest[:19]}"


def run_golden_vector(vec: dict[str, Any]) -> tuple[bool, str]:
    kind = vec.get("kind", "frida_captured_api_sign")
    if "request_map" in vec and "canonical" in vec:
        rebuilt = tts.canonical(vec["request_map"])
        if rebuilt != vec["canonical"]:
            return False, "canonical mismatch: " + _diff_canon_fields(rebuilt, vec["canonical"])

    if kind in ("frida_captured_api_sign", "deterministic_sign_replay"):
        with tempfile.TemporaryDirectory(prefix="fss-vec-") as td:
            canon_path = Path(td) / "canon.txt"
            canon_path.write_text(vec["canonical"], encoding="utf-8")
            rc, out, err = _run_signer(["sign", str(canon_path)])
        expected = vec["expected_sign"]
        got = _extract_hex(out, 64)
        if rc == 0 and got == expected:
            return True, f"sign byte-exact ({got[:16]}…), exit 0"
        return False, f"rc={rc} sign mismatch: got={got!r} want={expected!r} stderr={err[:200]!r}"

    if kind == "frida_captured_chkey":
        rc, out, err = _run_signer(["chkey"])
        expected = vec["expected_output"]
        got = out.splitlines()[-1].strip() if out else ""
        if rc == 0 and got == expected:
            return True, f"chKey byte-exact ({got}), exit 0"
        return False, f"rc={rc} chKey mismatch: got={got!r} want={expected!r} stderr={err[:200]!r}"

    if kind == "native_compute_digest":
        rc, out, err = _run_signer(["digest", vec["msg"], vec["key"]])
        expected = vec["expected_output"]
        got = _extract_hex(out, 32)
        if rc == 0 and got == expected:
            return True, f"computeDigest byte-exact ({got}), exit 0"
        return False, f"rc={rc} computeDigest mismatch: got={got!r} want={expected!r} stderr={err[:200]!r}"

    return False, f"unknown golden vector kind={kind!r}"


def run_negative_vector(neg: dict[str, Any]) -> tuple[bool, str]:
    kind = neg.get("kind")
    if kind == "gateway_response_classification":
        rc, out, err = _run_signer(["classify-response", json.dumps(neg["sample_response"])])
        if rc != 0:
            return False, f"classify-response rc={rc} stderr={err[:200]!r}"
        res = json.loads(out)
        got_cls = res.get("classification")
        want_cls = neg["expected_classification"]
        if got_cls != want_cls:
            return False, f"classification got={got_cls!r} want={want_cls!r}"
        return True, f"classified={got_cls} (remediation={neg['remediation_doc']})"

    if kind == "harness_mutation_divergence":
        with tempfile.TemporaryDirectory(prefix="fss-neg-") as td:
            canon_path = Path(td) / "canon.txt"
            canon_path.write_text(neg["canonical"], encoding="utf-8")
            rc, out, err = _run_signer(["sign", str(canon_path)])
        got = _extract_hex(out, 64)
        forbidden = neg["must_not_equal_sign"]
        if rc == 0 and len(got) == 64 and got != forbidden:
            return True, f"mutated canonical diverged cleanly ({got[:16]}… != {forbidden[:16]}…)"
        return False, f"expected distinct 64-hex sign: rc={rc} got={got!r} forbidden={forbidden!r} err={err[:160]!r}"

    if kind == "harness_wrong_secret_divergence":
        with tempfile.TemporaryDirectory(prefix="fss-neg-") as td:
            canon_path = Path(td) / "canon.txt"
            canon_path.write_text(neg["canonical"], encoding="utf-8")
            rc, out, err = _run_signer(
                ["sign", str(canon_path)],
                env_extra={"FSS_SIGN_SEED": neg["seed_override"]},
            )
        got = _extract_hex(out, 64)
        forbidden = neg["must_not_equal_sign"]
        if rc == 0 and len(got) == 64 and got != forbidden:
            return True, f"wrong seed diverged cleanly ({got[:16]}… != {forbidden[:16]}…)"
        return False, f"wrong seed did not diverge cleanly: rc={rc} got={got!r} forbidden={forbidden!r} err={err[:160]!r}"

    return False, f"unknown negative vector kind={kind!r}"


def main() -> int:
    v = json.loads(VECTORS.read_text(encoding="utf-8"))
    passed = failed = 0

    meta_ok, meta_msg = check_image_metadata(v.get("harness") or {})
    if meta_ok:
        print(f"  ✓ image-metadata: {meta_msg}")
        passed += 1
    else:
        print(f"  ✗ image-metadata: {meta_msg}")
        failed += 1

    for vec in v["golden"]:
        ok, msg = run_golden_vector(vec)
        mark = "✓" if ok else "✗"
        print(f"  {mark} golden [{vec['name']}]: {msg}")
        if ok:
            passed += 1
        else:
            failed += 1

    for neg in v["negative"]:
        ok, msg = run_negative_vector(neg)
        mark = "✓" if ok else "✗"
        print(f"  {mark} negative [{neg['name']}]: {msg}")
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"== tuya sign vectors: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
