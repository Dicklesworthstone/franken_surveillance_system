#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/manifest_audit.py"
spec = importlib.util.spec_from_file_location("manifest_audit", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary)
    (fixture / "a.txt").write_text("a\n", encoding="utf-8")
    (fixture / "b.txt").write_text("b2\n", encoding="utf-8")
    base = fixture / "MANIFEST.sha256"
    delta = fixture / "MANIFEST.delta.sha256"
    base.write_text(
        f"{sha(fixture / 'a.txt')}  a.txt\n"
        f"{hashlib.sha256(b'b1\\n').hexdigest()}  b.txt\n",
        encoding="utf-8",
    )
    delta.write_text(f"{sha(fixture / 'b.txt')}  b.txt\n", encoding="utf-8")
    old_root = module.ROOT
    module.ROOT = fixture
    try:
        report = module.audit(base, delta)
    finally:
        module.ROOT = old_root
    assert report["effectiveEntries"] == 2
    assert report["changedEntries"] == 1
    assert report["addedEntries"] == 0

with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary)
    (fixture / "a.txt").write_text("a\n", encoding="utf-8")
    base = fixture / "MANIFEST.sha256"
    delta = fixture / "MANIFEST.delta.sha256"
    digest = sha(fixture / "a.txt")
    base.write_text(f"{digest}  a.txt\n", encoding="utf-8")
    delta.write_text(f"{digest}  a.txt\n", encoding="utf-8")
    old_root = module.ROOT
    module.ROOT = fixture
    try:
        try:
            module.audit(base, delta)
        except module.ManifestError as exc:
            assert "redundant unchanged" in str(exc)
        else:
            raise AssertionError("redundant delta should fail")
    finally:
        module.ROOT = old_root

with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary)
    (fixture / "a.txt").write_text("tampered\n", encoding="utf-8")
    base = fixture / "MANIFEST.sha256"
    delta = fixture / "MANIFEST.delta.sha256"
    base.write_text(f"{hashlib.sha256(b'a\\n').hexdigest()}  a.txt\n", encoding="utf-8")
    delta.write_text("", encoding="utf-8")
    old_root = module.ROOT
    module.ROOT = fixture
    try:
        try:
            module.audit(base, delta)
        except module.ManifestError as exc:
            assert "digest mismatch" in str(exc)
        else:
            raise AssertionError("tampered source should fail")
    finally:
        module.ROOT = old_root

print("layered manifest audit tests passed")
