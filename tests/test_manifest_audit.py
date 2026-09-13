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

with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary)
    (fixture / "a.txt").write_text("a\n", encoding="utf-8")
    base = fixture / "MANIFEST.sha256"
    delta = fixture / "MANIFEST.delta.sha256"
    digest = sha(fixture / "a.txt")
    base.write_text(f"{digest}  a.txt\n{digest}  a.txt\n", encoding="utf-8")
    delta.write_text("", encoding="utf-8")
    old_root = module.ROOT
    module.ROOT = fixture
    try:
        try:
            module.audit(base, delta)
        except module.ManifestError as exc:
            assert str(exc) == "duplicate path in MANIFEST.sha256: a.txt"
        else:
            raise AssertionError("duplicate base row should fail with exact finding")
    finally:
        module.ROOT = old_root

with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary)
    (fixture / "a.txt").write_text("a\n", encoding="utf-8")
    base = fixture / "MANIFEST.sha256"
    delta = fixture / "MANIFEST.delta.sha256"
    digest = sha(fixture / "a.txt")
    base.write_text(f"{digest}  a.txt\n", encoding="utf-8")
    delta.write_text(f"{digest}  a.txt\n{digest}  a.txt\n", encoding="utf-8")
    old_root = module.ROOT
    module.ROOT = fixture
    try:
        try:
            module.audit(base, delta)
        except module.ManifestError as exc:
            # This fixture carries two real defects: the delta duplicates a.txt, and that delta
            # digest equals the base digest (redundant). All findings are reported (fss-14iuh).
            assert exc.findings == [
                "duplicate path in MANIFEST.delta.sha256: a.txt",
                "redundant unchanged delta entry: a.txt",
            ], exc.findings
        else:
            raise AssertionError("duplicate delta row should fail with exact finding")
    finally:
        module.ROOT = old_root

with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary)
    (fixture / "a.txt").write_text("a\n", encoding="utf-8")
    (fixture / "n.txt").write_text("new\n", encoding="utf-8")
    base = fixture / "MANIFEST.sha256"
    delta = fixture / "MANIFEST.delta.sha256"
    base.write_text(f"{sha(fixture / 'a.txt')}  a.txt\n", encoding="utf-8")
    n_digest = sha(fixture / "n.txt")
    delta.write_text(f"{n_digest}  n.txt\n{n_digest}  n.txt\n", encoding="utf-8")
    old_root = module.ROOT
    module.ROOT = fixture
    try:
        try:
            module.audit(base, delta)
        except module.ManifestError as exc:
            assert str(exc) == "duplicate path in MANIFEST.delta.sha256: n.txt"
            assert exc.findings == ["duplicate path in MANIFEST.delta.sha256: n.txt"]
        else:
            raise AssertionError("duplicate added delta row should fail with exact finding")
    finally:
        module.ROOT = old_root

# fss-14iuh: every duplicate path must be reported in one run, not just the first.
with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary)
    (fixture / "a.txt").write_text("a\n", encoding="utf-8")
    (fixture / "b.txt").write_text("b\n", encoding="utf-8")
    base = fixture / "MANIFEST.sha256"
    delta = fixture / "MANIFEST.delta.sha256"
    a_digest = sha(fixture / "a.txt")
    b_digest = sha(fixture / "b.txt")
    base.write_text(
        f"{b_digest}  b.txt\n{a_digest}  a.txt\n{b_digest}  b.txt\n{a_digest}  a.txt\n{a_digest}  a.txt\n",
        encoding="utf-8",
    )
    delta.write_text("", encoding="utf-8")
    old_root = module.ROOT
    module.ROOT = fixture
    try:
        try:
            module.audit(base, delta)
        except module.ManifestError as exc:
            assert exc.findings == [
                "duplicate path in MANIFEST.sha256: a.txt",
                "duplicate path in MANIFEST.sha256: b.txt",
            ], exc.findings
            assert str(exc) == (
                "duplicate path in MANIFEST.sha256: a.txt\n"
                "duplicate path in MANIFEST.sha256: b.txt"
            )
        else:
            raise AssertionError("two distinct duplicate base paths should both be reported")

        import contextlib
        import io
        import sys

        stdout, stderr = io.StringIO(), io.StringIO()
        old_argv = sys.argv
        sys.argv = ["manifest_audit.py", "--base", str(base), "--delta", str(delta)]
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = module.main()
        finally:
            sys.argv = old_argv
        assert rc == 1, rc
        assert stdout.getvalue() == "", stdout.getvalue()
        assert stderr.getvalue() == (
            "layered manifest audit failed: duplicate path in MANIFEST.sha256: a.txt\n"
            "layered manifest audit failed: duplicate path in MANIFEST.sha256: b.txt\n"
        ), stderr.getvalue()
    finally:
        module.ROOT = old_root

# fss-14iuh: all finding categories across base and delta are reported together, sorted, deterministically.
with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary)
    (fixture / "a.txt").write_text("a\n", encoding="utf-8")
    (fixture / "b.txt").write_text("b\n", encoding="utf-8")
    (fixture / "c.txt").write_text("tampered\n", encoding="utf-8")
    (fixture / "d.txt").write_text("unlisted\n", encoding="utf-8")
    base = fixture / "MANIFEST.sha256"
    delta = fixture / "MANIFEST.delta.sha256"
    a_digest = sha(fixture / "a.txt")
    b_digest = sha(fixture / "b.txt")
    c_actual = sha(fixture / "c.txt")
    c_listed = hashlib.sha256(b"c\n").hexdigest()
    e_listed = hashlib.sha256(b"e\n").hexdigest()
    base.write_text(
        f"{a_digest}  a.txt\n{a_digest}  a.txt\n{c_listed}  c.txt\n{e_listed}  e.txt\n",
        encoding="utf-8",
    )
    delta.write_text(f"{a_digest}  a.txt\n{b_digest}  b.txt\n{b_digest}  b.txt\n", encoding="utf-8")
    expected_findings = [
        f"base manifest digest mismatch: c.txt: expected {c_listed}, observed {c_actual}",
        "duplicate path in MANIFEST.delta.sha256: b.txt",
        "duplicate path in MANIFEST.sha256: a.txt",
        "layered manifest lists excluded/unknown files: e.txt",
        "redundant unchanged delta entry: a.txt",
        "source files missing from layered manifest: d.txt",
    ]
    old_root = module.ROOT
    module.ROOT = fixture
    try:
        for _ in range(2):
            try:
                module.audit(base, delta)
            except module.ManifestError as exc:
                assert exc.findings == expected_findings, exc.findings
                assert str(exc) == "\n".join(expected_findings)
            else:
                raise AssertionError("combined base+delta defects should fail closed")
    finally:
        module.ROOT = old_root

print("layered manifest audit tests passed")
