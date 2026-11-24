#!/usr/bin/env python3
"""Static regression guard for Asupersync structured concurrency invariants (fss-x4a.31.5.2).

Audits every non-test production Rust source file under `crates/*/src/**/*.rs`
(excluding test modules `#[cfg(test)]` / `#[cfg(all(test, ...))]` and dedicated
test files `tests.rs`, `*_tests.rs`, `*_test.rs`, `*/tests/*`, `*_tests/*`) and
fails closed on any violation:

  ASYNC-GUARD-001  Tokio runtime or `tokio::` import/path in production code.
  ASYNC-GUARD-002  Unbounded `mpsc::channel(` in production code (use bounded
                   `mpsc::sync_channel` or Asupersync bounded channels).
  ASYNC-GUARD-003  Detached `std::thread::spawn(` or `thread::Builder::new()`
                   in production code (use `std::thread::scope`, `asupersync`
                   regions, or `fss_runtime::asupersync_ops::ScopedWorkerGroup`).
  ASYNC-GUARD-004  Blocking `loop { ... }` containing `std::thread::sleep(` or
                   `thread::sleep(` without an explicit cancellation/budget
                   checkpoint (`is_cancel`, `checkpoint`, `shutdown`, `cancel`,
                   `lease.check`, `CxTimerBoundary`, or audited marker).

Zero external dependencies (Python 3 stdlib only). Secret-free output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]

# Zero-growth audited baseline allowlist for legacy detached thread spawns.
# Currently EMPTY: every workspace crate is at 0 detached std::thread::spawn.
# This set may NEVER grow.
DETACHED_THREAD_ALLOWLIST: frozenset[str] = frozenset()

# Crates required unconditionally to have zero detached threads and zero allowlist entries.
ZERO_DETACHED_CRATES: frozenset[str] = frozenset({
    "fss-cli",
    "fss-core",
    "fss-daemon",
    "fss-ipc",
    "fss-ledger",
    "fss-pack",
    "fss-projection-store",
    "fss-reference",
    "fss-runtime",
    "fss-vault",
})

TOKIO_RE = re.compile(
    r"(?:\buse\s+tokio\b|\bextern\s+crate\s+tokio\b|\btokio::)"
)
UNBOUNDED_MPSC_RE = re.compile(r"\bmpsc::channel\s*(?:::<[^>]*>)?\s*\(")
DETACHED_SPAWN_RE = re.compile(
    r"(?:\b(?:std::)?thread::spawn\s*\(|\b(?:std::)?thread::Builder::new\s*\()"
)
RAW_SLEEP_RE = re.compile(r"\b(?:std::)?thread::sleep\s*\(")
LOOP_START_RE = re.compile(r"(?:^|[^\w])loop\s*\{")
CFG_TEST_MOD_RE = re.compile(
    r"#\[cfg\([^\]]*\btest\b[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z0-9_]+\s*\{"
)
CFG_TEST_FN_RE = re.compile(
    r"#\[cfg\([^\]]*\btest\b[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z0-9_]+\s*[^{]*\{"
)

COOPERATIVE_LOOP_MARKERS = (
    "is_cancel",
    "checkpoint",
    "shutdown",
    "cancel",
    "lease.check",
    "CxTimerBoundary",
    "sleep_cooperative",
    "allow-cooperative-sleep",
    "deadline",
    "timeout",
    "remaining",
)


@dataclass(frozen=True)
class GuardFinding:
    code: str
    file: str
    line: int
    snippet: str
    remediation: str


def is_test_source_path(rel: Path) -> bool:
    name = rel.name
    if name in ("tests.rs", "test.rs") or name.endswith(("_tests.rs", "_test.rs")):
        return True
    for part in rel.parts:
        if part in ("tests", "benches") or part.endswith("_tests"):
            return True
    return False


def blank_comments_and_strings(text: str) -> str:
    """Replace Rust comments and string literals with spaces while preserving newlines."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        # Line comment
        if ch == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # Block comment (supports nesting)
        if ch == "/" and nxt == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if i + 1 < n and text[i] == "/" and text[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif i + 1 < n and text[i] == "*" and text[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
            continue
        # Raw string r#"..."# or br#"..."#
        if ch == "r" or (ch == "b" and nxt == "r"):
            start = i
            j = i + (2 if ch == "b" else 1)
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                out.extend(" " * (j - start + 1))
                i = j + 1
                end_seq = '"' + ("#" * hashes)
                end_pos = text.find(end_seq, i)
                if end_pos == -1:
                    end_pos = n
                else:
                    end_pos += len(end_seq)
                for k in range(i, end_pos):
                    out.append("\n" if text[k] == "\n" else " ")
                i = end_pos
                continue
        # Normal string literal
        if ch == '"':
            out.append(" ")
            i += 1
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append("\n" if text[i + 1] == "\n" else " ")
                    i += 2
                elif c == '"':
                    out.append(" ")
                    i += 1
                    break
                else:
                    out.append("\n" if c == "\n" else " ")
                    i += 1
            continue
        # Char literal (avoid confusing lifetimes like `'a`)
        if ch == "'" and i + 2 < n:
            if nxt == "\\":
                end_ch = text.find("'", i + 2)
                if end_ch != -1 and end_ch - i <= 10:
                    out.extend(" " * (end_ch - i + 1))
                    i = end_ch + 1
                    continue
            elif text[i + 2] == "'" and nxt != "\n":
                out.append("   ")
                i += 3
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def blank_braced_regions(code: str, pattern: re.Pattern[str]) -> str:
    """Blank brace-delimited blocks matched by `pattern`, keeping line numbers."""
    out: list[str] = []
    pos = 0
    for match in pattern.finditer(code):
        if match.start() < pos:
            continue
        depth = 0
        end = len(code)
        for idx in range(match.end() - 1, len(code)):
            c = code[idx]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        out.append(code[pos:match.start()])
        out.append("".join("\n" if c == "\n" else " " for c in code[match.start():end]))
        pos = end
    out.append(code[pos:])
    return "".join(out)


def strip_cfg_test_items(clean_code: str) -> str:
    stripped = blank_braced_regions(clean_code, CFG_TEST_MOD_RE)
    stripped = blank_braced_regions(stripped, CFG_TEST_FN_RE)
    return stripped


def scan_source_text(rel_path: str, raw_text: str) -> list[GuardFinding]:
    findings: list[GuardFinding] = []
    raw_lines = raw_text.splitlines()
    clean = strip_cfg_test_items(blank_comments_and_strings(raw_text))
    clean_lines = clean.splitlines()

    def line_of(offset: int) -> int:
        return clean.count("\n", 0, offset) + 1

    def snippet_of(line_no: int) -> str:
        if 1 <= line_no <= len(raw_lines):
            return raw_lines[line_no - 1].strip()
        return ""

    # Rule 1: No Tokio imports or paths in production code.
    for match in TOKIO_RE.finditer(clean):
        ln = line_of(match.start())
        findings.append(
            GuardFinding(
                code="ASYNC-GUARD-001",
                file=rel_path,
                line=ln,
                snippet=snippet_of(ln),
                remediation="Remove Tokio usage; FSS mandates Asupersync as sole async runtime (INT-AS-001).",
            )
        )

    # Rule 2: No unbounded std::sync::mpsc::channel( in production code.
    for match in UNBOUNDED_MPSC_RE.finditer(clean):
        ln = line_of(match.start())
        findings.append(
            GuardFinding(
                code="ASYNC-GUARD-002",
                file=rel_path,
                line=ln,
                snippet=snippet_of(ln),
                remediation="Replace unbounded mpsc::channel() with bounded mpsc::sync_channel(bound) or Asupersync bounded channel.",
            )
        )

    # Rule 3: Zero detached std::thread::spawn / thread::Builder::new().
    for match in DETACHED_SPAWN_RE.finditer(clean):
        ln = line_of(match.start())
        if rel_path in DETACHED_THREAD_ALLOWLIST:
            continue
        findings.append(
            GuardFinding(
                code="ASYNC-GUARD-003",
                file=rel_path,
                line=ln,
                snippet=snippet_of(ln),
                remediation="Replace detached thread spawn with std::thread::scope, asupersync::Cx::spawn, or fss_runtime::asupersync_ops::ScopedWorkerGroup.",
            )
        )

    # Rule 4: No un-Cx'd blocking infinite `loop { ... thread::sleep(...) ... }`.
    for match in LOOP_START_RE.finditer(clean):
        brace_idx = match.end() - 1
        depth = 0
        end = len(clean)
        for idx in range(brace_idx, len(clean)):
            c = clean[idx]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        body_clean = clean[brace_idx:end]
        sleep_match = RAW_SLEEP_RE.search(body_clean)
        if not sleep_match:
            continue
        start_ln = line_of(brace_idx)
        end_ln = line_of(end)
        raw_block = "\n".join(raw_lines[max(0, start_ln - 1):end_ln])
        if any(marker in raw_block for marker in COOPERATIVE_LOOP_MARKERS):
            continue
        sleep_ln = line_of(brace_idx + sleep_match.start())
        findings.append(
            GuardFinding(
                code="ASYNC-GUARD-004",
                file=rel_path,
                line=sleep_ln,
                snippet=snippet_of(sleep_ln),
                remediation="Gate blocking loop sleep with CxTimerBoundary / WorkerCancelToken or explicit cancellation/deadline checkpoint.",
            )
        )

    # Suppress unused variable warning for clean_lines if needed
    _ = clean_lines
    return findings


def iter_production_rust_files(root: Path) -> Iterable[Path]:
    crates_dir = root / "crates"
    if not crates_dir.is_dir():
        return []
    files: list[Path] = []
    for path in sorted(crates_dir.glob("*/src/**/*.rs")):
        rel = path.relative_to(root)
        if is_test_source_path(rel):
            continue
        files.append(path)
    return files


def audit_workspace(root: Path = ROOT) -> tuple[list[GuardFinding], dict[str, int]]:
    findings: list[GuardFinding] = []
    files_scanned = 0
    crates_seen: set[str] = set()
    scoped_thread_scopes = 0

    for crate in ZERO_DETACHED_CRATES:
        for allowed in DETACHED_THREAD_ALLOWLIST:
            if allowed.startswith(f"crates/{crate}/"):
                findings.append(
                    GuardFinding(
                        code="ASYNC-GUARD-003",
                        file=allowed,
                        line=1,
                        snippet="DETACHED_THREAD_ALLOWLIST",
                        remediation=f"Crate {crate} is locked to 0 detached threads and may not appear in DETACHED_THREAD_ALLOWLIST.",
                    )
                )

    for path in iter_production_rust_files(root):
        rel = path.relative_to(root).as_posix()
        files_scanned += 1
        parts = path.relative_to(root).parts
        if len(parts) >= 2:
            crates_seen.add(parts[1])
        text = path.read_text(encoding="utf-8")
        clean = strip_cfg_test_items(blank_comments_and_strings(text))
        scoped_thread_scopes += len(re.findall(r"\b(?:std::)?thread::scope\s*\(", clean))
        findings.extend(scan_source_text(rel, text))

    stats = {
        "files_scanned": files_scanned,
        "crates_scanned": len(crates_seen),
        "scoped_thread_scopes": scoped_thread_scopes,
        "allowlist_entries": len(DETACHED_THREAD_ALLOWLIST),
        "violations": len(findings),
    }
    return findings, stats


def run_self_test() -> int:
    """Proves every ASYNC-GUARD rule fails closed on planted violations and allows clean code."""
    cases = [
        ("ASYNC-GUARD-001", "use tokio::runtime::Runtime;\nfn f() {}"),
        ("ASYNC-GUARD-002", "use std::sync::mpsc;\nfn f() { let _ = mpsc::channel::<u8>(); }"),
        ("ASYNC-GUARD-003", "fn f() { let _ = std::thread::spawn(|| {}); }"),
        ("ASYNC-GUARD-003", "fn f() { let _ = std::thread::Builder::new().spawn(|| {}); }"),
        ("ASYNC-GUARD-004", "fn f() { loop { std::thread::sleep(std::time::Duration::from_millis(5)); } }"),
    ]
    for expected_code, snippet in cases:
        found = scan_source_text("crates/fss-test/src/planted.rs", snippet)
        codes = {f.code for f in found}
        if expected_code not in codes:
            print(f"[SELF-TEST FAIL] expected {expected_code} for {snippet!r}, got {codes}")
            return 1

    clean_cases = [
        "fn f() { std::thread::scope(|s| { s.spawn(|| {}); }); }",
        "use std::sync::mpsc;\nfn f() { let _ = mpsc::sync_channel::<u8>(8); }",
        "fn f(cancel: &AtomicBool) { loop { if cancel.load(Ordering::Acquire) { break; } std::thread::sleep(d); } }",
        "#[cfg(test)]\nmod tests { fn t() { let _ = std::thread::spawn(|| {}); let _ = mpsc::channel::<u8>(); } }",
        "// tokio::spawn and std::thread::spawn in comments are ignored\nfn f() {}",
    ]
    for snippet in clean_cases:
        found = scan_source_text("crates/fss-test/src/clean.rs", snippet)
        if found:
            print(f"[SELF-TEST FAIL] unexpected findings for clean snippet {snippet!r}: {found}")
            return 1

    print("[PASS] asupersync_concurrency_guard self-test passed (5 negative + 5 positive cases)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit production FSS Rust sources for Asupersync structured concurrency invariants."
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report.")
    parser.add_argument("--self-test", action="store_true", help="Run embedded planted-violation tests.")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    findings, stats = audit_workspace(ROOT)
    if args.json:
        payload = {
            "status": "pass" if not findings else "fail",
            "stats": stats,
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if findings:
            print(
                f"[FAIL] Asupersync concurrency guard found {len(findings)} violation(s) "
                f"across {stats['files_scanned']} production Rust files:"
            )
            for item in findings:
                print(f"  - [{item.code}] {item.file}:{item.line}: {item.snippet}")
                print(f"      remediation: {item.remediation}")
        else:
            print(
                f"[PASS] Asupersync concurrency guard passed: {stats['files_scanned']} production Rust files "
                f"across {stats['crates_scanned']} crates verified "
                f"(0 tokio, 0 unbounded mpsc::channel, 0 detached std::thread::spawn, "
                f"{stats['scoped_thread_scopes']} structured std::thread::scope sites, "
                f"{stats['allowlist_entries']} allowlist entries)"
            )
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
