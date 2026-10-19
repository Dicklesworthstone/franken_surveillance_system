#!/usr/bin/env python3
"""FSS-149: prove the production release closure contains no foreign model
runtime.

A sealed repeatable proof, not a presence check:
  1. Cargo.lock must contain none of the foreign model-runtime crate set
     (ONNX, Torch, TensorFlow, pyo3/OpenCV/GStreamer/FFmpeg bindings, ...).
  2. No workspace Rust source binds a foreign runtime (use/extern-crate
     constructs, with literals masked so pinned model-NAME data strings are
     not conflated with bindings).
  3. No release-path process invocation or dynamic loading of a foreign
     executable/runtime.
  4. No build script links, generates, or downloads a foreign runtime.
  5. NEGATIVE CONTROLS: the scanner is fed adversarial fixtures that MUST
     fail each rule — a scanner that cannot fail proves nothing.

Exit 0 = closure proven. Exit 1 = violation, evidence on stdout. Secret-free
by construction: paths, crate names, and rule ids only.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

FOREIGN_MODEL_RUNTIME_CRATES: frozenset[str] = frozenset({
    "onnxruntime", "ort", "tract-onnx", "tract-tensorflow",
    "tch", "torch-sys", "candle-onnx",
    "tensorflow", "tensorflow-sys",
    "pyo3", "opencv", "ffmpeg-next", "gstreamer", "gstreamer-sys",
    "ncnn", "tensorflow-lite", "tflite",
})

def _code_identifiers(names: frozenset[str]) -> list[str]:
    """Rust code identifiers for crate names: hyphens become underscores."""
    return sorted(name.replace("-", "_") for name in names)


FOREIGN_BINDING_CONSTRUCT = re.compile(
    r"\b(?:use|extern\s+crate)\s+(?:::)?(?:\w+::)*("
    + "|".join(re.escape(c) for c in _code_identifiers(FOREIGN_MODEL_RUNTIME_CRATES))
    + r")\b"
)

FOREIGN_PROCESS = re.compile(
    r"Command::new\s*\(\s*\"(?:ffmpeg|ffprobe|python|python3|node|onnxruntime|java)\""
)
DYNAMIC_LOADING = re.compile(r"\b(?:libloading|dlopen|LoadLibrary)\b")

BUILD_SCRIPT_NATIVE = re.compile(
    r"(?:println!\s*\(\s*\"cargo:(?:rustc-link-lib|rustc-link-search)"
    r"|bindgen|pkg_config|cmake|autotools|download"
    r"|reqwest|ureq|curl"
    r")"
)

RUST_SCAN_DIRS = ("crates",)

VIOLATIONS: list[str] = []


def violation(rule: str, where: str, detail: str) -> None:
    VIOLATIONS.append(f"[{rule}] {where}: {detail}")


def rule_lockfile() -> None:
    lock = REPO / "Cargo.lock"
    if not lock.is_file():
        violation("ERR-FR-MODEL-LOCK-001", "Cargo.lock", "lockfile missing")
        return
    names = {
        m.group(1)
        for m in re.finditer(r'^\s*name = "([^"]+)"', lock.read_text(encoding="utf-8"), re.M)
    }
    for name in sorted(names & FOREIGN_MODEL_RUNTIME_CRATES):
        violation("ERR-FR-MODEL-LOCK-001", "Cargo.lock", f"foreign model-runtime crate '{name}' in the closure")


def mask_string_literals(text: str) -> str:
    """Blank out string-literal contents so pinned model-NAME data (e.g.
    \"opencv-people-shadow-1\") is not conflated with a binding construct."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)


def rule_sources() -> None:
    for d in RUST_SCAN_DIRS:
        for rs in sorted((REPO / d).rglob("*.rs")):
            if any(p in {"target", ".claude"} for p in rs.parts):
                continue
            text = mask_string_literals(rs.read_text(encoding="utf-8"))
            rel = rs.relative_to(REPO)
            for m in FOREIGN_BINDING_CONSTRUCT.finditer(text):
                violation("ERR-FR-MODEL-BIND-002", str(rel), f"foreign runtime binding '{m.group(1)}'")
            # Foreign process invocation and dynamic loading keep literals
            # visible (they ARE the offense), so scan the raw text.
            if not any(seg in rs.as_posix() for seg in ("/tests/", "/benches/")):
                # Production surface only: the release closure is src/bin/
                # examples. Test harnesses may drive foreign tools by design
                # (sealed qualification drivers), which is NOT a production
                # path.
                raw = rs.read_text(encoding="utf-8")
                if FOREIGN_PROCESS.search(raw):
                    violation("ERR-FR-MODEL-PROC-003", str(rel), "foreign runtime/executable process invocation")
                if DYNAMIC_LOADING.search(mask_string_literals(raw)):
                    violation("ERR-FR-MODEL-DYN-004", str(rel), "dynamic loading of a native library")


def _strip_rust_comments(text: str) -> str:
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    return re.sub(r"//[^\n]*", "", text)


def rule_build_scripts() -> None:
    for bs in sorted(REPO.glob("crates/*/build.rs")):
        text = _strip_rust_comments(bs.read_text(encoding="utf-8"))
        if BUILD_SCRIPT_NATIVE.search(text):
            rel = bs.relative_to(REPO)
            violation("ERR-FR-MODEL-BUILD-005", str(rel), "build script links/generates/downloads a foreign or network-acquired artifact")
    for mf in sorted(REPO.glob("crates/*/Cargo.toml")):
        with mf.open("rb") as fh:
            doc = tomllib.load(fh)
        links = doc.get("package", {}).get("links")
        if isinstance(links, str) and links in FOREIGN_MODEL_RUNTIME_CRATES:
            violation("ERR-FR-MODEL-BUILD-005", str(mf.relative_to(REPO)), f"package.links = '{links}' names a foreign native library")


def mask_rust(text: str) -> str:
    return mask_string_literals(text)


def rule_negative_controls() -> tuple[int, int]:
    """Adversarial fixtures that MUST fail. Returns the number of controls
    that correctly fired; any control that does NOT fire is itself a
    violation (a blind scanner proves nothing)."""
    fired = 0
    fixtures = [
        # (rule-family, sample that must trip one of the patterns)
        ("binding", "use ort::session::Session;"),
        ("binding", "extern crate tch;"),
        ("binding", "use ffmpeg_next::codec;"),
        ("binding", "use tract_onnx::model;"),
        ("binding", "use ::torch_sys::lib_torch;"),
        ("process", 'Command::new("ffmpeg")'),
        ("dyn", "let l = libloading::Library::new(\"x\").ok();"),
        ("build", "println!(\"cargo:rustc-link-lib=onnxruntime\");"),
    ]
    for kind, sample in fixtures:
        hit = bool(
            FOREIGN_BINDING_CONSTRUCT.search(mask_rust(sample))
            or FOREIGN_PROCESS.search(sample)
            or DYNAMIC_LOADING.search(mask_rust(sample))
            or BUILD_SCRIPT_NATIVE.search(sample)
        )
        if not hit:
            violation(
                "ERR-FR-MODEL-CONTROL-006",
                "<negative-control>",
                f"fixture '{sample[:48]}' did not trip any rule — scanner is blind to this family",
            )
        else:
            fired += 1
    return fired, len(fixtures)


def main() -> int:
    rule_lockfile()
    rule_sources()
    rule_build_scripts()
    controls, control_total = rule_negative_controls()
    report = {
        "schema": "fss.foreign_model_runtime_absence.v1",
        "foreignCrateSetSize": len(FOREIGN_MODEL_RUNTIME_CRATES),
        "negativeControlsFired": controls,
        "negativeControlsTotal": control_total,
        "violations": VIOLATIONS,
        "verdict": "pass" if not VIOLATIONS else "fail",
    }
    print(json.dumps(report, indent=1))
    if VIOLATIONS:
        for v in VIOLATIONS:
            print(f"  {v}", file=sys.stderr)
        return 1
    print(
        "FOREIGN-MODEL-RUNTIME ABSENCE: proven "
        "(lockfile clean, no bindings/process/dynamic-loading/build-script paths, "
        f"{controls}/{control_total} negative controls fired)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
