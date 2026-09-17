#!/usr/bin/env python3
"""DRIFT-003: frozen seed catalog, generated mirrors, and replayable corpus proof.

No runtime/product claim is upgraded by this governance check. Only public contract
sources are scanned; source prose and diagnostic input values never enter logs.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import stable_id_audit
from schema_validate import canonical_json_bytes
from qualification_receipt import atomic_write_bytes

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "architecture/seed_requirements.json"
PLAN = "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md"
FIXTURES = "tests/fixtures/seed_requirements"
# Admission identity, not a second count authority. Changing ANY v1 contract byte
# requires a separately reviewed version/migration/claim-impact admission here.
ADMITTED = "sha256:51d967f452a8798834899cccd783b4c7d88a4343059f7b5e6f52889e39a0fa7a"
BEFORE_DIGEST = "sha256:6358e0d8881e46e63f3a8f5b93da1c4d575d4064853282a3a55dc98f66ad9019"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_CORPUS_BYTES = 64 * 1024 * 1024
MAX_SOURCES = 4096
ID_RE = re.compile(r"\bFSS-\d{3}\b")
ROW_RE = re.compile(r"^(\d+)\. `(FSS-\d{3})` (.+)$")
CLAIM_RE = re.compile(r"\bfirst[ -](\d+)\s+(?:implementation\s+)?(?:issues|beads|requirements)\b", re.I)
REPAIR = "Restore the admitted registry and regenerate mirrors; rebase and rerun the corpus proof. Count/intent changes need reviewed versioned migration and claim-impact admission."


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def finding(kind: str, path: str = REGISTRY, location: str = "#") -> dict[str, str]:
    return {"code": f"ERR-SEED-{kind}-001", "file": path, "location": location,
            "message": {"COUNT": "Declared count differs from the admitted seed extent.",
                        "IDENTITIES": "Missing, duplicate, malformed, or unexpected seed identity.",
                        "ORDER": "Published numeric identity order was changed.",
                        "MIGRATION": "Catalog/version/intent differs from reviewed admission.",
                        "MIRROR": "Generated seed mirror is missing or stale.",
                        "OWNER": "Seed reference or definition does not resolve to its canonical owner.",
                        "INPUT": "Public contract source is missing, malformed, or exceeds the input budget.",
                        "PROOF": "Proof is incomplete or unverifiable."}[kind]}


def validate_registry(document: Any) -> list[dict[str, str]]:
    errors = []
    if not isinstance(document, dict):
        return [finding("INPUT")]
    rows = document.get("requirements")
    count = document.get("expectedCount")
    if not isinstance(rows, list) or type(count) is not int or not 1 <= count <= 999:
        return [finding("INPUT"), finding("MIGRATION")]
    identities = [r.get("id") if isinstance(r, dict) else None for r in rows]
    expected = [f"FSS-{i:03}" for i in range(1, count + 1)]
    if len(rows) != count:
        errors.append(finding("COUNT"))
    if any(not isinstance(i, str) for i in identities) or sorted(i for i in identities if isinstance(i, str)) != expected:
        errors.append(finding("IDENTITIES"))
    elif identities != expected:
        errors.append(finding("ORDER"))
    if any(not isinstance(r, dict) or set(r) != {"id", "title"} or not isinstance(r.get("id"), str) or not isinstance(r.get("title"), str) or not r["title"].strip() for r in rows):
        errors.append(finding("INPUT"))
    if document.get("freezeDigest") != digest(canonical_json_bytes(rows)) or digest(canonical_json_bytes(document)) != ADMITTED:
        errors.append(finding("MIGRATION"))
    return errors


def corpus_paths(root: Path) -> list[Path]:
    paths = set(root.glob("*.md"))
    for directory in ("docs", "registries", "architecture", "schemas"):
        for suffix in ("*.md", "*.json", "*.toml"):
            paths.update((root / directory).rglob(suffix))
    return sorted(paths, key=lambda p: p.relative_to(root).as_posix())


def extract_rows(text: str) -> tuple[list[dict[str, str]], list[int], bool]:
    """Parses the normative Appendix F seed list only; prose elsewhere is not a seed row."""
    rows, numbers, malformed = [], [], False
    section = re.compile(r"^## Appendix F — First (\d+) implementation issues\s*$")
    started = False
    for line in text.splitlines():
        if not started:
            started = bool(section.fullmatch(line))
            continue
        if line.startswith("The next tranche"):
            break
        match = ROW_RE.fullmatch(line)
        if match:
            numbers.append(int(match[1]))
            rows.append({"id": match[2], "title": match[3]})
        elif line.startswith("     ") and rows:
            rows[-1]["title"] += "\n" + line
        elif re.match(r"^\s*\d+\.\s+`?FSS", line, re.I):
            malformed = True
    return rows, numbers, malformed


def check(root: Path = ROOT) -> dict[str, Any]:
    root = Path(root)
    findings, sources = [], []
    texts: dict[str, str] = {}
    consumed = 0
    paths = corpus_paths(root)
    if len(paths) > MAX_SOURCES:
        findings.append(finding("INPUT"))
        paths = []  # No truncated pass: complete corpus is required.
    for path in paths:
        rel = path.relative_to(root).as_posix()
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                raise ValueError()
            raw = path.read_bytes()
            consumed += len(raw)
            if consumed > MAX_CORPUS_BYTES:
                raise ValueError()
            text = raw.decode("utf-8-sig")
        except (OSError, ValueError, UnicodeError):
            findings.append(finding("INPUT", rel))
            continue
        texts[rel] = text
        # Only allowlisted IDs/count integers/locations, never source lines/titles.
        sources.append({"path": rel, "digest": digest(raw), "bytes": len(raw),
                        "identities": [{"id": m[0], "line": text.count("\n", 0, m.start()) + 1} for m in ID_RE.finditer(text)],
                        "claims": [{"count": int(m[1]), "line": text.count("\n", 0, m.start()) + 1} for m in CLAIM_RE.finditer(text)]})
    try:
        document = json.loads(texts[REGISTRY])
    except (KeyError, ValueError):
        document = {}
        findings.append(finding("INPUT"))
    registry_errors = validate_registry(document)
    findings.extend(registry_errors)
    count = document.get("expectedCount") if isinstance(document, dict) else None
    rows = document.get("requirements", []) if isinstance(document, dict) else []
    if registry_errors:
        # Never treat an altered catalog as authority, even if its own counts agree.
        count = None
    if not registry_errors:
        owners = {r["id"]: " ".join(r["title"].split()).rstrip(".") for r in rows}
        for mirror in document["mirrors"]:
            if texts.get(mirror["path"], "").splitlines().count(mirror["template"].format(count=count)) != 1:
                findings.append(finding("MIRROR", mirror["path"]))
        plan_rows, ordinals, malformed = extract_rows(texts.get(PLAN, ""))
        if malformed or plan_rows != rows or ordinals != list(range(1, count + 1)):
            findings.append(finding("MIRROR", PLAN, "Appendix F"))
        for source in sources:
            rel, text = source["path"], texts[source["path"]]
            for claim in source["claims"]:
                if claim["count"] != count:
                    # Historical claims require an explicit same-line supersession.
                    line = text.splitlines()[claim["line"] - 1]
                    if "superseded" not in line.lower():
                        findings.append(finding("COUNT", rel, str(claim["line"])))
            for ref in source["identities"]:
                if ref["id"] not in owners:
                    findings.append(finding("OWNER", rel, str(ref["line"])))
            for number, line in enumerate(text.splitlines(), 1):
                if re.search(r"\b(?:[fF][sS][sS][_-]\d+|FSS\d{3,})\b", line):
                    for token in re.findall(r"\b(?:[fF][sS][sS][_-]\d+|FSS\d{3,})\b", line):
                        if not ID_RE.fullmatch(token):
                            findings.append(finding("IDENTITIES", rel, str(number)))
            if rel.endswith(".md") and rel != PLAN:
                # Reuse the existing definition grammar, preserving other drift rules.
                reference_table = False
                for number, line in enumerate(text.splitlines(), 1):
                    if line.startswith("|") and "Existing bead" in line:
                        reference_table = True
                    elif not line.startswith("|"):
                        reference_table = False
                    if reference_table:
                        continue  # Typed reference crosswalk; its IDs were resolved above.
                    match = stable_id_audit.HEADING_DEF_RE.match(line) or stable_id_audit.TABLE_DEF_RE.match(line) or stable_id_audit.LIST_DEF_RE.match(line)
                    if match:
                        identifier = stable_id_audit._definition_candidate(match)
                        if identifier and identifier.startswith("FSS-"):
                            title = " ".join(stable_id_audit._definition_title(match).split()).rstrip(".")
                            if owners.get(identifier) != title:
                                findings.append(finding("OWNER", rel, str(number)))
    return {"status": "failed" if findings else "passed", "findings": findings,
            "sources": sources, "expectedCount": count, "actualCount": len(rows) if isinstance(rows, list) else None,
            "owner": REGISTRY, "repair": REPAIR, "continuation": None,
            "authority": "read-only public contract corpus; no device, network, credential, or effect authority",
            "cost": {"sourceReads": len(sources), "inputBytes": consumed,
                     "identityOccurrences": sum(len(s["identities"]) for s in sources),
                     "claimOccurrences": sum(len(s["claims"]) for s in sources),
                     "remainingBytes": max(0, MAX_CORPUS_BYTES - consumed), "maxBytes": MAX_CORPUS_BYTES},
            "obligations": "terminal; no runtime work started", "cancellation": "synchronous; no children or external effects",
            "expiry": "invalid on any scanned source or checker generation change",
            "claimImpact": ["GATE-000", "WP-000", "GATE-120"],
            "releaseClaim": "blocked pending all other gate evidence; seed completeness alone is not implementation qualification"}


def generate(root: Path) -> None:
    doc = json.loads((root / REGISTRY).read_text())
    if validate_registry(doc):
        raise ValueError("unadmitted catalog; refusing generation")
    count = doc["expectedCount"]
    for rel in sorted({m["path"] for m in doc["mirrors"]}):
        path = root / rel
        text = path.read_text()
        for mirror in [m for m in doc["mirrors"] if m["path"] == rel]:
            pattern = re.escape(mirror["template"]).replace(re.escape("{count}"), r"\d+")
            text, n = re.subn("^" + pattern + "$", lambda _: mirror["template"].format(count=count), text, flags=re.M)
            if n != 1:
                raise ValueError("missing or duplicate mirror; refusing generation")
        if rel == PLAN:
            start = text.index("1. `FSS-")
            end = text.index("\n\nThe next tranche", start)
            text = text[:start] + "\n".join(f"{i}. `{r['id']}` {r['title']}" for i, r in enumerate(doc["requirements"], 1)) + text[end:]
        path.write_text(text)


def validate_record(record: dict[str, Any]) -> None:
    """Use the repository's existing Draft 2020-12 instance validator, fail closed."""
    import jsonschema
    schema = json.loads((ROOT / FIXTURES / "proof.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    if list(jsonschema.Draft202012Validator(schema).iter_errors(record)):
        raise ValueError("proof record schema")


def publish_proof(root: Path, out: Path) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    artifacts = out / "artifacts"
    artifacts.mkdir(exist_ok=True)
    report = check(root)
    document = json.loads((root / REGISTRY).read_text())
    scenarios = [("corpus", report, report["status"] == "passed")]
    for name, mutate in (
        ("missing-first", lambda d: d["requirements"].pop(0)),
        ("missing-last", lambda d: d["requirements"].pop()),
        ("internal-gap", lambda d: d["requirements"].pop(100)),
        ("duplicate", lambda d: d["requirements"].append(d["requirements"][0])),
        ("reorder", lambda d: d["requirements"].reverse()),
        ("count-240", lambda d: d.update(expectedCount=240)),
        ("count-249", lambda d: d.update(expectedCount=249)),
        ("count-251", lambda d: d.update(expectedCount=251)),
        ("version", lambda d: d.update(version=2)),
    ):
        candidate = copy.deepcopy(document)
        mutate(candidate)
        errors = validate_registry(candidate)
        scenarios.append((name, {"status": "failed" if errors else "passed", "findings": errors,
                                 "expectedCount": document["expectedCount"], "actualCount": len(candidate["requirements"]),
                                 "candidateDigest": digest(canonical_json_bytes(candidate)), "owner": REGISTRY, "repair": REPAIR}, bool(errors)))
    # Exercise the real corpus path (not just a detached registry validator), then
    # recover by restoring the exact source. No private/runtime files are copied.
    with tempfile.TemporaryDirectory(prefix="seed-corpus-") as scratch:
        tree = Path(scratch)
        for path in corpus_paths(root):
            target = tree / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        readme = tree / "README.md"
        original = readme.read_text()
        for stale in (240, 249, 251):
            readme.write_text(original.replace(f"first {document['expectedCount']} issues", f"first {stale} issues"))
            failed = check(tree)
            scenarios.append((f"corpus-count-{stale}", failed, failed["status"] == "failed" and any(f["code"] == "ERR-SEED-MIRROR-001" for f in failed["findings"])))
        readme.write_text(original)
        recovered = check(tree)
        scenarios.append(("recovery", recovered, recovered["status"] == "passed"))
    before_raw = (root / FIXTURES / "before.json").read_bytes()
    if digest(before_raw) != BEFORE_DIGEST:
        raise ValueError("historical evidence changed")
    before = json.loads(before_raw)
    scenarios.append(("before", before, before["result"] == "failed"))
    records = []
    objects = []
    for name, payload, matched in scenarios:
        raw = canonical_json_bytes(payload)
        identity = digest(raw)
        atomic_write_bytes(artifacts / (identity[7:] + ".json"), raw)
        objects.append(identity)
        record = {"schema": "fss.seed_proof_record.v1", "scenario": name, "artifact": identity,
                  "matched": matched, "owner": REGISTRY, "recovery": REPAIR,
                  "context": {"seed": 0, "schedule": "sequential; no clock/randomness", "authority": "public contracts only", "obligations": "terminal", "continuation": None}}
        validate_record(record)
        if len(canonical_json_bytes(record)) > 65536:
            raise ValueError("proof record exceeds complete-object budget")
        records.append(record)
    transcript = b"".join(canonical_json_bytes(r) + b"\n" for r in records)
    atomic_write_bytes(out / "transcript.jsonl", transcript)
    summary = {"schema": "fss.seed_proof_summary.v1", "status": "passed" if all(r["matched"] for r in records) else "failed",
               "transcriptDigest": digest(transcript), "artifacts": objects,
               "checkerDigest": digest(Path(__file__).read_bytes()),
               "recordSchemaDigest": digest((ROOT / FIXTURES / "proof.schema.json").read_bytes()),
               "scope": "DRIFT-003 only; other drift resolutions and release prerequisites unchanged"}
    raw = canonical_json_bytes(summary)
    atomic_write_bytes(out / "summary.json", raw)
    atomic_write_bytes(out / "proof.root", (digest(raw) + "\n").encode())  # root last
    return summary


def verify_proof(out: Path, root: Path = ROOT) -> bool:
    """Independently recomputes digests and the live corpus; never trusts stored flags."""
    try:
        root = Path(root)
        raw = (out / "summary.json").read_bytes()
        if (out / "proof.root").read_text().strip() != digest(raw):
            return False
        summary = json.loads(raw)
        transcript = (out / "transcript.jsonl").read_bytes()
        if summary["transcriptDigest"] != digest(transcript):
            return False
        if summary["checkerDigest"] != digest(Path(__file__).read_bytes()) or summary["recordSchemaDigest"] != digest((ROOT / FIXTURES / "proof.schema.json").read_bytes()):
            return False
        records = [json.loads(line) for line in transcript.splitlines()]
        if not records or summary["artifacts"] != [r["artifact"] for r in records]:
            return False
        schema = json.loads((ROOT / FIXTURES / "proof.schema.json").read_text())
        if [r["scenario"] for r in records] != schema["properties"]["scenario"]["enum"]:
            return False
        for record in records:
            validate_record(record)
            payload = (out / "artifacts" / (record["artifact"][7:] + ".json")).read_bytes()
            if digest(payload) != record["artifact"] or not record["matched"]:
                return False
            data = json.loads(payload)
            if record["scenario"] in ("corpus", "recovery"):
                # Replay the live corpus result rather than trusting the stored one.
                replayed = check(root)
                if digest(canonical_json_bytes(replayed)) != record["artifact"]:
                    return False
            elif record["scenario"] == "before":
                original = (ROOT / FIXTURES / "before.json").read_bytes()
                if digest(original) != BEFORE_DIGEST or data != json.loads(original):
                    return False
            elif data.get("status") != "failed" or not data.get("findings"):
                return False
        return summary["status"] == "passed"
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    if args.verify:
        return 0 if verify_proof(args.verify, args.root) else 1
    try:
        if args.generate:
            generate(args.root)
        result = publish_proof(args.root, args.out) if args.out else check(args.root)
        return 0 if result["status"] == "passed" else 1
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        print(json.dumps({"status": "failed", "findings": [finding("INPUT")]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
