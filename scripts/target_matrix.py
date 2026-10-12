#!/usr/bin/env python3
"""scripts/target_matrix.py — release target-matrix state with interrupted
resume and no partial blessing (FSS-188, bead fss-x4a.26.8).

architecture/local_qualification.toml: `partial_target_matrix_may_publish =
false`. A release covers N targets; an interrupted build must resume the
MISSING targets without ever blessing the incomplete set:

  * the matrix state is one JSON document (schema fss.target_matrix.v1),
    written atomically (temp + rename), so a crash mid-write never corrupts
    it into a blessable shape;
  * `record` marks one target done with its artifact digest (idempotent;
    a different digest for a done target is a typed conflict, never
    silently overwritten);
  * `resume` prints the pending worklist (declared minus done) — the exact
    resume contract after an interruption;
  * `complete` is the blessing gate: true ONLY when every declared target is
    done; a re-declared (extended) matrix honestly returns to incomplete;
  * a missing or corrupt state file is a typed error, never "complete".

Exit codes: 0 ok/false-negative results are in the JSON; 1 conflict; 2
corrupt/missing state; 3 usage error.
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

SCHEMA = "fss.target_matrix.v1"


def _atomic_write(path: Path, data: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".matrix-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True, indent=1)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(_emit({"state": "corrupt", "detail": str(exc)}, 2))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("targets"), dict):
        raise SystemExit(_emit({"state": "corrupt", "detail": "not a target-matrix document"}, 2))
    return data


def _emit(payload: dict, code: int) -> int:
    print(json.dumps(payload, sort_keys=True))
    return code


def cmd_init(args: argparse.Namespace) -> int:
    state = {"schema": SCHEMA, "declared": sorted(set(args.targets)), "targets": {}}
    _atomic_write(args.state, state)
    return _emit({"state": "initialized", "declared": state["declared"]}, 0)


def cmd_record(args: argparse.Namespace) -> int:
    state = load_state(args.state)
    if args.target not in state["declared"]:
        return _emit({"state": "undeclared-target", "target": args.target}, 1)
    existing = state["targets"].get(args.target)
    if existing is not None and existing != args.digest:
        return _emit(
            {"state": "digest-conflict", "target": args.target, "recorded": existing, "offered": args.digest},
            1,
        )
    state["targets"][args.target] = args.digest
    _atomic_write(args.state, state)
    done = sorted(state["targets"])
    complete = set(done) >= set(state["declared"])
    return _emit({"state": "recorded", "target": args.target, "doneCount": len(done), "complete": complete}, 0)


def cmd_resume(args: argparse.Namespace) -> int:
    state = load_state(args.state)
    pending = sorted(set(state["declared"]) - set(state["targets"]))
    return _emit({"state": "pending", "pending": pending, "pendingCount": len(pending)}, 0)


def cmd_complete(args: argparse.Namespace) -> int:
    state = load_state(args.state)
    declared = set(state["declared"])
    done = set(state["targets"])
    missing = sorted(declared - done)
    extra = sorted(done - declared)
    complete = not missing and not extra and bool(declared)
    return _emit(
        {
            "state": "complete" if complete else "incomplete",
            "complete": complete,
            "missing": missing,
            "undeclared-done": extra,
        },
        0,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="FSS-188 target matrix state")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--targets", nargs="+", required=True)
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("record")
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--digest", required=True)
    p.set_defaults(fn=cmd_record)
    p = sub.add_parser("resume")
    p.add_argument("--state", type=Path, required=True)
    p.set_defaults(fn=cmd_resume)
    p = sub.add_parser("complete")
    p.add_argument("--state", type=Path, required=True)
    p.set_defaults(fn=cmd_complete)
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
