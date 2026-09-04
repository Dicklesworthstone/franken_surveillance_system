#!/usr/bin/env python3
"""Atomically update one beads JSONL record selected by external_ref."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import tempfile
from typing import Any

VALID_STATUSES = {"open", "in_progress", "blocked", "closed"}


def utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default=".beads/issues.jsonl")
    parser.add_argument("--external-ref", required=True)
    parser.add_argument("--status", choices=sorted(VALID_STATUSES), required=True)
    parser.add_argument("--author", default="repository-agent")
    parser.add_argument("--comment")
    parser.add_argument("--timestamp")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def append_comment(record: dict[str, Any], author: str, text: str, timestamp: str) -> None:
    comments = record.setdefault("comments", [])
    if not isinstance(comments, list):
        raise ValueError("comments must be a list")
    next_id = max((int(comment.get("id", 0)) for comment in comments if isinstance(comment, dict)), default=0) + 1
    comments.append(
        {
            "id": next_id,
            "issue_id": record["id"],
            "author": author,
            "text": text,
            "created_at": timestamp,
        }
    )


def update_record(
    record: dict[str, Any],
    *,
    external_ref: str,
    status: str,
    author: str,
    comment: str | None,
    timestamp: str,
) -> bool:
    if record.get("external_ref") != external_ref:
        return False
    record["status"] = status
    record["updated_at"] = timestamp
    if comment:
        append_comment(record, author, comment, timestamp)
    return True


def transform(
    source: pathlib.Path,
    *,
    external_ref: str,
    status: str,
    author: str,
    comment: str | None,
    timestamp: str,
) -> tuple[list[str], str]:
    output: list[str] = []
    matches = 0
    issue_id = ""
    with source.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            if not raw_line.strip():
                output.append(raw_line)
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid JSON on line {line_number}: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"line {line_number} is not a JSON object")
            if update_record(
                record,
                external_ref=external_ref,
                status=status,
                author=author,
                comment=comment,
                timestamp=timestamp,
            ):
                matches += 1
                issue_id = str(record.get("id", ""))
            output.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    if matches != 1:
        raise ValueError(f"expected exactly one external_ref={external_ref!r}, found {matches}")
    if not issue_id:
        raise ValueError("matched bead is missing id")
    return output, issue_id


def atomic_write(path: pathlib.Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, path.stat().st_mode)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    args = parse_args()
    path = pathlib.Path(args.file)
    timestamp = args.timestamp or utc_timestamp()
    lines, issue_id = transform(
        path,
        external_ref=args.external_ref,
        status=args.status,
        author=args.author,
        comment=args.comment,
        timestamp=timestamp,
    )
    if not args.dry_run:
        atomic_write(path, lines)
    print(
        json.dumps(
            {
                "external_ref": args.external_ref,
                "issue_id": issue_id,
                "status": args.status,
                "timestamp": timestamp,
                "dry_run": args.dry_run,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
