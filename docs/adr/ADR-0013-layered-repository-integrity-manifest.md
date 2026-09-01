# ADR-0013 — Layered repository integrity manifest

**Status:** Accepted  
**Date:** 2026-09-01

## Context

FSS originally stored every source-path SHA-256 in one `MANIFEST.sha256`. That is simple but turns
small, frequent commits into risky full-file rewrites. A typo in an unchanged line can invalidate an
otherwise correct packet, and hand-maintaining hundreds of unrelated rows is contrary to the
project's incremental-commit discipline.

## Decision

`MANIFEST.sha256` remains the immutable base layer. `MANIFEST.delta.sha256` is an ordered
incremental layer containing only new or changed source paths. Qualification computes the effective
manifest as `base ∪ delta`, with delta replacing the digest for an existing path.

`scripts/manifest_audit.py` is the authority for the effective manifest. It:

- rejects unsafe, self-referential, duplicate, stale, or missing paths;
- rejects unchanged/redundant delta rows;
- SHA-256 verifies every effective source file;
- proves exact source-set coverage after exclusions;
- emits a deterministic effective-root digest over sorted `(digest, path)` pairs.

Both manifest files are excluded from the covered source set to avoid self-reference. No source
file may be deleted through the delta format. A future removal protocol requires a distinct,
explicit tombstone design.

`scripts/check-policy.py` runs with `--skip-manifest` from the release qualifier; the layered
manifest audit immediately follows it. Direct `check-policy.py` remains useful for legacy/base
inspection but is not the release authority for repository integrity.

## Consequences

- Small commits can update only the paths they actually change.
- Full base compaction remains possible with `scripts/generate-manifest.py`, but is a deliberate
  maintenance operation rather than a prerequisite for every code packet.
- Release receipts bind the effective layered-manifest root, not merely the bytes of the base file.
- DSR qualification stays deterministic and fail-closed.
