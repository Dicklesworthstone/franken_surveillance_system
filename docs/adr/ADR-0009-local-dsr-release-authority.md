# ADR-0009 — Local DSR receipts are qualification and release authority

**Status:** Accepted

## Decision

A clean-snapshot local qualification executed through repository scripts and Doodlestein
Self-Releaser is authoritative. GitHub Actions workflows are portable executable specifications and
optional supplementary evidence. GitHub-hosted runners are never required.

## Rationale

FSS relies on exact nightly behavior, mutable sibling repositories, native platform/device labs,
large model/media fixtures, and long crash/soak campaigns. Hosted badges cannot establish the exact
closure or environment of shipped artifacts and may be throttled or unavailable.

## Consequences

`scripts/qualify.sh` is the one repository contract. Releases record exact sibling revisions,
toolchain, hosts, lanes, assets, SBOM/provenance/signatures, and download verification. Partial
matrices remain staged and unblessed.
