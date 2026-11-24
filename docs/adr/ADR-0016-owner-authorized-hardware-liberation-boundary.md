# ADR-0016 — Owner-Authorized Hardware Liberation and Laboratory Interoperability Boundary

**Status:** Accepted
**Date:** 2026-11-23

## Context

`AGENTS.md` defines the Security Boundary for Franken Surveillance System:

> Interoperability work is limited to devices and accounts the operator owns or is explicitly
> authorized to test. Never implement credential theft, authentication bypass, third-party account
> access, broad scanning, persistence on vendor devices, or evasion. Reverse engineering must be
> minimal, documented, reproducible against lab fixtures, and isolated from production credentials.

Meanwhile, the repository also contains owner-authored hardware recovery, backup, open-firmware
provisioning (Thingino), and local LAN diagnostic utilities under `deliverables/` and documentation
under `docs/exploit/` used exclusively by the repository owner on their own physically owned LAN
cameras (Wyze, Tapo, UniFi, AOSU, Owlet, Yi) to restore local RTSP/ONVIF interoperability and escape
mandatory vendor cloud lock-in.

Without an explicit architectural boundary record, the coexistence of `deliverables/` (owner-owned
hardware liberation scripts, Python/shell helpers, and recovery runbooks) alongside `crates/`
(first-party pure-Rust production FSS) created charter ambiguity during policy and reality-check
audits.

## Decision

1. **Strict Separation of Production FSS (`crates/`) vs. Owner-Hardware Liberation Tooling
   (`deliverables/`):**
   - Production FSS (`crates/`, release binaries, qualification receipts, and `Cargo.lock`) remains
     100% pure Rust, `#![forbid(unsafe_code)]`, standards-first (RTSP/ONVIF/local native adapters),
     and free of any vendor device modification, firmware flashing, MITM/spoofing, or Python/FFmpeg
     runtime bridges.
   - `deliverables/` and `docs/exploit/` are classified as **owner-local, non-release, laboratory
     and hardware-ownership recovery artifacts** (`DEP-CLASS-F4` operational boundary). They are
     never linked into, invoked by, or shipped with production FSS binaries or release artifacts.
2. **Owner-Only Authorization Invariant:**
   - Every utility in `deliverables/` is strictly limited to hardware physically owned by the
     operator on their own local network, with explicit pre-flight hardware backups and brick
     recovery runbooks (`deliverables/flash/*/BRICK-RECOVERY.md`).
   - Third-party targeting, credential theft, unauthorized access, broad external scanning, or
     stealth evasion remain unconditionally prohibited across the entire repository.
   - Zero production secrets, private keys, or credentials may be committed in source, configs,
     logs, traces, or fixtures.
3. **Pure-Rust Migration Path for Live Media Capture:**
   - Temporary Python local-RTSP bridges in `deliverables/scripts/` (such as `wyze_rtsp_bridge.py`)
     are explicitly non-production laboratory scaffolds scheduled for retirement once first-party
     pure-Rust in-band SPS/PPS learning, multi-track RTSP capture (`fss-x4a.31.3.1`), TUTK capture
     hardening (`fss-x4a.31.3.2`), and native UniFi Protect ingest (`fss-x4a.31.3.4`) complete.

## Rationale

Documenting the exact boundary between pure-Rust production FSS and owner-authorized hardware
ownership/liberation tooling preserves honesty (`AGENTS.md` §12), eliminates charter drift, protects
the release closure from foreign runtime contamination, and makes the migration from laboratory
workarounds to native pure-Rust capture explicit and auditable.

## Consequences

- Production FSS crates (`crates/`) must never depend on, spawn, or require anything under
  `deliverables/` or `docs/exploit/`.
- Release artifact packaging (`scripts/release_artifacts.py`) and laboratory-oracle absence checks
  (`scripts/lab_oracle_absence.py`, `scripts/foreign_model_runtime_absence.py`) continue to enforce
  that zero foreign scripts or lab oracles enter production release closures.
- Pre-existing owner work in `deliverables/` remains isolated and untouched by production crate
  changes while its media-bridge functionality is systematically superseded by pure-Rust adapters.
