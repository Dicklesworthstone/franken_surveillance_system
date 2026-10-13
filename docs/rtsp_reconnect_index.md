# Offline catalog completion for recovered RTSP attempts

`fss-capture-rtsp reconnect --recover index` completes discovery metadata for already durable AVC or HEVC recording windows. It uses the existing codec-specific catalog verifier and independently journaled writer. No camera connection, credential read, new recording, source rewriting, deletion, or cross-epoch merge occurs.

## Operator sequence

Keep the original reconnect options, including source generation, timing evidence, paths, codec and all resource settings. Remove the old `--approve` value.

1. Run with `--recover yes` to inspect saved work. Approve that recovery preview to restore the original pending window/catalog when needed. This operation does not create additional catalog pages.
2. Replace `--recover yes` with `--recover index`. This is **not a pure preview**: it opens and verifies every observed archive, replays original source custody and prepares the exact next catalog identity. It does not append journal records or publish catalogs. Review its new approval and the per-attempt window, page and command counts.
3. Repeat the index command with that separate `--approve` digest. Preserve every JSONL record. The `attempt_index` records contain every current catalog slot/root, including catalogs which predated this invocation, with the exact source and decode-clock scope for `fss-import-rtsp`.

The `--recovery-timeout-ms` allowance covers the entire indexing operation, not each attempt. The original per-attempt native limits remain in force. The command quotes the existing writer's whole-tail catalog shape; a tail above the native catalog bound is refused rather than silently split into a different format.

## Approval and interruption boundaries

The index approval commits to the original capture plan, complete observed journal tips and selected work pins, directory identities, verified archive snapshot digests, exact next catalog roots, command counts, timeout and output allowance. Capture, restore and index approvals are not interchangeable. Indexing refuses outstanding candidates and unsettled original work instead of recovering them implicitly.

All observed archives are source-verified and their locks held before the first new journal or catalog publication. Every newly prepared catalog passes through the existing candidate-pin synchronization, work-root durability, independent confirmation and root-last catalog publication. A writer command ceiling is checked before any new publication and is not replenished by a progress step.

The operation is incremental across attempts, not atomic. An output error stops before the next attempt. A work confirmation can precede a lost response or cancellation, leaving an original prepared catalog for `--recover yes`. Preserve both stores, inspect their current state and approve recovery explicitly, then preview indexing again. A missing/corrupt candidate never falls back to older work. No automatic tail repair is performed.

After successful indexing, the old approval is stale. A fresh preview over an already fully indexed archive produces a no-op plan, and its execution reports existing catalog identities without creating duplicate ordinals or journal records.

## Machine output and limits

The transport schema is `fss.rtsp_reconnect_index_cli.v1`. A planned JSON object contains `approval`, `capture_plan`, `recovery_timeout_ns` and `attempts[].index` (snapshot, durable/indexed counts, existing/new pages, maximum writer commands and next catalog root). Execution is ordered JSONL: `index_started`, optional `index_work_confirmed`, `attempt_index` and `index_terminal`.

Both missing stores remain `both_stores_unobserved`; the command does not infer that an attempt never ran. `index_complete` describes only checked archive discovery. `capture_complete`, `continuity_across_attempts`, `absence_certifiable`, `network_requested` and `source_bytes_emitted` remain false in the terminal report. Directory protection is still part of the trust boundary; this is not an independent malicious-rollback proof, encrypted custody, camera qualification or release authority.

Native regression tests reside in `crates/fss-cli/src/bin/fss-capture-rtsp/indexing_tests.rs`. They exercise actual HEVC source custody, original-slot restoration, independently locked journals, exact retries, command budgets, corruption and cancellation. Passing fixtures qualify only those reference paths, not arbitrary cameras or deployment performance.
