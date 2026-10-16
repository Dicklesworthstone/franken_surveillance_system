# Fresh verification reuse during archive recovery

Scope: FSS-017/FSS-018 and the repeated verification portion of P1 bead
`fss-7549c`. This is an implemented reference-path optimization, not closure of
that bead or a production performance/DSR qualification claim.

## Behavior and boundaries

`StagingSpool::open_with_verified_recovery` performs the ordinary bounded opening
scan under the same exclusive lock and explicit I/O capability. Every object is
still read and hashed. Only an intact object whose durable verification hold is
present is promoted to the current session's `Verified` state. Ordinary spool
constructors retain their original `Staged` behavior. A persistent hold is never
accepted as proof that bytes are intact; missing originals remain corrupt.

`LocalRootPublisher` uses a private, opening-only `RecoveryReferences` adapter to
reuse these fresh checks while classifying root records and transitive references.
An unheld reference still goes through ordinary verification and hold publication.
Manifest bodies are read and decoded as before. A shared media object no longer
gets rehashed for every referencing root or fixed-point validation pass.

After classification, `retain_verification` demotes objects not consumed by the
classifier. Unpublished/interrupted work and unrelated held objects therefore keep
their original requirement for explicit verification before subsequent publication.
The method only narrows eligibility: it cannot promote staged work, remove holds,
clear corruption, alter quota, or revive a poisoned owner.

The recovery adapter does not escape the opening operation. Later reads,
`require_verified`, new publication, idempotent publication, and pre-commit checks
still read and hash current bytes. Tombstones, indeterminate root markers,
reference-closure checks and root-directory durability barriers remain in force.
A failed final roots-directory sync leaves roots `Visible`, never `Durable`.

## Retained regression coverage

The two changes add twelve tests across:

- `crates/fss-object/tests/spool_verified_recovery.rs`: six tests for fresh checks,
  held/unheld separation, same-length corruption, vanished originals, late mutation,
  failed-open lock release, and narrowing verification without removing holds.
- `crates/fss-publication/tests/local_recovery_single_scan.rs`: five tests for shared
  transitive references, corruption, later publication, missing holds, and fsync failure.
- `crates/fss-publication/tests/doctor0_open_regression.rs`: one added late-mutation
  test. Its existing second-read corruption fixture now explicitly removes a hold,
  exercising the still-required verification rather than a removed redundant read.

Existing report, unpublished-object and crash-recovery state assertions were kept.

The eight-root shared-media fixture makes **25** recovery read calls, versus **69**
with the original publisher implementation. The same test was executed against the
original implementation and failed its exact-count assertion with `left: 69` and
`right: 25`; the optimized implementation passes. This measures deterministic
`SpoolIoCall::Read` invocations, not field latency, throughput or bytes saved.

## Executed validation — 2026-10-16

Using the repository-pinned `nightly-2026-08-31` compiler
(`rustc 1.100.0-nightly`, commit `908501772`, 2026-08-30), with offline resolution:

```sh
cargo test --offline -p fss-object -p fss-publication --all-targets --no-fail-fast
cargo test --offline -p fss-object -p fss-publication --doc
cargo clippy --offline -p fss-object -p fss-publication --all-targets
```

Results: **497 tests passed, zero failed, two existing tests ignored**; **two
doctests passed**. The ignored read-only filesystem tests require an unprivileged
execution context; no new test was ignored. Clippy returned success with warnings
in unchanged code (`fss-core` collapsible `if` statements and deprecated atomic
methods in publication custody-audit I/O). Strict `-D warnings` remains blocked by
an existing `fss-core` warning; it is not claimed clean. New test files were
formatted, and `git diff --check` passed.

No schema, persistent format, digest-domain, production dependency, or qualification
threshold was changed. The initial full-byte scan is still O(total stored bytes).
Lazy verified reads, large-archive wall-clock measurements, full workspace tests,
and the native DSR release matrix remain outside this result.
