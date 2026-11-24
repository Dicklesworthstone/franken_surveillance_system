# ADR-0015 — Asupersync Transitive Closure and Mechanism-Owned Class F3 Admission

**Status:** Accepted
**Date:** 2026-11-23

## Context

`AGENTS.md` and `DEPENDENCY_CONSTITUTION.md` mandate Rust 2024 on the pinned nightly toolchain,
`#![forbid(unsafe_code)]` across every FSS crate, Asupersync as the sole asynchronous runtime
(`INT-AS-001`), zero C/C++ FFI or dynamic loading in production, and zero Serde-derived canonical
durable bytes (`FSS-110`, `DEP-AUD-023`).

When `asupersync = "=0.5.0"` was pinned into the workspace (`Cargo.toml` / `Cargo.lock`, commit
`77b6146be`), `DEP-CLOSURE-001` (`architecture/dependency_allowlist.toml#asupersync_closure`) was
created to census its exact transitive closure. However, four governance gaps were left open,
preventing `scripts/qualify.sh --lane policy` from passing:

1. **Pending owner decision `fss-ndxis`:** `serde` and `serde_json` (plus `zmij`) were pulled into
   `Cargo.lock` unconditionally by `asupersync = "=0.5.0"`, yet remained parked in
   `[pending_owner_decisions.fss-ndxis]`, causing `ERR-DEP-PENDING-DECISION-001` and `DEP-AUD-047`.
   Meanwhile, zero FSS workspace manifests declare `serde*` and zero FSS `.rs` files use Serde
   derives, paths, or attributes.
2. **Direct mechanism-owned Class F3 crates already inside the closure:** `fss-reference` uses
   `chacha20poly1305 = "=0.11.0"` (`default-features = false, features = ["alloc", "zeroize"]`) and
   `zeroize = "=1.9.1"` (`default-features = false`) for pure-Rust AEAD encryption and secret
   zeroization, and `fss-cli` uses `nix = "0.31.3"` (`default-features = false, features = ["fs", "net"]`,
   Unix-only) for safe `O_NOFOLLOW`, `O_NONBLOCK`, `fcntl`, and `getifaddrs` wrappers without
   introducing `unsafe` into FSS crates. All three are already in `asupersync 0.5.0`'s transitive
   closure, yet were not admitted as direct dependencies (`DEP-AUD-016`).
3. **Transitive `asupersync` build scripts, proc macros, and `wasm32`-only link metadata:**
   `asupersync = "=0.5.0"` and its pinned pure-Rust ecosystem closure include 31 crates with offline
   `build.rs` probe scripts, 13 derive proc-macro crates, and `wasm-bindgen-shared` declaring
   `links = "wasm_bindgen"` (cfg-gated to `wasm32` only; never compiled or linked on native
   Linux/macOS/Windows targets). Unconditional checks in `dependency_constitution_checker.py` and
   `dependency_audit.py` flagged these external closure crates alongside FSS workspace members.
4. **Offline build-script static audit (`DEP-AUD-026`):** Three external `build.rs` files inside the
   pinned closure triggered static deny-list hits (`asupersync@0.5.0` and `wasm-bindgen-shared@0.2.128`
   invoke local `git rev-parse`/`git status` only; `rustversion@1.0.23` embeds an issue-tracker URL
   inside an `eprintln!` error string). None performs network I/O.

## Decision

1. **Resolve `fss-ndxis` (Control-Plane Closure Only; Zero Serde Durable Bytes):**
   - Close `fss-ndxis` as resolved: `serde`, `serde_json`, `zmij`, and the Serde-family transitive
     crates pulled by `asupersync = "=0.5.0"` (`serde_core`, `serde_derive`, `rmp-serde`) are
     admitted strictly as pinned transitive closure dependencies under `DEP-FUND-001` /
     `DEP-CLOSURE-001`.
   - **Invariant preserved unconditionally:** No FSS workspace crate may declare a direct dependency
     on any Serde-family codec crate (`serde*`, `bincode`, `postcard`, `ciborium`, `rmp-serde`), and
     no FSS Rust source file (`crates/**/*.rs`) may contain `#[derive(Serialize/Deserialize)]`,
     `#[serde(...)]`, or `use`/`extern crate`/path references to any Serde-family crate.
     `DEP-AUD-023` continues to fail closed on every direct FSS manifest entry and every FSS `.rs`
     source file. All durable FSS bytes continue to use the first-party canonical codec.
2. **Admit `chacha20poly1305`, `zeroize`, and `nix` as Bounded Mechanism-Owned Class F3 Crates:**
   - `chacha20poly1305` (`=0.11.0`, `default-features = false, features = ["alloc", "zeroize"]`):
     pure-Rust AEAD; semantic owner `fss-reference`; zero C/C++ FFI; already in `asupersync` closure.
   - `zeroize` (`=1.9.1`, `default-features = false`): pure-Rust memory zeroization on drop; semantic
     owner `fss-reference`; zero C/C++ FFI; already in `asupersync` closure.
   - `nix` (`0.31.3`, `default-features = false, features = ["fs", "net"]`, `cfg(unix)` only): safe
     Rust syscall wrappers preserving `#![forbid(unsafe_code)]` for `O_NOFOLLOW`, `O_NONBLOCK`,
     `fcntl`, and interface enumeration; semantic owner `fss-cli`; zero custom C/C++ FFI libraries;
     already in `asupersync` closure.
3. **Pin Audited Transitive Closure Build Scripts, Proc Macros, and `wasm32` Link Metadata:**
   - Record the exact audited crate lists in `architecture/dependency_allowlist.toml` under
     `[asupersync_closure]` (`audited_custom_build`, `audited_proc_macros`,
     `audited_target_cfg_links`, and SHA-256-pinned `audited_offline_build_scripts`), protected by
     `BASELINE_ALLOWLIST_FREEZE_DIGEST` in `scripts/dependency_authority.py`.
   - **Zero relaxation for FSS crates or un-audited crates:** Every workspace member crate (`fss-*`)
     and every external crate not explicitly pinned in those audited closure lists continues to fail
     closed on `custom-build`, `proc-macro`, `links`, dynamic crate types, and `DEP-AUD-026` static
     network patterns. Any single-byte change to an audited external `build.rs` breaks its SHA-256
     pin and immediately fails `DEP-AUD-026`.

## Rationale

`asupersync = "=0.5.0"` is constitutionally required as FSS's sole async runtime. Leaving its pinned
transitive closure in permanent contradiction with the policy lane disabled automated regression
catching for the entire repository. By pinning exact audited lists and SHA-256 build-script digests
inside the freeze-digested `architecture/dependency_allowlist.toml` while maintaining absolute
prohibitions on all FSS workspace crates, all Serde Rust source usage, and any un-audited external
crate, FSS regains a fail-closed, 100% green `scripts/qualify.sh --lane policy` gate without
weakening any architectural invariant.

## Consequences

- `architecture/dependency_allowlist.toml` moves `chacha20poly1305`, `zeroize`, and `nix` into
  `[fundamental].allowed_subject_to_audit`, empties `[pending_owner_decisions]`, records the
  `fss-ndxis` resolution in `[resolved_drifts]`, and adds the exact pinned audit lists under
  `[asupersync_closure]`.
- `scripts/dependency_authority.py` updates `BASELINE_ALLOWLIST_FREEZE_DIGEST` to pin the reviewed
  allowlist bytes.
- Upgrading `asupersync` or adding any new external crate with `build.rs`, `proc-macro`, or `links`
  still fails closed until explicitly reviewed, audited, and re-pinned in a subsequent ADR.
- `rustls` and `webpki-roots` remain unadmitted in `[exception_candidates]` pending `DEP-TLS-001`
  per ADR-0014.
