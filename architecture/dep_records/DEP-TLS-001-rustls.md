# DEP-TLS-001 — `rustls` (provider: `rustls-rustcrypto`) for camera-facing TLS

**Class:** F3 — fundamental external Rust crate (`DEPENDENCY_CONSTITUTION.md` §2.4)
**Opened by:** ADR-0014
**Status:** OPEN — policy decided; admission-gate evidence below is not yet collected

This record follows the exact field list in `DEPENDENCY_CONSTITUTION.md` §4. Every field below is
either a verified fact with its source, or marked `PENDING` with the exact command that will fill
it. No field is estimated or invented; a `PENDING` field must stay `PENDING` until that command has
actually run on a qualification branch and its output is attached here.

| Field | Value |
|---|---|
| `dependency_id` | `DEP-TLS-001` |
| `class` | `DEP-CLASS-F3` (fundamental-rust-data-shape) |
| `name` | `rustls` (primary crate); companions `rustls-rustcrypto` (provider), `webpki-roots` (fallback trust anchors) |
| `source_repository_or_distribution` | `https://github.com/rustls/rustls` (crates.io: `rustls`); `https://github.com/RustCrypto/rustls-rustcrypto` (crates.io: `rustls-rustcrypto`); `https://github.com/rustls/webpki-roots` (crates.io: `webpki-roots`) — repository identities only; not independently re-verified against a live network fetch in this sandbox |
| `exact_revision_or_version` | `PENDING` — `cargo add rustls --no-default-features --features std -p <boundary-crate> && cargo add rustls-rustcrypto && cargo add webpki-roots && cargo metadata --locked --offline --format-version 1` on a qualification branch, then pin by `Cargo.lock` |
| `content_digest` | `PENDING` — from the same offline resolution; recorded as the `Cargo.lock` package checksum, not computed by hand |
| `license_digest` | `PENDING` — `cargo metadata` license fields for the full transitive closure, cross-checked against each crate's own `LICENSE*` file; expected Apache-2.0/MIT dual for all three primary crates based on their public repositories, but not asserted here as verified |
| `feature_set` | Target: `rustls` with `default-features = false`, enabling only what the RTSP-over-TLS and HTTPS-ONVIF client paths need (no `aws-lc-rs`, no `ring`, no `logging` unless FSS's own tracing boundary requires it); `rustls-rustcrypto` as the sole `CryptoProvider`; `webpki-roots` for the public-root fallback path only. Exact feature list: `PENDING` the real resolution above. |
| `transitive_closure_digest` | `PENDING` — same offline resolution; this is the field that actually tells us whether "small, Rust-only" (constitution §2.4 condition 5) holds, so it is also the field most likely to force a return to this record before admission completes |
| `build_script_presence` | `PENDING` — `cargo metadata` + a census of each transitive crate's `build.rs`. Public knowledge: `ring`/`aws-lc-rs` are known to use build scripts for their native components, which is exactly why they are excluded by this ADR; `rustls-rustcrypto`'s closure is expected to be build-script-light as a pure-Rust provider, but that expectation is not evidence |
| `proc_macro_presence` | `PENDING` — same census |
| `unsafe_surface_must_be_none_for_fss_and_audited_for_dependencies` | N/A for FSS's own crates (no FSS code changes with this record alone). For the dependency: `PENDING` an actual `cargo-geiger`-class scan or equivalent manual audit of the resolved closure. Not assumed zero; RustCrypto-family crates have historically used narrow, documented unsafe in a small number of primitives even where the provider crate itself is pure-Rust at the API level — this must be checked, not asserted |
| `native_link_surface_must_be_none` | Expected `none` for the chosen closure (that is the entire reason `rustls-rustcrypto` was chosen over `ring`/`aws-lc-rs` in ADR-0014); confirmed only by the same offline resolution, `PENDING` |
| `runtime_or_thread_surface` | None expected — `rustls` is a synchronous, no-I/O TLS state machine; FSS's existing Asupersync-driven RTSP/ONVIF clients own the actual socket I/O and would drive `rustls`'s read/write buffers themselves, not hand it a runtime. This must be confirmed against the real `rustls` API surface at the pinned version when the boundary crate is written, not assumed from this record |
| `network/filesystem/clock/entropy authority` | `rustls-rustcrypto` needs an entropy source for key generation and nonces (TLS handshake randomness); FSS's existing `Cx`-scoped entropy boundary (see `crates/fss-cli/src/bin/fss-capture-rtsp/authentication.rs`'s Linux entropy backend, and the open gap for macOS, `VIT-007`) is the candidate authority to route this through rather than letting the crate reach `getrandom`/OS entropy ambiently, per `DEP-INV-005`. No filesystem or clock authority expected beyond certificate-file reads, which the FSS credential/manifest boundary already owns the shape of |
| `semantic_owner` | A new, narrow FSS boundary crate or module (not yet created) that owns "TLS session over a socket FSS already controls," analogous to how `fss_reference::rtsp::client` owns the plaintext RTSP session today. `rustls` itself is never called directly from a capture-plan or CLI binary |
| `replacement_prohibition` | Camera-facing TLS routes only (RTSPS, HTTPS ONVIF, cloud-VMS HTTPS). This record does not authorize using `rustls`/`rustls-rustcrypto` for Ed25519 lease signing (D2(b)), footage encryption at rest (D2(c)), or any other FSS boundary; each of those needs its own `DEP-*` record even if it reuses a `RustCrypto`-family primitive |
| `reference_oracle` | A loopback TLS fixture server (to be built alongside the boundary crate) presenting a known certificate, exercised the same way FSS's existing loopback RTSP/ONVIF fixtures are; no vendor camera or live console is a reference oracle for this record |
| `fault_campaign` | `PENDING` design — expected to mirror the existing RTSP fault lanes (`docs/rtsp_reordered_cadence.md`-style campaigns): handshake failure, certificate mismatch against both the pinned cert and the public-root fallback, mid-session renegotiation refusal (FSS does not need or want renegotiation), truncated/corrupted TLS records, and timeout/cancellation through Asupersync's region ownership |
| `platform_matrix` | Linux first (matches the site-node deployment target in the plan's Deployment section); macOS only if `VIT-007`'s entropy-backend gap closes first, since this record's entropy authority depends on it |
| `admission_gate` | `scripts/qualify.sh` once the boundary crate and its tests exist; this record alone does not pass it and is not release evidence |
| `expiry_or_requalification_trigger` | Any of: a security advisory against `rustls`, `rustls-rustcrypto`, or `webpki-roots`; `rustls-rustcrypto` reaching (or being abandoned short of) a stable release; a version bump in any of the three; discovery of unsafe code, a build script, or a native link in the resolved closure that was not expected above. Per `DEPENDENCY_CONSTITUTION.md` §8, any of these blocks or quarantines — it does not silently upgrade. |

## Next concrete step

On 2026-11-05, the upstream `rustls-rustcrypto` README at Git revision
[`70f76c039e587192688af18a80d5d6435dedaf22`](https://github.com/RustCrypto/rustls-rustcrypto/blob/70f76c039e587192688af18a80d5d6435dedaf22/README.md)
explicitly advised against production use and described its TLS implementation
as incomplete. This is an upstream development-head observation, not the
admission of a particular crate release or a completed security assessment.
Before qualifying a camera-facing provider, reconcile that upstream position
with the required operating environment and review the exact pinned release,
feature closure, supported camera handshake, and the project's pure-Rust policy.
This observation does not change the existing provider decision by itself.
At that same upstream revision, [`src/lib.rs`](https://github.com/RustCrypto/rustls-rustcrypto/blob/70f76c039e587192688af18a80d5d6435dedaf22/src/lib.rs)
uses `getrandom::SysRng` in its provider randomness hook; its
[`src/kx.rs`](https://github.com/RustCrypto/rustls-rustcrypto/blob/70f76c039e587192688af18a80d5d6435dedaf22/src/kx.rs)
also invokes `SysRng` directly during key exchange, as does its randomized
signer in [`src/sign.rs`](https://github.com/RustCrypto/rustls-rustcrypto/blob/70f76c039e587192688af18a80d5d6435dedaf22/src/sign.rs).
Thus replacing only the provider's `secure_random` hook would not by itself
demonstrate compliance with the explicit entropy-authority requirement. These
are source observations about that development revision, not a resolved crate
version, runtime trace, or proof about every cryptographic path. An exact
candidate closure and its complete entropy paths still require review.

Whoever picks up VIT-016 should start by running the `PENDING` command above on a qualification
branch, attaching its output to this record, and only then writing the boundary crate against a
real, pinned closure. This record's job was to make every required field explicit and to make clear
which of them are already settled by ADR-0014 (the provider choice) versus which need real tooling
(everything else) — not to shortcut the second group.
