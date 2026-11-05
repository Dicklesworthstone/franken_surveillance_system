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

An isolated `asupersync = 0.5.0` server experiment with `rustls = 0.23.46`
and `rustls-pure = 0.15.4` passed eight disposable tests on `hz3`. They include
an encrypted, task-owned controller-to-media fixture, independent OpenSSL
trust controls, a silent-peer timeout and an interrupted ciphertext write.
See [the laboratory record](../../experiments/unifi_tls_05_server_lab/README.md)
for exact scope and hashes. This server adapter has not been exercised against
a camera and does not close provider admission, explicit entropy authority,
key custody, peer authentication, full-duplex backpressure or platform gates.

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

On 2026-11-05, the isolated `experiments/unifi_tls_v1_lab` ran a
credential-free interoperability probe against the owner's G4 Instant.
The camera presented a self-signed X.509 v1 certificate. The rustls 0.23.43
certificate-based signature helper rejected it with `UnsupportedCertVersion`.
With a separately parsed certificate and its extracted SPKI, the lab's
raw-public-key P-256 signature verification completed TLS 1.2 and 1.3 against
that endpoint. A changed pin and a different valid P-256 key were rejected in
both versions. The observed pin was obtained on the same network and was not
independently authenticated; the lab does not check hostname, validity or
chain and sent no credentials or application data. Its precise sources,
lockfile and limits are recorded in the lab README and UniFi direct reference.
This finding does not admit the provider or change the open entropy, security,
dependency-closure, identity, or inbound-server requirements.

A second lab in `experiments/unifi_tls_async_lab` repeated both positive TLS
handshakes and all four negative pin/key controls through Asupersync 0.5.0 TCP.
That standalone lab has its own lockfile, bounded transport loops and no FSS
task/entropy authority. It provides live runtime interoperability evidence,
not dependency admission or authenticated camera identity.

On 2026-11-05, the separately maintained [`rustls-pure` 0.15.4](https://docs.rs/crate/rustls-pure/0.15.4)
was examined as a possible TLS 1.3-only alternative. Its published package
identifies source revision `1a9f2297133d8a4c176412f73f31d0d94f4b4619`.
The provider itself forbids unsafe Rust, supports TLS 1.3 with P-256 and
Ed25519, and its authors report interoperability and vector tests; they also
state that it has not received an outside security audit. Its published
[source](https://docs.rs/crate/rustls-pure/0.15.4/source/src/lib.rs) calls
`getrandom::fill` in its `SecureRandom` implementation and separately through
key-exchange randomness, so replacing only the `secure_random` hook would not
establish the explicit entropy-authority boundary. This is a source review of
one released package, not an audited dependency closure, an independently
verified test suite, or an admission decision. At that point it had not yet been tested against
the G4; the subsequent interoperability observation below does not change the existing provider decision.

The isolated `experiments/unifi_tls_pure_lab` subsequently tested that exact
released provider in a credential-free client-side TLS 1.3 handshake against
the owner's G4. The matching same-network observed certificate and its P-256
key succeeded; a changed certificate and a different valid key were rejected.
All three returned completed FSS task receipts. This is interoperability evidence
only: the observed pin is not independently authenticated, the camera-to-controller server role was not exercised, and the unaudited
provider still accesses entropy outside the FSS authority boundary. The Linux active dependency tree contained neither
`ring` nor `aws-lc-rs`, but did contain `getrandom`. The experimental binary,
lockfile, exact build overlay and limitations are in the laboratory README.
A synthetic same-provider loopback subsequently exercised the TLS 1.3 server
role with a disposable P-256 certificate and task-owned Asupersync transport;
this is not an independent client or a camera session. This does not change
provider admission or the registry decision.

Whoever picks up VIT-016 should start by running the `PENDING` command above on a qualification
branch, attaching its output to this record, and only then writing the boundary crate against a
real, pinned closure. This record's job was to make every required field explicit and to make clear
which of them are already settled by ADR-0014 (the provider choice) versus which need real tooling
(everything else) — not to shortcut the second group.

### Isolated Asupersync 0.6 acceptor observation (2026-11-05)

An isolated `asupersync = 0.6.2` `tls-core` build accepted an explicitly
supplied `rustls-pure = 0.15.4` provider without linking `ring` or `aws-lc-rs`
in the Linux normal dependency tree. A disposable loopback fixture completed
one TLS 1.3 exchange using the cancellation-aware accept and context-aware
read/write/flush APIs. Both peers used the same provider; the test did not
exercise FSS task authority, metering, camera authentication, or an independent
implementation. The binary SHA-256 was
`ec200efd45e713868d9bf207194689ce39dcdee3ddc3750b5056d3ac9fc2f3f2`.
This does not admit the provider or upgrade the FSS runtime: external review,
explicit entropy authority, and runtime integration remain open.

An independent OpenSSL 3.5.5 client subsequently validated the disposable
server certificate and hostname, negotiated TLS 1.3 and exchanged fixed
fixture payloads with this Asupersync server on `trj`; a different CA caused
the client to reject the server. The same-provider loopback also passed in
the same run: 3 tests passed. This is server-side wire interoperability with
one independent implementation, not client authentication, camera-session
compatibility, a provider audit, FSS task authority or provider admission.
The binary SHA-256 was
`1f072da45997bf9ee0f0cba4182bcad65309935f3c3af2942d1eff096ecf1c85`.

A native-loopback cancellation control waited for a silent peer's handshake to
return `Pending`, requested cancellation on the runtime context, and observed
`Interrupted` and peer EOF. Together with the independent OpenSSL and prior
same-provider controls, four disposable-fixture tests passed on `trj` (binary
SHA-256 `76232b155b8cde120fcc3e921ccbed20ff3e0f1088ece8a488fa434177c1550a`).
It is one cancellation case, not FSS task ownership, device qualification, or
provider admission.

The pinned rustls 0.23.46 API stores `SecureRandom` and its supported key
exchange groups as process-lifetime trait-object references, and their callbacks
receive no task or connection context. The selected provider separately calls
its OS randomness helper from X25519, P-256, P-384 and the hybrid key exchange.
An FSS integration therefore needs an explicit, concurrency-safe way to bind
*each* call to the correct authorized task and cover all enabled algorithms;
swapping only `secure_random`, relying on an unscoped global, or leaking one
static object per session would not establish that boundary. A provider/API
adaptation and its concurrent-session, cancellation and entropy-exhaustion
fault tests are still design work, not something demonstrated by these labs.
