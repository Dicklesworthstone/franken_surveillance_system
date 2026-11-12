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

### Scoped server hook prototype (2026-11-12)

An isolated patch against exact rustls 0.23.46 adds a server-configuration
random source and a TLS 1.3 server key-exchange hook receiving that same source.
The [research harness](../../experiments/unifi_tls_scoped_entropy_lab/README.md)
constructs distinct configurations for two interleaved synthetic sessions and
installs panic-on-use ambient server hooks. It also exercises entropy exhaustion
before and during key exchange, simulated revocation, incomplete hook pairs,
an invalid X25519 peer, and a certificate-verified independent OpenSSL client.
Strict-remote ts1 job `30105869848936729` passed 4/4 tests. A workspace freshly
prepared from the checksum-pinned upstream crate and the recorded patch passed
the same 4/4 tests in job `30105869848936730`; both jobs acknowledged terminal
results and released source and pair. An earlier job `30105869848936721` failed
one of three tests because its disposable CA was also used as the leaf; the
fixture was corrected to use a CA-signed leaf before the passing runs.

This is a research API modification, not a dependency admission or a finding
that the whole process has no ambient entropy. The test source is deterministic,
the client and the experimental `rustls-pure` provider are outside this ADR's
production provider decision, and other TLS paths have not been audited. The
prototype permits configuration sharing and does not bind its owned source to
an FSS task or `Cx`. Production still needs a scoped entropy source, enforceable
per-connection ownership, the chosen provider's full dependency/unsafe audit,
cancellation and revocation qualification, server-key custody, identity, and
release evidence. It neither changes the open record nor authorizes a camera
handoff.

### Task-owned entropy research follow-up (2026-11-12 UTC)

The isolated [research harness](../../experiments/unifi_tls_scoped_entropy_lab/README.md)
now supplies bounded Linux `/dev/urandom` bytes under a real FSS task grant and
budget to a per-session experimental TLS server. Strict-remote `hz2` job
`30106308287922181` passed two synthetic loopback tests: one encrypted exchange
with fallback server random and key-exchange hooks forbidden, and denial without
`AdapterAuth`. It also compiled the fleet transport adapter and tested its
configuration refusals. The job's exact scratch base was
`e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, overlay fingerprint
`3fed00a32d258a42912bc60c59503758fe20782376d5dd6d238089b7e04ea7a3`, and FSS
base was `d5995229b0b42fbcd5b9fa5956ac74626804b405`. Terminal status was
acknowledged and source and pair custody released. An earlier build failed on
a task/clock lifetime mismatch, corrected before these tests.

This does not admit `rustls-pure`, the patched Rustls fork, or this entropy
boundary. A synthetic routed fleet TLS/WebSocket handshake subsequently passed in job
`30106308287922186`, while a separate handshake remained stalled; the same
fixture also checked the capacity limit. A physical-camera routed handshake,
camera identity, cancellation races and complete provider entropy closure
remain untested. The entropy read
is synchronous, and an effect interrupted during a poll may be indeterminate.
No camera or recorder was modified in these tests.

### Scoped TLS client API research (2026-11-12 UTC)

A second isolated Rustls patch extends the laboratory API to client handshake
randomness and key exchange. Scoped mode rejects partial hook pairs, TLS 1.2,
ECH, early data and QUIC. It routes the TLS 1.3 key-exchange retry through the
scoped callback, and the laboratory client and server configurations report
non-FIPS status when scoped hooks are installed. Strict-remote `ts1` job
`30106308287922185` passed four synthetic client tests and four pre-existing
server tests, including independent OpenSSL interoperability in each direction,
client entropy exhaustion and unsupported retry-group refusal. It used scratch
base `b5c668dc2ce70e2e2824d2ae27c13fdf11cdf2b1` and overlay fingerprint
`8b7a52c35b9d1da8e451eee2f9ac3185422a2cbdf80538a3ab97e091a1c44961`;
its terminal result was acknowledged and source and pair custody released.

The client fixtures use predictable bytes and deliberately forbidden ambient
hooks; no FSS task-bound client or real camera was exercised. Client resumption,
certificate and clock authority, provider security and the whole dependency
entropy closure remain open. This does not admit Rustls or `rustls-pure` for
production. The patch can be reproduced from the isolated laboratory harness.

### Task-bound client and routed fleet fixture (2026-11-12 UTC)

The isolated harness now includes a Linux client session that consumes a
configuration and a task-metered transport, disables resumption, and uses the
same bounded task-authorized entropy lease as the experimental server. In
strict-remote `hz2` job `30106308287922187`, its two loopback tests, two
server-side loopback tests, and one reduced synthetic two-camera fleet test all
passed (5/5). The fleet case verifies one routed TLS/WebSocket upgrade while
another handshake is stalled, plus a separate capacity-one refusal. The job
used scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS base
`d5995229b0b42fbcd5b9fa5956ac74626804b405`, and overlay
`39d7e1da86529a9d4d80f3cb998a773f457aa2196c67ebe7d44d32b19c9babea`.
Its terminal result was acknowledged, and source and pair custody released.
A fresh prepared workspace reproduced the tested source bytes and resolved its
lockfile offline; this is not a second execution of the five tests.

The synthetic fixture and local operating-system entropy lease do not qualify
the provider, authenticate a real camera, settle interrupted effects, or prove
continuous capture. Entropy acquisition still uses synchronous filesystem I/O;
provider entropy paths, certificate and clock authority, cancellation races,
platforms other than Linux, and production dependency admission remain open.

### Synthetic setup using both task-bound TLS directions (2026-11-12 UTC)

The fleet fixture now uses the scoped task-owned TLS client for camera-facing
setup as well as the scoped task-owned fleet server. Strict-remote `hz2` job
`30106308287922189` passed that synthetic two-camera scenario and four separate
client/server authority tests (5/5). It used scratch base
`e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS base
`d5995229b0b42fbcd5b9fa5956ac74626804b405`, and overlay
`ec5995d26cb7b2668f166c1737c7f869739e856807a03ffd29716c1916027c4b`;
terminal status was acknowledged and source and pair custody released.

The camera-facing laboratory verifier checks the exact caller-supplied DER
certificate and handshake signature, but does not validate a chain, hostname or
certificate dates, or establish the pin independently. No physical camera was
used. Provider admission, nonblocking entropy acquisition, identity, task
revocation races, and prior physical-effect reconciliation remain open.

### Task-bound client pin refusal (2026-11-12 UTC)

Strict-remote `ts1` job `30106308287922190` passed two synthetic tests of the
scoped, task-owned pinned client: the correct disposable certificate permitted
an exchange, and a different pin was refused before plaintext was sent. The
job used scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS base
`d5995229b0b42fbcd5b9fa5956ac74626804b405`, and overlay
`1b1a07f9fd862d253e7baebc6d23d1ab95d8b473ea1ebf29133e4d47d4c31495`;
the terminal result was acknowledged and source and pair custody released.
An earlier submission was refused before Cargo under `hz2` critical memory
pressure. This is an exact-pin test, not independent physical identity or
certificate-chain and time validation, and it does not admit the provider.

### Entropy lease closure under contention (2026-11-12 UTC)

The laboratory lease formerly used `try_lock` when closing, which could leave
unused entropy in its allocation if a fill held the lock. A targeted synthetic
regression reproduced that failure in strict-remote `ts1` job
`30106308287922194` (the preceding job `30106308287922192` failed to compile
because a test-only context constructor was unavailable). The lease now uses
bounded atomic byte slots: a fill claims a disjoint range and clears consumed
bytes; close, cancellation and exhaustion fence the lease and clear its slots.
Overlapping fills may complete before the close linearization point.

Job `30106308287922197` passed five lease tests plus fifteen existing synthetic
TLS, authorization, pin and fleet tests (20/20). It used scratch base
`e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS base
`d5995229b0b42fbcd5b9fa5956ac74626804b405`, and overlay
`4b5620d8afe8b769a3a5a31ceabaae2a78ef45c25eb9968068ccf30258604ad9`;
the terminal result was acknowledged and source and pair custody released.
The concurrency check is a finite test, not an exhaustive scheduling proof.
The operating-system entropy read remains synchronous, and provider, identity,
revocation races and other production admission requirements remain open.

### Drainable blocking-pool entropy acquisition (2026-11-12 UTC)

The isolated lab now offers a task-bound entropy acquisition owner built on
`fss_runtime::drained_blocking`. It validates and debits task authority before
pool admission, refuses a missing pool, waits for closure release, and checks
the task again before returning a one-use lease. The experimental client and
server can consume those leases. Strict-remote `ts1` job `30106308287922198`
passed 26/26 synthetic tests: offloaded client and server exchanges and
missing-authority controls, missing-pool refusal, explicit cancellation with a
still-running worker, and the previously reported TLS and fleet checks. It
used scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS base
`d5995229b0b42fbcd5b9fa5956ac74626804b405`, and overlay
`54f3aded5445d810d32fafc13980137505f3d23772594736d272a4716dd71c44`.
Its result was acknowledged and source and pair custody released.

The acquisition owner must be retained and joined even after cancellation;
dropping it alone does not synchronously drain a running system call. The
current fleet and pinned-camera adapters still use the earlier synchronous
path; a supervised per-camera lease supply is not integrated. This is not
provider admission, physical-camera identity, or a general cancellation proof.

### Pre-acquired leases for synthetic fleet setup (2026-11-12 UTC)

The lab adds a lease-consuming fleet transport and pinned camera connection.
A caller explicitly acquires and joins each one-use lease before installing or
passing it; the transport itself starts no blocking work. Installation rejects
unknown resources, duplicate occupied slots, and leases bound to a different
task, runtime, resource or exact clock mapping. `MeteredClock::same_mapping`
is now exposed for this cross-layer check without changing its comparison.

Strict-remote `ts1` job `30106308287922200` passed 27/27 synthetic tests,
including the two-camera setup and routed TLS/WebSocket scenario using
pre-acquired leases on both sides, resource/clock mismatch controls, duplicate
lease refusal, and the earlier cancellation and interoperability checks. It used
scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, isolated FSS commit
`47bda273e8fd189643d0357c5ffa283b9354b134` (base
`d5995229b0b42fbcd5b9fa5956ac74626804b405` plus the visibility change), and
overlay `77f11ab103eeab22ce34cb94397caaf15654010b1ceb2ed6ec4a9d9c83acb29e`.
The result was acknowledged and source and pair custody released.

This is not unattended replenishment: callers still supervise and drain
acquisition owners, explicitly install leases, and handle empty slots. Legacy
synchronous paths remain. Provider admission, real-camera identity and effect
reconciliation, and production recording remain open.

### Bounded lease replenishment experiment (2026-11-12 UTC)

The isolated lab has a caller-polled `LeaseSupply` for a fixed inventory. It
starts bounded acquisitions for empty slots, replenishes leases after use,
latches acquisition failures until explicit rearm, and retains in-flight owners
through requested stop and drain. A second supply owner is refused. Strict-remote
`ts1` job `30106308287922206` passed 27/27 synthetic tests, including two-camera
replenishment and a shutdown immediately after worker admission; the existing
acquisition test separately holds a running worker until release. It used
scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS commit
`47bda273e8fd189643d0357c5ffa283b9354b134`, and overlay
`714d0020ca1ede474ca87992e35e24722d13b813c8820dbf94ca03fd869377d6`.
The result was acknowledged and source and pair custody released.

The caller must poll the owner and drain it after stop; drop cannot join a
running worker. Dynamic inventory, service supervision, provider admission,
physical-camera identity and effect reconciliation remain unproven.

### Shared discovery and lease-supply polling (2026-11-12 UTC)

The research supply can now be polled together with the existing discovery and
controller acceptor pump. The acceptor exposes its retained protected transport
for an exact shared-slot identity check; a mismatched supply is refused before
polling. The pump alternates preference and dropping the borrowing wait retains
both owners. Strict-remote `ts1` job `30106308287922209` passed 27/27 synthetic
tests, including discovery and replenishment during a stalled handshake,
mismatched supply, dropped wait and shutdown. It used scratch base
`e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, isolated FSS commit
`9a65f784739e9feb61b505168789a1ef239d6eb8`, and overlay
`4b21a8d0dbaf18e12b2d444abf702b2035a0542f538ff482131074330184de81`.
The result was acknowledged and source and pair custody released.

That fixture preloaded initial leases and the then-current transport refused an
empty slot. The caller had to drive and drain the owners; this was not a service,
dynamic camera enrollment, production TLS admission, or a real-camera handoff.

### Waiting for a fleet entropy lease (2026-11-12 UTC)

The laboratory transport now retains a routed handshake on an empty resource
slot and registers one bounded, cancellable waiter. A matching installation
wakes it; a live competing waiter is refused, and a stale registration left by
reentrant drop does not prevent a successor. Each poll rechecks task authority
and the route gate. The acceptor's existing deadline still bounds the handshake.

The prior implementation failed a new synthetic reconnect regression in `ts1`
job `30106308287922210`, with exit 101; it refused the empty slot. Revised job
`30106308287922214` passed 29/29 synthetic tests. The fixture reconnects before
replenishment, completes the same TLS/WebSocket connection afterward, and checks
that owner shutdown closes another waiting socket. Unit tests cover competing
and cancelled registrations, including a reentrant drop. The passing job used
scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, isolated FSS commit
`9a65f784739e9feb61b505168789a1ef239d6eb8`, and overlay
`4f620f0277f2496d758f924e4ecad6eeb5968ba68b56f1ed5fedf9eb8d2799c6`.
Both results were acknowledged and source and pair custody released.

This is not a production TLS admission, a complete cancellation proof, dynamic
enrollment, unattended service, or a physical-camera handoff.

### Append-only fleet resource synchronization (2026-11-12 UTC)

The research transport now uses 128 preallocated stable resource slots. A
caller can synchronize an existing owner-supplied fleet into the resource list
without moving names borrowed by active handshakes. The operation checks the
existing prefix before publication, appends bounded new names, and wakes a
parked supply; an initially empty inventory is supported. A resource inventory
admits one transport binding at a time. Synchronization does not itself enroll
or authenticate a camera and must still be invoked by the caller.

Strict-remote `ts1` job `30106308287922218` passed 30/30 synthetic tests. The
fleet fixture added an owner-supplied but unobserved enrollment while another
handshake was active, synchronized resources, and exercised supply wakeup,
empty startup, mismatched-prefix refusal and the existing two-camera route.
It used scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS commit
`9a65f784739e9feb61b505168789a1ef239d6eb8`, and overlay
`39b76e05d442318abca8f85a949bd50bcb0909a1776e8d2651076fcb906e13dd`.
The result was acknowledged and source and pair custody released. An earlier
build, job `30106308287922215`, failed before tests on fixture lifetime errors.
This is not production TLS admission, automatic enrollment, real-camera
handoff, or unattended recording.

### Automatic resource synchronization from the routed fleet (2026-11-12 UTC)

The laboratory combined pump now synchronizes lease resources from its
acceptor's exact fleet and waits on owner-enrollment changes. The fleet publishes
an append notification after its snapshot is updated; the wait checks the
Asupersync context when polled. Strict-remote `ts1` job `30106308287922226`
passed one reference-crate notification test (2,404 unrelated tests filtered),
covering two waiters, a later first poll, duplicate refusal and interruption
when polled after cancellation. Job `30106308287922227` passed 30/30 synthetic
lab tests, including a discovered simulated camera explicitly enrolled while
the loop was parked, wakeup and resource acquisition while another handshake
remained active. The jobs used FSS commit
`a9205759c3be92137c55c4dc8fe8ed688019cd2b`; the lab used scratch base
`e5cb2f08fde252bd4697b56e2f8fd912b67beffc` and overlay
`5dccada7bb441c932bf475b10360a82a5e0bd9abdbddbddb45bbba4c378c2426`.
Both results were acknowledged and source and pair custody released.

Discovery remains an untrusted claim, and the fixture supplies enrollment and
credentials explicitly. This does not establish automatic camera setup,
production TLS admission, physical identity, live handoff, or unattended
recording. It does not prove that cancellation wakes a parked waiter on every
runtime schedule; the direct test repolls after cancellation.

### Camera setup work alongside the TLS fleet pump (2026-11-12 UTC)

The research pump can now drive the existing bounded `CameraWorkSet` alongside
discovery, routing and entropy supply, alternately preferring completed camera
work and fleet progress. It returns the camera index and exact output; callers
retain setup traces, effect obligations and pending work. The supply/acceptor
binding is checked before camera work is polled. No detached task is created.

Strict-remote `ts1` job `30106308287922231` passed 30/30 synthetic lab tests.
After discovery and explicit enrollment, a third simulated camera used the
pinned client and existing HTTPS setup owner, retained a setup operation trace,
and completed a routed TLS/WebSocket connection. Its login reply was gated until
a second camera's controller connection completed while the first handshake
remained stalled. The fixture also checked a mismatched supply before work was
polled and retention of pending camera work after a borrowing wait was dropped.
The job used scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS
commit `a9205759c3be92137c55c4dc8fe8ed688019cd2b`, and overlay
`80be5fdb0604d28dfe34f66416a789cb82d322f1664178ea2f8582ea6907fceb`;
its result was acknowledged and source and pair custody released.

The caller still constructs and authorizes camera work, resolves credentials,
handles results and reconciles effects. The fixture uses disposable identities;
it does not admit the TLS provider, authenticate a physical camera, or establish
unattended setup, a production service or continuous recording.

### Selecting ready owner enrollments for setup (2026-11-12 UTC)

The laboratory loop now has a bounded `AutomaticWork` owner that selects ready,
explicitly enrolled fleet entries and requests setup futures from a caller's
factory. It verifies the exact fleet and transport, synchronizes resource names,
latches each admission attempt for the owner's lifetime, and returns factory
failures and rejected futures. Stopping admission retains pending futures for
explicit retirement. The factory's obligation to avoid synchronous effects is a
caller contract, not a type-enforced guarantee.

Strict-remote `ts1` job `30106308287922242` passed 30/30 synthetic tests. A
selector parked before a discovered simulated camera was explicitly enrolled;
it woke and admitted work. A separate factory-provided future completed the
existing HTTPS setup and controller route concurrently with other camera
activity. The fixture checked mismatched fleet/transport refusal, stop and
pending-work retention, and that a factory refusal was not silently retried.
The job used scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, FSS
commit `a9205759c3be92137c55c4dc8fe8ed688019cd2b`, and overlay
`e83dbb4fb18b9e41f17b4144ceae1481e906cb04fbe350b974beaf6c141153d8`;
its result was acknowledged and source and pair custody released.

The latch is not durable and does not authorize a retry after interruption.
The caller still supplies enrollment, credential resolution, effect authority
and setup work. The result does not admit production TLS, establish physical
identity or handoff, or qualify a recording service.

### Enrolled camera setup with a certificate-bound client (2026-11-12 UTC)

The laboratory now supplies a concrete camera setup future using a previously
acquired and drained task-bound entropy lease. It checks the supplied DER's
SHA-256 digest against the enrollment, matches the supplied credential handle,
resource, discovery source and listener, and checks caller admission and login
authority before opening the connection. It then performs the task-metered pinned
TLS connection and invokes the existing tracked setup owner. The trace and effect
journal remain caller-owned; cancellation by dropping the future closes its
connection and lease but does not settle a prepared or dispatched effect.

Strict-remote `ts1` job `30106308287922248` passed 30/30 synthetic tests. The
loopback fixture completed setup and a controller route, and verified six
pre-connection refusals: valid wrong certificate, wrong credential handle,
wrong discovery address, wrong resource, denied login and denied candidate
admission. Both probe sockets remained unaccepted in each case. The job used
scratch base `e5cb2f08fde252bd4697b56e2f8fd912b67beffc`, isolated FSS commit
`a9205759c3be92137c55c4dc8fe8ed688019cd2b`, and overlay
`10bcc5106cb3e6737d5949a57468c53a8cb7340d66e2c6bcec210ebd30bf6787`.
Its result was acknowledged and source and pair custody released.

The caller must independently provision the certificate and camera identity,
resolve credential bytes to the handle, retain and reconcile effect obligations,
and supply the drained lease. The provider is not production-admitted and no
physical camera or recorder was changed.

### Scoped P-256 client and live TLS-only observation (2026-11-12 UTC)

The experimental client now implements task-scoped P-256 ECDH as well as
X25519. It obtains a fixed-width scalar from the existing per-connection entropy
source, bounds rejection sampling, emits an uncompressed SEC1 point and refuses
invalid peer points. The camera TLS configuration permits one explicitly
selected group; it does not automatically discover group compatibility. The
new direct `p256` dependency is confined to this non-production laboratory.

The first TLS-only G4 probe, configured for X25519, failed its handshake. An
independent OpenSSL check also failed with only X25519, while P-256 succeeded
and the observed certificate matched the previously retained network pin.
After the scoped P-256 change, a TLS-only probe from ts1 to the observed G4
completed TLS 1.3 with that pin and verified the server handshake signature.
It sent no HTTP request or credentials and made no settings change. The same
probe's independent disposable P-256 server fixture passed matching-pin and
wrong-pin cases, observing zero application bytes. The first fixture version
returned a server-side BrokenPipe while it attempted to issue TLS tickets; the
reported fixture result uses a no-ticket server and successful completed runs.

Strict-remote ts1 test job `30106308287922255` passed 33/33 tests
(12+4+1+4+4+4+4), including P-256 agreement, malformed-point and invalid
scalar refusals and pinned-client success and wrong-pin refusal. It exited
zero, was acknowledged and released source and pair. Its source overlay
fingerprint was `e8a719bdae713628684f4c633d81b0e121a7b07cea731a10aa662f95757bd087`.
Build job `30106308287922256` completed remotely with exit zero; its wrapper
returned 102 because RCH rejected installing a Linux binary on macOS. Its
terminal result was acknowledged and source and pair were released. The Linux
probe used for fixture and G4 checks had SHA-256
`dc7a0f12aa48b6fc4a124aac0998e50ebe4d33e90ca730dd527051003c29aadb`,
matched before and after the live check. The observed network certificate
digest was `f266d3f9dbede6c30bc062c2d06d0b8091431d8347e5c6898de5ed09832bae36`.
The recorder and both relevant timers were active with NRestarts=0 afterward.

This is an actual-camera TLS handshake, not a login, video stream, physical
identity authentication, production TLS admission, automatic setup or a
recording. The pin was collected on the same network. No prior camera effect
was retried or reconciled; the original trial sources used ordinary journals
without the later independent pin-retention mechanism. No pin store was found
in the retained original trial directories. The old handoff and time-sync
outcomes remain indeterminate. The repository fleet gate also reported stale
ARP data and unrelated launchd/plist findings during this investigation; it
was not changed or treated as a UniFi qualification pass.

### Scoped P-256 controller-side TLS (2026-11-12 UTC)

The experimental task-owned controller TLS server now supports P-256 as well
as X25519, using the same scoped key-exchange implementation as the client.
It rejects malformed P-256 points before consuming server entropy; the
successful exchange uses the task-owned one-use entropy pool. The caller
still selects the server's supported group configuration. No claim is made
about which groups the G4 offers when it acts as a TLS client.

Strict-remote ts1 job `30106308287922266` passed the selected Cargo test run
and exited zero with terminal acknowledgement and source/pair release. Its
overlay fingerprint was
`5deadd01091dd50a577bdaddb4c4912e1d72f2fd82653faa6ea3ab874ce83ce3`.
The displayed output was truncated, so two retained test binaries were run
again separately on ts1 using the same disposable test identity: the
controller transport passed 7/7 tests, including a Python/OpenSSL P-256-only
client verifying the test CA and hostname with its normal strict policy; the
fleet route passed 1/1, exercising the P-256 configuration in its two-camera
case. The binary SHA-256 values recorded after these reruns were
`94279051f5c7b23085199a0675939adfb0aa8676c896694e70eb0c2cc352e12b`
and `63a8362bd59bc389250f432f3256399d892bb6797ea32f508f82cdb91f72205f`.

An earlier selected run, job `30106308287922264`, failed one independent
peer test because the generated disposable leaf certificate lacked an
authority-key identifier. The test certificate generator was corrected to
include that identifier and an appropriate CA key usage; independent strict
OpenSSL verification succeeded before the passing rerun. That earlier job
exited 101 and was acknowledged with source/pair release.

These are synthetic TLS and routed-controller tests, not evidence that the
physical camera supports this exact inbound negotiation or that an earlier
G4 handshake failed for this reason. No camera handoff or settings change
was performed; prior indeterminate effects remain unresolved. The existing
recorder and its two relevant timers were active with NRestarts=0 after the
test. TLS provider admission, physical identity, direct native video and
continuous recording remain open.
