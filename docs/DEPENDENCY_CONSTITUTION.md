# Dependency constitution for `franken_surveillance_system`

**Document class:** normative dependency, language, and process-boundary constitution
**Revision:** 1
**Date:** 2026-08-31
**Status:** binding design input; machine policy in `architecture/dependency_allowlist.toml`

---

## 0. Thesis

FSS will not become trustworthy by assembling a conventional computer-vision stack and wrapping it
in Rust. The system has to own the semantics that determine whether a camera was live, whether a
frame belonged to the claimed interval, whether two tracks could be the same entity, whether an
alert was justified, whether evidence reached durable storage, and whether shutdown left an effect
indeterminate. Those are precisely the places where a large opaque dependency graph destroys local
reasoning.

The dependency rule is therefore:

> **The production dependency universe is closed around the Rust standard library, Asupersync,
> explicitly admitted Franken-suite crates, and individually justified fundamental Rust crates.
> Every production semantic path is Rust and every FSS workspace crate forbids unsafe code.
> Foreign executables, language runtimes, native libraries, vendor SDKs, and proprietary helper
> applications are laboratory or migration oracles only and are absent from the production release
> closure.**

This is not minimalism for its own sake. It is a control strategy. A dependency is acceptable only
when the project can state which semantic contract it owns, what authority crosses the boundary,
what exact version was qualified, how cancellation and resource limits work, and how FSS behaves
when the dependency is absent or wrong.

## 1. Constitutional invariants

### `DEP-INV-001` — one asynchronous semantics

Asupersync is the only asynchronous runtime in production FSS processes. Tokio, async-std, smol,
Glommio, Monoio, and runtime-bearing transitive dependencies are forbidden. An adapter that hides a
second executor in a feature flag is a constitutional violation even if the public API accepts a
`Cx`.

### `DEP-INV-002` — one shipping language

All production FSS services, CLIs, model execution kernels, protocol implementations, state
machines, and release qualification binaries are Rust. Python, JavaScript/TypeScript, Java, Go,
C++, and shell are not production runtime dependencies.

Bash remains permissible for DSR/bootstrap orchestration because it starts Rust tools and executes
workflow specifications; it does not own surveillance semantics. The current Python policy checker
is a bootstrap artifact and has an explicit replacement work item: `fss-qualify` must subsume it
before the first operational release.

### `DEP-INV-003` — every FSS crate is safe Rust

Every crate in the FSS workspace carries `#![forbid(unsafe_code)]`, including binaries, examples,
tests, build helpers, protocol adapters, media kernels, model kernels, and platform integration
crates. FSS defines no local unsafe exception process.

When an operating-system or hardware capability cannot be reached through safe Rust, the primitive
must be provided by an independently owned and separately qualified first-party substrate project
such as Asupersync or another admitted Franken-suite crate. FSS consumes only its safe public
contract. The need for such a primitive does not authorize an ad hoc FSS unsafe island, C/C++ FFI,
dynamic library, vendor SDK, or foreign helper process.

### `DEP-INV-004` — no runtime acquisition

A production process never downloads model weights, native libraries, schemas, code generators,
firmware tools, or package-manager artifacts. Every executable, model, registry, and helper is
named by a release manifest and verified before activation.

### `DEP-INV-005` — no ambient authority

A crate cannot gain filesystem, network, clock, entropy, secret, subprocess, camera-control, or
alert authority merely because a transitive dependency exposes it. Authority is passed through
owned interfaces and Asupersync capability contexts. Build scripts and proc macros have no network
access.

### `DEP-INV-006` — exact sibling closure

Every release receipt names the exact clean revisions of Asupersync and each Franken-suite sibling
incorporated into the build. A binary attributed to one FSS commit cannot silently contain mutable
path dependencies from another checkout.

### `DEP-INV-007` — the transitive graph is part of the product

Direct-dependency approval is insufficient. `cargo metadata --locked --offline` is converted into a
canonical dependency closure. New packages, default-feature changes, license changes, build scripts,
proc macros, native links, runtime implementations, and unsafe-code surfaces fail the dependency
gate until reviewed.

### `DEP-INV-008` — laboratory oracles cannot become hidden production paths

NetworkX, PyTorch, FFmpeg libraries, OpenCV, ONNX Runtime, CUDA framework bindings, Python model
servers, vendor SDKs, and reference implementations may be used in isolated conformance labs when
legally and technically appropriate. Their outputs are oracle evidence. They are never silently
selected by production fallback, included in the default release, or granted effect authority.

### `DEP-INV-009` — absence must degrade explicitly

When an admitted sibling capability is unavailable, FSS uses a named deterministic reference path,
returns a typed degradation, or refuses the operation. It does not fetch an ecosystem substitute.

### `DEP-INV-010` — optimization cannot expand authority

SIMD, accelerators, shared memory, memory mapping, direct I/O, and zero-copy paths are admitted only
behind the same semantic interface and output digest as the safe scalar/reference implementation.
They may reduce cost; they may not change evidence, ordering, tie-break, precision policy, or
cancellation semantics without a new policy epoch.

## 2. Dependency classes

### 2.1 Class F0 — Rust language and standard library

The pinned latest-nightly toolchain is part of the source identity. FSS intentionally uses nightly
for portable SIMD, const/type-system improvements, and optimization opportunities, but no nightly
feature may become an undocumented semantic dependency. The qualification receipt records:

- `rustc -Vv`;
- Cargo version;
- target and host triples;
- enabled unstable features;
- codegen/LTO/panic settings;
- standard-library source identity when reproducibility requires it.

The project updates to the newest qualified nightly continuously. “Latest” means the newest date
that passed the complete local release matrix, not an untested moving channel at build time.

### 2.2 Class F1 — Asupersync

Asupersync owns structured concurrency, context-carried authority, budgets, cancellation, outcomes,
obligations, deterministic laboratory execution, and ATP. No local replacement of these semantics
is permitted inside feature crates.

FSS may wrap Asupersync in domain-specific types, but wrappers must preserve:

- region ownership and quiescence;
- request → drain → finalize cancellation;
- reason propagation;
- two-phase effect/queue semantics;
- deterministic time and fault injection;
- no orphan tasks or detached retry loops.

### 2.3 Class F2 — admitted Franken-suite crates

The intended owned universe is:

| Project | Production role | Admission posture |
|---|---|---|
| `frankensqlite` | canonical MVCC ledger, migrations, snapshot reads, crash recovery | admitted one API family at a time after kill-point qualification |
| `frankenfs` | local spool/object custody, staged publication, repair planning, retrievability | admission by storage profile and platform |
| `frankensearch` | derived lexical/semantic retrieval and progressive result shaping | search never becomes source of truth |
| `franken_markdown` | deterministic human/agent evidence reports | render outputs are sibling artifacts under root-last publication |
| `frankengraphdb` | versioned graph storage/query/incremental projections where measured useful | live effect path remains independent |
| `franken_networkx` native Rust crates | canonical graph algorithms, CGSE tie-break policy, complexity witnesses | Python compatibility layer is not linked into FSS |
| `frankentorch` | typed tensor/operator/autograd/serialization substrate for pure-Rust model execution | operator/model families admitted by differential gauntlet |
| `fastmcp_rust` | bounded capability-scoped MCP presentation plane | MCP never owns domain semantics |
| `eidetic_engine_cli` crates | deployment memory, feedback, anti-patterns, deterministic context packs | memory is advisory and derived |
| `frankentui` | terminal operator surface, diff rendering, deterministic input/replay | presentation never owns domain truth or effect authority |
| `franken_networkx`/`frankengraphdb` proof crates | graph reference/certificate support | no Python/PyO3 in shipping processes |

An entry in this table is permission to design an integration, not evidence that the current
version is qualified. `architecture/franken_imports.json` records the admitted mechanism and gate.

### 2.4 Class F3 — fundamental external Rust crates

An external crate is “fundamental” only when all of the following hold:

1. its semantics are narrow, stable, and not an application framework;
2. reimplementation would create more correctness or security risk than a bounded audit;
3. it carries no asynchronous runtime, hidden thread pool, network client, filesystem policy,
   model loader, plugin system, dynamic library, or native link;
4. every enabled feature is named and default features are disabled unless individually approved;
5. its complete transitive closure is small, Rust-only, locked, offline-resolvable, and audited;
6. the FSS boundary has deterministic success, failure, malformed-input, and compatibility tests;
7. license, maintenance, build-script, proc-macro, and unsafe surfaces are recorded;
8. the exact version is pinned by `Cargo.lock` and the DSR source-closure receipt.

The initial direct exception set is intentionally tiny:

- `serde` and `serde_json` for bounded, non-durable control/configuration JSON. Serde layout is never
  a durable byte format, object identity, or compatibility promise.

Other candidates, including digest, authenticated-encryption, key-agreement, TLS, zeroization, and
error-derivation crates, are **not admitted by category**. Each requires a `DEP-*` record, ADR,
transitive audit, safe-Rust verification, and release-gate evidence. Prefer an existing admitted
Franken-suite primitive when one provides the needed contract.

Convenience crates such as CLI frameworks, async HTTP stacks, ORM layers, image/media frameworks,
graph libraries, tensor frameworks, generic parsers, logging frameworks, retry frameworks, and
configuration frameworks are not fundamental merely because they are popular. FSS or an admitted
Franken sibling owns those surfaces.

### 2.5 Class F4 — laboratory and migration oracles

A Class F4 component is **not a production dependency or production boundary**. It may exist only in
a sealed research, reverse-engineering, conformance, or one-time migration lane whose outputs are
re-imported as immutable fixtures, differential reports, or model-conversion evidence.

Examples include pinned FFmpeg/ffprobe binaries, NetworkX, PyTorch, ONNX Runtime, OpenCV, vendor
applications, vendor SDKs, browser capture, and proprietary diagnostic tools. The lane must have:

- exact source/binary/model identity and license basis;
- fixture-only inputs, with no production credentials or live effect authority;
- no path from the production runtime to invoke or select the oracle;
- bounded resources, filesystem, network, and output schemas;
- reproducible commands and retained stdout/stderr/exit status;
- explicit taint/provenance on every imported artifact;
- a pure-Rust FSS or Franken-suite implementation whose behavior is being compared;
- a release check proving the oracle is absent from the production package, SBOM, process tree,
  dependency graph, and runtime configuration.

A proprietary camera that cannot be integrated through an owned wire protocol, documented local
interface, standards surface, or safe first-party substrate remains unsupported in production. A
vendor helper is not an acceptable permanent adapter. Likewise, a model or codec without an
admitted pure-Rust execution path remains a laboratory-only capability.

## 3. Explicitly forbidden production dependencies

The following are constitutionally forbidden unless this document is amended by a published ADR
and release gate:

- Tokio, async-std, smol, Rayon, hidden thread pools, or a second cancellation model;
- Python interpreters or Python model servers;
- Node/Bun/Deno/Electron;
- JVM or Go services;
- libtorch, ONNX Runtime, TensorRT, OpenCV, GStreamer, FFmpeg libraries or executables, generic
  NVR frameworks, vendor cloud SDKs, vendor applications, or vendor protocol helpers in the
  production release closure or process tree;
- PyO3 in shipping crates;
- a generic SQL client/ORM in place of FrankenSQLite contracts;
- a generic graph engine in place of the registered graph semantics;
- a general web framework in the core control plane;
- runtime plugin download or dynamic library discovery;
- package-manager invocation from production;
- unpinned Git dependencies or mutable branch dependencies;
- dependencies whose build scripts download or execute unverified artifacts;
- a library or helper that starts background threads or child processes outside Asupersync region
  ownership and drain semantics;
- direct camera/model/archive credentials in a third-party library that the capability layer cannot
  confine.

### 3.1 Agent ergonomics is not a dependency exception

A coherent agent interface does not justify importing a general agent framework, orchestration
framework, browser/server stack, prompt-template runtime, vector database, policy engine, workflow
engine, or alternate task system. The public `fss/1` operation/view/schema registries and the
agent-cognition crates own those semantics directly over Asupersync and admitted Franken
substrates. Natural-language compilation is a bounded typed transform; it is not permission to
execute arbitrary tools or dynamically acquire plugins.

## 4. Dependency admission record

Every admitted package or executable has a record containing:

```text
dependency_id
class
name
source_repository_or_distribution
exact_revision_or_version
content_digest
license_digest
feature_set
transitive_closure_digest
build_script_presence
proc_macro_presence
unsafe_surface_must_be_none_for_fss_and_audited_for_dependencies
native_link_surface_must_be_none
runtime_or_thread_surface
network/filesystem/clock/entropy authority
semantic_owner
replacement_prohibition
reference_oracle
fault_campaign
platform_matrix
admission_gate
expiry_or_requalification_trigger
```

A version upgrade creates a new record and enters shadow qualification. It does not mutate the old
record.

## 5. Cargo and workspace policy

### 5.1 Workspace inheritance

The root workspace owns edition, toolchain expectations, lint levels, release profiles, and common
dependency versions. Member crates do not weaken `unsafe_code`, warning, or runtime policies.

### 5.2 Feature policy

- `default-features = false` for external dependencies unless a reviewed reason is recorded.
- Features are additive capability declarations, not vague build modes.
- No feature may silently select a second runtime, network transport, model backend, or native
  library.
- Release manifests name the exact feature set.
- Mutually exclusive semantic modes use distinct types or binaries when accidental mixture would
  be dangerous.

### 5.3 Build scripts and proc macros

Build scripts are prohibited by default. An exception must be deterministic, offline, input-sealed,
and produce a manifest of generated outputs. Checked-in generated protocol/schema code is preferred
when it makes review and reproducibility stronger.

Proc macros are permitted only when they remove boilerplate without hiding authority, background
work, or serialization layout. Generated code remains inspectable with a qualification command.

### 5.4 Offline resolution

Release qualification runs:

```bash
cargo metadata --locked --offline --format-version 1
cargo build --locked --offline --workspace --all-targets
```

The build snapshot contains every sibling source and registry artifact required to resolve without
network access. A network-successful build that fails offline is not releasable.

## 6. Pure-Rust protocol strategy

FSS intentionally owns the narrow protocol slices it needs:

- RTSP/RTP/RTCP session and packet semantics;
- ONVIF SOAP/XML subset and WS-Discovery subset;
- UVC/UAC negotiation wrappers over a narrow OS/device boundary;
- S3-compatible object operations required by the archive contract;
- WebRTC/CMAF live-delivery subset if and when admitted;
- JSON-RPC/MCP through FastMCP Rust;
- image/tensor preprocessing through owned kernels;
- graph algorithms through FrankenNetworkX/GraphDB;
- model operators through FrankenTorch.

The goal is not to reproduce every standard. Each implementation begins from a semantic census of
what FSS actually uses, pins a reference oracle, rejects unknown critical fields, bounds all input,
and records every recovery decision. This follows Quill’s “beat the exact narrow waist” doctrine:
a focused engine can be smaller, faster, and more verifiable than a general framework.

## 7. Performance doctrine under the closed universe

Closing the dependency graph is not a performance concession. It creates optimization freedom:

- stable memory layouts without framework conversion taxes;
- arenas and bounded pools sized from operation-cost rows;
- safe portable SIMD through nightly `std::simd`;
- schema-specialized parsers and preprocessing kernels;
- container/GOP-aware zero-copy custody and remux paths;
- immutable snapshot sharing rather than cloning;
- columnar event/track/embedding layouts;
- factorized graph/query intermediates;
- tiled and fused tensor kernels;
- deadline-aware batching under one scheduler;
- exact same-binary A/B arms with semantic digests;
- no GIL, FFI conversion, generic framework dispatch, or opaque allocator in the hot path.

Every optimization is admitted only after the reference path, workload manifest, semantic output
digest, A/A null, distributional measurements, and negative result ledger exist.

## 8. Dependency drift and incident response

Requalification is triggered by:

- new direct or transitive package;
- version/feature/source change;
- license or maintainer compromise signal;
- build-script/proc-macro/native-link change;
- any unsafe code in the FSS workspace or newly reachable unsafe/native surface in a dependency;
- runtime/thread behavior change;
- security advisory affecting reachable behavior;
- sibling semantic/API epoch change;
- model or protocol output drift;
- toolchain change affecting codegen or deterministic bytes.

A drift finding can:

1. block build;
2. quarantine only the affected profile;
3. roll back to the prior dependency generation;
4. invoke the deterministic reference implementation;
5. force a read-only/degraded mode.

It never silently upgrades.

## 9. Release evidence

The dependency proof bundle contains:

- canonical Cargo metadata and dependency graph;
- `Cargo.lock` digest;
- exact sibling revision closure;
- source snapshot digest;
- toolchain receipt;
- license/SBOM inventory;
- unsafe/native/build-script/proc-macro census;
- denied-package/pattern report;
- offline resolution transcript;
- platform/profile-specific admission results;
- prior-generation diff;
- signed DSR qualification receipt.

A hosted workflow may reproduce a subset of this bundle, but it is neither required nor release authority. See
`docs/LOCAL_QUALIFICATION_AND_RELEASE.md`.

## 10. Initial admission sequence

1. Keep the reference contracts and skeleton dependency-free.
2. Admit Asupersync and prove region/cancellation semantics.
3. Admit serde only for control-plane JSON and freeze durable formats independently.
4. Admit any required digest/crypto/TLS primitives one crate and one feature set at a time, or consume an already-qualified first-party wrapper.
5. Admit FrankenSQLite storage APIs after deterministic/file-ledger equivalence and kill-point tests.
6. Admit FrankenFS object custody after root-last and repair gates.
7. Admit native FrankenNetworkX algorithms and graph witnesses.
8. Admit FrankenTorch operator families needed by the first model, not an entire opaque runtime.
9. Admit Frankensearch, FrankenGraphDB, FastMCP Rust, and Eidetic Engine projections one surface at
   a time.
10. Keep FFmpeg, vendor applications, SDKs, and foreign model stacks in laboratory-only oracle lanes; do not ship the affected capability until the pure-Rust path passes its admission gate.

The closed universe is successful only if each admitted component makes FSS easier to reason about,
not merely more internally branded.
