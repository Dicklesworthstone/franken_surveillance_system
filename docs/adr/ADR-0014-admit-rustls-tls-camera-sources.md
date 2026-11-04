# ADR-0014 — Admit TLS for camera-facing sources through `rustls` with the pure-Rust provider

**Status:** Accepted (policy); admission gate not yet satisfied — see Consequences
**Date:** 2026-11-04

## Context

The vittles footage-plane plan (`docs/VITTLES_FOOTAGE_PLANE_PLAN.md`, decision D2) needs TLS to
reach three standards routes that FSS cannot use today: UniFi Protect's RTSPS port (7441) and its
HTTPS Integration API, HTTPS-only ONVIF installations, and any cloud VMS (Verkada, Meraki). The
owner decided on 2026-11-04 to admit TLS via `rustls` for camera-facing sources, with certificate
pinning per site manifest; plain RTSP stays allowed on the site LAN or VPN only. That decision
settled the policy question. It did not settle the provider question, and `DEPENDENCY_CONSTITUTION.md`
§2.4 (Class F3) does not admit a crate "by category" — `rustls` and `webpki-roots` remain listed in
`architecture/dependency_allowlist.toml`'s `exception_candidates`, unresolved, until this ADR and a
`DEP-*` record exist.

The unresolved tension this ADR exists to close: `rustls` itself has no cryptography — it delegates
to a `CryptoProvider`. The two mature providers, `aws-lc-rs` and `ring`, both carry C or assembly
beneath their Rust API. `DEPENDENCY_CONSTITUTION.md` §0's dependency rule forbids C/C++ FFI in the
production closure (`production.cCppFfi = false`), and §2.4 condition 5 requires a Class F3 crate's
"complete transitive closure" to be "small, **Rust-only**, locked, offline-resolvable, and audited."
Neither `aws-lc-rs` nor `ring` can satisfy "Rust-only" under any reading of that word. The remaining
option, `rustls-rustcrypto` (a `CryptoProvider` built on the `RustCrypto` project's pure-Rust
primitives), satisfies "Rust-only" but is marked experimental by its own maintainers as of this
plan's research (`docs/VITTLES_FOOTAGE_PLANE_PLAN.md` finding, owner decision D2 row).

## Decision

Admit `rustls` as a Class F3 fundamental crate, configured with **`default-features = false`** and
the **`rustls-rustcrypto`** provider, not `ring` or `aws-lc-rs`. `webpki-roots` is admitted alongside
it for certificate chain validation against the public root set; a site's pinned certificate
(named in its manifest, per D2) is checked first and takes precedence, so `webpki-roots` is a
fallback path for camera consoles that present a publicly-rooted certificate, not the primary trust
anchor.

This is the only choice that does not require a separate FFI-policy exception on top of the TLS
admission itself. The experimental status of `rustls-rustcrypto` is accepted as a tracked risk, not
waived:

- it is scoped to camera-facing TLS only (RTSPS, HTTPS ONVIF, cloud VMS HTTPS), never to Asupersync,
  Ed25519 lease signing (ADR pending under D6/D2(a)), or any other FSS TLS surface, so a defect in
  it cannot silently widen into an unrelated boundary;
- `architecture/dependency_allowlist.toml` records a requalification trigger (below) rather than a
  one-time pass;
- if `rustls-rustcrypto` is later judged unfit, the fallback is not silently switching providers —
  it is TLS admission itself reverting to "not admitted" for the affected route, per
  `DEPENDENCY_CONSTITUTION.md` §8's "it never silently upgrades."

## What this ADR does **not** close

Per `DEPENDENCY_CONSTITUTION.md` §4, admission also needs a `DEP-*` record, a transitive audit, and
release-gate evidence. `architecture/dep_records/DEP-TLS-001-rustls.md` is the record this ADR
opens; it is **not complete**. Specifically still pending, and listed there rather than guessed at
here:

- the exact pinned versions of `rustls`, `rustls-rustcrypto`, and `webpki-roots` and their complete
  transitive closures, from a real `cargo add` + `cargo metadata --locked --offline` run on a
  qualification branch;
- the unsafe/build-script/proc-macro/native-link census across that closure;
- license identities for every transitive crate;
- the FSS-boundary deterministic success/failure/malformed-input/compatibility test suite;
- the fault campaign and platform matrix results;
- the signed DSR qualification receipt.

`architecture/dependency_allowlist.toml`'s `exception_candidates` entry for `rustls`/`webpki-roots`
is **not** moved to an admitted table by this ADR. It gains a pointer to this ADR and the DEP record,
and stays in `exception_candidates` until that record's evidence fields are filled from a real
build, not from this document's own research.

## Consequences

- VIT-016 (TLS-gated sources) and the UniFi inventory-fetch TLS work (bead request F10) can proceed
  against a named, citable provider choice instead of an open question; they still block on the DEP
  record's evidence fields, which are separate engineering work from this decision.
- Ed25519 signing for D6's leases and receipts is a **separate** admission (D2(b) in the plan's
  table), even though it may eventually share a `RustCrypto`-family primitive; this ADR's scope is
  TLS only and does not pre-admit a signing crate.
- A future finding that `rustls-rustcrypto` cannot carry production camera-TLS load (performance,
  unmaintained status, a security advisory) reopens this ADR. It does not authorize a quiet switch
  to `ring`/`aws-lc-rs` without a new ADR and a new FFI-policy exception, since that would be exactly
  the "silent upgrade" §8 forbids.
- Plain RTSP on the site LAN/VPN remains the default and unaffected; nothing in this ADR narrows what
  already works.

## Rejected alternatives

**`ring` or `aws-lc-rs` as the `CryptoProvider`.** Both are mature and widely deployed, and either
would likely clear a transitive-audit bar faster than an experimental pure-Rust provider. Rejected
because both embed C or assembly, which the dependency constitution forbids in the production
closure without its own separate, additional policy exception — admitting TLS should not also force
re-opening the C/C++ FFI prohibition as a side effect of a provider pick.

**Defer the provider choice, admit only the policy of "TLS, provider TBD."** Rejected because the
provider choice determines whether a *second* constitutional exception (C/C++ FFI) is even in play;
leaving it open would let VIT-016 and bead request F10 proceed against an ambiguous foundation and
would understate how constrained the real choice actually is — there are only three live providers,
and two of them are off the table for a reason worth recording now, not rediscovering later.

**Wait for `rustls-rustcrypto` to leave experimental status before deciding anything.** Rejected
because the owner's D2 ruling already set the policy to "admit TLS," and the plan's build order
(VIT-016, step 8) is sequenced after D2; sitting on the provider question would leave that step
blocked on nothing citable. The experimental status is recorded as a tracked risk instead, per the
Decision section above, rather than used to defer the whole question.
