# Contributing

FSS welcomes architecture review, standards expertise, device interoperability work on devices you
own or are authorized to test, Rust implementation, model evaluation, privacy review, red-team
fixtures, and operational testing.

## Before opening code

1. Read `AGENTS.md`, the comprehensive plan, `SECURITY.md`, and `PRIVACY.md`.
2. Identify the stable requirement, work package, gate, and readiness dimensions affected.
3. Check whether the change introduces a new dependency, authority, durable schema, model identity,
   effect class, secret path, privacy surface, or compatibility claim.
4. Add or update the relevant registry before relying on prose.
5. State what negative evidence would falsify the proposed approach.

## Hard rules

- No credential bypass, unauthorized access, covert deployment, or third-party footage.
- No committed credentials, tokens, device certificates, private packet captures, or household
  footage.
- No model or device support claim without an exact immutable identity and qualification artifact.
- No `unsafe` in core crates. A future boundary exception needs an ADR, narrow crate, audit owner,
  safe facade, fuzz target, and ledger entry.
- No Tokio ecosystem in the workspace.
- No detached task or unowned subprocess.
- No hidden network downloads during build or test.
- No mutable durable format serialized from an unversioned Rust enum.
- No benchmark result without raw samples, environment, oracle, variance, and reproduction command.
- No rewrite of canonical evidence by a cognition or memory component.

## Required local checks

```bash
python3 scripts/check-policy.py
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Device, model, archive, and performance changes add their own qualification lanes. Hosted CI is not
a substitute for the local proof bundle.

## Fixture policy

Fixtures must be synthetic, public-domain, or explicitly consented. Include a provenance manifest,
consent class, deletion owner, expected observations, expected non-observations, and known limits.
Sanitize packet captures so they contain no credentials, unique device secrets, account IDs,
private network names, faces, license plates, addresses, or unrelated audio.

## Commit discipline

Prefer small semantic commits whose message names the stable work item. Documentation, schemas,
registries, implementation, tests, and status must move together. A feature is not complete merely
because its happy-path code exists.
