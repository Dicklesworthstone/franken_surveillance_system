# Dependency registry

The normative doctrine is [`docs/DEPENDENCY_CONSTITUTION.md`](../docs/DEPENDENCY_CONSTITUTION.md); the machine allowlist is `architecture/dependency_allowlist.toml`.

| ID | Class | Rule | Scope |
|---|---|---|---|
| `DEP-OWNED-001` | Owned runtime and Franken-suite families | admitted after per-mechanism integration gate | `Production` |
| `DEP-FUND-001` | serde / serde_json | control-plane schemas only; never durable bytes or authority | `Production subject to audit` |
| `DEP-LAB-001` | Pinned codec/model/vendor/reference executables | sealed fixture/oracle lanes only; no production invocation path and absent from release closure | `Development/migration only` |
| `DEP-ORACLE-001` | Python/reference ecosystems | held-out conformance and lab fixtures only; absent from release closure | `Development only` |
| `DEP-EXCEPTION-001` | Any other external crate | requires DEP record, ADR, source/feature census, semantic owner, substitute prohibition, and removal plan | `Not admitted` |

No exception is implied by appearance in `Cargo.lock`. Release qualification computes and records the complete source/feature closure and fails closed on unknown provenance.
