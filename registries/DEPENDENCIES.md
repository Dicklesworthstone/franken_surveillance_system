# Dependency registry

The normative doctrine is [`docs/DEPENDENCY_CONSTITUTION.md`](../docs/DEPENDENCY_CONSTITUTION.md); the machine allowlist is `architecture/dependency_allowlist.toml`.
This file mirrors `architecture/dependencies.json` field by field. `scripts/dependency_registry_checker.py` parses both tables strictly and refuses drift, duplicate rows, and dependency identifiers anywhere outside the row table.

| Field | Value |
|---|---|
| `schema` | `fss.dependencies.v2` |
| `generation` | `gen:fss1:dependencies-v2` |
| `freezeDigest` | `sha256:8f198c9ce7b3eca519c678beb4bde773fe42d8bc93b55b9f0af375d38208a9c1` |
| `sourceDocument` | `registries/DEPENDENCIES.md` |
| `constitution` | `architecture/dependency_constitution.json` |
| `policy` | `architecture/dependency_allowlist.toml` |
| `contractBasis` | `fss.agent_contract_basis.v1` |
| `ownerRationale` | `Every row is owned by scripts/dependency_audit.py, the module that enforces it. DEP-INV-002 names fss-qualify as the replacement for the Python policy checker, but fss-qualify is not declared in architecture/crate_topology.json, so it cannot be a resolvable owner yet; the owners move to fss-qualify when it is declared, and the registry checker reports the moment it is.` |
| `futureOwner` | `fss-qualify` |

| ID | Constitution Class | Constitution Classes | Class | Rule | Scope | Status | Superseded By | Tombstone Decision | Owner | Producers | Consumers |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `DEP-OWNED-001` | `DEP-CLASS-F2` | `DEP-CLASS-F2`, `DEP-CLASS-F1` | Owned runtime and Franken-suite families | admitted after per-mechanism integration gate | `Production` | `active` | — | — | `scripts/dependency_audit.py` | `architecture/dependency_allowlist.toml#in_house`, `architecture/franken_imports.json` | `scripts/dependency_audit.py`, `scripts/dependency_registry_checker.py`, `scripts/dependency_constitution_checker.py`, `scripts/check-policy.py` |
| `DEP-FUND-001` | `DEP-CLASS-F3` | `DEP-CLASS-F3` | serde / serde_json | control-plane schemas only; never durable bytes or authority | `Production subject to audit` | `active` | — | — | `scripts/dependency_audit.py` | `architecture/dependency_allowlist.toml#fundamental`, `architecture/dependency_allowlist.toml#pending_owner_decisions` | `scripts/dependency_audit.py`, `scripts/dependency_registry_checker.py`, `scripts/dependency_constitution_checker.py`, `scripts/check-policy.py` |
| `DEP-LAB-001` | `DEP-CLASS-F4` | `DEP-CLASS-F4` | Pinned codec/model/vendor/reference executables | sealed fixture/oracle lanes only; no production invocation path and absent from release closure | `Development/migration only` | `active` | — | — | `scripts/dependency_audit.py` | `architecture/dependency_allowlist.toml#laboratory_oracles` | `scripts/dependency_audit.py`, `scripts/dependency_registry_checker.py`, `scripts/dependency_constitution_checker.py`, `scripts/check-policy.py` |
| `DEP-ORACLE-001` | `DEP-CLASS-F4` | `DEP-CLASS-F4` | Python/reference ecosystems | held-out conformance and lab fixtures only; absent from release closure | `Development only` | `active` | — | — | `scripts/dependency_audit.py` | `architecture/dependency_allowlist.toml#laboratory_oracles` | `scripts/dependency_audit.py`, `scripts/dependency_registry_checker.py`, `scripts/dependency_constitution_checker.py`, `scripts/check-policy.py` |
| `DEP-EXCEPTION-001` | `DEP-CLASS-F3` | `DEP-CLASS-F3` | Any other external crate | requires DEP record, ADR, source/feature census, semantic owner, substitute prohibition, and removal plan | `Not admitted` | `active` | — | — | `scripts/dependency_audit.py` | `architecture/dependency_allowlist.toml#exception_candidates` | `scripts/dependency_audit.py`, `scripts/dependency_registry_checker.py`, `scripts/dependency_constitution_checker.py`, `scripts/check-policy.py` |

No exception is implied by appearance in `Cargo.lock`. Release qualification computes and records the complete source/feature closure and fails closed on unknown provenance.
