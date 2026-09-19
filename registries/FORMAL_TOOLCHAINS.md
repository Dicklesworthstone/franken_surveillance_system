# Formal toolchains

Machine registry: `architecture/formal_toolchains.json` (`fss.formal_toolchains.v1`,
generation `gen:fss1:formal-toolchains-v1`). The checker
(`scripts/claim_proof_bundle_checker.py`) loads this registry fail-closed: an unregistered
checker id cannot back a `proof` claim, and an artifact suffix outside the registered
toolchain's suffixes is refused.

| Toolchain | Kind | Source suffixes | Backs theorem claims |
|---|---|---|---|
| `lean4` | theorem_prover | `.lean` | yes |
| `tlaps` | theorem_prover | `.tla` | yes |

Model checkers (TLC, Apalache) check invariants of bounded models and do not check THEOREMs,
so they are not registered here and cannot back a `proof` claim. Adding one requires a
registry generation bump with a recomputed freeze digest (SWARM RULE) and this mirror
updated in the same commit.
