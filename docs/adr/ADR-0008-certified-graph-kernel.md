# ADR-0008 — Graph intelligence uses registered deterministic algorithms with witnesses

**Status:** Accepted

## Decision

Every planning-relevant graph algorithm names a projection, anchor, directedness/multiedge/weight
semantics, numeric policy, canonical tie-break, complexity contract, budget, output order, stale
policy, and reference implementation. Executions emit `GraphAlgorithmWitness` artifacts.

## Rationale

Equivalent mathematical answers are not operationally equivalent for replay, association, coverage,
or alert reasoning. Generic graph-library calls hide ordering, complexity, authorization, and
snapshot semantics.

## Consequences

FrankenNetworkX/FrankenGraphDB mechanisms are imported behind reference oracles and adversarial
gauntlets. Authorization is compiled before expansion. Optimized or specialized kernels replace the
reference only after semantic and performance proof.
