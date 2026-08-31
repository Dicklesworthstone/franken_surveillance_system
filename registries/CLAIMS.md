# Claim registry

Machine source: `architecture/claims.json`.

| Claim class | Meaning | Minimum evidence |
|---|---|---|
| `invariant` | behavior forbidden/required for all reachable states | contract, mechanical check, adversarial counterexample suite |
| `proof` | theorem under declared formal model | formal artifact, assumptions, toolchain identity, check receipt |
| `bounded_model` | analytically derived bound under assumptions | derivation, units, assumptions, sensitivity and invalidators |
| `statistical` | estimated population/task behavior | sealed dataset manifest, sampling protocol, raw results, confidence interval |
| `slo` | operational latency/availability/cost target achieved | operation-cost row, environment, workload, raw measurements, failures |
| `benchmark` | comparative performance | pinned same-workload oracle, exact versions, raw samples, variance, command |
| `compatibility` | exact device/model/provider tuple works | tuple identity, fixture, conformance/soak/crash/security evidence |

## Forbidden claim promotions

- schema/source presence → feature support;
- one happy-path demo → compatibility;
- published crate/version → conformance;
- frame accuracy/mAP → event-level intrusion recall;
- one property → universal deployment result;
- no observed miss → never-miss guarantee;
- adapter ACK → live/continuous stream;
- object-store PUT response → durable/retrievable evidence root;
- cloud/SDK marketing text → exact product support;
- model-card benchmark → FSS security quality;
- research-only checkpoint → production-eligible model;
- mutable dashboard number → release evidence.
