# TLA+ proof targets

Modeled and TLC-checked (tla2tools 1.8.0, SHA-256
`15d103b7e5617780bcc904c0af12f1ad242e2b345c0301136c5be4588f17edac`):

- **Root-last archive publication** — `RootLastPublication.tla`
  (FSS-029). Objects climb Staged → Visible → Durable → Replicated →
  Protected; roots activate only at Durable or beyond; retirement requires
  no active root. Invariants R1–R5 (see module header). 81 distinct
  states, no errors. Negative control: weakening activation to Visible
  violates `RootLast`.
- **Effect prepare/commit/observe/verify idempotency** —
  `EffectIdempotency.tla` (FSS-028). Duplicates and reorderings of every
  request kind are absorbed by guards; at most one dispatch per operation;
  obligations resolve once; cancellation lands only pre-commit. Invariants
  E1–E5 (see module header). 64 distinct states, no errors. Negative
  control: allowing duplicate dispatch violates `SingleDispatch`.

TLC is a model checker: these runs are bounded-model evidence for the
invariants listed, not theorem claims (see
`registries/FORMAL_TOOLCHAINS.md` for what may back `proof` claims).

Reproduce:

```sh
java -cp tla2tools.jar tlc2.TLC -deadlock -config RootLastPublication.cfg RootLastPublication.tla
java -cp tla2tools.jar tlc2.TLC -deadlock -config EffectIdempotency.cfg   EffectIdempotency.tla
```

Planned models:

- lease fencing for competing agents;
- deletion closure across canonical and derived artifacts;
- stream cancellation and quiescence.
