# Three Semantic Planes Enforcement Contract (ADR-0001 / FSS-001)

This normative document enforces the three semantic planes doctrine defined in `docs/adr/ADR-0001-three-semantic-planes.md`
and mandated by `AGENTS.md`:

> "Authority, cognition, and effect planes are type-distinct:
>  - A value from one plane must not convert into another plane's type without an explicit, audited boundary type.
>  - A cognition output (model score, recommendation) can never grant effect authority."

## Where the invariants are proven

Every invariant below is proven by a doctest attached to the real public item that owns the
boundary, compiled against the crate's actual public API. The doctests run in the normal cargo
test wave (`cargo test --doc -p fss-core` and `cargo test --doc -p fss-reference`). This
document intentionally contains no compile-fail blocks of its own: a standalone markdown file
has no link to the workspace crates, so any example here would fail for an unresolved path
rather than for the plane violation it claims to show.

The `semantic-plane-doctests` step of `scripts/qualify.sh --lane policy` verifies this map: the
document must contain no Rust code blocks, every invariant section must have at least one row,
and every row must name a doctest (or `#[test]`) in the listed file whose doc comment is
attached to the listed item, carries the listed marker, and declares the listed rustdoc kind
(including the exact expected error code for compile-fail blocks).

| Invariant | Kind | File | Item | Marker |
| --- | --- | --- | --- | --- |
| 1 | `compile_fail,E0277` | `crates/fss-core/src/effect.rs` | `EffectAuthority` | `adr-0001/inv-1` |
| 2 | `compile_fail,E0277` | `crates/fss-core/src/effect.rs` | `EffectIntent` | `adr-0001/inv-2` |
| 3 | `compile_fail,E0277` | `crates/fss-core/src/effect.rs` | `EffectAuthority` | `adr-0001/inv-3` |
| 4 | `compile_fail,E0308` | `crates/fss-core/src/effect.rs` | `prepare_effect` | `adr-0001/inv-4` |
| 4 | `compile_fail,E0308` | `crates/fss-reference/src/alert.rs` | `dispatch_reference_alert` | `adr-0001/inv-4-reference` |
| 5 | `compile_fail,E0277` | `crates/fss-core/src/event.rs` | `ProbabilityInterval` | `adr-0001/inv-5` |
| 5 | `compile_fail,E0277` | `crates/fss-reference/src/alert.rs` | `ReferenceAlertPlan` | `adr-0001/inv-5-reference` |
| legal-path | `doctest` | `crates/fss-core/src/effect.rs` | `prepare_effect` | `adr-0001/legal-path` |

## Invariant 1: Cognition output cannot convert to EffectAuthority

A model score, track confidence, or belief interval is in the cognition plane. It may propose an action,
but it can never be converted into or grant `EffectAuthority`. There is no `From`/`Into`
implementation from any cognition type into `EffectAuthority`; the compile-fail doctest on
`fss_core::effect::EffectAuthority` (imports `use fss_core::belief::BeliefInterval;` and
`use fss_core::effect::EffectAuthority;`) fails with `E0277` because the conversion trait bound
is unsatisfied.

## Invariant 2: Cognition output cannot directly construct EffectIntent

Cognition representations cannot coerce into effect intents without audited boundary mediation.
The compile-fail doctest on `fss_core::effect::EffectIntent` (imports
`use fss_core::belief::BeliefInterval;` and `use fss_core::effect::EffectIntent;`) fails with
`E0277`.

## Invariant 3: Effect authority cannot convert into cognition belief

Authority tokens and receipts are canonical facts. They cannot be coerced into probabilistic
epistemic belief intervals. The compile-fail doctest lives on `fss_core::effect::EffectAuthority`
(the authority side of the boundary) rather than on `BeliefInterval`: `crates/fss-core/src/belief.rs`
is declared a cognition module in `architecture/semantic_plane_registry.json`, and an authority
import there would itself be a cross-plane import. It fails with `E0277`.

## Invariant 4: Effect dispatch requires prepared effect plan, rejecting cognition types directly

An effect dispatch interface cannot accept cognition hypotheses or belief intervals directly;
effect execution requires an explicit prepared effect plan encapsulating `EffectIntent`,
obligation identity, and preconditions. Two real interfaces are proven:

- `fss_core::effect::EffectJournal::prepare_effect` accepts only a `PreparedEffect`; passing a
  `BeliefInterval` fails with mismatched types (`E0308`).
- `fss_reference::dispatch_reference_alert` accepts only a `&ReferenceAlertPlan`
  (`use fss_reference::ReferenceAlertPlan;`); passing a `&BeliefInterval` fails with `E0308`.

The legal path is shown by the compiling doctest on `prepare_effect` (marker
`adr-0001/legal-path`): a belief contributes only its content digest as an `EffectIntent`
precondition, the effect plane builds the `PreparedEffect`, and an explicit `EffectAuthority`
from the authority plane is recorded on the resulting `OperationReceipt`.

## Invariant 5: VLM/model output cannot directly convert to EffectIntent (NEG-003)

Per NEG-003 and AGENTS.md, a frontier VLM or model output is derived cognition and can never
trigger an effect directly. It must route through situation capsule, affordance frontier, and
witnessed plan before effect preparation. Two model-output types are proven:

- `fss_core::ProbabilityInterval`, the model-score form carried by event hypotheses, has no
  conversion into `EffectIntent` (`E0277`).
- `fss_reference::MockModelOutput` (`use fss_reference::MockModelOutput;`), the reference model
  executor output, has no conversion into `EffectIntent` (`E0277`). This doctest is attached to
  `ReferenceAlertPlan` in `crates/fss-reference/src/alert.rs` because the model module is owned
  by concurrent work.
