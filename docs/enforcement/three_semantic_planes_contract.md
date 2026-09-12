# Three Semantic Planes Enforcement Contract (ADR-0001 / FSS-001)

This normative document enforces the three semantic planes doctrine defined in `docs/adr/ADR-0001-three-semantic-planes.md`
and mandated by `AGENTS.md`:

> "Authority, cognition, and effect planes are type-distinct:
>  - A value from one plane must not convert into another plane's type without an explicit, audited boundary type.
>  - A cognition output (model score, recommendation) can never grant effect authority."

The following `compile_fail` doctests are executed by `rustdoc --test docs/enforcement/three_semantic_planes_contract.md --edition 2024`
and audited by `scripts/semantic_plane_checker.py`.

## Invariant 1: Cognition output cannot convert to EffectAuthority

A model score, track confidence, or belief interval is in the cognition plane. It may propose an action,
but it can never be converted into or grant `EffectAuthority`.

```rust,compile_fail,E0277
use fss_core::belief::BeliefInterval;
use fss_core::effect::EffectAuthority;

fn execute_guarded_effect(_auth: EffectAuthority) {}

fn forbidden_grant(belief: BeliefInterval) {
    // FORBIDDEN: Cognition output cannot convert to EffectAuthority.
    // Compilation must fail because From/Into is never implemented across planes.
    let granted_auth: EffectAuthority = belief.into();
    execute_guarded_effect(granted_auth);
}

fn main() {}
```

## Invariant 2: Cognition output cannot directly construct EffectIntent

Cognition representations cannot coerce into effect intents without audited boundary mediation.

```rust,compile_fail,E0277
use fss_core::belief::BeliefInterval;
use fss_core::effect::EffectIntent;

fn forbidden_intent(belief: BeliefInterval) {
    // FORBIDDEN: Direct cross-plane coercion from cognition representation to EffectIntent
    let intent: EffectIntent = belief.into();
    let _ = intent;
}

fn main() {}
```

## Invariant 3: Effect authority cannot convert into cognition belief

Authority tokens and receipts are canonical facts. They cannot be coerced into probabilistic
epistemic belief intervals.

```rust,compile_fail,E0277
use fss_core::belief::BeliefInterval;
use fss_core::effect::EffectAuthority;

fn forbidden_belief(auth: EffectAuthority) {
    // FORBIDDEN: Authority cannot be converted into probabilistic cognition belief
    let belief: BeliefInterval = auth.into();
    let _ = belief;
}

fn main() {}
```

## Invariant 4: Effect dispatch requires prepared effect plan, rejecting cognition types directly

An effect dispatch interface cannot accept cognition hypotheses or belief intervals directly;
effect execution requires an explicit prepared effect plan (`ReferenceAlertPlan`) encapsulating
`EffectIntent`, obligation identity, and preconditions. Attempting to pass a cognition representation
to effect dispatch fails compilation with mismatched types (`E0308`).

```rust,compile_fail,E0308
use fss_core::belief::BeliefInterval;
use fss_reference::ReferenceAlertPlan;

fn execute_plan(_plan: &ReferenceAlertPlan) {}

fn forbidden_dispatch(belief: &BeliefInterval) {
    // FORBIDDEN: Attempting to pass a cognition type directly to an effect plan interface fails type checking
    execute_plan(belief);
}

fn main() {}
```

## Invariant 5: VLM/model output cannot directly convert to EffectIntent (NEG-003)

Per NEG-003 and AGENTS.md, a frontier VLM or model output is derived cognition and can never
trigger an effect directly. It must route through situation capsule, affordance frontier, and
witnessed plan before effect preparation.

```rust,compile_fail,E0277
use fss_core::effect::EffectIntent;
use fss_reference::MockModelOutput;

fn forbidden_conversion(output: MockModelOutput) {
    // FORBIDDEN by NEG-003: Model output cannot directly convert to EffectIntent.
    // Compilation must fail because cross-plane From/Into is prohibited.
    let intent: EffectIntent = output.into();
    let _ = intent;
}

fn main() {}
```
