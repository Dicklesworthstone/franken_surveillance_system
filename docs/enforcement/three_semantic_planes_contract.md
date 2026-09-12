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

```rust,compile_fail
// Cognition plane: probabilistic belief interval
pub struct BeliefInterval {
    pub lower: u64,
    pub upper: u64,
}

// Authority plane: explicit capability lease
pub struct EffectAuthority {
    pub capability_lease: String,
}

fn execute_guarded_effect(_auth: EffectAuthority) {}

fn main() {
    let high_confidence_belief = BeliefInterval {
        lower: 990_000,
        upper: 999_000,
    };

    // FORBIDDEN: Cognition output cannot convert to EffectAuthority.
    // Compilation must fail because From/Into is never implemented across planes.
    let granted_auth: EffectAuthority = high_confidence_belief.into();
    execute_guarded_effect(granted_auth);
}
```

## Invariant 2: Cognition output cannot directly construct EffectIntent

Cognition representations cannot coerce into effect intents without audited boundary mediation.

```rust,compile_fail
// Cognition plane: model recommendation
pub struct ModelRecommendation {
    pub action: String,
    pub score: f64,
}

// Effect plane: prepared mutation intent
pub struct EffectIntent {
    pub operation_id: String,
    pub action: String,
}

fn main() {
    let recommendation = ModelRecommendation {
        action: "isolate_camera".to_string(),
        score: 0.98,
    };

    // FORBIDDEN: Direct cross-plane coercion from cognition recommendation to EffectIntent
    let intent: EffectIntent = recommendation.into();
    let _ = intent;
}
```

## Invariant 3: Effect authority cannot convert into cognition belief

Authority tokens and receipts are canonical facts. They cannot be coerced into probabilistic
epistemic belief intervals.

```rust,compile_fail
// Authority plane: capability lease
pub struct EffectAuthority {
    pub capability_token: String,
}

// Cognition plane: belief interval
pub struct BeliefInterval {
    pub lower: u64,
    pub upper: u64,
}

fn main() {
    let auth = EffectAuthority {
        capability_token: "lease-auth-998822".to_string(),
    };

    // FORBIDDEN: Authority cannot be converted into probabilistic cognition belief
    let belief: BeliefInterval = auth.into();
    let _ = belief;
}
```

## Invariant 4: Direct effect dispatch without authority token fails compilation

An effect dispatch interface cannot accept cognition hypotheses or recommendations directly; it strictly requires
an explicit `EffectAuthority` parameter.

```rust,compile_fail
pub struct ModelHypothesis {
    pub hypothesis_id: String,
    pub confidence: f64,
}

pub struct EffectAuthority {
    pub capability_lease: String,
}

pub struct EffectExecutor;

impl EffectExecutor {
    pub fn dispatch(&self, _auth: &EffectAuthority) {}
}

fn main() {
    let hypothesis = ModelHypothesis {
        hypothesis_id: "hypo-101".to_string(),
        confidence: 0.999,
    };

    let executor = EffectExecutor;

    // FORBIDDEN: Attempting to dispatch an effect using a cognition hypothesis fails type checking
    executor.dispatch(&hypothesis);
}
```
