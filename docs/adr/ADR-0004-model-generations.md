# ADR-0004 — Models are immutable qualified generations, not mutable names

**Status:** Accepted for architecture bootstrap

## Decision

A model generation binds exact weights/files, source revision, license, runtime, accelerator,
preprocessing, output schema, resource envelope, and qualification bundle. Activation is atomic and
rollback retains the prior generation.

## Rationale

Model names and Hugging Face repository heads drift. Scores cannot be reproduced or compared
without exact byte and runtime identity, and license restrictions may differ across variants.

## Consequences

Acquisition is explicit, build scripts remain offline, every result carries generation identity,
and research-only/noncommercial models cannot silently enter default release profiles.
