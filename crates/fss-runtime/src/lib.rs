#![forbid(unsafe_code)]
//! The FSS explicit-authority runtime core (FSS-021 slice 1, bead fss-x4a.8.1;
//! import record IMP-AS-CANCEL-001, admission gate INT-AS-001).
//!
//! Composition, not reinvention: the Asupersync `Cx` is the cancellation and
//! capability substrate underneath, and `fss-core`'s region hierarchy
//! (`RegionTree`/`ContextAuthority`) owns structural scoping above it. What
//! this crate adds is the layer FSS's charter requires between the two:
//!
//! * **Explicit authority, never ambient.** Every `AuthorityCx` is
//!   constructed explicitly and passed by value; there is deliberately no
//!   `Cx::current`-style ambient lookup here. The asupersync ambient API
//!   exists but is not surfaced by this crate.
//! * **Typed cancellation, four-valued.** The cancellation state machine is
//!   request → drain → finalize with outcomes `Completed | Cancelled |
//!   Failed | Indeterminate`; non-cooperative work ends `Indeterminate`,
//!   never silently dropped-as-cancelled or timeout-as-success (the import
//!   record's failure boundary, verbatim).
//! * **Budgets are spent, obligations are tracked.** A budget only ever
//!   decrements to a typed exhaustion state; the obligation leak oracle
//!   names every non-terminal obligation at region finalize.
//!
//! Reference behavior is deterministic: no clock of its own, no RNG, no
//! ambient authority, no leaked state on any path. Laboratory schedule
//! control (virtual time) composes through asupersync's lab modules and is
//! not re-implemented here.

pub mod authority;
pub mod budget;
pub mod cancellation;
pub mod obligation;
