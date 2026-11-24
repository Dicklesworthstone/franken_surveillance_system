#![forbid(unsafe_code)]
//! Conservative temporal interval and directed transit-corridor matching.
//!
//! Enforces strict worst-case interval admission: matching abstains cleanly with
//! [`MatchDisposition::ClockUncertaintyAbstained`] whenever either camera's capture-time
//! uncertainty exceeds the operational cap, and never guesses across uncertain boundaries.

use super::clock::BoundedCaptureInterval;

/// Conservative temporal match classification between two bounded capture intervals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchDisposition {
    /// Every pair of instants in `a` and `b` falls within `max_separation_ns`.
    Compatible {
        /// Smallest attainable absolute time separation (ns).
        min_separation_ns: u128,
        /// Largest attainable absolute time separation (ns).
        max_separation_ns: u128,
    },
    /// Every pair `(t_from, t_to)` satisfies `min_transit_ns <= t_to - t_from <= max_transit_ns`.
    TransitCompatible {
        /// Smallest attainable signed transit time `t_to - t_from` (ns).
        min_elapsed_ns: i128,
        /// Largest attainable signed transit time `t_to - t_from` (ns).
        max_elapsed_ns: i128,
    },
    /// Clock uncertainty exceeded `max_allowed_ns`; matching honestly abstained.
    ClockUncertaintyAbstained {
        /// Worst-case clock uncertainty width observed (ns).
        uncertainty_ns: u128,
        /// Configured ceiling above which temporal matching abstains (ns).
        max_allowed_ns: u64,
    },
    /// Every attainable instant pair violates the overlap or transit window.
    TemporalMismatch {
        /// Smallest attainable separation/elapsed magnitude (ns).
        min_separation_ns: u128,
        /// Largest attainable separation/elapsed magnitude (ns).
        max_separation_ns: u128,
    },
    /// Some instants satisfy the gate and others violate it due to interval width; never guessed.
    TemporalBoundaryUncertain {
        /// Smallest attainable separation/elapsed magnitude (ns).
        min_separation_ns: u128,
        /// Largest attainable separation/elapsed magnitude (ns).
        max_separation_ns: u128,
    },
}

impl MatchDisposition {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatible { .. } => "compatible",
            Self::TransitCompatible { .. } => "transit_compatible",
            Self::ClockUncertaintyAbstained { .. } => "clock_uncertainty_abstained",
            Self::TemporalMismatch { .. } => "temporal_mismatch",
            Self::TemporalBoundaryUncertain { .. } => "temporal_boundary_uncertain",
        }
    }

    /// Returns `true` iff every attainable instant pair satisfies the temporal gate.
    #[must_use]
    pub const fn is_admissible(self) -> bool {
        matches!(
            self,
            Self::Compatible { .. } | Self::TransitCompatible { .. }
        )
    }
}

/// Evaluates conservative worst-case simultaneous interval compatibility.
///
/// Abstains cleanly with [`MatchDisposition::ClockUncertaintyAbstained`] whenever either
/// interval's uncertainty exceeds `max_clock_uncertainty_ns`. Admits only when the worst-case
/// separation over all pairs `(t_a, t_b)` lies within `max_separation_ns`.
#[must_use]
pub fn intervals_compatible(
    a: BoundedCaptureInterval,
    b: BoundedCaptureInterval,
    max_separation_ns: u64,
    max_clock_uncertainty_ns: u64,
) -> MatchDisposition {
    let worst_unc = a
        .effective_uncertainty_ns()
        .max(b.effective_uncertainty_ns());
    if worst_unc > u128::from(max_clock_uncertainty_ns) {
        return MatchDisposition::ClockUncertaintyAbstained {
            uncertainty_ns: worst_unc,
            max_allowed_ns: max_clock_uncertainty_ns,
        };
    }
    let min_sep = if a.latest_ns < b.earliest_ns {
        b.earliest_ns.abs_diff(a.latest_ns)
    } else if b.latest_ns < a.earliest_ns {
        a.earliest_ns.abs_diff(b.latest_ns)
    } else {
        0
    };
    let max_sep = a
        .latest_ns
        .abs_diff(b.earliest_ns)
        .max(b.latest_ns.abs_diff(a.earliest_ns));
    let gate = u128::from(max_separation_ns);
    if max_sep <= gate {
        MatchDisposition::Compatible {
            min_separation_ns: min_sep,
            max_separation_ns: max_sep,
        }
    } else if min_sep > gate {
        MatchDisposition::TemporalMismatch {
            min_separation_ns: min_sep,
            max_separation_ns: max_sep,
        }
    } else {
        MatchDisposition::TemporalBoundaryUncertain {
            min_separation_ns: min_sep,
            max_separation_ns: max_sep,
        }
    }
}

/// Evaluates conservative directed transit-corridor compatibility from `from` to `to`.
///
/// Abstains cleanly with [`MatchDisposition::ClockUncertaintyAbstained`] whenever either
/// interval's uncertainty exceeds `max_clock_uncertainty_ns`. Admits only when every attainable
/// pair `(t_from, t_to)` satisfies `min_transit_ns <= t_to - t_from <= max_transit_ns`.
#[must_use]
pub fn transit_compatible(
    from: BoundedCaptureInterval,
    to: BoundedCaptureInterval,
    min_transit_ns: u64,
    max_transit_ns: u64,
    max_clock_uncertainty_ns: u64,
) -> MatchDisposition {
    let worst_unc = from
        .effective_uncertainty_ns()
        .max(to.effective_uncertainty_ns());
    if worst_unc > u128::from(max_clock_uncertainty_ns) {
        return MatchDisposition::ClockUncertaintyAbstained {
            uncertainty_ns: worst_unc,
            max_allowed_ns: max_clock_uncertainty_ns,
        };
    }
    let (Some(min_elapsed), Some(max_elapsed)) = (
        to.earliest_ns.checked_sub(from.latest_ns),
        to.latest_ns.checked_sub(from.earliest_ns),
    ) else {
        return MatchDisposition::ClockUncertaintyAbstained {
            uncertainty_ns: u128::MAX,
            max_allowed_ns: max_clock_uncertainty_ns,
        };
    };
    let (lo, hi) = (i128::from(min_transit_ns), i128::from(max_transit_ns));
    if min_elapsed >= lo && max_elapsed <= hi {
        MatchDisposition::TransitCompatible {
            min_elapsed_ns: min_elapsed,
            max_elapsed_ns: max_elapsed,
        }
    } else if max_elapsed < lo || min_elapsed > hi {
        MatchDisposition::TemporalMismatch {
            min_separation_ns: min_elapsed.unsigned_abs(),
            max_separation_ns: max_elapsed.unsigned_abs(),
        }
    } else {
        MatchDisposition::TemporalBoundaryUncertain {
            min_separation_ns: min_elapsed.unsigned_abs(),
            max_separation_ns: max_elapsed.unsigned_abs(),
        }
    }
}
