#![forbid(unsafe_code)]
//! Exact changes to the set of masked image pixels when declaring a policy.

use fss_core::RedactedRegion;

use super::PrivacyMaskPolicy;

/// Counts on the previous and proposed pixel grids, including rectangle overlap only once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskImpact {
    /// Resolution of the current retained mask, absent on a first declaration.
    pub previous_resolution: Option<[u32; 2]>,
    /// Number of masked pixels under the current policy, or zero on a first declaration.
    pub previous_masked: u32,
    /// Number of masked pixels under the proposed policy.
    pub proposed_masked: u32,
    /// Pixels masked by both policies. Absent if the resolution changed, since the
    /// two pixel grids have no declared correspondence.
    pub still_masked: Option<u32>,
}

impl MaskImpact {
    pub(super) fn between(
        previous: Option<&PrivacyMaskPolicy>,
        proposed: &PrivacyMaskPolicy,
    ) -> Self {
        let mut regions: Vec<_> = proposed.regions().iter().collect();
        let proposed_masked = union_area(&regions);
        let split = regions.len();
        if let Some(policy) = previous {
            regions.extend(policy.regions());
        }
        let previous_masked = union_area(&regions[split..]);
        let previous_resolution = previous.map(PrivacyMaskPolicy::resolution);
        let still_masked = match previous_resolution {
            None => Some(0),
            Some(grid) if grid == proposed.resolution() => {
                Some(previous_masked + proposed_masked - union_area(&regions))
            }
            Some(_) => None,
        };
        Self {
            previous_resolution,
            previous_masked,
            proposed_masked,
            still_masked,
        }
    }

    /// Number of previously visible pixels the proposal would mask on the same grid.
    #[must_use]
    pub fn newly_masked(self) -> Option<u32> {
        self.still_masked.map(|both| self.proposed_masked - both)
    }

    /// Number of previously masked pixels the proposal would expose on the same grid.
    #[must_use]
    pub fn newly_visible(self) -> Option<u32> {
        self.still_masked.map(|both| self.previous_masked - both)
    }
}

// Between neighboring x edges the active rectangles are constant. Merge their y
// intervals to count the union once per strip. Declarations cap this at 64 rectangles
// across the two policies, each contained in a grid of at most 4096 x 4096 pixels.
fn union_area(regions: &[&RedactedRegion]) -> u32 {
    let mut edges = Vec::with_capacity(2 * regions.len());
    for r in regions {
        edges.extend([r.x(), r.x() + r.width()]);
    }
    edges.sort_unstable();
    edges.dedup();
    let mut intervals = Vec::with_capacity(regions.len());
    let mut area = 0;
    for strip in edges.windows(2) {
        intervals.clear();
        for r in regions {
            if r.x() <= strip[0] && strip[0] < r.x() + r.width() {
                intervals.push((r.y(), r.y() + r.height()));
            }
        }
        intervals.sort_unstable();
        let mut end = 0;
        let mut height = 0;
        for &(top, bottom) in &intervals {
            height += bottom.saturating_sub(top.max(end));
            end = end.max(bottom);
        }
        area += (strip[1] - strip[0]) * height;
    }
    area
}
