#![forbid(unsafe_code)]
//! Owned, bounded traversal of independently decodable retained frames.
//!
//! The runtime supplies the authenticated loader, selection/export state and finalizer.
//! State is moved into this traversal and dropped on any load or consumer refusal. Only
//! successful exhaustion can reach the finalizer; callers cannot certify an earlier prefix.
//! A single borrowed budget reaches every load, and only one loaded frame is held at a time.

use std::io;

pub(crate) const MAX_FRAMES: usize = 1024;

pub(crate) struct FrameRange {
    first: usize,
    count: usize,
}

impl FrameRange {
    pub(crate) fn new(first: usize, count: usize, available: usize) -> io::Result<Self> {
        if !(1..=MAX_FRAMES).contains(&count)
            || first.checked_add(count).is_none_or(|end| end > available)
        {
            return Err(io::Error::other(
                "requested JPEG range exceeds retained source or frame bounds",
            ));
        }
        Ok(Self { first, count })
    }

    pub(crate) fn run<B, S, F, T, E>(
        self,
        budget: &mut B,
        mut state: S,
        mut load: impl FnMut(usize, &mut B) -> Result<F, E>,
        mut consume: impl FnMut(&mut S, usize, usize, F) -> Result<(), E>,
        finish: impl FnOnce(S, usize) -> Result<T, E>,
    ) -> Result<T, E> {
        for ordinal in 0..self.count {
            // The complete range was checked before any source load or output state is used.
            let segment = self.first + ordinal;
            let frame = load(segment, budget)?;
            consume(&mut state, ordinal, segment, frame)?;
        }
        finish(state, self.count)
    }
}
