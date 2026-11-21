#![forbid(unsafe_code)]
//! Borrowed cancellation of an already owned transport request.

/// A probe of the request owner's existing cancellation state.
///
/// This grants no read, session, clock, or effect authority and creates no independent
/// cancellation tree. The owner keeps the probe alive until native execution has joined.
/// A probe must remain cancelled after it first returns `true`. Native readers consult it
/// at their existing bounded checkpoints; a started effect retains its own durable owner.
#[derive(Clone, Copy)]
pub struct RequestControl<'a> {
    cancelled: &'a (dyn Fn() -> bool + Sync),
}

impl<'a> RequestControl<'a> {
    /// Borrow the cancellation probe of the transport's existing request owner.
    #[must_use]
    pub const fn new(cancelled: &'a (dyn Fn() -> bool + Sync)) -> Self {
        Self { cancelled }
    }

    /// Preserve the original synchronous CLI behavior, without a cancellation source.
    #[must_use]
    pub fn uncancelled() -> Self {
        Self::new(&never_cancelled)
    }

    /// Observe the owner's cancellation without changing any native effect or receipt.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        (self.cancelled)()
    }
}

fn never_cancelled() -> bool {
    false
}

#[cfg(test)]
mod tests;
