#![forbid(unsafe_code)]
//! Explicit JPEG capture and cold reconstruction through existing native source owners.

#[path = "jpeg/operation.rs"]
pub(crate) mod operation;
#[path = "jpeg/plan.rs"]
pub(crate) mod plan;
#[path = "jpeg/runtime.rs"]
mod runtime;

pub(super) use plan::HELP;

pub(super) fn run(options: &plan::Options) -> Result<(), &'static str> {
    if options.approval.is_none() {
        return super::write_bounded((options.preview()? + "\n").as_bytes());
    }
    options.admit()?;
    runtime::execute(options)
}

#[cfg(test)]
#[path = "jpeg/tests.rs"]
mod tests;
