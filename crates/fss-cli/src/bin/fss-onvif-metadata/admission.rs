#![forbid(unsafe_code)]
//! Borrowed live owner admission for synchronous metadata custody checkpoints.

use fss_reference::ReplayAdmissionError;

use super::runtime;

pub(super) fn check(scope: &runtime::Scope<'_, '_>) -> Result<(), ReplayAdmissionError> {
    scope.output().map_err(|code| match code {
        "ERR-ONVIF-CANCELLED-001" => ReplayAdmissionError::Cancelled,
        "ERR-ONVIF-DEADLINE-001" => ReplayAdmissionError::Deadline,
        "ERR-ONVIF-BUDGET-001" => ReplayAdmissionError::Budget,
        _ => ReplayAdmissionError::Authority,
    })
}

pub(super) const fn code(error: ReplayAdmissionError) -> &'static str {
    match error {
        ReplayAdmissionError::Cancelled => "ERR-ONVIF-CANCELLED-001",
        ReplayAdmissionError::Deadline => "ERR-ONVIF-DEADLINE-001",
        ReplayAdmissionError::Authority => "ERR-ONVIF-AUTHORITY-001",
        ReplayAdmissionError::Budget => "ERR-ONVIF-BUDGET-001",
        ReplayAdmissionError::Reentrant => "ERR-ONVIF-STORAGE-REENTRANT-001",
        ReplayAdmissionError::Panicked => "ERR-ONVIF-STORAGE-PANIC-001",
    }
}
