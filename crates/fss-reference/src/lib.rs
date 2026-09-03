#![forbid(unsafe_code)]
//! Deterministic virtual acquisition and replay reference for FSS.
//!
//! Source truth is generated before transport truth. Delivery loss, duplication, reordering, and
//! corruption are explicit derived observations and can never rewrite retained source bytes. The
//! end-to-end helper publishes source/delivery object graphs root-last and then commits one
//! canonical authority delta through `fss-publication`.

mod alert;
mod bundle;
mod capture;
mod delivery;
mod error;
mod meaningful_delta;
mod model;
mod outcome;
mod policy;
mod situation;
mod situation_guard;
mod situation_sections;
mod source;

#[cfg(test)]
mod alert_tests;
#[cfg(test)]
mod bundle_tests;
#[cfg(test)]
mod meaningful_delta_tests;
#[cfg(test)]
mod model_tests;
#[cfg(test)]
mod outcome_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod situation_guard_tests;
#[cfg(test)]
mod situation_sections_tests;
#[cfg(test)]
mod situation_tests;
#[cfg(test)]
mod tests;

pub use alert::{
    ReferenceAlertPlan, ReferenceAlertProvider, ReferenceProviderBehavior,
    dispatch_reference_alert, prepare_reference_alert, reconcile_reference_alert,
};
pub use bundle::{ReplayBundle, ReplayBundleError, ReplayCursor};
pub use capture::{ReferenceCapture, ReferenceCaptureReceipt, run_reference_capture};
pub use delivery::{
    DeliveryContinuity, DeliveryDirective, DeliveryMutation, DeliveryPacket, DeliveryPlan,
    MAX_DELIVERY_DIRECTIVES,
};
pub use error::ReferenceError;
pub use meaningful_delta::classify_reference_meaningful_delta;
pub use model::{
    MockAbstentionReason, MockModelOutcome, MockModelResult, MockModelScript, MockModelSpec,
    MockSemanticLabel, execute_mock_model,
};
pub use outcome::{
    ReferenceAlertOutcome, ReferenceAlertOutcomeReceipt, publish_reference_alert_outcome,
};
pub use policy::{
    ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyAction,
    ReferencePolicyDecision, evaluate_unknown_presence, publish_reference_event,
};
pub use situation_guard::{
    ReferenceSituation, ReferenceSituationRequest, compile_reference_situation,
    compile_reference_situation_with_operation_receipt, seal_reference_handoff,
};
pub use situation_sections::{
    ReferenceProjectionSpec, ReferenceSituationPublication,
    compile_reference_situation_publication,
    compile_reference_situation_publication_with_operation_receipt,
    project_reference_situation, seal_reference_publication_handoff,
};
pub use source::{
    MAX_VIRTUAL_PACKET_BYTES, MAX_VIRTUAL_PACKETS, SourcePacket, VirtualCameraSpec, generate_source,
};

pub(crate) use delivery::DeliveryTrace;
pub(crate) use source::SourceTrace;
