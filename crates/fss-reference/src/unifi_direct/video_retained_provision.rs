#![forbid(unsafe_code)]
//! Retained generation admission for a managed video provisioning session.
//! This is not a restart supervisor or proof of custody independence.

use super::{video_provision as provision, video_session as session};

fn supplies_required(step: &provision::Step) -> bool {
    matches!(
        step,
        provision::Step::Managed(session::ManagedStep::SuppliesRequired(_))
    )
}

include!("retained_provision_shared.rs");
