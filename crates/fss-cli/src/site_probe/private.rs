#![forbid(unsafe_code)]
//! Protected source variants share the existing native file and network owners.

use std::cell::Cell;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::site::{SiteProbeReceipt, SourceKind};

use super::native::{self, Facts};
use super::plan::{ProbePlan, receipt_json};
use super::unifi::{private_file, request, runtime};
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string};

/// Exactly one protected source kind can own a native probe.
pub(super) enum PrivateProbe {
    Unifi(super::unifi::PrivateProbe),
    Onvif(super::onvif::PrivateProbe),
}

impl PrivateProbe {
    pub(super) fn kind(&self) -> SourceKind {
        match self {
            Self::Unifi(_) => SourceKind::UnifiProtect,
            Self::Onvif(_) => SourceKind::Onvif,
        }
    }

    pub(super) fn source(&self) -> &Path {
        match self {
            Self::Unifi(value) => &value.spec.source,
            Self::Onvif(value) => &value.spec.source,
        }
    }

    fn receipt_file(&self) -> &Path {
        match self {
            Self::Unifi(value) => &value.receipt_file,
            Self::Onvif(value) => &value.receipt_file,
        }
    }

    fn receipt_parent_identity(&self) -> ContentDigest {
        match self {
            Self::Unifi(value) => value.receipt_parent_identity,
            Self::Onvif(value) => value.receipt_parent_identity,
        }
    }

    fn output_error(&self) -> &'static str {
        match self {
            Self::Unifi(_) => super::unifi::OUTPUT,
            Self::Onvif(_) => super::onvif::OUTPUT,
        }
    }

    fn publication_selection(&self) -> PublicationSelection {
        match self {
            Self::Unifi(value) => PublicationSelection::Unifi {
                camera_ref: value.camera_ref,
                view: value.view,
                quality: value.spec.quality.as_str(),
            },
            Self::Onvif(value) => PublicationSelection::Onvif {
                onboarding_plan: value.onboarding_plan,
                profile_digest: value.profile_digest,
            },
        }
    }

    pub(super) fn verify(&self, input: &private_file::InputLease) -> Result<(), &'static str> {
        match self {
            Self::Unifi(value) => value.verify(input),
            Self::Onvif(value) => value.verify(input),
        }
    }

    pub(super) fn encode(&self, encoder: &mut CanonicalEncoder) -> Result<(), &'static str> {
        // Each existing owner retains its original canonical encoding. An added
        // enum discriminant would needlessly invalidate all prior UniFi approvals.
        match self {
            Self::Unifi(value) => value.encode(encoder),
            Self::Onvif(value) => value.encode(encoder),
        }
    }

    pub(super) fn preview(&self) -> (&'static str, String) {
        match self {
            Self::Unifi(value) => ("unifi", value.preview()),
            Self::Onvif(value) => ("onvif", value.preview()),
        }
    }
}

/// Published selection coordinates only; no protected source path, profile token or RTSP URI.
#[derive(Clone, Copy)]
enum PublicationSelection {
    Unifi {
        camera_ref: ContentDigest,
        view: &'static str,
        quality: &'static str,
    },
    Onvif {
        onboarding_plan: ContentDigest,
        profile_digest: ContentDigest,
    },
}

impl PublicationSelection {
    fn schema(self) -> &'static str {
        match self {
            Self::Unifi { .. } => "fss.site_unifi_probe_result.v1",
            Self::Onvif { .. } => "fss.site_onvif_probe_result.v1",
        }
    }

    fn contact_field(self) -> &'static str {
        match self {
            Self::Unifi { .. } => "console_contacted",
            Self::Onvif { .. } => "onvif_http_contacted",
        }
    }

    fn fields(self) -> Vec<(&'static str, String)> {
        match self {
            Self::Unifi {
                camera_ref,
                view,
                quality,
            } => vec![
                ("camera_ref", string(&camera_ref.to_text())),
                ("view", string(view)),
                ("quality", string(quality)),
            ],
            Self::Onvif {
                onboarding_plan,
                profile_digest,
            } => vec![
                ("onboarding_plan", string(&onboarding_plan.to_text())),
                ("profile_digest", string(&profile_digest.to_text())),
                (
                    "binding_basis",
                    string("operator-bound-historical-consistency"),
                ),
                ("onvif_http_origin_verified", "false".to_owned()),
            ],
        }
    }
}

/// Observed writer outcome, after the actual committing request has returned.
/// Late owner errors preserve a completed write; a failed write only reports possible existence.
#[derive(Clone, Copy)]
struct PublicationOutcome {
    receipt_saved: bool,
    receipt_file_may_exist: bool,
    error: Option<&'static str>,
    post_commit_error: Option<&'static str>,
    finalization_error: Option<&'static str>,
}

/// Private receipt bytes remain separate from the public result projection.
struct PublicationContext<'a> {
    approval: ContentDigest,
    site_id: &'a str,
    source_id: &'a str,
    selection: PublicationSelection,
    receipt_file: &'a Path,
    receipt: &'a SiteProbeReceipt,
    receipt_digest: ContentDigest,
    file_digest: ContentDigest,
}

/// The native request has finalized before publication begins. Only a fully
/// acknowledged observation is saved, and the durable outcome survives a late
/// writer cancellation or request-retirement failure.
pub(super) fn save_receipt(
    plan: &ProbePlan<'_>,
    receipt: &SiteProbeReceipt,
    facts: Facts,
) -> (String, ExitIdentity) {
    let Some(private) = &plan.private else {
        return native::refusal(
            "ERR-SITE-PROBE-OUTPUT-001",
            facts,
            ExitIdentity::RUNTIME_FAILURE,
        );
    };
    let output_error = private.output_error();
    // Reuse the session owner's complete accounting and close-evidence checks.
    // Its private rendering is never emitted for a protected source.
    if super::report::success(plan, receipt, facts).is_err()
        || receipt.presentation != plan.route.presentation()
        || receipt.control_root != plan.route.control_root()
    {
        return native::refusal(output_error, facts, ExitIdentity::RUNTIME_FAILURE);
    }
    let receipt_digest = match receipt.digest() {
        Ok(digest) => digest,
        Err(_) => return native::refusal(output_error, facts, ExitIdentity::RUNTIME_FAILURE),
    };
    let bytes = array(&[receipt_json(receipt)]).into_bytes();
    if bytes.is_empty() || bytes.len() > private_file::MAX_FILE_BYTES {
        return native::refusal(output_error, facts, ExitIdentity::RUNTIME_FAILURE);
    }
    let file_digest = ContentDigest::sha256(&bytes);
    let may_exist = Cell::new(false);
    let saved = runtime::run_committing(
        request(plan.approval, &plan.options.principal, true),
        |scope| {
            let input = private_file::InputLease::open(private.source(), &|| scope.input())?;
            private.verify(&input)?;
            let checkpoint = || {
                scope.output()?;
                input.revalidate(&|| scope.input())
            };
            let output = private_file::Output::prepare(private.receipt_file(), &checkpoint)?;
            if ContentDigest::sha256(&output.fingerprint()) != private.receipt_parent_identity() {
                return Err(output_error);
            }
            may_exist.set(true);
            output.write(&bytes, &checkpoint)?;
            Ok(runtime::Committed::new(()))
        },
    );
    let (receipt_saved, error, post_commit, finalization) = match saved {
        Ok(completed) => (
            true,
            None,
            completed.post_commit_error,
            completed.finalization_error,
        ),
        Err(code) => (false, Some(code), None, None),
    };
    render_publication(
        PublicationContext {
            approval: plan.approval,
            site_id: &plan.manifest.site_id,
            source_id: &plan.options.source,
            selection: private.publication_selection(),
            receipt_file: private.receipt_file(),
            receipt,
            receipt_digest,
            file_digest,
        },
        facts,
        PublicationOutcome {
            receipt_saved,
            receipt_file_may_exist: may_exist.get(),
            error,
            post_commit_error: post_commit,
            finalization_error: finalization,
        },
    )
}

/// Pure public projection of an already observed publication outcome. This function performs
/// no write, grants no authority and cannot establish that the supplied receipt was acquired.
fn render_publication(
    context: PublicationContext<'_>,
    facts: Facts,
    outcome: PublicationOutcome,
) -> (String, ExitIdentity) {
    let exit = if outcome.receipt_saved
        && outcome.post_commit_error.is_none()
        && outcome.finalization_error.is_none()
    {
        ExitIdentity::SUCCESS
    } else {
        ExitIdentity::RUNTIME_FAILURE
    };
    let optional = |value: Option<&str>| value.map_or_else(|| "null".to_owned(), string);
    let mut fields = vec![
        ("schema", string(context.selection.schema())),
        (
            "status",
            string(if exit == ExitIdentity::SUCCESS {
                "ok"
            } else {
                "refused"
            }),
        ),
        ("approval", string(&context.approval.to_text())),
        (
            "manifest_digest",
            string(&context.receipt.manifest_digest.to_text()),
        ),
        ("site_id", string(context.site_id)),
        ("source_id", string(context.source_id)),
    ];
    fields.extend(context.selection.fields());
    fields.extend([
        (
            "receipt_file",
            string(context.receipt_file.to_str().unwrap_or("")),
        ),
        (
            "receipt_digest",
            if outcome.receipt_saved {
                string(&context.receipt_digest.to_text())
            } else {
                "null".to_owned()
            },
        ),
        (
            "receipt_file_digest",
            if outcome.receipt_saved {
                string(&context.file_digest.to_text())
            } else {
                "null".to_owned()
            },
        ),
        ("receipt_saved", outcome.receipt_saved.to_string()),
        (
            "receipt_file_may_exist",
            outcome.receipt_file_may_exist.to_string(),
        ),
        (
            "connection_attempted",
            facts.connection_attempted.to_string(),
        ),
        (
            "credential_access_attempted",
            facts.credential_access_attempted.to_string(),
        ),
        (
            "teardown_acknowledged",
            facts.teardown_acknowledged.to_string(),
        ),
        (
            "remote_session_may_exist",
            facts.remote_session_may_exist.to_string(),
        ),
        ("source_retained", "false".to_owned()),
        (context.selection.contact_field(), "false".to_owned()),
        ("retry_automatically", "false".to_owned()),
        ("error_id", optional(outcome.error)),
        ("post_commit_error", optional(outcome.post_commit_error)),
        ("finalization_error", optional(outcome.finalization_error)),
        ("exit_id", string(exit.identifier)),
        ("exit_code", exit.code.to_string()),
    ]);
    (object(&fields), exit)
}

#[cfg(test)]
#[path = "private_tests.rs"]
mod tests;
