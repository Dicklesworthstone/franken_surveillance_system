#![forbid(unsafe_code)]
//! Bounded native probing of an exact protected historical ONVIF handoff.
//!
//! The management endpoint remains in the original site manifest. Its HTTP
//! origin is not authenticated by a private file: the operator independently
//! binds the RTSP peer, authority, profile and control subtree. A separate
//! approval permits one native RTSP observation and a private receipt, never
//! camera configuration, recording, HTTP discovery or automatic retry.

use std::path::{Path, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::site::probe_route::{OnvifCaptureRoute, ProbeRoute};
use fss_reference::site::{ProbeCodec, SiteManifest, SourceKind};

use super::native::{self, Facts};
use super::plan::{ProbeOutput, ProbePlan, SiteProbeOptions};
use super::unifi::{
    FILE_OPERATIONS, FILE_TIMEOUT_NS, FILE_WORKING_BYTES, private_file, request, runtime,
};
use crate::error::ExitIdentity;
use crate::json_output::{object, string};
use crate::onvif_plan::{OnvifSourceSpec, ProtectedOnvifInput};
use crate::site_cmd::InputAuthority;
use crate::site_onvif::{MAX_SITE_ONVIF_BINDINGS_BYTES, probe_binding};

const INPUT: &str = "ERR-SITE-ONVIF-PROBE-INPUT-001";
pub(super) const OUTPUT: &str = "ERR-SITE-ONVIF-PROBE-OUTPUT-001";
const SELECTION: &str = "ERR-SITE-ONVIF-PROBE-SELECTION-001";

/// Immutable protected input and output identities; no diagnostic formatting.
pub(super) struct PrivateProbe {
    pub(super) spec: OnvifSourceSpec,
    pub(super) onboarding_plan: ContentDigest,
    pub(super) profile_digest: ContentDigest,
    file_identity: ContentDigest,
    bindings_digest: ContentDigest,
    pub(super) receipt_file: PathBuf,
    pub(super) receipt_parent_identity: ContentDigest,
}

impl PrivateProbe {
    pub(super) fn encode(&self, encoder: &mut CanonicalEncoder) -> Result<(), &'static str> {
        encoder.text("fss.site_onvif_probe_private.v1");
        encoder.text(self.spec.source.to_str().ok_or(INPUT)?);
        encoder.digest(self.spec.expected);
        encoder.digest(self.file_identity);
        encoder.digest(self.bindings_digest);
        encoder.digest(self.onboarding_plan);
        encoder.digest(self.profile_digest);
        encoder.text(self.receipt_file.to_str().ok_or(OUTPUT)?);
        encoder.digest(self.receipt_parent_identity);
        encoder.text("protected-create-new:mode-0600:sync-and-readback:retain-committed-outcome");
        encoder.u64(FILE_TIMEOUT_NS);
        encoder.u64(FILE_WORKING_BYTES);
        encoder.u64(FILE_OPERATIONS);
        encoder.u64(private_file::MAX_FILE_BYTES as u64);
        Ok(())
    }

    pub(super) fn preview(&self) -> String {
        object(&[
            ("bindings_digest", string(&self.bindings_digest.to_text())),
            ("source_digest", string(&self.spec.expected.to_text())),
            ("file_identity", string(&self.file_identity.to_text())),
            ("onboarding_plan", string(&self.onboarding_plan.to_text())),
            ("profile_digest", string(&self.profile_digest.to_text())),
            (
                "binding_basis",
                string("operator-bound-historical-consistency"),
            ),
            ("onvif_http_origin_verified", "false".to_owned()),
            ("onvif_http_contacted", "false".to_owned()),
            ("route_projection", string("sha256_digests")),
            ("private_handoff_read", "true".to_owned()),
            (
                "receipt_file",
                string(self.receipt_file.to_str().unwrap_or("")),
            ),
            ("receipt_file_mode", string("0600")),
            (
                "receipt_parent_identity",
                string(&self.receipt_parent_identity.to_text()),
            ),
            ("receipt_file_create_only", "true".to_owned()),
            ("file_timeout_ns", FILE_TIMEOUT_NS.to_string()),
            ("file_working_bytes", FILE_WORKING_BYTES.to_string()),
            ("file_operations", FILE_OPERATIONS.to_string()),
            (
                "max_receipt_bytes",
                private_file::MAX_FILE_BYTES.to_string(),
            ),
        ])
    }

    pub(super) fn verify(&self, input: &private_file::InputLease) -> Result<(), &'static str> {
        if ContentDigest::sha256(input.bytes()) != self.spec.expected
            || ContentDigest::sha256(&input.fingerprint()) != self.file_identity
        {
            return Err(INPUT);
        }
        Ok(())
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

/// Reject inadmissible selections and output modes before any input is opened.
fn preflight<'a>(
    manifest: &SiteManifest,
    options: &'a SiteProbeOptions,
) -> Result<(&'a Path, PathBuf), &'static str> {
    manifest.validate().map_err(|_| SELECTION)?;
    options.validate()?;
    if options.codec == ProbeCodec::Jpeg || options.output != ProbeOutput::Receipts {
        return Err(SELECTION);
    }
    let source_index = manifest
        .sources
        .iter()
        .position(|source| source.source_id == options.source)
        .ok_or(SELECTION)?;
    let source = &manifest.sources[source_index];
    if source.kind != SourceKind::Onvif || !source.owner_authorized || !source.plaintext {
        return Err(SELECTION);
    }
    let bindings_file = options.onvif_bindings.as_deref().ok_or(SELECTION)?;
    let receipt_file = private_file::absolute_path(
        options
            .receipt_file
            .as_deref()
            .and_then(Path::to_str)
            .ok_or(SELECTION)?,
    )?;
    Ok((bindings_file, receipt_file))
}

/// The private file owners additionally require canonical handoff/output paths
/// and an absent output, so a relative binding alias cannot be overwritten.
fn check_paths(
    manifest: &SiteManifest,
    binding: &crate::site_onvif::Binding,
    bindings_file: &Path,
    receipt_file: &Path,
) -> Result<(), &'static str> {
    if overlaps(receipt_file, &binding.spec.source)
        || overlaps(receipt_file, bindings_file)
        || manifest
            .sources
            .iter()
            .filter_map(|item| item.authentication.as_ref())
            .any(|auth| {
                overlaps(&binding.spec.source, Path::new(&auth.credential_file))
                    || overlaps(receipt_file, Path::new(&auth.credential_file))
            })
    {
        return Err(INPUT);
    }
    Ok(())
}

fn prepare<'a>(
    manifest: &'a SiteManifest,
    options: &'a SiteProbeOptions,
) -> Result<ProbePlan<'a>, &'static str> {
    let (bindings_file, receipt_file) = preflight(manifest, options)?;
    let bytes = InputAuthority::for_inputs(&[(bindings_file, MAX_SITE_ONVIF_BINDINGS_BYTES)])
        .read(bindings_file)
        .map_err(|_| INPUT)?;
    let binding = probe_binding(manifest, &bytes, &options.source).map_err(|_| INPUT)?;
    check_paths(manifest, &binding, bindings_file, &receipt_file)?;
    let bindings_digest = ContentDigest::sha256(&bytes);
    runtime::run(
        request(bindings_digest, &options.principal, false),
        |scope| {
            prepare_owned(
                manifest,
                options,
                binding,
                bindings_digest,
                receipt_file,
                &|| scope.input(),
            )
        },
    )
}

/// The protected-input owner is independently exercisable with explicit bounded
/// file authority. Native execution still requires the exact resulting approval.
fn prepare_owned<'a>(
    manifest: &'a SiteManifest,
    options: &'a SiteProbeOptions,
    binding: crate::site_onvif::Binding,
    bindings_digest: ContentDigest,
    receipt_file: PathBuf,
    checkpoint: &impl Fn() -> Result<(), &'static str>,
) -> Result<ProbePlan<'a>, &'static str> {
    let input = private_file::InputLease::open(&binding.spec.source, checkpoint)?;
    let fingerprint = input.fingerprint();
    let selected = binding.spec.prepare(
        ProtectedOnvifInput {
            bytes: input.bytes(),
            fingerprint: &fingerprint,
        },
        &[],
    )?;
    if selected.onboarding_plan() != binding.onboarding_plan
        || selected.profile_digest() != binding.profile_digest
        || selected.codec() != options.codec.as_str()
    {
        return Err(SELECTION);
    }
    let route = selected.with_route(|peer, authority, presentation| {
        if peer != binding.peer || authority != binding.authority {
            return Err(SELECTION);
        }
        let historical = OnvifCaptureRoute::new(
            manifest,
            binding.source_index,
            binding.spec.expected,
            peer,
            authority,
            presentation,
            &binding.control_root,
        )
        .map_err(|_| SELECTION)?;
        ProbeRoute::from_onvif(
            manifest,
            binding.source_index,
            &historical,
            binding.onboarding_plan,
            binding.profile_digest,
            options.codec,
        )
        .map_err(|_| SELECTION)
    })??;
    let destination = private_file::Output::prepare(&receipt_file, checkpoint)?;
    let private = PrivateProbe {
        file_identity: selected.file_identity(),
        bindings_digest,
        onboarding_plan: binding.onboarding_plan,
        profile_digest: binding.profile_digest,
        spec: binding.spec,
        receipt_file,
        receipt_parent_identity: ContentDigest::sha256(&destination.fingerprint()),
    };
    let plan = ProbePlan::with_onvif(manifest, options, private, route)?;
    input.revalidate(checkpoint)?;
    Ok(plan)
}

pub(super) fn execute(
    manifest: &SiteManifest,
    options: &SiteProbeOptions,
) -> (String, ExitIdentity) {
    let result = prepare(manifest, options).and_then(|plan| match plan.check_approval()? {
        false => plan
            .preview()
            .map(|preview| (preview, ExitIdentity::SUCCESS)),
        true => Ok(native::execute(&plan)),
    });
    result.unwrap_or_else(|code| {
        native::refusal(code, Facts::default(), ExitIdentity::MALFORMED_VALUE)
    })
}

#[cfg(all(test, target_os = "linux"))]
#[path = "onvif_tests.rs"]
mod tests;
