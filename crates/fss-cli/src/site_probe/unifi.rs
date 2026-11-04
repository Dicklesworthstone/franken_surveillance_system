#![forbid(unsafe_code)]
//! Exact protected UniFi input and create-only private probe receipts.
//!
//! Capability-bearing routes never appear in a preview or on stdout. The existing
//! private-file owner checks every native file boundary, while the probe retains
//! the original manifest and uses the ordinary native RTSP observation owner.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::site::probe_route::ProbeRoute;
use fss_reference::site::{ProbeCodec, SiteManifest, SiteProbeReceipt, SourceKind};
use fss_reference::unifi::ProtectSource;

use super::native::{self, Facts};
use super::plan::{ProbeOutput, ProbePlan, SiteProbeOptions, receipt_json};
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string};
use crate::site_cmd::InputAuthority;
use crate::site_unifi::{MAX_SITE_UNIFI_BINDINGS_BYTES, probe_source_spec};
use crate::unifi_plan::UnifiSourceSpec;

// Reuse the site's actual protected-file owner, including its lease type, rather
// than compiling another independent inclusion of the same file boundary.
pub(super) use crate::site_unifi::private_file;
#[allow(dead_code, reason = "Shared bounded request and durable output owner")]
#[path = "../bin/fss-onvif/runtime.rs"]
mod runtime;

const INPUT: &str = "ERR-SITE-UNIFI-PROBE-INPUT-001";
const OUTPUT: &str = "ERR-SITE-UNIFI-PROBE-OUTPUT-001";
const SELECTION: &str = "ERR-SITE-UNIFI-PROBE-SELECTION-001";
const FILE_TIMEOUT_NS: u64 = 5_000_000_000;
const FILE_WORKING_BYTES: u64 = 32 * 1024 * 1024;
const FILE_OPERATIONS: u64 = 16_384;

/// Private selection coordinates are immutable after the bounded preview read.
/// Diagnostic formatting is deliberately absent: export paths and routes are private.
#[derive(Clone)]
pub(super) struct PrivateProbe {
    pub(super) spec: UnifiSourceSpec,
    pub(super) camera_ref: ContentDigest,
    pub(super) view: &'static str,
    file_identity: ContentDigest,
    bindings_digest: ContentDigest,
    receipt_file: PathBuf,
    receipt_parent_identity: ContentDigest,
}

impl PrivateProbe {
    pub(super) fn encode(&self, encoder: &mut CanonicalEncoder) -> Result<(), &'static str> {
        encoder.text("fss.site_unifi_probe_private.v1");
        encoder.text(self.spec.source.to_str().ok_or(INPUT)?);
        encoder.digest(self.spec.expected);
        encoder.digest(self.file_identity);
        encoder.digest(self.bindings_digest);
        encoder.digest(self.camera_ref);
        encoder.text(self.view);
        encoder.text(self.spec.quality.as_str());
        encoder.text(self.spec.transport_name());
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
            ("camera_ref", string(&self.camera_ref.to_text())),
            ("view", string(self.view)),
            ("quality", string(self.spec.quality.as_str())),
            ("stream_transport", string(self.spec.transport_name())),
            ("route_projection", string("sha256_digests")),
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
            ("console_contacted", "false".to_owned()),
            ("private_export_read", "true".to_owned()),
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

fn request(approval: ContentDigest, principal: &str, write: bool) -> runtime::Request {
    runtime::Request {
        approval,
        principal: principal.to_owned(),
        timeout_ns: FILE_TIMEOUT_NS,
        bytes: FILE_WORKING_BYTES,
        network_bytes: 0,
        storage_operations: FILE_OPERATIONS,
        network: false,
        write,
        secrets: false,
    }
}

fn prepare<'a>(
    manifest: &'a SiteManifest,
    options: &'a SiteProbeOptions,
) -> Result<ProbePlan<'a>, &'static str> {
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
    if source.kind != SourceKind::UnifiProtect || !source.owner_authorized || !source.plaintext {
        return Err(SELECTION);
    }
    let bindings_file = options.unifi_bindings.as_deref().ok_or(SELECTION)?;
    let receipt_file = private_file::absolute_path(
        options
            .receipt_file
            .as_deref()
            .and_then(Path::to_str)
            .ok_or(SELECTION)?,
    )?;
    let bytes = InputAuthority::for_inputs(&[(bindings_file, MAX_SITE_UNIFI_BINDINGS_BYTES)])
        .read(bindings_file)
        .map_err(|_| INPUT)?;
    let spec = probe_source_spec(manifest, &bytes, &options.source).map_err(|_| INPUT)?;
    if overlaps(&receipt_file, &spec.source)
        || overlaps(&receipt_file, bindings_file)
        || manifest
            .sources
            .iter()
            .filter_map(|item| item.authentication.as_ref())
            .any(|auth| {
                overlaps(&spec.source, Path::new(&auth.credential_file))
                    || overlaps(&receipt_file, Path::new(&auth.credential_file))
            })
    {
        return Err(INPUT);
    }
    let bindings_digest = ContentDigest::sha256(&bytes);
    runtime::run(
        request(bindings_digest, &options.principal, false),
        |scope| {
            let input = private_file::InputLease::open(&spec.source, &|| scope.input())?;
            if ContentDigest::sha256(input.bytes()) != spec.expected {
                return Err(INPUT);
            }
            let export = ProtectSource::parse(input.bytes()).map_err(|_| SELECTION)?;
            let selected = export
                .select(spec.quality, spec.transport)
                .map_err(|_| SELECTION)?;
            let route =
                ProbeRoute::from_unifi(manifest, source_index, &selected).map_err(|_| SELECTION)?;
            // Preflight only: preview and stale approval never create a receipt file.
            let destination = private_file::Output::prepare(&receipt_file, &|| scope.input())?;
            let private = PrivateProbe {
                camera_ref: ContentDigest::sha256(selected.camera().id().as_bytes()),
                view: selected.view().as_str(),
                file_identity: ContentDigest::sha256(&input.fingerprint()),
                bindings_digest,
                spec,
                receipt_file,
                receipt_parent_identity: ContentDigest::sha256(&destination.fingerprint()),
            };
            let plan = ProbePlan::with_unifi(manifest, options, private, route)?;
            input.revalidate(&|| scope.input())?;
            Ok(plan)
        },
    )
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

/// The native request has finalized before publication begins. Only a fully
/// acknowledged observation is saved, and the durable outcome survives a late
/// writer cancellation or request-retirement failure.
pub(super) fn save_receipt(
    plan: &ProbePlan<'_>,
    receipt: &SiteProbeReceipt,
    facts: Facts,
) -> (String, ExitIdentity) {
    let Some(private) = &plan.private else {
        return native::refusal(OUTPUT, facts, ExitIdentity::RUNTIME_FAILURE);
    };
    // Reuse the session owner's complete accounting and close-evidence checks.
    // Its private rendering is never emitted for a UniFi source.
    if super::report::success(plan, receipt, facts).is_err()
        || receipt.presentation != plan.route.presentation()
        || receipt.control_root != plan.route.control_root()
    {
        return native::refusal(OUTPUT, facts, ExitIdentity::RUNTIME_FAILURE);
    }
    let receipt_digest = match receipt.digest() {
        Ok(digest) => digest,
        Err(_) => return native::refusal(OUTPUT, facts, ExitIdentity::RUNTIME_FAILURE),
    };
    let bytes = array(&[receipt_json(receipt)]).into_bytes();
    if bytes.is_empty() || bytes.len() > private_file::MAX_FILE_BYTES {
        return native::refusal(OUTPUT, facts, ExitIdentity::RUNTIME_FAILURE);
    }
    let file_digest = ContentDigest::sha256(&bytes);
    let may_exist = Cell::new(false);
    let saved = runtime::run_committing(
        request(plan.approval, &plan.options.principal, true),
        |scope| {
            let input = private_file::InputLease::open(&private.spec.source, &|| scope.input())?;
            private.verify(&input)?;
            let checkpoint = || {
                scope.output()?;
                input.revalidate(&|| scope.input())
            };
            let output = private_file::Output::prepare(&private.receipt_file, &checkpoint)?;
            if ContentDigest::sha256(&output.fingerprint()) != private.receipt_parent_identity {
                return Err(OUTPUT);
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
    let exit = if receipt_saved && post_commit.is_none() && finalization.is_none() {
        ExitIdentity::SUCCESS
    } else {
        ExitIdentity::RUNTIME_FAILURE
    };
    let optional = |value: Option<&str>| value.map_or_else(|| "null".to_owned(), string);
    let output = object(&[
        ("schema", string("fss.site_unifi_probe_result.v1")),
        (
            "status",
            string(if exit == ExitIdentity::SUCCESS {
                "ok"
            } else {
                "refused"
            }),
        ),
        ("approval", string(&plan.approval.to_text())),
        (
            "manifest_digest",
            string(&receipt.manifest_digest.to_text()),
        ),
        ("site_id", string(&plan.manifest.site_id)),
        ("source_id", string(&plan.options.source)),
        ("camera_ref", string(&private.camera_ref.to_text())),
        ("view", string(private.view)),
        ("quality", string(private.spec.quality.as_str())),
        (
            "receipt_file",
            string(private.receipt_file.to_str().unwrap_or("")),
        ),
        (
            "receipt_digest",
            if receipt_saved {
                string(&receipt_digest.to_text())
            } else {
                "null".to_owned()
            },
        ),
        (
            "receipt_file_digest",
            if receipt_saved {
                string(&file_digest.to_text())
            } else {
                "null".to_owned()
            },
        ),
        ("receipt_saved", receipt_saved.to_string()),
        ("receipt_file_may_exist", may_exist.get().to_string()),
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
        ("console_contacted", "false".to_owned()),
        ("retry_automatically", "false".to_owned()),
        ("error_id", optional(error)),
        ("post_commit_error", optional(post_commit)),
        ("finalization_error", optional(finalization)),
        ("exit_id", string(exit.identifier)),
        ("exit_code", exit.code.to_string()),
    ]);
    (output, exit)
}
