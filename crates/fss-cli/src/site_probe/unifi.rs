#![forbid(unsafe_code)]
//! Exact protected UniFi input and create-only private probe receipts.
//!
//! Capability-bearing routes never appear in a preview or on stdout. The existing
//! private-file owner checks every native file boundary, while the probe retains
//! the original manifest and uses the ordinary native RTSP observation owner.

use std::path::{Path, PathBuf};

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::site::probe_route::ProbeRoute;
use fss_reference::site::{ProbeCodec, SiteManifest, SourceKind};
use fss_reference::unifi::ProtectSource;

use super::native::{self, Facts};
use super::plan::{ProbeOutput, ProbePlan, SiteProbeOptions};
use crate::error::ExitIdentity;
use crate::json_output::{object, string};
use crate::site_cmd::InputAuthority;
use crate::site_unifi::{MAX_SITE_UNIFI_BINDINGS_BYTES, probe_source_spec};
use crate::unifi_plan::UnifiSourceSpec;

// Reuse the site's actual protected-file owner, including its lease type, rather
// than compiling another independent inclusion of the same file boundary.
pub(super) use crate::site_unifi::private_file;
#[allow(dead_code, reason = "Shared bounded request and durable output owner")]
#[path = "../bin/fss-onvif/runtime.rs"]
pub(super) mod runtime;

const INPUT: &str = "ERR-SITE-UNIFI-PROBE-INPUT-001";
pub(super) const OUTPUT: &str = "ERR-SITE-UNIFI-PROBE-OUTPUT-001";
const SELECTION: &str = "ERR-SITE-UNIFI-PROBE-SELECTION-001";
pub(super) const FILE_TIMEOUT_NS: u64 = 5_000_000_000;
pub(super) const FILE_WORKING_BYTES: u64 = 32 * 1024 * 1024;
pub(super) const FILE_OPERATIONS: u64 = 16_384;

/// Private selection coordinates are immutable after the bounded preview read.
/// Diagnostic formatting is deliberately absent: export paths and routes are private.
#[derive(Clone)]
pub(super) struct PrivateProbe {
    pub(super) spec: UnifiSourceSpec,
    pub(super) camera_ref: ContentDigest,
    pub(super) view: &'static str,
    file_identity: ContentDigest,
    bindings_digest: ContentDigest,
    pub(super) receipt_file: PathBuf,
    pub(super) receipt_parent_identity: ContentDigest,
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

pub(super) fn request(approval: ContentDigest, principal: &str, write: bool) -> runtime::Request {
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
