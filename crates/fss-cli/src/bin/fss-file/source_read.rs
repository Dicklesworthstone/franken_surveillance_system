#![forbid(unsafe_code)]
//! Immutable source inspection, movie-time selection and extraction, without publisher ownership.

use std::fs;
use std::io::Write;
use std::time::{Duration, Instant};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_reference::ReplayCx;
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::{AcquisitionRetention, RetainedFileImport};
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedSource,
};

use super::{Action, Options, ParseResult, RunResult, Values, malformed, replay_origin, write_new};

const DEADLINE: Duration = Duration::from_secs(60);
const DEFAULT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BYTES: u64 = 4 * DEFAULT_BYTES;
const DEFAULT_READS: u64 = 1_000_000;
const MAX_READS: u64 = 4_000_000;

pub(super) fn is_command(command: &str) -> bool {
    matches!(command, "inspect" | "verify" | "extract" | "select-movie" | "select-matroska")
}

pub(super) fn parse_limits(values: &Values) -> ParseResult<ImmutableRetainedReadLimits> {
    let bound = |key, default, maximum| -> ParseResult<usize> {
        let value = match values.get(key) {
            None => default,
            Some(raw) => {
                let text = raw
                    .to_str()
                    .ok_or_else(|| malformed("read allowance must be UTF-8"))?;
                let value = text
                    .parse::<u64>()
                    .map_err(|_| malformed("invalid read allowance"))?;
                if text != value.to_string() {
                    return Err(malformed(
                        "read allowance must use canonical positive decimal spelling",
                    ));
                }
                value
            }
        };
        if value == 0 || value > maximum {
            return Err(malformed(
                "aggregate read allowance exceeds the native bound",
            ));
        }
        usize::try_from(value).map_err(|_| malformed("read allowance exceeds the address range"))
    };
    Ok(ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: bound("--max-read-bytes", DEFAULT_BYTES, MAX_BYTES)?,
        max_read_objects: bound("--max-read-objects", DEFAULT_READS, MAX_READS)?,
    })
}

pub(super) fn run(options: &Options, out: &mut impl Write) -> RunResult<()> {
    let (identity, operation) = match &options.action {
        Action::Inspect(id) => (*id, "inspect"),
        Action::Verify(id) => (*id, "verify"),
        Action::Extract { identity, .. } => (*identity, "extract"),
        Action::Movie(action) => (action.identity(), "select-movie"),
        Action::Matroska(action) => (action.identity(), "select-matroska"),
        _ => return Err("immutable source inspection requires a read command".into()),
    };
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err("existing non-symlink deployment required".into());
    }
    let root = fs::canonicalize(&options.root)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:file-read-cli".to_owned(),
        operation_id: OperationId::parse("operation:file-read-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.read_limits.max_read_bytes as u64)
            .storage_operations(options.read_limits.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".to_owned(),
        retention_scope: "retention:existing-deployment-policy".to_owned(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
    let started = Instant::now();
    let cancelled = || started.elapsed() >= DEADLINE;
    let result = (|| -> RunResult<()> {
        let owner =
            ImmutableRetainedSource::open_cancellable(&root, options.read_limits, &cx, &cancelled)?;
        if owner.site_lineage() != options.site {
            return Err("deployment site does not match".into());
        }
        let retained = RetainedFileImport::open(&owner, identity, options.limits, &cx)?;
        // Buffer the complete report and optional exports. Custody failure must never release
        // success-looking headers, a manifest, or raw source from a partially checked read.
        let mut report = Vec::new();
        metadata(&owner, &retained, identity, operation, &mut report)?;
        let source_export = match &options.action {
            Action::Verify(_) => {
                let digest = retained.verify_source(&owner, options.limits, &cx)?;
                writeln!(report, "verified_source_sha256={digest}")?;
                None
            }
            Action::Extract {
                segment, output, ..
            } => {
                let capsule = fss_reference::ingest::recorded_decode::retained_source_capsule(
                    &owner, &retained, *segment,
                )?;
                fss_reference::ingest::privacy_mask::refuse_unmasked_source(
                    &owner,
                    &capsule.sensor_id,
                )?;
                let bytes = retained.read_segment(&owner, *segment, options.limits, &cx)?;
                writeln!(report, "extracted_segment={segment}")?;
                writeln!(report, "extracted_bytes={}", bytes.len())?;
                writeln!(report, "extracted_sha256={}", ContentDigest::sha256(&bytes))?;
                Some((output, bytes))
            }
            Action::Inspect(_) => None,
            Action::Matroska(action) => {
                super::matroska::run(action, &retained, &owner, options.limits, &cx, &mut report)?;
                None
            }
            Action::Movie(action) => {
                super::movie::run(action, &retained, &owner, options.limits, &cx, &mut report)?;
                None
            }
            _ => return Err("immutable source inspection requires a read command".into()),
        };
        if matches!(&options.action, Action::Inspect(_) | Action::Verify(_))
            && retained.manifest().adapter_id == fss_reference::ingest::rtsp_import::replay::ADAPTER
        {
            replay_origin::report(&owner, identity, options.limits, &cx, &mut report)?;
        }
        let manifest = options
            .manifest_output
            .as_ref()
            .map(|path| (path, retained.manifest().canonical_bytes()));
        if manifest.is_some() {
            writeln!(report, "canonical_manifest_written=true")?;
        }
        owner.revalidate()?;
        let usage = owner.usage();
        writeln!(report, "deployment_mutated=false")?;
        writeln!(report, "payload_read_bytes={}", usage.read_bytes)?;
        writeln!(report, "payload_read_attempts={}", usage.read_objects)?;
        if let Some((path, bytes)) = source_export {
            write_new(path, &bytes, &root, &cx)?;
        }
        if let Some((path, bytes)) = manifest {
            write_new(path, &bytes, &root, &cx)?;
        }
        out.write_all(&report)?;
        Ok(())
    })();
    cx.drain_and_finalize();
    result
}

/// Preserve the same native source/acquisition fields for both publishing and read paths.
pub(super) fn metadata(
    deployment: &dyn RetainedSource,
    retained: &RetainedFileImport,
    identity: ContentDigest,
    operation: &str,
    out: &mut impl Write,
) -> RunResult<()> {
    let manifest = retained.manifest();
    writeln!(out, "operation={operation}")?;
    writeln!(out, "import_identity={}", retained.import_identity())?;
    writeln!(out, "import_root={}", retained.import_root())?;
    writeln!(out, "manifest_digest={}", retained.manifest_digest())?;
    writeln!(
        out,
        "authority_sequence={}",
        retained.authority_anchor().commit_sequence
    )?;
    writeln!(out, "input_sha256={}", manifest.input_sha256)?;
    writeln!(out, "input_bytes={}", manifest.input_bytes)?;
    writeln!(out, "media_format={}", manifest.format)?;
    writeln!(out, "segment_count={}", manifest.segment_spans.len())?;
    // MP4/Matroska container structure (boxes or elements, other tracks, parameter sets) is
    // accounted source, not lost media: it is counted apart from omissions.
    let structure = manifest
        .omission_spans
        .iter()
        .filter(|span| span.is_container_structure())
        .count();
    writeln!(
        out,
        "omission_count={}",
        manifest.omission_spans.len() - structure
    )?;
    writeln!(out, "container_structure_count={structure}")?;
    writeln!(out, "capture_time_class={}", manifest.capture_time_label)?;
    // The retained acquisition lifecycle, replayed through the core session; its absence
    // gate decides `absence_certifiable` (a file session never certifies absence).
    let acquisition = AcquisitionRetention::open(deployment, identity)?;
    match acquisition.history() {
        Some(history) => {
            writeln!(out, "acquisition_history={}", history.kinds_text())?;
            writeln!(out, "acquisition_terminal={}", history.terminal().as_str())?;
            writeln!(out, "acquisition_ending={}", history.ending().as_str())?;
            let refusal = match history.absence_claim() {
                Ok(()) => "none".to_owned(),
                Err(refusal) => refusal.to_string(),
            };
            writeln!(out, "acquisition_absence_refusal={refusal}")?;
        }
        None => writeln!(out, "acquisition_history=not_recorded")?,
    }
    let absence_certifiable = acquisition
        .history()
        .is_some_and(|history| history.absence_claim().is_ok());
    writeln!(out, "absence_certifiable={absence_certifiable}")?;
    Ok(())
}
