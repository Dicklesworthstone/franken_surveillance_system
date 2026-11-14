#![forbid(unsafe_code)]
//! Native event inspection through immutable custody, without a publisher or recovery.

use std::collections::BTreeSet;
use std::time::Instant;

use fss_reference::ingest::analysis::{AnalysisPlan, AnalysisReport};
use fss_reference::ingest::package_event::{PackageEvent, PackageEventError};
use fss_reference::ingest::recorded_event::RecordedEvent;
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedSource};

use super::*;

pub(super) fn run(mut options: Options, destination: &mut impl Write) -> RunResult<()> {
    options.root = fs::canonicalize(&options.root)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-cli".into(),
        operation_id: OperationId::parse("operation:event-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.read_limits.max_read_bytes as u64)
            .storage_operations(options.read_limits.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())?;
    let started = Instant::now();
    let cancelled = || started.elapsed() >= retained_read::DEADLINE;
    let result = (|| -> RunResult<()> {
        let deployment = ImmutableRetainedSource::open_cancellable(
            &options.root,
            options.read_limits,
            &cx,
            &cancelled,
        )?;
        if deployment.site_lineage() != options.site {
            return Err(io::Error::other("retained deployment site lineage mismatch").into());
        }
        let mut budget = AnalysisBudget::new(options.detection_units, options.association_units);
        let mut exports = Vec::new();
        let mut buffer = Vec::new();
        let out = &mut buffer;
        match &options.action {
            Action::Report {
                import,
                interpretation,
                detector,
                tracking,
                runs,
                output,
            } => {
                let plan = AnalysisPlan::new(
                    *import,
                    *interpretation,
                    detector.clone(),
                    *tracking,
                    read_runs(runs, &cx)?,
                )?;
                let report =
                    AnalysisReport::read(&deployment, &plan, &options.limits, &mut budget, &cx)?;
                exports.push((output.clone(), report.encoded().to_vec()));
                let tracks: BTreeSet<_> = report
                    .observations()
                    .iter()
                    .flat_map(|o| &o.tracking().tracks)
                    .filter(|t| t.observed_row.is_some())
                    .map(|t| t.id)
                    .collect();
                writeln!(
                    out,
                    "operation=report_verified\nreport_digest={}\nplan_digest={}\nframes={}\ntrack_count={}",
                    report.digest(),
                    plan.digest(),
                    report.observations().len(),
                    tracks.len()
                )?;
                for track in tracks {
                    writeln!(out, "track={track}")?;
                }
                writeln!(
                    out,
                    "detection_work_units={}\nassociation_work_units={}\nabsence_certifiable=false\neffects_authorized=false",
                    budget.detection.used(),
                    budget.association.used()
                )?;
            }
            Action::PackageReport {
                report,
                label,
                tracking,
                output,
            } => {
                let analysis =
                    PackageAnalysisReport::read(&deployment, *report, label, *tracking, &cx)?;
                if analysis.encoded().len() > options.limits.maximum_report_bytes {
                    return Err(PackageEventError::Limit.into());
                }
                exports.push((output.clone(), analysis.encoded().to_vec()));
                let retained = analysis.retained();
                let record = retained.record();
                let confirmed: Vec<_> = analysis.tracks().iter().filter(|t| t.confirmed).collect();
                writeln!(
                    out,
                    "operation=package_report_verified\nreport_digest={}\npackage_report={}\npackage_detection_root={}\npackage_digest={}\nmodel_id={}\ngeneration={}\nlabel={}\nframes={}\ntrack_count={}",
                    analysis.digest(),
                    record.report_digest,
                    retained.root(),
                    record.package_digest,
                    record.model_id,
                    record.generation,
                    analysis.label(),
                    record.frames.len(),
                    confirmed.len()
                )?;
                for track in confirmed {
                    writeln!(out, "track={}", track.identity)?;
                }
                writeln!(
                    out,
                    "scores=uncalibrated\nabsence_certifiable=false\neffects_authorized=false"
                )?;
            }
            Action::Read(id) if id.as_str().starts_with("event:package:") => {
                read_package_event(&options, &deployment, id, &cx, out, &mut exports)?;
            }
            Action::Read(id) => {
                let record =
                    RecordedEvent::open(&deployment, id, &options.limits, &mut budget, &cx)?;
                let event = record.event();
                if let Some(path) = &options.event_out {
                    exports.push((path.clone(), event.to_canonical_json().into_bytes()));
                }
                if let Some(path) = &options.report_out {
                    exports.push((path.clone(), record.report().encoded().to_vec()));
                }
                writeln!(
                    out,
                    "event_root={}\nauthority_sequence={}\nreport_digest={}\ntrack={}",
                    record.root(),
                    record.authority_anchor().commit_sequence,
                    record.report().digest(),
                    record.track()
                )?;
                writeln!(
                    out,
                    "operation=read_verified\nevent_id={}\nrevision={}\nevent_revision_digest={}\nprovenance_root={}",
                    event.event_id,
                    event.revision,
                    event.revision_digest(),
                    event.decision_path.fingerprint
                )?;
                writeln!(
                    out,
                    "event_state={}\nevent_kind={}\nmodel_receipts={}\nevidence_items={}\ndetection_work_units={}\nassociation_work_units={}",
                    event.state.as_str(),
                    event.kind.as_str(),
                    event.model_receipts.len(),
                    event.evidence.len(),
                    budget.detection.used(),
                    budget.association.used()
                )?;
                writeln!(out, "absence_certifiable=false\neffects_authorized=false")?;
            }
            _ => return Err(io::Error::other("event inspection requires read or report").into()),
        }
        if buffer.len() > options.limits.maximum_report_bytes {
            return Err(io::Error::other("event inspection output bound exceeded").into());
        }
        // Re-read the opening metadata, every selected payload, custody and publication under
        // the same nonrenewing allowance. No report or export escapes a failed final check.
        deployment.revalidate_snapshot_metadata()?;
        deployment.revalidate()?;
        for (path, bytes) in exports {
            export(&path, &bytes, &options.root, &cx)?;
        }
        destination.write_all(&buffer)?;
        Ok(())
    })();
    cx.drain_and_finalize();
    result
}

fn read_package_event(
    options: &Options,
    deployment: &dyn RetainedSource,
    id: &EventId,
    cx: &ReplayCx,
    out: &mut impl Write,
    exports: &mut Vec<(PathBuf, Vec<u8>)>,
) -> RunResult<()> {
    use fss_cli::agent_json::{array, object, string};

    let record = PackageEvent::open(deployment, id, cx)?;
    if record.report().encoded().len() > options.limits.maximum_report_bytes {
        return Err(PackageEventError::Limit.into());
    }
    // Project only exact rows assigned by the verified analysis. No adjacent detections,
    // supplied scores or additional source reads can enter this inventory.
    let report = record.report();
    let native = report.retained().record();
    let track = report
        .tracks()
        .iter()
        .find(|track| track.identity == record.track())
        .ok_or(PackageEventError::Mismatch)?;
    let mut observations = Vec::with_capacity(track.observations.len());
    for observation in &track.observations {
        cx.checkpoint("package_event:selector_inventory")?;
        let (row, score_bits, bounds, _) =
            observation.detection.ok_or(PackageEventError::Mismatch)?;
        let frame = native
            .frames
            .iter()
            .find(|frame| {
                frame.segment == observation.segment
                    && frame.capsule_digest == observation.capsule_digest
            })
            .ok_or(PackageEventError::Mismatch)?;
        let detection = frame
            .detections
            .iter()
            .find(|detection| detection.row == row && detection.class_index == report.class_index())
            .ok_or(PackageEventError::Mismatch)?;
        if detection.score_bits != score_bits || detection.bounds != bounds {
            return Err(PackageEventError::Mismatch.into());
        }
        observations.push(object(&[
            ("sensor_id", string(&frame.sensor_id)),
            (
                "capture_ns",
                array(&[
                    string(&frame.capture.earliest.0.to_string()),
                    string(&frame.capture.latest.0.to_string()),
                ]),
            ),
            ("score_f32_bits", score_bits.to_string()),
            (
                "selector",
                object(&[
                    ("event_id", string(id.as_str())),
                    (
                        "capsule_digest",
                        string(&observation.capsule_digest.to_text()),
                    ),
                    ("segment", observation.segment.to_string()),
                    ("detection_row", row.to_string()),
                ]),
            ),
        ]));
    }
    let selectors = object(&[
        ("site_lineage", string(deployment.site_lineage())),
        (
            "current_authority_sequence",
            string(&deployment.current_anchor().commit_sequence.to_string()),
        ),
        (
            "expected_authority_root",
            string(&deployment.current_anchor().state_root.to_text()),
        ),
        ("event_id", string(id.as_str())),
        ("expected_event_root", string(&record.root().to_text())),
        ("report_digest", string(&report.digest().to_text())),
        ("track", string(&record.track().to_text())),
        ("package_digest", string(&native.package_digest.to_text())),
        ("model_digest", string(&native.model_digest.to_text())),
        ("contract_digest", string(&native.contract_digest.to_text())),
        ("class_index", report.class_index().to_string()),
        ("label", string(report.label())),
        ("source_custody_verified", "true".to_owned()),
        ("effects_authorized", "false".to_owned()),
        ("observations", array(&observations)),
    ]);
    if selectors.len() > options.limits.maximum_report_bytes {
        return Err(PackageEventError::Limit.into());
    }
    if let Some(path) = &options.event_out {
        exports.push((path.clone(), record.event().to_canonical_json().into_bytes()));
    }
    if let Some(path) = &options.report_out {
        exports.push((path.clone(), record.report().encoded().to_vec()));
    }
    writeln!(
        out,
        "event_root={}\nauthority_sequence={}\nreport_digest={}\ntrack={}\nretained_supervisor_sources={}",
        record.root(),
        record.authority_anchor().commit_sequence,
        record.report().digest(),
        record.track(),
        selectors
    )?;
    print_package_event(record.event(), "read_verified", out)
}

