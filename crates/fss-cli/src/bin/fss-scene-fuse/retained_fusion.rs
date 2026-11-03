#![forbid(unsafe_code)]
//! Reconstruct scene hypotheses only from source-owner-authenticated native track samples.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, object, string};
use fss_cli::retained_continuity_query::{
    anchor_digest, authority_anchor_json, source_binding_json,
};
use fss_cli::scene_rig::SceneRig;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::WorkBudget;
use fss_reference::ingest::package_handoffs::{
    PackageHandoffProjection, contract::MAX_PACKAGE_HANDOFF_SOURCE_BYTES,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::{ImportLimits, import_twin};

use super::{
    DEFAULT_WORK, MAX_JSON_BYTES, MAX_REPORT_BYTES, MAX_TWIN_BYTES, MAX_WORK, Result, checkpoint,
    document, fail, input, input_error, read_input, report, retained_fusion_input as selection,
    retained_handoffs, write_report,
};

const HELP: &str = "fss-scene-fuse retained-fuse --root DEPLOYMENT --site SITE\n\
    --twin PROPERTY.fsstwin --rig CAMERAS.json --selection QUERY.json\n\
    [--principal PRINCIPAL] [--report-out REPORT.json]\n\
    [--expected-input sha256:HEX] [--expected-anchor sha256:HEX]\n\
    [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Reconstruct 3D points or constant-velocity trajectories from actual retained package tracks.\n\
The selection names exact native track observations and explicit common-feature rectangles.\n\
Source identities, detector bounds and capture intervals come from verified retained custody;\n\
they cannot be replaced by the query. Camera placements, correspondence, image-domain mapping\n\
and additive clock alignment remain explicit assumptions. No event or effect is activated.\n\n\
The schema is fss.scene_fusion_retained_query.v1. Select at most 32 native tracks from four\n\
report/label/tracking recipes, pin each source generation to a rig camera, and supply bounded\n\
feature selections within actual detector rectangles. All geometry uses one property frame\n\
and reference time. Static, supplied-velocity and inferred-velocity modes are supported.\n\
Missing, changed or privacy-stale custody refuses the complete request. A geometric refusal\n\
retains its hypothesis and sources alongside successful companions. Complete source bindings,\n\
original timing uncertainty, assumptions and exact authority anchor remain in the report.\n\n\
An existing deployment is required; its ordinary startup recovery remains in effect. Inputs\n\
are bounded regular files: 64 MiB twin and 1 MiB each for rig/selection. Original-byte reads\n\
share a cumulative 4 GiB allowance across all recipes and final revalidation. Default work\n\
is 100000000 units; maximum 1000000000. Default timeout is 30000 ms; maximum 3600000.\n\
Geometry work charges check the same cancellation/deadline as the source-owner boundary.\n\
The complete report is at most 8 MiB including newline. --report-out exclusively creates a\n\
private new file with the same bytes as stdout. Exit 0: all hypotheses solved; 3: one or more\n\
geometric refusals; 2: input, custody, authority, cancellation or complete-output failure.\n\
See docs/RETAINED_SCENE_FUSION.md for the exact input and provenance contract.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    twin: PathBuf,
    rig: PathBuf,
    selection: PathBuf,
    report_out: Option<PathBuf>,
    expected_input: Option<ContentDigest>,
    expected_anchor: Option<ContentDigest>,
    work: u64,
    timeout: Duration,
    report_bytes: usize,
}

fn options(args: &[OsString]) -> Result<Option<Options>> {
    if matches!(args, [flag] if matches!(flag.to_str(), Some("--help" | "-h"))) {
        return Ok(None);
    }
    if args.len() > 24
        || args.len() % 2 != 0
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(input_error(
            "expected bounded retained-fuse option/value pairs",
        ));
    }
    let mut values = BTreeMap::new();
    for [key, value] in args.as_chunks::<2>().0 {
        let key = key
            .to_str()
            .ok_or_else(|| input_error("option must be UTF-8"))?;
        if ![
            "--root",
            "--site",
            "--principal",
            "--twin",
            "--rig",
            "--selection",
            "--report-out",
            "--expected-input",
            "--expected-anchor",
            "--work-units",
            "--timeout-ms",
            "--max-report-bytes",
        ]
        .contains(&key)
            || value.is_empty()
            || value.to_str().is_some_and(|s| s.starts_with("--"))
            || values.insert(key, value).is_some()
        {
            return Err(input_error("unknown/duplicate option or missing value"));
        }
    }
    let path = |key: &str| -> Result<PathBuf> {
        values
            .get(key)
            .map(PathBuf::from)
            .ok_or_else(|| input_error(format!("{key} is required")))
    };
    let name = |key: &str, default: Option<&str>| -> Result<String> {
        let value = values
            .get(key)
            .map(|value| {
                value
                    .to_str()
                    .ok_or_else(|| input_error("identity must be UTF-8"))
            })
            .transpose()?
            .or(default)
            .ok_or_else(|| input_error(format!("{key} is required")))?;
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
        {
            return Err(input_error("identity is outside its bounded ASCII grammar"));
        }
        Ok(value.to_owned())
    };
    let pin = |key: &str| -> Result<Option<ContentDigest>> {
        values
            .get(key)
            .map(|value| {
                let value = value
                    .to_str()
                    .ok_or_else(|| input_error("pin must be UTF-8"))?;
                if !value.starts_with("sha256:") {
                    return Err(input_error("pin must use sha256:HEX"));
                }
                ContentDigest::parse(value).map_err(|_| input_error("invalid content pin"))
            })
            .transpose()
    };
    let integer = |key: &str, default: u64, minimum: u64, maximum: u64| -> Result<u64> {
        let Some(value) = values.get(key) else {
            return Ok(default);
        };
        let value = value
            .to_str()
            .ok_or_else(|| input_error("numeric option must be UTF-8"))?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(input_error("expected decimal option value"));
        }
        value
            .parse::<u64>()
            .ok()
            .filter(|value| (minimum..=maximum).contains(value))
            .ok_or_else(|| input_error(format!("{key} is outside {minimum}..={maximum}")))
    };
    Ok(Some(Options {
        root: path("--root")?,
        site: name("--site", None)?,
        principal: name("--principal", Some("principal:local-operator"))?,
        twin: path("--twin")?,
        rig: path("--rig")?,
        selection: path("--selection")?,
        report_out: values.get("--report-out").map(PathBuf::from),
        expected_input: pin("--expected-input")?,
        expected_anchor: pin("--expected-anchor")?,
        work: integer("--work-units", DEFAULT_WORK, 1, MAX_WORK)?,
        timeout: Duration::from_millis(integer("--timeout-ms", 30_000, 1, 3_600_000)?),
        report_bytes: integer(
            "--max-report-bytes",
            MAX_REPORT_BYTES as u64,
            1024,
            MAX_REPORT_BYTES as u64,
        )? as usize,
    }))
}

fn authority(options: &Options) -> Result<ContextAuthority> {
    ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-scene-fusion-cli".into(),
        operation_id: OperationId::parse("operation:retained-scene-fusion-cli")
            .map_err(|_| input_error("operation identity"))?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(
                MAX_PACKAGE_HANDOFF_SOURCE_BYTES
                    + (MAX_TWIN_BYTES + 2 * MAX_JSON_BYTES + MAX_REPORT_BYTES) as u64,
            )
            .build()
            .map_err(|_| input_error("resource allowance"))?,
        privacy_scope: "privacy:local-authorized-retained-scene-analysis".into(),
        retention_scope: "retention:operator-selected-report".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "retained analysis authority refused",
        )
    })
}

fn check_cancel(cx: &ReplayCx, cancelled: &impl Fn() -> bool) -> Result<()> {
    if cancelled() {
        cx.request_cancellation();
        return Err(fail(
            "ERR-SCENE-FUSION-CANCELLED-001",
            "retained scene analysis cancelled or deadline reached",
        ));
    }
    checkpoint(cx, "retained_fusion:checkpoint")
}

fn analyze(options: &Options, root: &Path, cx: &ReplayCx) -> Result<report::Report> {
    checkpoint(cx, "retained_fusion:begin")?;
    let started = Instant::now();
    let cancelled = || cx.is_cancelled() || started.elapsed() >= options.timeout;
    if let Some(path) = &options.report_out {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(fail(
                    "ERR-SCENE-FUSION-OUTPUT-001",
                    "report output already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(fail(
                    "ERR-SCENE-FUSION-OUTPUT-001",
                    "report output cannot be inspected",
                ));
            }
        }
    }
    let bytes = read_input(&options.selection, MAX_JSON_BYTES, cx)?;
    let input_document = ContentDigest::sha256(&bytes);
    if options
        .expected_input
        .is_some_and(|pin| pin != input_document)
    {
        return Err(input_error("selection bytes differ from --expected-input"));
    }
    check_cancel(cx, &cancelled)?;
    let rig_bytes = read_input(&options.rig, MAX_JSON_BYTES, cx)?;
    let rig_document = document(&rig_bytes)?;
    let (package_sha256, source_scene_sha256, basis) = input::twin_expectation(&rig_document)?;
    let twin_bytes = read_input(&options.twin, MAX_TWIN_BYTES, cx)?;
    let mut work = WorkBudget::with_cancellation_probe(options.work, &cancelled);
    let twin = import_twin(
        &twin_bytes,
        fss_twin::ImportExpectation {
            package_sha256,
            source_scene_sha256,
            basis,
        },
        ImportLimits::default(),
        &mut work,
    )
    .map_err(|error| fail("ERR-SCENE-FUSION-TWIN-001", error.to_string()))?;
    let rig = SceneRig::from_document(&rig_document, &twin, &mut work)
        .map_err(|error| fail("ERR-SCENE-FUSION-RIG-001", error.to_string()))?;
    let rig_digest = ContentDigest::sha256(&rig_bytes);
    let parsed = selection::parse(&bytes, rig_digest, &rig)?;
    check_cancel(cx, &cancelled)?;
    let deployment = ReferenceDeployment::reopen(root, &options.site, cx)
        .map_err(|error| fail("ERR-SCENE-FUSION-INPUT-001", error.to_string()))?;
    if options
        .expected_anchor
        .is_some_and(|pin| pin != anchor_digest(deployment.current_anchor()))
    {
        return Err(input_error("deployment differs from --expected-anchor"));
    }
    let projection =
        PackageHandoffProjection::read_with_cancel(&deployment, &parsed.request, cx, &cancelled)
            .map_err(|error| fail(error.stable_id(), error.to_string()))?;
    let query = selection::build_query(&parsed, projection.bindings(), &rig)?;
    check_cancel(cx, &cancelled)?;
    let geometry = report::compute(
        &twin,
        &rig,
        &query,
        rig_digest,
        report::SourceProvenance::RetainedPackage(input_document),
        &mut work,
        cx,
    )?;
    check_cancel(cx, &cancelled)?;
    let body = object(&[
        ("schema", string("fss.scene_fusion_retained.v1")),
        (
            "outcome",
            string(if geometry.all_solved {
                "complete"
            } else {
                "complete_with_refusals"
            }),
        ),
        ("authority", string("derived_cognition_no_effect_authority")),
        (
            "source_provenance",
            string("verified_retained_package_observations"),
        ),
        ("physical_identity_established", "false".into()),
        ("input_document_digest", string(&input_document.to_text())),
        ("projection_digest", string(&projection.digest().to_text())),
        (
            "anchor_digest",
            string(&anchor_digest(projection.anchor()).to_text()),
        ),
        ("anchor", authority_anchor_json(projection.anchor())),
        (
            "bindings",
            array(
                &projection
                    .bindings()
                    .iter()
                    .map(source_binding_json)
                    .collect::<Vec<_>>(),
            ),
        ),
        ("declarations", parsed.declarations_json().to_owned()),
        ("track_aliases", parsed.track_aliases_json()),
        ("geometry", geometry.json),
        (
            "assumptions",
            array(
                &[
                    "rig_camera_placements_and_source_to_rig_mapping_are_operator_declarations",
                    "source_pixels_are_assumed_to_match_the_declared_undistorted_image_domain",
                    "clock_offsets_and_common_clock_are_operator_declarations",
                    "feature_rectangles_and_cross_camera_correspondence_are_operator_declarations",
                    "source_custody_does_not_establish_detector_accuracy_or_physical_identity",
                    "geometric_covariance_covers_only_declared_independent_pixel_noise",
                ]
                .map(string),
            ),
        ),
    ]);
    let json = object(&[
        ("schema", string("fss.scene_fusion_retained.v1")),
        (
            "report_digest",
            string(&ContentDigest::sha256(body.as_bytes()).to_text()),
        ),
        ("report", body),
    ]);
    if json.len() + 1 > options.report_bytes {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete retained scene report exceeds output allowance",
        ));
    }
    // No source-derived report escapes unless the same owner reopens and verifies all
    // retained bytes, privacy bindings and the full anchor after geometric work.
    projection
        .revalidate_with_cancel(&deployment, cx, &cancelled)
        .map_err(|error| fail(error.stable_id(), error.to_string()))?;
    check_cancel(cx, &cancelled)?;
    checkpoint(cx, "retained_fusion:complete")?;
    Ok(report::Report {
        json,
        all_solved: geometry.all_solved,
    })
}

fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let authority = authority(options)?;
    // The shared preflight checks before ReplayCx can create any region directory.
    let root = retained_handoffs::preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())
        .map_err(|error| fail("ERR-SCENE-FUSION-AUTHORITY-001", error.to_string()))?;
    let result = (|| {
        let result = analyze(options, &root, &cx)?;
        if let Some(path) = &options.report_out {
            write_report(path, result.json.as_bytes(), &cx)?;
        } else {
            checkpoint(&cx, "retained_fusion:stdout")?;
        }
        writeln!(out, "{}", result.json).map_err(|_| {
            fail(
                "ERR-SCENE-FUSION-OUTPUT-001",
                "stdout failed; any completed report file remains available",
            )
        })?;
        Ok(result.all_solved)
    })();
    cx.drain_and_finalize();
    result
}

pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<bool> {
    match options(args)? {
        None => {
            out.write_all(HELP.as_bytes())
                .map_err(|_| fail("ERR-SCENE-FUSION-OUTPUT-001", "help output failed"))?;
            Ok(true)
        }
        Some(options) => execute(&options, out),
    }
}

#[cfg(test)]
#[path = "retained_fusion_tests.rs"]
mod tests;
