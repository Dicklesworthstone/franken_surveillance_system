#![forbid(unsafe_code)]
//! Actual additive wire, frozen tracks-v1 and lineage production source, with no custody facade.

extern crate self as fss_cli;
extern crate self as fss_reference;

#[path = "../../fss-reference/src/onvif/metadata/tracks/contract.rs"]
pub mod tracks;
#[path = "../../fss-reference/src/onvif/wire.rs"]
pub mod wire;
/// Real production paths consumed by the pure overlay.
pub mod onvif {
    pub use crate::wire;
    /// Metadata production contracts.
    pub mod metadata {
        /// Original frozen vendor run contract.
        pub mod tracks {
            pub use crate::tracks as contract;
        }
        /// Actual lifecycle overlay contract.
        pub mod lifecycle {
            pub use crate::lifecycle as contract;
        }
    }
}
#[path = "../../fss-reference/src/onvif/metadata/lifecycle/contract.rs"]
pub mod lifecycle;

#[path = "../../fss-cli/src/json_output.rs"]
pub mod json_output;
#[path = "../../fss-cli/src/bin/fss-onvif-metadata/analysis/lifecycle_json.rs"]
mod lifecycle_json;

use fss_core::{ContentDigest, Plane, ProvenanceClass};
use lifecycle::{
    LifecycleBoundary as Boundary, LifecycleEndpointState as State, LifecycleError as Error,
    LifecycleFrameInput, LifecycleIssue as Issue, LifecycleLimits,
    LifecycleObservationBasis as Basis, LifecycleReport, project_lifecycle,
};
use tracks::{TrackFrameInput, TrackLimits, TrackletReport, project_tracklets};
use wire::{
    EventDocument, LifecycleDocument, LifecycleParseLimits, parse_metadata_document,
    parse_metadata_lifecycle_document,
};

type Checked<T> = Result<T, Box<dyn std::error::Error>>;
type Test = Checked<()>;

fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn object(id: &str) -> String {
    format!(r#"<t:Object ObjectId="{id}"/>"#)
}
fn at(second: u8, module: &str, body: &str) -> String {
    format!(
        r#"<t:Frame UtcTime="2026-11-09T01:00:{second:02}Z" Source="{module}">{body}</t:Frame>"#
    )
}
fn tree(body: &str) -> String {
    format!("<t:ObjectTree>{body}</t:ObjectTree>")
}
fn rename(from: &str, to: &str) -> String {
    tree(&format!(
        r#"<t:Rename><t:from ObjectId="{from}"/><t:to ObjectId="{to}"/></t:Rename>"#
    ))
}
struct Parsed {
    original: EventDocument,
    overlay: LifecycleDocument,
    digest: ContentDigest,
}
fn parse(body: &str) -> Checked<Parsed> {
    let xml = format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema" xmlns:v="urn:vendor"><t:VideoAnalytics>{body}</t:VideoAnalytics></t:MetadataStream>"#
    );
    Ok(Parsed {
        original: parse_metadata_document(xml.as_bytes())?,
        overlay: parse_metadata_lifecycle_document(
            xml.as_bytes(),
            LifecycleParseLimits::default(),
            || true,
        )?,
        digest: digest(&xml),
    })
}
fn inputs(parsed: &Parsed) -> Vec<TrackFrameInput<'_>> {
    parsed
        .original
        .analytics_frames
        .iter()
        .enumerate()
        .map(|(index, frame)| TrackFrameInput {
            scope: digest("sensor-device-profile-parser-transport-generation"),
            source_identity: digest("retained-source"),
            source_root: digest("retained-root"),
            source_digest: parsed.digest,
            frame_digest: digest(&format!("frame-{index}")),
            document_index: 0,
            frame_index: index,
            frame,
            boundary_before: false,
            uninterpreted_source: false,
        })
        .collect()
}
fn overlays(parsed: &Parsed) -> Vec<LifecycleFrameInput<'_>> {
    parsed
        .overlay
        .frames
        .iter()
        .enumerate()
        .map(|(frame_ordinal, frame)| LifecycleFrameInput {
            frame_ordinal,
            source_digest: parsed.digest,
            frame,
            uninterpreted_source: parsed.overlay.unsupported_sections != 0,
        })
        .collect()
}
fn project(parsed: &Parsed) -> Checked<(TrackletReport, LifecycleReport)> {
    let sources = inputs(parsed);
    let tracks = project_tracklets(&sources, TrackLimits::default(), || true)?;
    let report = project_lifecycle(
        &sources,
        &tracks,
        &overlays(parsed),
        LifecycleLimits::default(),
        || true,
    )?;
    Ok((tracks, report))
}
fn rename_fixture() -> Checked<Parsed> {
    parse(
        &(at(0, "motion", &object("+001"))
            + &at(1, "motion", &(object("2") + &rename("01", "+002")))),
    )
}

#[test]
fn rename_links_exact_original_occurrences_without_merging_frozen_runs() -> Test {
    let parsed = rename_fixture()?;
    let (tracks, report) = project(&parsed)?;
    assert_eq!(report.operations.len(), 1);
    assert_eq!(report.operations[0].state, State::Observed);
    let from = &report.operations[0].from[0];
    let to = &report.operations[0].to[0];
    assert_eq!(from.reference.object_id.as_deref(), Some("01"));
    assert_eq!(to.reference.object_id.as_deref(), Some("+002"));
    assert_eq!(from.observations[0].basis, Basis::PreviousModuleFrame);
    assert_eq!(
        from.observations[0].occurrence_identity,
        tracks.occurrences[0].identity
    );
    assert_eq!(
        to.observations[0].occurrence_identity,
        tracks.occurrences[1].identity
    );
    assert_ne!(
        from.observations[0].tracklet_identity,
        to.observations[0].tracklet_identity
    );
    assert_eq!(report.tracklet_report_digest, tracks.report_digest);
    assert!(
        tracks.frames[1]
            .barriers
            .contains(&tracks::TrackBreakReason::UninterpretedContent)
    );
    assert!(
        !report.frames[1]
            .barriers
            .contains(&Boundary::UninterpretedContent)
    );
    assert_eq!(
        tracks,
        project_tracklets(&inputs(&parsed), tracks.limits, || true)?
    );
    assert_eq!(report, project(&parsed)?.1);
    assert_eq!(report.plane(), Plane::Cognition);
    assert_eq!(report.provenance(), ProvenanceClass::Derived);
    assert_eq!(report.source_provenance(), ProvenanceClass::VendorClaimed);
    Ok(())
}

#[test]
fn split_and_merge_retain_every_ordered_endpoint() -> Test {
    let split = tree(
        r#"<t:Split><t:from ObjectId="1"/><t:to ObjectId="2"/><t:to ObjectId="3"/></t:Split>"#,
    );
    let merge = tree(
        r#"<t:Merge><t:from ObjectId="3"/><t:from ObjectId="2"/><t:to ObjectId="4"/></t:Merge>"#,
    );
    let parsed = parse(
        &(at(0, "m", &object("1"))
            + &at(1, "m", &(object("2") + &object("3") + &split))
            + &at(2, "m", &(object("4") + &merge))),
    )?;
    let (_, report) = project(&parsed)?;
    assert_eq!(report.operations.len(), 2);
    assert!(
        report
            .operations
            .iter()
            .all(|row| row.state == State::Observed)
    );
    assert_eq!(report.operations[0].to.len(), 2);
    assert_eq!(
        report.operations[1]
            .from
            .iter()
            .map(|row| row.observations[0].object_index)
            .collect::<Vec<_>>(),
        [1, 0]
    );
    Ok(())
}

#[test]
fn idle_removed_and_empty_behaviour_do_not_create_deletions() -> Test {
    let body = r#"<t:Object ObjectId="1"><t:Behaviour><t:Idle/><t:Removed/></t:Behaviour></t:Object><t:Object ObjectId="2"><t:Behaviour/></t:Object>"#;
    let parsed = parse(&(at(0, "m", body) + &at(1, "m", &(object("1") + &object("2")))))?;
    let (_, report) = project(&parsed)?;
    assert_eq!(report.behaviours.len(), 2);
    assert!(report.behaviours[0].idle && report.behaviours[0].removed);
    assert!(!report.behaviours[1].idle && !report.behaviours[1].removed);
    assert!(
        report
            .behaviours
            .iter()
            .all(|row| row.state == State::Observed)
    );
    assert!(report.reuses.is_empty());
    assert!(report.operations.is_empty());
    Ok(())
}

#[test]
fn explicit_delete_and_later_integer_reuse_are_linked_conflicts() -> Test {
    let deletion = tree(r#"<t:Delete ObjectId="+007"/>"#);
    let parsed = parse(
        &(at(0, "m", &(object("7") + &deletion))
            + &at(1, "m", "")
            + &at(
                2,
                "m",
                r#"<t:Object ObjectId="007"><t:Behaviour><t:Idle/></t:Behaviour></t:Object>"#,
            )),
    )?;
    let (_, report) = project(&parsed)?;
    assert_eq!(report.operations[0].state, State::Observed);
    assert_eq!(report.reuses.len(), 1);
    assert_eq!(
        report.reuses[0].deleted_by_operation,
        report.operations[0].identity
    );
    assert_eq!(report.reuses[0].deleted_at_frame, 0);
    assert_eq!(report.reuses[0].occurrence.frame_ordinal, 2);
    assert_eq!(report.behaviours[0].state, State::Conflicted);
    assert_eq!(report.behaviours[0].issues, [Issue::DeletedIdReused]);
    Ok(())
}

#[test]
fn unobserved_delete_stays_unresolved_and_can_explain_later_reuse() -> Test {
    let parsed =
        parse(&(at(0, "m", &tree(r#"<t:Delete ObjectId="9"/>"#)) + &at(1, "m", &object("9"))))?;
    let (_, report) = project(&parsed)?;
    assert_eq!(report.operations[0].state, State::Unresolved);
    assert_eq!(report.operations[0].from[0].issues, [Issue::NoObservation]);
    assert_eq!(report.reuses.len(), 1);
    Ok(())
}

#[test]
fn uuid_is_preserved_opaquely_and_never_matched_even_with_integer() -> Test {
    let op = tree(
        r#"<t:Rename><t:from ObjectId="1" UUID="private-uuid-canary"/><t:to ObjectId="2"/></t:Rename>"#,
    );
    let parsed = parse(&(at(0, "m", &object("1")) + &at(1, "m", &(object("2") + &op))))?;
    let (_, report) = project(&parsed)?;
    let endpoint = &report.operations[0].from[0];
    assert_eq!(endpoint.state, State::Unresolved);
    assert!(endpoint.observations.is_empty());
    assert!(endpoint.issues.contains(&Issue::UnsupportedReference));
    assert!(
        report.frames[1]
            .barriers
            .contains(&Boundary::UninterpretedContent)
    );
    assert!(!format!("{report:?}").contains("private-uuid-canary"));
    Ok(())
}

#[test]
fn alias_repeats_and_overlapping_roles_are_conflicted() -> Test {
    for operation in [
        r#"<t:Merge><t:from ObjectId="1"/><t:from ObjectId="+001"/><t:to ObjectId="2"/></t:Merge>"#,
        r#"<t:Rename><t:from ObjectId="1"/><t:to ObjectId="+001"/></t:Rename>"#,
    ] {
        let parsed = parse(&at(
            0,
            "m",
            &(object("1") + &object("2") + &tree(operation)),
        ))?;
        let (_, report) = project(&parsed)?;
        assert_eq!(report.operations[0].state, State::Conflicted);
    }
    Ok(())
}

#[test]
fn competing_operations_and_preexisting_destination_do_not_become_edges() -> Test {
    let operations = tree(concat!(
        "<t:Rename><t:from ObjectId=\"1\"/><t:to ObjectId=\"2\"/></t:Rename>",
        "<t:Rename><t:from ObjectId=\"1\"/><t:to ObjectId=\"3\"/></t:Rename>"
    ));
    let parsed = parse(
        &(at(0, "m", &(object("1") + &object("2")))
            + &at(1, "m", &(object("2") + &object("3") + &operations))),
    )?;
    let (_, report) = project(&parsed)?;
    assert!(
        report
            .operations
            .iter()
            .all(|row| row.state == State::Conflicted)
    );
    assert!(
        report.operations[0].from[0]
            .issues
            .contains(&Issue::CompetingOperations)
    );
    assert!(
        report.operations[0].to[0]
            .issues
            .contains(&Issue::DestinationPreexists)
    );
    Ok(())
}

#[test]
fn sequential_same_frame_dependencies_remain_unresolved() -> Test {
    let operations = tree(concat!(
        "<t:Rename><t:from ObjectId=\"1\"/><t:to ObjectId=\"2\"/></t:Rename>",
        "<t:Rename><t:from ObjectId=\"2\"/><t:to ObjectId=\"3\"/></t:Rename>"
    ));
    let parsed = parse(&at(
        0,
        "m",
        &(object("1") + &object("2") + &object("3") + &operations),
    ))?;
    let (_, report) = project(&parsed)?;
    assert!(
        report
            .operations
            .iter()
            .all(|row| row.state == State::Unresolved)
    );
    assert!(
        report.operations[0].to[0]
            .issues
            .contains(&Issue::SequentialDependency)
    );
    Ok(())
}

#[test]
fn missing_observation_and_other_module_do_not_supply_endpoints() -> Test {
    for prior in [
        at(0, "other", &object("1")),
        at(0, "m", &object("1")) + &at(1, "m", ""),
    ] {
        let parsed = parse(&(prior + &at(2, "m", &(object("2") + &rename("1", "2")))))?;
        let (_, report) = project(&parsed)?;
        assert_eq!(report.operations[0].from[0].issues, [Issue::NoObservation]);
        assert!(report.operations[0].from[0].observations.is_empty());
    }
    Ok(())
}

#[test]
fn module_interleaving_uses_only_the_previous_frame_of_the_same_module() -> Test {
    let parsed = parse(
        &(at(0, "m", &object("1"))
            + &at(0, "other", &object("9"))
            + &at(1, "m", &(object("2") + &rename("1", "2")))),
    )?;
    let (_, report) = project(&parsed)?;
    assert_eq!(report.operations[0].state, State::Observed);
    assert_eq!(
        report.operations[0].from[0].observations[0].frame_ordinal,
        0
    );
    Ok(())
}

#[test]
fn nonincreasing_vendor_time_and_gap_block_previous_matching() -> Test {
    for (time, barrier) in [
        (0, Boundary::VendorTimeNotIncreasing),
        (7, Boundary::VendorTimeGap),
    ] {
        let parsed = parse(
            &(at(0, "m", &object("1")) + &at(time, "m", &(object("2") + &rename("1", "2")))),
        )?;
        let (_, report) = project(&parsed)?;
        assert!(report.frames[1].barriers.contains(&barrier));
        assert_eq!(report.operations[0].from[0].issues, [Issue::NoObservation]);
    }
    Ok(())
}

#[test]
fn explicit_transport_and_scope_boundaries_reset_observations_and_deletions() -> Test {
    let parsed = rename_fixture()?;
    for change_scope in [false, true] {
        let mut sources = inputs(&parsed);
        if change_scope {
            sources[1].scope = digest("changed-generation");
        } else {
            sources[1].boundary_before = true;
        }
        let tracks = project_tracklets(&sources, TrackLimits::default(), || true)?;
        let report = project_lifecycle(
            &sources,
            &tracks,
            &overlays(&parsed),
            LifecycleLimits::default(),
            || true,
        )?;
        assert_eq!(report.operations[0].from[0].issues, [Issue::NoObservation]);
        assert!(report.frames[1].barriers.contains(&if change_scope {
            Boundary::GenerationChanged
        } else {
            Boundary::SourceBoundary
        }));
    }
    Ok(())
}

#[test]
fn unknown_lifecycle_and_appearance_content_stays_opaque() -> Test {
    for addition in ["<v:Unknown/>", "<t:ObjectTree><v:Unknown/></t:ObjectTree>"] {
        let body = if addition.contains("ObjectTree") {
            object("1") + addition
        } else {
            format!(r#"<t:Object ObjectId="1"><t:Appearance>{addition}</t:Appearance></t:Object>"#)
        };
        let parsed = parse(&(at(0, "m", &body) + &at(1, "m", &(object("2") + &rename("1", "2")))))?;
        let (_, report) = project(&parsed)?;
        assert!(
            report.frames[0]
                .barriers
                .contains(&Boundary::UninterpretedContent)
        );
        assert_eq!(report.operations[0].from[0].issues, [Issue::NoObservation]);
    }
    Ok(())
}

#[test]
fn frame_transform_change_blocks_cross_frame_endpoint_support() -> Test {
    let transformation = r#"<t:Transformation><t:Scale x="2" y="2"/></t:Transformation>"#;
    let parsed = parse(
        &(at(0, "m", &object("1"))
            + &at(
                1,
                "m",
                &(transformation.to_owned() + &object("2") + &rename("1", "2")),
            )),
    )?;
    let (_, report) = project(&parsed)?;
    assert!(
        report.frames[1]
            .barriers
            .contains(&Boundary::FrameTransformChanged)
    );
    assert_eq!(report.operations[0].from[0].issues, [Issue::NoObservation]);
    Ok(())
}

#[test]
fn forged_original_digest_membership_or_policy_is_refused() -> Test {
    let parsed = rename_fixture()?;
    let (tracks, _) = project(&parsed)?;
    for change in 0..4 {
        let mut forged = tracks.clone();
        match change {
            0 => forged.report_digest = digest("forged"),
            1 => forged.occurrences[0].tracklet_identity = forged.occurrences[1].tracklet_identity,
            2 => forged.tracklets[0].occurrence_indices.push(1),
            _ => forged.policy_digest = digest("forged-policy"),
        }
        assert_eq!(
            project_lifecycle(
                &inputs(&parsed),
                &forged,
                &overlays(&parsed),
                LifecycleLimits::default(),
                || true
            ),
            Err(Error::InvalidInput)
        );
    }
    Ok(())
}

#[test]
fn incomplete_or_mismatched_overlay_refuses_atomically() -> Test {
    let mut parsed = rename_fixture()?;
    let (tracks, _) = project(&parsed)?;
    let sources = inputs(&parsed);
    let mut paired = overlays(&parsed);
    paired.pop();
    assert_eq!(
        project_lifecycle(
            &sources,
            &tracks,
            &paired,
            LifecycleLimits::default(),
            || true
        ),
        Err(Error::InvalidInput)
    );
    let mut paired = overlays(&parsed);
    paired[0].source_digest = digest("wrong-xml");
    assert_eq!(
        project_lifecycle(
            &sources,
            &tracks,
            &paired,
            LifecycleLimits::default(),
            || true
        ),
        Err(Error::InvalidInput)
    );
    parsed.overlay.frames[1].objects[0].reference.object_id = Some("99".into());
    assert_eq!(
        project_lifecycle(
            &inputs(&parsed),
            &tracks,
            &overlays(&parsed),
            LifecycleLimits::default(),
            || true
        ),
        Err(Error::InvalidInput)
    );
    Ok(())
}

#[test]
fn all_shape_bounds_and_complete_output_limit_refuse_without_prefix() -> Test {
    let parsed = rename_fixture()?;
    let (tracks, _) = project(&parsed)?;
    for limits in [
        LifecycleLimits {
            max_frames: 1,
            ..LifecycleLimits::default()
        },
        LifecycleLimits {
            max_objects: 1,
            ..LifecycleLimits::default()
        },
        LifecycleLimits {
            max_references: 1,
            ..LifecycleLimits::default()
        },
        LifecycleLimits {
            max_output_bytes: 1,
            ..LifecycleLimits::default()
        },
    ] {
        assert_eq!(
            project_lifecycle(
                &inputs(&parsed),
                &tracks,
                &overlays(&parsed),
                limits,
                || true
            ),
            Err(Error::Limit)
        );
    }
    let limits = LifecycleLimits {
        max_operations: 0,
        ..LifecycleLimits::default()
    };
    assert_eq!(
        project_lifecycle(
            &inputs(&parsed),
            &tracks,
            &overlays(&parsed),
            limits,
            || true
        ),
        Err(Error::InvalidLimits)
    );
    Ok(())
}

#[test]
fn work_limit_reserves_original_reconstruction_and_reproduces_exact_threshold() -> Test {
    let parsed = rename_fixture()?;
    let (tracks, report) = project(&parsed)?;
    let sources = inputs(&parsed);
    let paired = overlays(&parsed);
    assert!(report.work_units > tracks.limits.max_work_units);
    let exact = LifecycleLimits {
        max_work_units: report.work_units,
        ..LifecycleLimits::default()
    };
    assert!(project_lifecycle(&sources, &tracks, &paired, exact, || true).is_ok());
    let below = LifecycleLimits {
        max_work_units: report.work_units - 1,
        ..LifecycleLimits::default()
    };
    assert_eq!(
        project_lifecycle(&sources, &tracks, &paired, below, || true),
        Err(Error::BudgetExceeded)
    );
    let no_oracle = LifecycleLimits {
        max_work_units: tracks.limits.max_work_units,
        ..LifecycleLimits::default()
    };
    assert_eq!(
        project_lifecycle(&sources, &tracks, &paired, no_oracle, || true),
        Err(Error::BudgetExceeded)
    );
    Ok(())
}

#[test]
fn every_admission_cut_cancels_including_the_final_checkpoint() -> Test {
    let parsed = rename_fixture()?;
    let (tracks, _) = project(&parsed)?;
    let sources = inputs(&parsed);
    let paired = overlays(&parsed);
    let mut calls = 0usize;
    project_lifecycle(
        &sources,
        &tracks,
        &paired,
        LifecycleLimits::default(),
        || {
            calls += 1;
            true
        },
    )?;
    for cut in 0..calls {
        let mut at = 0;
        assert_eq!(
            project_lifecycle(
                &sources,
                &tracks,
                &paired,
                LifecycleLimits::default(),
                || {
                    let permitted = at != cut;
                    at += 1;
                    permitted
                }
            ),
            Err(Error::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn all_debug_layers_redact_source_module_ids_time_and_uuid() -> Test {
    let op = tree(
        r#"<t:Rename><t:from ObjectId="+000123456789" UUID="private-uuid-canary"/><t:to ObjectId="987654321"/></t:Rename>"#,
    );
    let parsed = parse(&at(
        0,
        "private-module-canary",
        &(object("987654321") + &op),
    ))?;
    let (_, report) = project(&parsed)?;
    let debug = format!("{report:?}");
    for canary in [
        "private-module-canary",
        "private-uuid-canary",
        "+000123456789",
        "987654321",
        "2026-11-09T01:00:00Z",
    ] {
        assert!(!debug.contains(canary));
    }
    Ok(())
}

#[test]
fn policy_and_source_changes_bind_report_but_never_rewrite_old_occurrences() -> Test {
    let parsed = rename_fixture()?;
    let (tracks, report) = project(&parsed)?;
    let changed = project_lifecycle(
        &inputs(&parsed),
        &tracks,
        &overlays(&parsed),
        LifecycleLimits {
            max_operations: 8,
            ..LifecycleLimits::default()
        },
        || true,
    )?;
    assert_ne!(report.report_digest, changed.report_digest);
    assert_ne!(report.policy_digest, changed.policy_digest);
    assert_eq!(report.input_digest, changed.input_digest);
    assert_eq!(
        report.operations[0].identity,
        changed.operations[0].identity
    );
    assert_eq!(
        report.operations[0].from[0].observations,
        changed.operations[0].from[0].observations
    );
    let mut sources = inputs(&parsed);
    sources[0].frame_digest = digest("different-source-frame");
    let rebound = project_tracklets(&sources, tracks.limits, || true)?;
    let changed = project_lifecycle(
        &sources,
        &rebound,
        &overlays(&parsed),
        LifecycleLimits::default(),
        || true,
    )?;
    assert_ne!(report.input_digest, changed.input_digest);
    assert_ne!(report.report_digest, changed.report_digest);
    Ok(())
}

#[test]
fn empty_input_and_zero_statement_frames_remain_complete_reports() -> Test {
    let empty = parse("")?;
    let (_, report) = project(&empty)?;
    assert!(
        report.frames.is_empty() && report.operations.is_empty() && report.behaviours.is_empty()
    );
    let parsed = parse(&(at(0, "m", "") + &at(1, "m", "<t:ObjectTree/>")))?;
    let (_, report) = project(&parsed)?;
    assert_eq!(report.frames.len(), 2);
    assert_eq!(report.frames[1].object_tree_child_index, Some(0));
    assert!(
        report
            .frames
            .iter()
            .all(|frame| frame.occurrence_count == 0 && frame.operation_count == 0)
    );
    Ok(())
}

#[test]
fn normative_merge_and_split_can_preserve_one_existing_integer() -> Test {
    let merge = tree(
        r#"<t:Merge><t:from ObjectId="12"/><t:from ObjectId="17"/><t:to ObjectId="12"/></t:Merge>"#,
    );
    let split = tree(
        r#"<t:Split><t:from ObjectId="12"/><t:to ObjectId="12"/><t:to ObjectId="17"/></t:Split>"#,
    );
    let parsed = parse(
        &(at(0, "m", &(object("12") + &object("17")))
            + &at(1, "m", &(object("12") + &merge))
            + &at(2, "m", &(object("12") + &object("17") + &split))),
    )?;
    let (_, report) = project(&parsed)?;
    assert!(
        report
            .operations
            .iter()
            .all(|row| row.state == State::Observed)
    );
    assert!(
        report
            .operations
            .iter()
            .flat_map(|row| row.from.iter().chain(&row.to))
            .all(|row| row.issues.is_empty())
    );
    assert_eq!(report.operations[0].to[0].observations.len(), 2);
    assert_eq!(report.operations[1].to[0].observations.len(), 2);
    Ok(())
}

fn json(report: &LifecycleReport, include_values: bool) -> Result<String, std::fmt::Error> {
    let mut output = String::new();
    lifecycle_json::write_json(&mut output, report, include_values)?;
    Ok(output)
}
fn json_field<'a>(
    value: &'a fss_core::json_input::Value,
    key: &str,
) -> Checked<&'a fss_core::json_input::Value> {
    value
        .object()
        .and_then(|value| value.get(key))
        .ok_or_else(|| format!("missing JSON field {key}").into())
}
fn json_rows<'a>(
    value: &'a fss_core::json_input::Value,
    key: &str,
) -> Checked<&'a [fss_core::json_input::Value]> {
    json_field(value, key)?
        .array()
        .ok_or_else(|| "expected JSON array".into())
}

#[test]
fn actual_json_renderer_defaults_to_private_values_and_closed_source_references() -> Test {
    let parsed = rename_fixture()?;
    let (tracks, report) = project(&parsed)?;
    let output = json(&report, false)?;
    let value = fss_core::json_input::parse(&output)?;
    assert_eq!(
        value
            .object()
            .ok_or("object")?
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "generation",
            "report_digest",
            "policy_digest",
            "input_digest",
            "tracklet_report_digest",
            "work_units",
            "encoded_bytes",
            "limits",
            "frames",
            "operations",
            "behaviours",
            "reuses"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        json_field(&value, "tracklet_report_digest")?.text(),
        Some(tracks.report_digest.to_text().as_str())
    );
    let frames = json_rows(&value, "frames")?;
    assert_eq!(frames.len(), 2);
    assert!(matches!(
        json_field(&frames[0], "values")?,
        fss_core::json_input::Value::Null
    ));
    assert_eq!(
        json_field(&frames[0], "source_digest")?.text(),
        Some(parsed.digest.to_text().as_str())
    );
    let operation = &json_rows(&value, "operations")?[0];
    let from = &json_rows(operation, "from")?[0];
    let reference = json_field(from, "reference")?;
    assert!(matches!(
        json_field(reference, "values")?,
        fss_core::json_input::Value::Null
    ));
    let observed = &json_rows(from, "observations")?[0];
    assert_eq!(
        json_field(observed, "occurrence_identity")?.text(),
        Some(tracks.occurrences[0].identity.to_text().as_str())
    );
    assert_eq!(
        json_field(observed, "tracklet_identity")?.text(),
        Some(tracks.occurrences[0].tracklet_identity.to_text().as_str())
    );
    assert!(
        !output.contains("+002")
            && !output.contains("2026-11-09T01:00:01Z")
            && !output.contains("motion")
    );
    Ok(())
}

#[test]
fn disclosed_json_escapes_modules_preserves_integer_spellings_and_never_discloses_uuid() -> Test {
    let module = "private-module &quot;quoted&quot; \\ 路線&#x2028;";
    let operation = tree(
        r#"<t:Rename><t:from ObjectId="+000123456789" UUID="private-uuid-canary"/><t:to ObjectId="987654321"/></t:Rename>"#,
    );
    let parsed = parse(&at(0, module, &(object("987654321") + &operation)))?;
    let (_, report) = project(&parsed)?;
    let hidden = json(&report, false)?;
    let shown = json(&report, true)?;
    assert!(
        !hidden.contains("private-module")
            && !hidden.contains("123456789")
            && !hidden.contains("987654321")
    );
    assert!(!hidden.contains("private-uuid-canary") && !shown.contains("private-uuid-canary"));
    let value = fss_core::json_input::parse(&shown)?;
    let frame = &json_rows(&value, "frames")?[0];
    assert_eq!(
        json_field(json_field(frame, "values")?, "module_source")?.text(),
        Some("private-module \"quoted\" \\ 路線\u{2028}")
    );
    let reference = json_field(
        &json_rows(&json_rows(&value, "operations")?[0], "from")?[0],
        "reference",
    )?;
    assert_eq!(
        json_field(json_field(reference, "values")?, "object_id")?.text(),
        Some("+000123456789")
    );
    assert!(matches!(
        json_field(reference, "uuid_present")?,
        fss_core::json_input::Value::Bool(true)
    ));
    assert_eq!(reference.object().ok_or("object")?.len(), 4);
    Ok(())
}

struct FiniteWriter {
    value: String,
    maximum: usize,
    calls: usize,
    cancel_at: Option<usize>,
}
impl std::fmt::Write for FiniteWriter {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let call = self.calls;
        self.calls += 1;
        if self.cancel_at == Some(call)
            || self
                .value
                .len()
                .checked_add(text.len())
                .is_none_or(|total| total > self.maximum)
        {
            return Err(std::fmt::Error);
        }
        self.value.push_str(text);
        Ok(())
    }
}

#[test]
fn renderer_propagates_capacity_and_admission_refusals_without_success() -> Test {
    let (_, report) = project(&rename_fixture()?)?;
    let expected = json(&report, true)?;
    for maximum in [0, 1, 256, expected.len() - 1, expected.len()] {
        let mut writer = FiniteWriter {
            value: String::new(),
            maximum,
            calls: 0,
            cancel_at: None,
        };
        let result = lifecycle_json::write_json(&mut writer, &report, true);
        assert_eq!(result.is_ok(), maximum == expected.len());
        assert!(writer.value.len() <= maximum);
        if result.is_ok() {
            assert_eq!(writer.value, expected);
        }
    }
    let mut complete = FiniteWriter {
        value: String::new(),
        maximum: expected.len(),
        calls: 0,
        cancel_at: None,
    };
    lifecycle_json::write_json(&mut complete, &report, true)?;
    for cut in [0, complete.calls / 2, complete.calls - 1] {
        let mut writer = FiniteWriter {
            value: String::new(),
            maximum: expected.len(),
            calls: 0,
            cancel_at: Some(cut),
        };
        assert!(lifecycle_json::write_json(&mut writer, &report, true).is_err());
    }
    Ok(())
}

#[test]
fn renderer_keeps_deletion_reuse_and_both_behaviour_flags_separate() -> Test {
    let parsed = parse(
        &(at(0, "m", &tree(r#"<t:Delete ObjectId="5"/>"#))
            + &at(
                1,
                "m",
                r#"<t:Object ObjectId="5"><t:Behaviour><t:Idle/><t:Removed/></t:Behaviour></t:Object>"#,
            )),
    )?;
    let (_, report) = project(&parsed)?;
    let value = fss_core::json_input::parse(&json(&report, false)?)?;
    let behaviour = &json_rows(&value, "behaviours")?[0];
    assert!(matches!(
        json_field(behaviour, "idle")?,
        fss_core::json_input::Value::Bool(true)
    ));
    assert!(matches!(
        json_field(behaviour, "removed")?,
        fss_core::json_input::Value::Bool(true)
    ));
    assert_eq!(json_field(behaviour, "state")?.text(), Some("conflicted"));
    let reuse = &json_rows(&value, "reuses")?[0];
    assert_eq!(
        json_field(reuse, "deleted_by_operation")?.text(),
        Some(report.operations[0].identity.to_text().as_str())
    );
    Ok(())
}
