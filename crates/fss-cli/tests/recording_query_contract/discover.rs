#![forbid(unsafe_code)]
//! Complete namespace discovery through the real CLI and protected deployment owner.

use super::*;
use fss_reference::rtsp::recording_archive::{ArchiveNamespace, hevc::HevcArchiveNamespace};

fn canonical_slots(fixture: &Fixture, ordinal: usize) -> TestResult<(SlotName, SlotName)> {
    let scope = fixture.request.recording.scope.clone();
    Ok(match fixture.request.recording.codec {
        RecordingQueryCodec::Avc => {
            let namespace = ArchiveNamespace::new(scope)?;
            (
                namespace.window_slot(ordinal)?,
                namespace.page_slot(ordinal)?,
            )
        }
        RecordingQueryCodec::Hevc => {
            let namespace = HevcArchiveNamespace::new(scope)?;
            (
                namespace.window_slot(ordinal)?,
                namespace.page_slot(ordinal)?,
            )
        }
    })
}

/// Real native windows and independently sealed one-window pages; no source payload files.
fn canonical_archive(fixture: &Fixture) -> TestResult<Vec<(SlotName, ContentDigest)>> {
    let mut pages = Vec::new();
    for ordinal in 0..2 {
        let (slot, page_slot) = canonical_slots(fixture, ordinal)?;
        let scope = fixture.request.recording.scope.clone();
        let (manifest, index) = match fixture.request.recording.codec {
            RecordingQueryCodec::Avc => {
                let window = if ordinal == 0 {
                    avc_window(1, 3600)?
                } else {
                    avc_window(3, 10800)?
                };
                publish(&fixture.archive, &slot, window.manifest())?;
                let page = prepare_catalog(
                    scope,
                    &[CatalogWindow {
                        slot: &slot,
                        recording: &window,
                    }],
                )?;
                (page.manifest().clone(), page.index_bytes().to_vec())
            }
            RecordingQueryCodec::Hevc => {
                let window =
                    hevc_catalog_support::window(if ordinal == 0 { 1_000 } else { 100_000 })?;
                publish(&fixture.archive, &slot, window.manifest())?;
                let page = prepare_hevc_catalog(
                    scope,
                    &[HevcCatalogWindow {
                        slot: &slot,
                        recording: &window,
                    }],
                )?;
                (page.manifest().clone(), page.index_bytes().to_vec())
            }
        };
        put(&fixture.archive, &index)?;
        publish(&fixture.archive, &page_slot, &manifest)?;
        pages.push((page_slot, manifest.root()));
    }
    Ok(pages)
}

fn args(fixture: &Fixture) -> TestResult<Vec<OsString>> {
    let mut args = fixture.args();
    for flag in ["--catalog-slot", "--catalog-root"] {
        let at = args
            .iter()
            .position(|arg| arg == flag)
            .ok_or("missing singleton fixture flag")?;
        args.drain(at..at + 2);
    }
    args.extend(["--discover-catalogs".into(), "yes".into()]);
    Ok(args)
}

fn replace(args: &mut [OsString], flag: &str, value: &str) -> TestResult {
    let at = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or("fixture flag")?;
    args[at + 1] = value.into();
    Ok(())
}

fn run(args: Vec<OsString>) -> TestResult<(String, ExitIdentity)> {
    let answer = execute_fss_with_exit(parse_fss_args(args.clone())?);
    let process = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    assert_eq!(process.status.code(), Some(i32::from(answer.1.code)));
    assert_eq!(
        String::from_utf8(process.stdout)?,
        format!("{}\n", answer.0)
    );
    assert!(process.stderr.is_empty());
    parse_json(&answer.0)?;
    Ok(answer)
}

#[test]
fn actual_avc_and_hevc_discovery_returns_current_context_and_exact_metadata_handles() -> TestResult
{
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = Fixture::new(&format!("discover-{}", codec.as_str()), codec)?;
        fixture.publish_hypothesis("event:protected-discovery")?;
        canonical_archive(&fixture)?;
        let before = tree(&fixture.directory)?;
        let (output, exit) = run(args(&fixture)?)?;
        assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
        let envelope = parse_json(&output)?;
        assert_eq!(text_at(&envelope, &["principalId"])?, PRINCIPAL);
        assert_eq!(
            text_at(&envelope, &["payload", "coverage", "stopReason"])?,
            "archive_namespace_exhausted"
        );
        assert_eq!(
            text_at(
                proposition(
                    &envelope,
                    "claim:recordings-discovery:physical-observability"
                )?,
                &["state"]
            )?,
            "unknown"
        );
        let inventory = text_at(
            proposition(&envelope, "claim:recordings-discovery:inventory")?,
            &["statement"],
        )?;
        assert!(inventory.contains("catalogs=2"), "{inventory}");
        assert!(inventory.contains("scanned_windows=2"), "{inventory}");
        assert!(inventory.contains("selected_windows=2"), "{inventory}");
        assert!(output.contains("event:protected-discovery"));
        let handles = at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?;
        assert_eq!(handles.len(), 4);
        for handle in handles {
            assert_eq!(text_at(handle, &["hydration"])?, "H0");
            assert_eq!(
                at(handle, &["allowedHydration"])?
                    .array()
                    .ok_or("hydration")?,
                &[Value::Text("H0".to_owned())]
            );
        }
        for cell in propositions(&envelope)? {
            if text_at(cell, &["id"])?.starts_with("claim:recordings-discovery:indexed-gap:") {
                assert_eq!(text_at(cell, &["state"])?, "not_observable");
            }
        }
        assert_eq!(tree(&fixture.directory)?, before);
    }
    Ok(())
}

#[test]
fn narrow_discovery_keeps_full_inventory_identity_but_projects_only_selected_catalogs() -> TestResult
{
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = Fixture::new(&format!("discover-narrow-{}", codec.as_str()), codec)?;
        canonical_archive(&fixture)?;
        let mut args = args(&fixture)?;
        replace(
            &mut args,
            "--end-tick",
            if codec == RecordingQueryCodec::Avc {
                "3601"
            } else {
                "1001"
            },
        )?;
        let (output, exit) = run(args)?;
        assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
        let envelope = parse_json(&output)?;
        let inventory = text_at(
            proposition(&envelope, "claim:recordings-discovery:inventory")?,
            &["statement"],
        )?;
        assert!(inventory.contains("catalogs=2"));
        assert!(inventory.contains("selected_windows=1"));
        assert_eq!(
            at(&envelope, &["payload", "evidenceHandles"])?
                .array()
                .ok_or("handles")?
                .len(),
            2
        );
        assert!(proposition(&envelope, "claim:recordings-discovery:catalog:0").is_ok());
        assert!(proposition(&envelope, "claim:recordings-discovery:catalog:1").is_err());
    }
    Ok(())
}

#[test]
fn empty_namespace_is_explicit_unknown_coverage_with_current_hypotheses() -> TestResult {
    let fixture = Fixture::new("discover-empty", RecordingQueryCodec::Avc)?;
    // The fixture's manually named catalog is outside the canonical namespace.
    fixture.publish_hypothesis("event:discovery-no-index")?;
    let before = tree(&fixture.directory)?;
    let (output, exit) = run(args(&fixture)?)?;
    assert_eq!(exit, ExitIdentity::SUCCESS, "{output}");
    let envelope = parse_json(&output)?;
    let inventory = text_at(
        proposition(&envelope, "claim:recordings-discovery:inventory")?,
        &["statement"],
    )?;
    assert!(inventory.contains("catalogs=0"));
    assert!(inventory.contains("selected_windows=0"));
    assert_eq!(
        text_at(
            proposition(&envelope, "claim:recordings-discovery:indexed-gap:0")?,
            &["state"]
        )?,
        "not_observable"
    );
    assert_eq!(
        text_at(
            proposition(
                &envelope,
                "claim:recordings-discovery:physical-observability"
            )?,
            &["state"]
        )?,
        "unknown"
    );
    assert!(output.contains("event:discovery-no-index"));
    assert!(
        at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?
            .is_empty()
    );
    assert_eq!(tree(&fixture.directory)?, before);
    Ok(())
}

#[test]
fn discovery_output_overflow_refuses_without_a_successful_prefix() -> TestResult {
    let fixture = Fixture::new("discover-output-limit", RecordingQueryCodec::Avc)?;
    canonical_archive(&fixture)?;
    let mut args = args(&fixture)?;
    replace(&mut args, "--max-windows", "1")?;
    let before = tree(&fixture.directory)?;
    let (output, exit) = run(args)?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{output}");
    assert!(!output.contains("claim:recordings-discovery:window:"));
    assert!(!output.contains("archive_namespace_exhausted"));
    assert_eq!(tree(&fixture.directory)?, before);
    Ok(())
}

#[test]
fn unselected_corruption_or_an_unindexed_tail_invalidates_the_actual_discovery_query() -> TestResult
{
    for tail in [false, true] {
        let fixture = Fixture::new(
            if tail {
                "discover-tail"
            } else {
                "discover-corrupt"
            },
            RecordingQueryCodec::Avc,
        )?;
        let pages = canonical_archive(&fixture)?;
        let mut args = args(&fixture)?;
        replace(&mut args, "--end-tick", "3601")?;
        if tail {
            let (slot, _) = canonical_slots(&fixture, 2)?;
            publish(&fixture.archive, &slot, avc_window(5, 18000)?.manifest())?;
        } else {
            fs::write(
                object_path(&fixture.archive, pages[1].1),
                b"corrupt unselected catalog",
            )?;
        }
        let before = tree(&fixture.directory)?;
        let (output, exit) = run(args)?;
        assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{output}");
        assert!(!output.contains("claim:recordings-discovery:window:"));
        assert!(!output.contains("archive_namespace_exhausted"));
        assert_eq!(tree(&fixture.directory)?, before);
    }
    Ok(())
}
