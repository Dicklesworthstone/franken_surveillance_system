#![forbid(unsafe_code)]
//! Multi-catalog projection through the actual fss binary and shared library entrypoint.

use super::*;

fn add_catalog(fixture: &Fixture) -> TestResult<(SlotName, ContentDigest)> {
    let repeated_slot = SlotName::parse("first-window")?;
    let third_slot = SlotName::parse("third-window")?;
    let scope = fixture.request.recording.scope.clone();
    let (manifest, bytes) = match fixture.request.recording.codec {
        RecordingQueryCodec::Avc => {
            let repeated = avc_window(1, 3600)?;
            let third = avc_window(5, 18000)?;
            publish(&fixture.archive, &third_slot, third.manifest())?;
            let catalog = prepare_catalog(
                scope,
                &[
                    CatalogWindow {
                        slot: &repeated_slot,
                        recording: &repeated,
                    },
                    CatalogWindow {
                        slot: &third_slot,
                        recording: &third,
                    },
                ],
            )?;
            (catalog.manifest().clone(), catalog.index_bytes().to_vec())
        }
        RecordingQueryCodec::Hevc => {
            let repeated = hevc_catalog_support::window(1_000)?;
            let third = hevc_catalog_support::window(200_000)?;
            publish(&fixture.archive, &third_slot, third.manifest())?;
            let catalog = prepare_hevc_catalog(
                scope,
                &[
                    HevcCatalogWindow {
                        slot: &repeated_slot,
                        recording: &repeated,
                    },
                    HevcCatalogWindow {
                        slot: &third_slot,
                        recording: &third,
                    },
                ],
            )?;
            (catalog.manifest().clone(), catalog.index_bytes().to_vec())
        }
    };
    let slot = SlotName::parse("catalog-second")?;
    put(&fixture.archive, &bytes)?;
    publish(&fixture.archive, &slot, &manifest)?;
    Ok((slot, manifest.root()))
}

fn args(
    fixture: &Fixture,
    second: &(SlotName, ContentDigest),
    reverse: bool,
) -> TestResult<Vec<OsString>> {
    let mut args = fixture.args();
    for flag in ["--catalog-slot", "--catalog-root"] {
        let at = args
            .iter()
            .position(|arg| arg == flag)
            .ok_or("missing singleton fixture flag")?;
        args.drain(at..at + 2);
    }
    let end = args
        .iter()
        .position(|arg| arg == "--end-tick")
        .ok_or("missing end")?;
    args[end + 1] = "400000".into();
    let mut pins = [
        format!(
            "{}={}",
            fixture.request.recording.catalog_slot.as_str(),
            fixture.request.recording.catalog_root
        ),
        format!("{}={}", second.0.as_str(), second.1),
    ];
    if reverse {
        pins.reverse();
    }
    args.extend(["--catalogs".into(), pins.join(",").into()]);
    Ok(args)
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
fn actual_avc_and_hevc_catalog_sets_preserve_unique_handles_gaps_and_current_context() -> TestResult
{
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = Fixture::new(&format!("set-{}", codec.as_str()), codec)?;
        fixture.publish_hypothesis("event:protected-catalog-set")?;
        let second = add_catalog(&fixture)?;
        let before = tree(&fixture.directory)?;
        let answer = run(args(&fixture, &second, false)?)?;
        assert_eq!(answer.1, ExitIdentity::SUCCESS, "{}", answer.0);
        assert_eq!(run(args(&fixture, &second, true)?)?, answer);
        let envelope = parse_json(&answer.0)?;
        assert_eq!(text_at(&envelope, &["outcome"])?, "ok");
        assert_eq!(text_at(&envelope, &["principalId"])?, PRINCIPAL);
        assert_eq!(
            text_at(&envelope, &["payload", "coverage", "stopReason"])?,
            "pinned_catalog_set_exhausted"
        );
        assert_eq!(
            text_at(
                proposition(&envelope, "claim:recordings-set:physical-observability")?,
                &["state"]
            )?,
            "unknown"
        );
        let selection = text_at(
            proposition(&envelope, "claim:recordings-set:catalog-selection")?,
            &["statement"],
        )?;
        assert!(selection.contains("scanned_descriptors=4"));
        assert!(selection.contains("unique_windows=3"));
        assert!(selection.contains("selected_windows=3"));
        assert!(
            answer.0.contains("event:protected-catalog-set"),
            "current protected context was lost"
        );
        let handles = at(&envelope, &["payload", "evidenceHandles"])?
            .array()
            .ok_or("handles")?;
        assert_eq!(handles.len(), 5);
        for handle in handles {
            assert_eq!(text_at(handle, &["hydration"])?, "H0");
            assert_eq!(
                at(handle, &["allowedHydration"])?
                    .array()
                    .ok_or("hydration")?,
                &[Value::Text("H0".to_owned())]
            );
        }
        let first = text_at(
            proposition(&envelope, "claim:recordings-set:window:0")?,
            &["statement"],
        )?;
        assert!(first.contains("catalog_index:ordinal=[0:0,1:0]"));
        for cell in propositions(&envelope)? {
            if text_at(cell, &["id"])?.starts_with("claim:recordings-set:indexed-gap:") {
                assert_eq!(text_at(cell, &["state"])?, "not_observable");
            }
        }
        assert_eq!(tree(&fixture.directory)?, before);
    }
    Ok(())
}

#[test]
fn catalog_set_actual_cli_refuses_overflow_without_returning_a_successful_prefix() -> TestResult {
    let fixture = Fixture::new("set-result-limit", RecordingQueryCodec::Avc)?;
    let second = add_catalog(&fixture)?;
    let mut args = args(&fixture, &second, false)?;
    let at = args
        .iter()
        .position(|arg| arg == "--max-windows")
        .ok_or("missing limit")?;
    args[at + 1] = "2".into();
    let before = tree(&fixture.directory)?;
    let (output, exit) = run(args)?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{output}");
    assert!(!output.contains("claim:recordings-set:window:"));
    assert!(!output.contains("pinned_catalog_set_exhausted"));
    assert_eq!(tree(&fixture.directory)?, before);
    Ok(())
}

#[test]
fn unselected_corrupt_catalog_invalidates_the_entire_actual_cli_query() -> TestResult {
    let fixture = Fixture::new("set-late-corruption", RecordingQueryCodec::Avc)?;
    let second = add_catalog(&fixture)?;
    let mut args = args(&fixture, &second, false)?;
    let end = args
        .iter()
        .position(|arg| arg == "--end-tick")
        .ok_or("missing end")?;
    args[end + 1] = "3601".into();
    fs::write(object_path(&fixture.archive, second.1), b"corrupt manifest")?;
    let before = tree(&fixture.directory)?;
    let (output, exit) = run(args)?;
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{output}");
    assert!(!output.contains("claim:recordings-set:window:"));
    assert_eq!(tree(&fixture.directory)?, before);
    Ok(())
}
