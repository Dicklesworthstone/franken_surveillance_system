#![forbid(unsafe_code)]
//! Native process contracts for inert profile authoring, not activation or source validation.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use fss_cli::event_fusion::EventFusionProfile;
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const COUNTS: &str = r#"{
  "schema":"fss.event_class_fusion_counts.v1",
  "class_index":0,"prior":[-500,-500],"looks":1,"now_ns":9007199254740993,
  "policy":{"generation":"policy:operator","alert_threshold":1000,
    "retain_threshold":-500,"reject_threshold":-1500,"min_independent_support":2,
    "urgent_single_domain_threshold":null,"max_wait_ns":10,
    "look_penalty_per_doubling":301,"operator_confirmation_available":true},
  "severity":{"expected_harm":1000,"false_alert_cost":10,
    "delay_cost_per_second":0,"reversible":false},
  "calibrations":[{"sensor":"sensor:a","failure_domains":["shared:weather"],
    "calibration":{"schema":"fss.score_calibration_counts.v1",
      "generation":"camera-mode-v1","bins":[
        {"lo_ppm":0,"true_positives":100,"false_positives":9900},
        {"lo_ppm":500000,"true_positives":9900,"false_positives":100}]}}]
}"#;
fn pin(bytes: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(bytes.as_ref())
}
fn args(paired: bool, bytes: &[u8]) -> Vec<String> {
    vec![
        "--scope".into(),
        if paired { "corroborate" } else { "watch" }.into(),
        "--counts-digest".into(),
        pin(bytes).to_text(),
        "--analysis-digest".into(),
        pin("complete analysis").to_text(),
        "--detector-recipe-digest".into(),
        pin("native recipe").to_text(),
        "--analysis-roots".into(),
        if paired {
            format!("{},{}", pin("camera a"), pin("camera b"))
        } else {
            pin("camera a").to_text()
        },
    ]
}
fn run(args: &[String], bytes: &[u8]) -> Test<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-fusion-profile"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Every test document fits a bounded pipe payload except the explicit oversize test.
    // A broken pipe is expected when pure argument validation or the byte bound refuses.
    let mut input = child.stdin.take().ok_or("missing child stdin")?;
    let sent = input.write_all(bytes);
    drop(input);
    if let Err(error) = sent
        && error.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(error.into());
    }
    Ok(child.wait_with_output()?)
}
fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|o| o.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}
fn success(output: &Output) -> Test<&str> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    Ok(std::str::from_utf8(&output.stdout)?)
}

#[test]
fn both_scopes_emit_exact_reusable_native_profiles() -> Test {
    for paired in [false, true] {
        let output = run(&args(paired, COUNTS.as_bytes()), COUNTS.as_bytes())?;
        let text = success(&output)?;
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
        let profile = EventFusionProfile::from_json(&output.stdout, pin(&output.stdout))?;
        assert_eq!(profile.spec().plan_digest, pin("complete analysis"));
        assert_eq!(profile.spec().cascade_digest, pin("native recipe"));
        assert_eq!(profile.spec().now_ns, 9_007_199_254_740_993);
        assert_eq!(profile.spec().looks, 1);
        assert!(profile.spec().coverage_digests.is_empty());
        assert_eq!(profile.spec().calibrations[0].calibration.positives, 10_000);
        if paired {
            assert_eq!(
                profile.long_corroboration_analysis_roots(),
                Some([pin("camera a"), pin("camera b")])
            );
            assert_eq!(profile.long_watch_analysis_root(), None);
        } else {
            assert_eq!(profile.long_watch_analysis_root(), Some(pin("camera a")));
            assert_eq!(profile.long_corroboration_analysis_roots(), None);
        }
        assert_eq!(text, profile.to_json()? + "\n");
        assert_eq!(
            run(&args(paired, COUNTS.as_bytes()), COUNTS.as_bytes())?.stdout,
            output.stdout
        );
    }
    Ok(())
}

#[test]
fn report_digest_names_exact_profile_file_bytes_including_newline() -> Test {
    let plain_args = args(true, COUNTS.as_bytes());
    let plain = run(&plain_args, COUNTS.as_bytes())?;
    success(&plain)?;
    let mut report_args = plain_args;
    report_args.extend(["--format".into(), "report".into()]);
    let output = run(&report_args, COUNTS.as_bytes())?;
    let report = parse(success(&output)?)?;
    let profile = EventFusionProfile::from_json(&plain.stdout, pin(&plain.stdout))?;
    assert_eq!(
        field(&report, "profile_file_digest")?.text(),
        Some(pin(&plain.stdout).to_text().as_str())
    );
    assert_eq!(
        field(&report, "profile_digest")?.text(),
        Some(profile.digest().to_text().as_str())
    );
    assert_eq!(
        field(&report, "profile_file_bytes")?.integer(),
        Some(plain.stdout.len() as i128)
    );
    assert_eq!(field(&report, "profile")?, &parse(success(&plain)?)?);
    for key in ["source_scope_verified", "published", "effect_authority"] {
        assert_eq!(field(&report, key)?.boolean(), Some(false));
    }
    Ok(())
}

#[test]
fn cardinality_duplicates_unknown_flags_and_missing_scope_refuse_before_reading() -> Test {
    let original = args(true, COUNTS.as_bytes());
    let mut cases = Vec::new();
    for roots in [
        pin("camera a").to_text(),
        format!("{0},{0}", pin("camera a")),
        format!("{},{},{}", pin("a"), pin("b"), pin("c")),
        "sha256:bad".into(),
    ] {
        let mut changed = original.clone();
        changed[9] = roots;
        cases.push(changed);
    }
    for (key, value) in [
        ("--approve", "yes"),
        ("--format", "invalid"),
        ("--scope", "watch"),
    ] {
        let mut changed = original.clone();
        changed.extend([key.into(), value.into()]);
        cases.push(changed);
    }
    cases.push(original[2..].to_vec());
    for case in cases {
        let output = run(&case, b"")?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}

#[test]
fn scope_and_derived_value_injection_in_counts_cannot_override_external_pins() -> Test {
    for injection in [
        "\"analysis_digest\":\"foreign\",",
        "\"coverage_digests\":[],",
        "\"long_corroboration_analysis_roots\":[],",
        "\"effect_authority\":true,",
    ] {
        let document = COUNTS.replacen('{', &format!("{{{injection}"), 1);
        let output = run(&args(true, document.as_bytes()), document.as_bytes())?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    let document = COUNTS.replace(
        "\"generation\":\"camera-mode-v1\"",
        "\"generation\":\"camera-mode-v1\",\"digest\":\"forged\"",
    );
    let output = run(&args(true, document.as_bytes()), document.as_bytes())?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn corrupted_non_utf8_and_oversized_documents_fail_without_output_or_input_echo() -> Test {
    let mut invalid = args(true, COUNTS.as_bytes());
    invalid[3] = pin("different bytes").to_text();
    let output = run(&invalid, COUNTS.as_bytes())?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    for bytes in [vec![0xff, 0xfe], vec![b'x'; 256 * 1024 + 1]] {
        let output = run(&args(true, &bytes), &bytes)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.len() < 200);
    }
    Ok(())
}

#[test]
fn changing_order_or_labelled_counts_requires_a_new_profile_digest() -> Test {
    let a = run(&args(true, COUNTS.as_bytes()), COUNTS.as_bytes())?;
    let mut reordered = args(true, COUNTS.as_bytes());
    reordered[9] = format!("{},{}", pin("camera b"), pin("camera a"));
    let b = run(&reordered, COUNTS.as_bytes())?;
    success(&a)?;
    success(&b)?;
    assert_ne!(pin(&a.stdout), pin(&b.stdout));
    let counts = COUNTS.replacen("\"true_positives\":100", "\"true_positives\":101", 1);
    let changed = run(&args(true, counts.as_bytes()), counts.as_bytes())?;
    success(&changed)?;
    assert_ne!(pin(&a.stdout), pin(&changed.stdout));
    Ok(())
}
