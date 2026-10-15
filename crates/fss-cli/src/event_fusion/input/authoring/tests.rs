#![forbid(unsafe_code)]
use super::*;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}
fn request() -> Value {
    parse(r#"{
      "schema":"fss.event_class_fusion_counts.v1",
      "class_index":0,"prior":[-500,-500],"looks":1,"now_ns":9007199254740993,
      "policy":{"generation":"policy:test","alert_threshold":1000,
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
    }"#).unwrap()
}
fn build(request: &Value) -> Result<EventFusionProfile> {
    let json = encode(request)?;
    EventFusionProfile::from_counts_json(
        json.as_bytes(), ContentDigest::sha256(json.as_bytes()),
        d("plan"), d("cascade"), &BTreeSet::from([d("coverage")]),
    )
}
fn root(value: &mut Value) -> &mut Object {
    match value {
        Value::Object(value) => value,
        _ => panic!("object fixture"),
    }
}
fn table(value: &mut Value) -> &mut Object {
    let bindings = root(value).get_mut("calibrations").unwrap();
    let Value::Array(bindings) = bindings else { panic!("array fixture") };
    root(root(&mut bindings[0]).get_mut("calibration").unwrap())
}

#[test]
fn authoring_reconstructs_native_counts_and_roundtrips_complete_profile() -> Test {
    let profile = build(&request())?;
    let expected = ScoreCalibration::from_counts(
        "camera-mode-v1", &[0, 500_000], &[(100, 9900), (9900, 100)],
    )?;
    assert_eq!(profile.spec().calibrations[0].calibration.digest, expected.digest);
    let output = profile.to_json()?;
    let restored = EventFusionProfile::from_json(
        output.as_bytes(), ContentDigest::sha256(output.as_bytes()),
    )?;
    assert_eq!(restored.digest(), profile.digest());
    assert_eq!(restored.to_json()?, output);
    assert_eq!(restored.spec().now_ns, 9_007_199_254_740_993);
    assert_eq!(restored.spec().plan_digest, d("plan"));
    assert_eq!(restored.spec().cascade_digest, d("cascade"));
    assert_eq!(restored.spec().coverage_digests, BTreeSet::from([d("coverage")]));
    assert!(output.contains("wilson_z2_per_bin_not_simultaneous"));
    assert!(output.contains("llr_millibans"));
    assert!(output.contains("shared:weather"));
    Ok(())
}

#[test]
fn request_cannot_override_scope_or_inject_derived_values() {
    for key in ["plan_digest", "cascade_digest", "coverage_digests", "effect_authority"] {
        let mut value = request();
        root(&mut value).insert(key.to_owned(), text_value(d("foreign")));
        assert!(build(&value).is_err(), "{key}");
    }
    for key in ["digest", "prior_log_odds_millibans", "probability", "interval"] {
        let mut value = request();
        table(&mut value).insert(key.to_owned(), text_value("untrusted"));
        assert!(build(&value).is_err(), "{key}");
    }
}

#[test]
fn no_policy_prior_clock_or_consequence_default_is_invented() {
    for key in ["prior", "policy", "severity", "looks", "now_ns", "class_index"] {
        let mut value = request();
        root(&mut value).remove(key);
        assert!(build(&value).is_err(), "{key}");
    }
    let mut value = request();
    root(&mut value).insert("looks".to_owned(), numeric(0));
    assert!(build(&value).is_err());
}

#[test]
fn changed_counts_change_both_native_calibration_and_profile_identity() -> Test {
    let first = build(&request())?;
    let mut value = request();
    let Value::Array(bins) = table(&mut value).get_mut("bins").unwrap() else {
        panic!("bins fixture")
    };
    root(&mut bins[0]).insert("true_positives".to_owned(), numeric(101));
    let second = build(&value)?;
    assert_ne!(first.digest(), second.digest());
    assert_ne!(
        first.spec().calibrations[0].calibration.digest,
        second.spec().calibrations[0].calibration.digest,
    );
    Ok(())
}

#[test]
fn native_validation_refuses_duplicate_sensors_domains_and_invalid_bins() {
    let mut value = request();
    let Value::Array(bindings) = root(&mut value).get_mut("calibrations").unwrap() else {
        panic!("bindings fixture")
    };
    bindings.push(bindings[0].clone());
    assert!(build(&value).is_err());
    let mut value = request();
    let Value::Array(bindings) = root(&mut value).get_mut("calibrations").unwrap() else {
        panic!("bindings fixture")
    };
    root(&mut bindings[0]).insert(
        "failure_domains".to_owned(),
        Value::Array(vec![text_value("same"), text_value("same")]),
    );
    assert!(build(&value).is_err());
    let mut value = request();
    table(&mut value).insert("bins".to_owned(), Value::Array(Vec::new()));
    assert!(build(&value).is_err());
}

#[test]
fn raw_digest_duplicate_json_keys_and_input_bound_are_enforced() {
    let bytes = encode(&request()).unwrap();
    assert!(EventFusionProfile::from_counts_json(
        bytes.as_bytes(), d("wrong bytes"), d("plan"), d("cascade"),
        &BTreeSet::from([d("coverage")]),
    ).is_err());
    for bytes in [
        br#"{"schema":"one","schema":"two"}"#.to_vec(),
        vec![0xff],
        vec![b' '; MAX_PROFILE_BYTES + 1],
        Vec::new(),
    ] {
        assert!(EventFusionProfile::from_counts_json(
            &bytes, ContentDigest::sha256(&bytes), d("plan"), d("cascade"),
            &BTreeSet::from([d("coverage")]),
        ).is_err());
    }
}

#[test]
fn escaped_text_and_exact_output_bound_are_preserved() -> Test {
    let value = text_value("\"quoted\"\\line\n\tλ");
    assert_eq!(parse(&encode(&value)?)?, value);
    assert_eq!(encode(&text_value("x".repeat(MAX_PROFILE_BYTES - 2)))?.len(), MAX_PROFILE_BYTES);
    assert_eq!(encode(&text_value("x".repeat(MAX_PROFILE_BYTES - 1))), Err(EventFusionError::Limit));
    Ok(())
}
