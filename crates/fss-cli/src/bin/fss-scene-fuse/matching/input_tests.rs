#![forbid(unsafe_code)]

use super::*;

fn pin(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}
fn fixture() -> String {
    let view = |camera: u64| {
        format!(
            r#"{{"camera":{camera},"source_digest":"{}","image_domain_digest":"{}","mapping_basis":"{}","capture_ns":[90,110],"sigma_pixels":0.5,"component_interpretation":"grayscale","mask":{{"kind":"all_allowed"}}}}"#,
            pin(&format!("image{camera}")),
            pin(&format!("mode{camera}")),
            pin("mapping")
        )
    };
    format!(
        r#"{{"schema":"fss.scene_feature_match_query.v1","camera_rig_digest":"{}","privacy_domain":2,"clock":1,"clock_evidence":"{}","association_basis":"{}","reference_time_ns":100,"max_capture_span_ns":20,"motion":"static_during_capture_hull","left":{},"right":{},"extraction":{{"threshold":20,"maximum_features":128,"separation":6}},"matching":{{"maximum_hamming_distance":64,"ratio_percent":80,"maximum_epipolar_distance_pixels":1}}}}"#,
        pin("rig"),
        pin("clock"),
        pin("stationary"),
        view(1),
        view(2)
    )
}
fn read(text: &str) -> Result<Query> {
    parse(text.as_bytes(), ContentDigest::sha256(b"rig"))
}

#[test]
fn strict_query_retains_full_declarations_and_exact_native_policy()
-> std::result::Result<(), String> {
    let query = read(&fixture()).map_err(|e| format!("{e:?}"))?;
    assert_eq!(query.views[0].camera, 1);
    assert_eq!(query.views[1].camera, 2);
    assert_eq!(query.matching.reference_time_ns, 100);
    assert_eq!(query.matching.triangulation.min_views, 2);
    assert_eq!(query.matching.triangulation.max_outliers, 0);
    assert_eq!(query.extraction.maximum_features, 128);
    let again = read(&query.declarations).map_err(|e| format!("{e:?}"))?;
    assert_eq!(query.declarations, again.declarations);
    Ok(())
}

#[test]
fn missing_unknown_duplicate_and_implicit_assumptions_refuse() {
    for text in [
        fixture().replacen("\"clock\":1,", "", 1),
        fixture().replacen("\"clock\":1", "\"clock\":1,\"unrecognized\":true", 1),
        fixture().replacen("\"clock\":1", "\"clock\":1,\"clock\":1", 1),
        fixture().replace("static_during_capture_hull", "static"),
        fixture().replacen("\"mask\":{\"kind\":\"all_allowed\"}", "\"mask\":{}", 1),
        fixture().replacen(
            "\"component_interpretation\":\"grayscale\"",
            "\"component_interpretation\":\"auto\"",
            1,
        ),
    ] {
        assert!(read(&text).is_err(), "accepted {text}");
    }
}

#[test]
fn source_camera_rig_and_mapping_pins_cannot_be_omitted_or_reused() {
    let zero = format!("sha256:{}", "0".repeat(64));
    for text in [
        fixture().replace(&pin("rig"), &pin("other-rig")),
        fixture().replace(&pin("image2"), &pin("image1")),
        fixture().replace("\"camera\":2", "\"camera\":1"),
        fixture().replace(&pin("mapping"), &zero),
        fixture().replace(&pin("clock"), &zero),
        fixture().replace(&pin("mode1"), &zero),
    ] {
        assert!(read(&text).is_err(), "accepted {text}");
    }
}

#[test]
fn all_inventory_and_matching_limits_are_explicit() {
    for (old, new) in [
        ("\"maximum_features\":128", "\"maximum_features\":129"),
        ("\"maximum_features\":128", "\"maximum_features\":0"),
        ("\"threshold\":20", "\"threshold\":255"),
        ("\"separation\":6", "\"separation\":0"),
        (
            "\"maximum_hamming_distance\":64",
            "\"maximum_hamming_distance\":257",
        ),
        ("\"ratio_percent\":80", "\"ratio_percent\":100"),
        (
            "\"maximum_epipolar_distance_pixels\":1",
            "\"maximum_epipolar_distance_pixels\":-1",
        ),
        ("\"sigma_pixels\":0.5", "\"sigma_pixels\":0"),
        (
            "\"max_capture_span_ns\":20",
            "\"max_capture_span_ns\":1000000001",
        ),
    ] {
        assert!(
            read(&fixture().replace(old, new)).is_err(),
            "accepted {new}"
        );
    }
}

#[test]
fn exact_integer_time_survives_u64_range_and_fractional_literals_refuse()
-> std::result::Result<(), String> {
    let text = fixture()
        .replace(
            "[90,110]",
            "[\"18446744073709551605\",\"18446744073709551615\"]",
        )
        .replace(
            "\"reference_time_ns\":100",
            "\"reference_time_ns\":\"18446744073709551610\"",
        );
    let query = read(&text).map_err(|e| format!("{e:?}"))?;
    assert_eq!(query.views[0].capture, [u64::MAX - 10, u64::MAX]);
    assert_eq!(query.matching.reference_time_ns, u64::MAX - 5);
    for bad in ["1e2", "100.0", "-1", "\"0100\"", "18446744073709551616"] {
        assert!(
            read(&fixture().replace(
                "\"reference_time_ns\":100",
                &format!("\"reference_time_ns\":{bad}")
            ))
            .is_err()
        );
    }
    assert!(read(&fixture().replace("[90,110]", "[110,90]")).is_err());
    Ok(())
}

#[test]
fn pinned_mask_and_both_view_geometry_contract_cannot_be_weakened()
-> std::result::Result<(), String> {
    let mask = format!(
        r#""mask":{{"kind":"file","digest":"{}"}}"#,
        pin("allowed pixels")
    );
    let text = fixture().replacen("\"mask\":{\"kind\":\"all_allowed\"}", &mask, 1);
    let query = read(&text).map_err(|e| format!("{e:?}"))?;
    assert!(matches!(query.views[0].mask, Mask::File(_)));
    for triangulation in [
        r#"{"min_views":3}"#,
        r#"{"max_outliers":1}"#,
        r#"{"unknown":1}"#,
    ] {
        let text = fixture().replacen(
            "\"extraction\":",
            &format!("\"triangulation\":{triangulation},\"extraction\":"),
            1,
        );
        assert!(read(&text).is_err());
    }
    Ok(())
}

#[test]
fn decimal_string_policies_round_trip_and_negative_zero_is_not_canonical()
-> std::result::Result<(), String> {
    let text = fixture()
        .replace("\"threshold\":20", "\"threshold\":\"20\"")
        .replace("\"maximum_features\":128", "\"maximum_features\":\"128\"")
        .replace("\"separation\":6", "\"separation\":\"6\"")
        .replace("\"maximum_hamming_distance\":64", "\"maximum_hamming_distance\":\"64\"")
        .replace("\"ratio_percent\":80", "\"ratio_percent\":\"80\"")
        .replacen("\"extraction\":", "\"triangulation\":{\"min_views\":\"2\",\"max_outliers\":\"0\",\"max_iterations\":\"16\"},\"extraction\":", 1);
    let query = read(&text).map_err(|e| format!("{e:?}"))?;
    assert_eq!(query.extraction.maximum_features, 128);
    assert_eq!(query.matching.ratio_percent, 80);
    assert_eq!(query.matching.triangulation.max_iterations, 16);
    assert!(read(&query.declarations).is_ok());
    assert!(read(&text.replace("\"max_outliers\":\"0\"", "\"max_outliers\":\"-0\"")).is_err());
    Ok(())
}
