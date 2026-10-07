#![forbid(unsafe_code)]

use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn declaration(domain: &str, cameras: &[&str]) -> FailureDomainDeclaration {
    FailureDomainDeclaration {
        domain: domain.into(),
        cameras: cameras.iter().map(|camera| (*camera).into()).collect(),
    }
}

fn camera(name: &str) -> CameraFailureDomains {
    CameraFailureDomains {
        camera: name.into(),
        sensor_digest: ContentDigest::sha256(format!("sensor:{name}").as_bytes()),
        import_identity: ContentDigest::sha256(format!("import:{name}").as_bytes()),
        import_root: ContentDigest::sha256(format!("root:{name}").as_bytes()),
        failure_domains: Vec::new(),
        support_domain: String::new(),
    }
}

#[test]
fn transitive_common_causes_contract_every_connected_sensor() -> TestResult {
    let declarations = CorroborationDependencies::new(vec![
        declaration("network:lan", &["alpha", "beta"]),
        declaration("power:grid", &["beta", "gamma"]),
    ])?;
    let assessment = CorroborationDependencyReport::from_sources(
        &declarations,
        vec![
            camera("alpha"),
            camera("beta"),
            camera("gamma"),
            camera("delta"),
        ],
    )?;
    assert_eq!(assessment.clusters().len(), 2);
    assert_eq!(
        assessment.support_domain("alpha")?,
        assessment.support_domain("gamma")?
    );
    assert_ne!(
        assessment.support_domain("alpha")?,
        assessment.support_domain("delta")?
    );
    let joined = assessment
        .clusters()
        .iter()
        .find(|cluster| cluster.cameras.len() == 3)
        .ok_or("missing transitive component")?;
    assert_eq!(joined.cameras, ["alpha", "beta", "gamma"]);
    assert!(joined.failure_domains.contains(&"network:lan".to_owned()));
    assert!(joined.failure_domains.contains(&"power:grid".to_owned()));
    assert_eq!(
        joined
            .failure_domains
            .iter()
            .filter(|domain| domain.starts_with("recorded-sensor:"))
            .count(),
        3
    );
    Ok(())
}

#[test]
fn camera_and_declaration_permutations_preserve_exact_assessment() -> TestResult {
    let declarations = CorroborationDependencies::new(vec![
        declaration("clock:shared", &["west", "east"]),
        declaration("host:left", &["east"]),
    ])?;
    let permuted = CorroborationDependencies::new(vec![
        declaration("host:left", &["east"]),
        declaration("clock:shared", &["east", "west"]),
    ])?;
    assert_eq!(declarations.digest(), permuted.digest());
    assert_eq!(declarations.to_bytes(), permuted.to_bytes());
    let original = CorroborationDependencyReport::from_sources(
        &declarations,
        vec![camera("east"), camera("west")],
    )?;
    let reordered = CorroborationDependencyReport::from_sources(
        &permuted,
        vec![camera("west"), camera("east")],
    )?;
    assert_eq!(original, reordered);
    assert_eq!(original.to_json(), reordered.to_json());
    Ok(())
}

#[test]
fn singleton_causes_bind_provenance_without_claiming_independence() -> TestResult {
    let sources = vec![camera("east"), camera("west")];
    let empty = CorroborationDependencyReport::from_sources(
        &CorroborationDependencies::default(),
        sources.clone(),
    )?;
    assert_eq!(empty.clusters().len(), 2);
    assert!(empty.to_json().contains("sensor_only_assumption"));
    let declarations = CorroborationDependencies::new(vec![
        declaration("model:east", &["east"]),
        declaration("model:west", &["west"]),
    ])?;
    let declared = CorroborationDependencyReport::from_sources(&declarations, sources)?;
    assert_eq!(declared.clusters().len(), 2);
    assert_ne!(declared.digest(), empty.digest());
    assert!(declared.to_json().contains("\"independence\":\"unknown\""));
    assert!(
        declared
            .to_json()
            .contains("\"undeclared_dependencies\":\"unknown_not_absent\"")
    );
    assert!(
        declared
            .to_json()
            .contains("\"independence_certified\":false")
    );
    Ok(())
}

#[test]
fn sensor_identity_is_intrinsic_despite_camera_and_domain_relabelling() -> TestResult {
    let first = camera("east");
    let mut second = camera("west");
    second.sensor_digest = first.sensor_digest;
    let declarations = CorroborationDependencies::new(vec![
        declaration("replay:first", &["east"]),
        declaration("replay:renamed", &["west"]),
    ])?;
    let declared = CorroborationDependencyReport::from_sources(
        &declarations,
        vec![first.clone(), second.clone()],
    )?;
    assert_eq!(declared.clusters().len(), 1);
    let compatibility = CorroborationDependencyReport::from_sources(
        &CorroborationDependencies::default(),
        vec![first, second],
    )?;
    assert_eq!(compatibility.clusters().len(), 1);
    assert_eq!(
        compatibility.cameras()[0].support_domain,
        compatibility.cameras()[1].support_domain
    );
    Ok(())
}

#[test]
fn unknown_oversized_duplicate_and_malformed_declarations_fail_closed() -> TestResult {
    for malformed in [
        "",
        "network",
        "network:",
        "other:lan",
        "network:foo bar",
        "power:x=y",
        "host:x,y",
        "clock:x\n",
    ] {
        assert!(
            CorroborationDependencies::new(vec![declaration(malformed, &["east"])]).is_err(),
            "{malformed:?}"
        );
    }
    assert!(
        CorroborationDependencies::new(vec![declaration(
            &format!("network:{}", "x".repeat(129)),
            &["east"]
        )])
        .is_err()
    );
    assert!(CorroborationDependencies::new(vec![declaration("host:a", &[])]).is_err());
    assert!(
        CorroborationDependencies::new(vec![declaration("host:a", &["east", "east"])]).is_err()
    );
    assert!(CorroborationDependencies::new(vec![declaration("host:a", &["not/a/name"])]).is_err());
    assert!(
        CorroborationDependencies::new(vec![
            declaration("host:a", &["east"]),
            declaration("host:a", &["west"])
        ])
        .is_err()
    );
    assert!(
        CorroborationDependencies::new(vec![
            declaration("host:a", &["east"]);
            MAX_CORROBORATION_FAILURE_DOMAINS + 1
        ])
        .is_err()
    );
    let declarations = CorroborationDependencies::new(vec![declaration(
        "calibration:shared",
        &["east", "unknown"],
    )])?;
    assert!(
        declarations
            .validate_cameras(&["east".into(), "west".into()])
            .is_err()
    );
    assert!(
        CorroborationDependencyReport::from_sources(
            &declarations,
            vec![camera("east"), camera("west")]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn stored_assessment_rederives_components_and_refuses_tampered_claims() -> TestResult {
    let declarations =
        CorroborationDependencies::new(vec![declaration("network:lan", &["east", "west"])])?;
    assert_eq!(
        CorroborationDependencies::from_bytes(&declarations.to_bytes())?,
        declarations
    );
    let assessment = CorroborationDependencyReport::from_sources(
        &declarations,
        vec![camera("east"), camera("west")],
    )?;
    assert_eq!(
        CorroborationDependencyReport::from_bytes(assessment.to_bytes())?,
        assessment
    );
    for length in [
        0,
        1,
        assessment.to_bytes().len() / 2,
        assessment.to_bytes().len() - 1,
    ] {
        assert!(
            CorroborationDependencyReport::from_bytes(&assessment.to_bytes()[..length]).is_err()
        );
    }
    let mut forged = assessment.to_bytes().to_vec();
    let prefix = b"recorded-cluster:";
    let start = forged
        .windows(prefix.len())
        .position(|window| window == prefix)
        .ok_or("missing cluster")?
        + prefix.len();
    forged[start] = if forged[start] == b'0' { b'1' } else { b'0' };
    assert!(CorroborationDependencyReport::from_bytes(&forged).is_err());
    let mut appended = assessment.to_bytes().to_vec();
    appended.push(0);
    assert!(CorroborationDependencyReport::from_bytes(&appended).is_err());
    assert!(
        CorroborationDependencies::from_bytes(&vec![0; MAX_CORROBORATION_DEPENDENCY_BYTES + 1])
            .is_err()
    );
    Ok(())
}

#[test]
fn exact_source_root_and_generation_are_bound_even_for_the_same_components() -> TestResult {
    let declarations =
        CorroborationDependencies::new(vec![declaration("host:nvr", &["east", "west"])])?;
    let sources = vec![camera("east"), camera("west")];
    let original = CorroborationDependencyReport::from_sources(&declarations, sources.clone())?;
    let mut changed_sources = sources;
    changed_sources[0].import_root = ContentDigest::sha256(b"different retained root");
    let changed = CorroborationDependencyReport::from_sources(&declarations, changed_sources)?;
    assert_eq!(original.clusters(), changed.clusters());
    assert_ne!(original.digest(), changed.digest());
    let another =
        CorroborationDependencies::new(vec![declaration("host:nvr-v2", &["east", "west"])])?;
    assert_ne!(declarations.digest(), another.digest());
    Ok(())
}
