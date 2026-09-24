#![forbid(unsafe_code)]
//! Tests exercise actual native twin bytes, not forged private graph storage.

use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis, GeometryError, WorkBudget};
use fss_twin::{
    ImportExpectation, ImportLimits, MovementClass, NavigationError, NavigationProfile,
    PropertyTwin, RouteOutcome, RouteQuery, SupportLocation, SupportNetwork, TwinError,
    import_twin,
};
use std::sync::atomic::AtomicBool;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn budget() -> WorkBudget<'static> {
    WorkBudget::new(100_000_000)
}
fn text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}
fn scene(
    vertices: &[[f64; 3]],
    faces: &[([u32; 3], u32)],
    kinds: &[u8],
) -> Result<PropertyTwin, Box<dyn std::error::Error>> {
    let mut body = vec![1; 32];
    text(&mut body, "navigation-test/Z-up");
    text(&mut body, "synthetic");
    body.push(0);
    for n in [0.0f64, -1.0, 0.0] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    for n in [kinds.len(), kinds.len(), vertices.len(), faces.len()] {
        body.extend_from_slice(&(n as u32).to_le_bytes());
    }
    for (i, kind) in kinds.iter().enumerate() {
        text(&mut body, &format!("f{i:04}"));
        body.push(*kind);
    }
    for i in 0..kinds.len() {
        text(&mut body, &format!("o{i:04}"));
        body.extend_from_slice(&(i as u32).to_le_bytes());
        body.extend_from_slice(&[1, 0]);
    }
    for point in vertices {
        for n in point {
            body.extend_from_slice(&n.to_le_bytes());
        }
    }
    for (indices, object) in faces {
        for n in indices {
            body.extend_from_slice(&n.to_le_bytes());
        }
        body.extend_from_slice(&object.to_le_bytes());
    }
    let mut bytes = b"FSSTWIN1".to_vec();
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    Ok(import_twin(
        &bytes,
        ImportExpectation {
            package_sha256: ContentDigest::sha256(&bytes).bytes(),
            source_scene_sha256: [1; 32],
            basis: GeometryBasis::new(1, 1)?,
        },
        ImportLimits::default(),
        &mut budget(),
    )?)
}
fn square() -> Result<PropertyTwin, Box<dyn std::error::Error>> {
    scene(
        &[[0., 0., 0.], [2., 0., 0.], [2., 2., 0.], [0., 2., 0.]],
        &[([0, 1, 2], 0), ([0, 2, 3], 1)],
        &[1, 2],
    )
}
fn query(twin: &PropertyTwin) -> Result<RouteQuery, NavigationError> {
    Ok(RouteQuery {
        basis: twin.basis(),
        twin_digest: twin.digest(),
        start: SupportLocation::new(0, [0.25, 0.5, 0.25])?,
        destination_feature: 1,
        profile: NavigationProfile::new(MovementClass::Person, 0.9, 0.0, 1)?,
        max_points: 256,
    })
}

#[test]
fn extracts_a_supported_corridor_with_lineage() -> TestResult {
    let twin = square()?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    assert_eq!(net.support_count(), 2);
    assert_eq!(net.portal_count(), 1);
    let search = net.route_to_feature(query(&twin)?, &mut budget())?;
    let RouteOutcome::Found(route) = search.outcome else {
        return Err("missing route".into());
    };
    assert_eq!(route.triangles(), &[0, 1]);
    assert_eq!(route.points()[0], [1.5, 0.5, 0.]);
    assert!(route.points().contains(&[1., 1., 0.]));
    assert_eq!(route.twin_digest(), twin.digest());
    assert_eq!(route.basis(), twin.basis());
    assert!(!route.all_pedestrian());
    assert!(route.distance() > 0.0);
    assert!((route.distance() - route.weighted_cost()).abs() < 1e-12);
    Ok(())
}
#[test]
fn exact_edges_weld_across_separate_object_vertices() -> TestResult {
    let twin = scene(
        &[
            [0., 0., 0.],
            [2., 0., 0.],
            [2., 2., 0.],
            [0., 0., 0.],
            [2., 2., 0.],
            [0., 2., 0.],
        ],
        &[([0, 1, 2], 0), ([3, 4, 5], 1)],
        &[1, 2],
    )?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    assert_eq!(net.portal_count(), 1);
    assert!(matches!(
        net.route_to_feature(query(&twin)?, &mut budget())?.outcome,
        RouteOutcome::Found(_)
    ));
    Ok(())
}
#[test]
fn nearby_edges_and_overlapping_decks_do_not_connect() -> TestResult {
    for shift in [1e-6, 1.0] {
        let twin = scene(
            &[
                [0., 0., 0.],
                [2., 0., 0.],
                [2., 2., 0.],
                [0., 0., shift],
                [2., 2., shift],
                [0., 2., shift],
            ],
            &[([0, 1, 2], 0), ([3, 4, 5], 1)],
            &[1, 4],
        )?;
        let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
        assert_eq!(net.portal_count(), 0);
        assert_eq!(
            net.route_to_feature(query(&twin)?, &mut budget())?.outcome,
            RouteOutcome::NoModeledConnection
        );
    }
    Ok(())
}
#[test]
fn point_contacts_do_not_create_portals() -> TestResult {
    let twin = scene(
        &[
            [0., 0., 0.],
            [1., 0., 0.],
            [0., 1., 0.],
            [2., 0., 0.],
            [2., 1., 0.],
        ],
        &[([0, 1, 2], 0), ([1, 3, 4], 1)],
        &[1, 2],
    )?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    assert_eq!(net.portal_count(), 0);
    Ok(())
}
#[test]
fn duplicate_and_nonmanifold_support_fail_closed() -> TestResult {
    let duplicate = scene(
        &[[0., 0., 0.], [1., 0., 0.], [0., 1., 0.]],
        &[([0, 1, 2], 0), ([2, 1, 0], 1)],
        &[1, 2],
    )?;
    assert!(matches!(
        SupportNetwork::compile(&duplicate, 16, &mut budget()),
        Err(NavigationError::DuplicateFace)
    ));
    let crowded = scene(
        &[
            [0., 0., 0.],
            [1., 0., 0.],
            [0., 1., 0.],
            [0., -1., 0.],
            [0., 0., 1.],
        ],
        &[([0, 1, 2], 0), ([1, 0, 3], 1), ([0, 1, 4], 2)],
        &[1, 2, 4],
    )?;
    assert!(matches!(
        SupportNetwork::compile(&crowded, 16, &mut budget()),
        Err(NavigationError::NonManifold)
    ));
    Ok(())
}
#[test]
fn winding_does_not_change_support_slope() -> TestResult {
    let twin = scene(
        &[[0., 0., 0.], [2., 0., 0.], [2., 2., 0.], [0., 2., 0.]],
        &[([2, 1, 0], 0), ([0, 2, 3], 1)],
        &[1, 2],
    )?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    assert!(matches!(
        net.route_to_feature(query(&twin)?, &mut budget())?.outcome,
        RouteOutcome::Found(_)
    ));
    Ok(())
}
#[test]
fn class_conditioning_never_gives_bears_human_path_priors() -> TestResult {
    for class in [
        MovementClass::Bear,
        MovementClass::OtherAnimal,
        MovementClass::Unknown,
    ] {
        assert_eq!(
            NavigationProfile::new(class, 0.9, 0., 4),
            Err(NavigationError::Options)
        );
        let p = NavigationProfile::new(class, 0.9, 0., 1)?;
        assert_eq!(p.class(), class);
        assert_eq!(p.person_path_multiplier(), 1);
    }
    let p = NavigationProfile::new(MovementClass::Person, 0.9, 0., 4)?;
    assert_eq!(p.without_preference().person_path_multiplier(), 1);
    Ok(())
}
#[test]
fn preference_changes_cost_not_length_or_grass_reachability() -> TestResult {
    let twin = square()?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    let a = query(&twin)?;
    let mut b = a;
    b.profile = NavigationProfile::new(MovementClass::Person, 0.9, 0., 4)?;
    let RouteOutcome::Found(ra) = net.route_to_feature(a, &mut budget())?.outcome else {
        return Err("route".into());
    };
    let RouteOutcome::Found(rb) = net.route_to_feature(b, &mut budget())?.outcome else {
        return Err("route".into());
    };
    assert_eq!(ra.points(), rb.points());
    assert_eq!(ra.distance(), rb.distance());
    assert!(rb.weighted_cost() < ra.weighted_cost());
    Ok(())
}
#[test]
fn portal_width_and_slope_exclusions_are_explicit() -> TestResult {
    let twin = square()?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    let mut q = query(&twin)?;
    q.profile = NavigationProfile::new(MovementClass::Person, 0.9, 3., 1)?;
    assert_eq!(
        net.route_to_feature(q, &mut budget())?.outcome,
        RouteOutcome::NoModeledConnection
    );
    let slope = scene(
        &[[0., 0., 0.], [1., 0., 1.], [0., 1., 0.], [1., 1., 1.]],
        &[([0, 1, 2], 0), ([1, 3, 2], 1)],
        &[3, 3],
    )?;
    let net = SupportNetwork::compile(&slope, 16, &mut budget())?;
    let q = query(&slope)?;
    assert_eq!(
        net.route_to_feature(q, &mut budget())?.outcome,
        RouteOutcome::StartExcludedByProfile
    );
    Ok(())
}
#[test]
fn destination_on_too_steep_face_is_not_physical_absence() -> TestResult {
    let twin = scene(
        &[[0., 0., 0.], [1., 0., 0.], [0., 1., 0.], [0., 0., 1.]],
        &[([0, 1, 2], 0), ([1, 0, 3], 1)],
        &[1, 3],
    )?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    assert_eq!(
        net.route_to_feature(query(&twin)?, &mut budget())?.outcome,
        RouteOutcome::NoAdmissibleDestination
    );
    Ok(())
}
#[test]
fn invalid_simplex_and_profiles_are_rejected() -> TestResult {
    for p in [
        [0., 0., 0.],
        [-0.1, 0.5, 0.6],
        [f64::NAN, 0., 1.],
        [0., 0., 2.],
    ] {
        assert!(SupportLocation::new(0, p).is_err());
    }
    for x in [f64::NAN, -1., 2.] {
        assert!(NavigationProfile::new(MovementClass::Person, x, 0., 1).is_err());
    }
    assert!(NavigationProfile::new(MovementClass::Person, 0., -1., 1).is_err());
    assert!(NavigationProfile::new(MovementClass::Person, 0., 0., 0).is_err());
    Ok(())
}
#[test]
fn stale_package_or_geometry_never_reuses_triangle_handles() -> TestResult {
    let twin = square()?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    let mut q = query(&twin)?;
    q.twin_digest[0] ^= 1;
    assert_eq!(
        net.route_to_feature(q, &mut budget()),
        Err(NavigationError::Twin(TwinError::Basis))
    );
    q = query(&twin)?;
    q.basis = GeometryBasis::new(1, 2)?;
    assert_eq!(
        net.route_to_feature(q, &mut budget()),
        Err(NavigationError::Twin(TwinError::Basis))
    );
    Ok(())
}
#[test]
fn output_limit_refuses_instead_of_returning_a_path_prefix() -> TestResult {
    let twin = square()?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    let mut q = query(&twin)?;
    q.max_points = 2;
    assert_eq!(
        net.route_to_feature(q, &mut budget()),
        Err(NavigationError::Limit)
    );
    assert!(matches!(
        SupportNetwork::compile(&twin, 1, &mut budget()),
        Err(NavigationError::Limit)
    ));
    Ok(())
}
#[test]
fn cancellation_and_work_limits_do_not_publish_partial_graphs() -> TestResult {
    let twin = square()?;
    assert!(matches!(
        SupportNetwork::compile(&twin, 16, &mut WorkBudget::new(0)),
        Err(NavigationError::Twin(TwinError::Geometry(
            GeometryError::BudgetExhausted
        )))
    ));
    let flag = AtomicBool::new(true);
    assert!(matches!(
        SupportNetwork::compile(&twin, 16, &mut WorkBudget::cancellable(1000, &flag)),
        Err(NavigationError::Twin(TwinError::Geometry(
            GeometryError::Cancelled
        )))
    ));
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    assert!(matches!(
        net.route_to_feature(query(&twin)?, &mut WorkBudget::new(0)),
        Err(NavigationError::Twin(TwinError::Geometry(
            GeometryError::BudgetExhausted
        )))
    ));
    Ok(())
}
#[test]
fn already_at_destination_keeps_observed_position() -> TestResult {
    let twin = square()?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    let mut q = query(&twin)?;
    q.destination_feature = 0;
    let RouteOutcome::Found(route) = net.route_to_feature(q, &mut budget())?.outcome else {
        return Err("route".into());
    };
    assert_eq!(route.points(), &[[1.5, 0.5, 0.]]);
    assert_eq!(route.distance(), 0.);
    Ok(())
}
#[test]
fn fixed_input_and_profile_produce_identical_route_and_counts() -> TestResult {
    let twin = square()?;
    let net = SupportNetwork::compile(&twin, 16, &mut budget())?;
    let a = net.route_to_feature(query(&twin)?, &mut budget())?;
    for _ in 0..50 {
        assert_eq!(net.route_to_feature(query(&twin)?, &mut budget())?, a);
    }
    Ok(())
}

#[test]
fn pedestrian_preference_changes_a_route_around_a_real_mesh_hole() -> TestResult {
    let mut vertices = Vec::new();
    for y in 0..4 {
        for x in 0..4 {
            vertices.push([f64::from(x), f64::from(y), 0.]);
        }
    }
    let mut faces = Vec::new();
    let mut start_triangle = 0;
    for y in 0..3 {
        for x in 0..3 {
            if x == 1 && y == 1 {
                continue;
            }
            let feature = if x == 0 && y == 1 {
                0
            } else if x == 2 && y == 1 {
                1
            } else if y == 2 {
                2
            } else {
                3
            };
            let a = y * 4 + x;
            if feature == 0 {
                start_triangle = faces.len() as u32;
            }
            faces.push(([a, a + 1, a + 5], feature));
            faces.push(([a, a + 5, a + 4], feature));
        }
    }
    let twin = scene(&vertices, &faces, &[2, 2, 1, 2])?;
    let net = SupportNetwork::compile(&twin, 64, &mut budget())?;
    let mut q = query(&twin)?;
    q.start = SupportLocation::new(start_triangle, [0.2, 0.4, 0.4])?;
    q.profile = NavigationProfile::new(MovementClass::Person, 0.9, 0., 16)?;
    let RouteOutcome::Found(route) = net.route_to_feature(q, &mut budget())?.outcome else {
        return Err("route".into());
    };
    assert!(route.triangles().iter().any(|t| faces[*t as usize].1 == 2));
    for segment in route.points().windows(2) {
        for step in 1..100 {
            let t = f64::from(step) / 100.0;
            let p: [f64; 3] =
                std::array::from_fn(|i| segment[0][i] * (1.0 - t) + segment[1][i] * t);
            assert!(!(p[0] > 1.0 && p[0] < 2.0 && p[1] > 1.0 && p[1] < 2.0));
        }
    }
    Ok(())
}
