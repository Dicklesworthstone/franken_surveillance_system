#![forbid(unsafe_code)]

use super::*;
use fss_twin::multiview::{CommonPointMotion, FusionInput, FusionRequest, fuse_scene_point};
use fss_twin::{ContactObservation, ImportExpectation, ImportLimits, import_twin};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn wire_text(out: &mut Vec<u8>, s: &str) -> Result<(), Box<dyn std::error::Error>> {
    out.extend_from_slice(&u16::try_from(s.len())?.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn twin() -> Result<PropertyTwin, Box<dyn std::error::Error>> {
    let mut body = vec![1; 32];
    wire_text(&mut body, "test/asymmetric_z_up")?;
    wire_text(&mut body, "synthetic")?;
    body.push(0);
    for n in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    for n in [1_u32, 1, 3, 1] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    wire_text(&mut body, "walk")?;
    body.push(1);
    wire_text(&mut body, "ground")?;
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[1, 1]);
    for vertex in [[0.0_f64, 0.0, 0.0], [5.0, 0.0, 0.0], [0.0, 5.0, 0.0]] {
        for n in vertex {
            body.extend_from_slice(&n.to_le_bytes());
        }
    }
    for n in [0_u32, 1, 2, 0] {
        body.extend_from_slice(&n.to_le_bytes());
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
            basis: GeometryBasis::new(1, 2)?,
        },
        ImportLimits::default(),
        &mut WorkBudget::new(1_000_000),
    )?)
}

fn document(twin: &PropertyTwin) -> Result<Value, Box<dyn std::error::Error>> {
    let row = |id: u64, translation: i32| {
        format!(
            r#"{{
      "camera":{id},"calibration":2,"image_domain":{id},"clock":7,"privacy_domain":1,
      "validity_ns":[0,18446744073709551615],"source_object_id":"source-camera-{id}",
      "image_model":"undistorted_pinhole","status":"authored_nominal","error":null,
      "world_to_camera":{{"rotation":[[1,0,0],[0,0,-1],[0,1,0]],"translation":[{translation},3,5]}},
      "intrinsics":{{"width":640,"height":480,"fx":300,"fy":300,"cx":320,"cy":240}}
    }}"#
        )
    };
    Ok(parse(&format!(
        r#"{{
      "schema":"fss.scene_camera_rig.v1","source_scene_digest":"sha256:{}",
      "twin_digest":"sha256:{}","geometry_basis":{{"property":1,"revision":2}},
      "coordinate_frame":"RH_Z_UP","evaluation_scope":"test/asymmetric_z_up",
      "cameras":[{},{}]
    }}"#,
        "01".repeat(32),
        twin.digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        row(2, -2),
        row(1, 2)
    ))?)
}

fn cameras_mut(doc: &mut Value) -> Result<&mut Vec<Value>, Box<dyn std::error::Error>> {
    if let Value::Object(fields) = doc {
        if let Some(Value::Array(rows)) = fields.get_mut("cameras") {
            return Ok(rows);
        }
    }
    Err("test cameras missing".into())
}

fn replace(value: &mut Value, key: &str, new: Value) -> TestResult {
    if let Value::Object(fields) = value {
        fields.insert(key.to_owned(), new);
        return Ok(());
    }
    Err("test object missing".into())
}

#[test]
fn admitted_rig_unifies_two_authored_views_with_unknown_pose_error() -> TestResult {
    let map = twin()?;
    let rig = SceneRig::from_document(&document(&map)?, &map, &mut WorkBudget::new(100_000))?;
    assert_eq!(
        rig.cameras()
            .iter()
            .map(|r| r.camera.camera)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(rig.coordinate_frame(), "RH_Z_UP");
    assert_eq!(rig.evaluation_scope(), map.evaluation_scope());
    assert_eq!(rig.twin_digest().bytes(), map.digest());
    assert_eq!(rig.source_scene_digest().bytes(), map.source_scene_digest());
    let first = rig.camera(1).ok_or("camera absent")?.camera;
    assert_eq!(first.pose.center(), [-2.0, -5.0, 3.0]);
    assert_eq!(
        first.pose.project(first.intrinsics, [0.0, 0.0, 1.0])?,
        [440.0, 360.0]
    );
    assert!(rig.camera(3).is_none());
    assert!(rig.cameras().iter().all(|r| r.camera.error.is_none()));
    let inputs: Vec<_> = rig
        .cameras()
        .iter()
        .map(|row| {
            let c = row.camera;
            let pixel = if c.camera == 1 {
                [440.0, 360.0]
            } else {
                [200.0, 360.0]
            };
            FusionInput {
                camera: c,
                privacy_domain: row.privacy_domain,
                sigma_pixels: 1.0,
                observation: ContactObservation {
                    evidence: [c.camera as u8; 32],
                    track: c.camera,
                    camera: c.camera,
                    exposure: 1,
                    image_domain: c.image_domain,
                    clock: c.clock,
                    capture: [1_000_000_000; 2],
                    pixel_min: pixel,
                    pixel_max: pixel,
                    visible_contact: true,
                },
            }
        })
        .collect();
    let result = fuse_scene_point(
        &map,
        &inputs,
        FusionRequest {
            association_evidence: [9; 32],
            privacy_domain: 1,
            reference_time_ns: 1_000_000_000,
            max_capture_span_ns: 0,
            motion: CommonPointMotion::Static,
            triangulation: Default::default(),
        },
        &mut WorkBudget::new(1_000_000),
    )?;
    for (actual, expected) in result.estimate().position.into_iter().zip([0.0, 0.0, 1.0]) {
        assert!((actual - expected).abs() < 1e-9);
    }
    assert_eq!(result.inputs().len(), 2);
    assert!(!result.has_nominal_occlusion_conflict());
    Ok(())
}

#[test]
fn semantic_identity_is_order_independent_and_binds_image_and_clock_modes() -> TestResult {
    let map = twin()?;
    let mut doc = document(&map)?;
    let a = SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000))?;
    cameras_mut(&mut doc)?.reverse();
    let b = SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000))?;
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.cameras(), b.cameras());
    replace(
        &mut cameras_mut(&mut doc)?[0],
        "clock",
        Value::Number("8".into()),
    )?;
    let changed = SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000))?;
    assert_ne!(a.digest(), changed.digest());
    Ok(())
}

#[test]
fn mismatched_twin_source_basis_and_scope_never_make_a_camera() -> TestResult {
    let map = twin()?;
    for (key, value) in [
        (
            "twin_digest",
            Value::Text(format!("sha256:{}", "02".repeat(32))),
        ),
        (
            "source_scene_digest",
            Value::Text(format!("sha256:{}", "03".repeat(32))),
        ),
        ("evaluation_scope", Value::Text("other_frame".into())),
        ("geometry_basis", parse(r#"{"property":1,"revision":3}"#)?),
    ] {
        let mut doc = document(&map)?;
        replace(&mut doc, key, value)?;
        assert!(matches!(
            SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000)),
            Err(SceneRigError::Basis)
        ));
    }
    Ok(())
}

#[test]
fn duplicated_camera_and_authored_object_are_both_refused() -> TestResult {
    let map = twin()?;
    for (key, value) in [
        ("camera", Value::Number("1".into())),
        ("source_object_id", Value::Text("source-camera-1".into())),
    ] {
        let mut doc = document(&map)?;
        replace(&mut cameras_mut(&mut doc)?[0], key, value)?;
        assert!(matches!(
            SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000)),
            Err(SceneRigError::Duplicate)
        ));
    }
    Ok(())
}

#[test]
fn refuses_unsupported_uncertainty_lens_status_and_unknown_fields() -> TestResult {
    let map = twin()?;
    for (key, value) in [
        ("error", Value::Number("0".into())),
        ("image_model", Value::Text("raw_fisheye".into())),
        ("status", Value::Text("qualified".into())),
    ] {
        let mut doc = document(&map)?;
        replace(&mut cameras_mut(&mut doc)?[0], key, value)?;
        assert!(matches!(
            SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000)),
            Err(SceneRigError::Unsupported)
        ));
    }
    let mut doc = document(&map)?;
    replace(
        &mut cameras_mut(&mut doc)?[0],
        "url",
        Value::Text("never opened".into()),
    )?;
    assert!(matches!(
        SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000)),
        Err(SceneRigError::Format)
    ));
    Ok(())
}

#[test]
fn numeric_and_budget_failures_are_explicit() -> TestResult {
    let map = twin()?;
    for (key, value) in [
        ("camera", Value::Number("0".into())),
        ("validity_ns", parse("[2,1]")?),
        ("clock", Value::Number("18446744073709551616".into())),
    ] {
        let mut doc = document(&map)?;
        replace(&mut cameras_mut(&mut doc)?[0], key, value)?;
        assert!(matches!(
            SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000)),
            Err(SceneRigError::Numeric)
        ));
    }
    let mut doc = document(&map)?;
    replace(
        &mut cameras_mut(&mut doc)?[0],
        "world_to_camera",
        parse(r#"{"rotation":[[-1,0,0],[0,1,0],[0,0,1]],"translation":[0,0,0]}"#)?,
    )?;
    assert!(matches!(
        SceneRig::from_document(&doc, &map, &mut WorkBudget::new(100_000)),
        Err(SceneRigError::Geometry(GeometryError::InvalidRotation))
    ));
    let doc = document(&map)?;
    assert!(matches!(
        SceneRig::from_document(&doc, &map, &mut WorkBudget::new(1)),
        Err(SceneRigError::Geometry(GeometryError::BudgetExhausted))
    ));
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    assert!(matches!(
        SceneRig::from_document(
            &doc,
            &map,
            &mut WorkBudget::cancellable(100_000, &cancelled)
        ),
        Err(SceneRigError::Geometry(GeometryError::Cancelled))
    ));
    Ok(())
}

#[test]
fn strict_byte_reader_refuses_duplicate_keys_and_oversized_input() -> TestResult {
    let map = twin()?;
    assert!(matches!(
        parse_scene_rig(
            br#"{"schema":"a","schema":"b"}"#,
            &map,
            &mut WorkBudget::new(100_000)
        ),
        Err(SceneRigError::Format)
    ));
    assert!(matches!(
        parse_scene_rig(
            &vec![b' '; MAX_INPUT_BYTES + 1],
            &map,
            &mut WorkBudget::new(100_000)
        ),
        Err(SceneRigError::Limit)
    ));
    Ok(())
}
