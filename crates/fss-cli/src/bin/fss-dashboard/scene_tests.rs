#![forbid(unsafe_code)]
//! Native geometry and read-boundary tests. Fixtures are explicit, not field-calibration claims.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::{ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let p=std::env::temp_dir().join(format!("fss-spatial-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
        fs::create_dir(&p)?; Ok(Self(p))
    }
}
impl Drop for Directory { fn drop(&mut self) { let _=fs::remove_dir_all(&self.0); } }
fn baseline() -> Value {
    parse(r#"{"format":"fss.operator_scene.v1","site":"site:spatial-test","frame":"property:z-up","scale":{"kind":"estimated","metresPerUnit":1,"error":null},"ledgerRoot":null,"mesh":{"vertices":[[3,0,0],[5,0,0],[3,2,0]],"triangles":[[0,1,2,0]],"materials":[{"name":"Ground","role":"terrain","color":[0.2,0.3,0.4]}]},"sensors":[{"id":"sensor:front","label":"Front camera","kind":"camera","status":"available","knowledge":"observed","basis":"Explicit fixture, not field calibration","position":[3,5,2],"pose":{"rotation":[[1,0,0],[0,0,-1],[0,1,0]],"translation":[-3,2,-5]},"intrinsics":{"width":800,"height":600,"fx":400,"fy":300,"cx":310,"cy":260,"imageDomain":"undistorted_pinhole"},"frame":null,"reading":null}],"placements":[]}"#).expect("literal fixture")
}
fn replace(v: &mut Value, path: &[&str], replacement: Value) {
    if path.is_empty(){*v=replacement;return;}
    match v {
        Value::Object(m)=>replace(m.get_mut(path[0]).expect("fixture key"),&path[1..],replacement),
        Value::Array(a)=>replace(&mut a[path[0].parse::<usize>().expect("fixture index")],&path[1..],replacement),
        _=>panic!("fixture path is not a container"),
    }
}
fn options(directory: &Directory) -> Options {
    Options{root:Some(directory.0.join("deployment")),site:Some("site:spatial-test".into()),scene:Some(directory.0.join("scene.json")),allow_frames:false,demo:false,snapshot:false,port:0,seconds:10}
}
fn deployment(directory: &Directory) -> Test {
    let authority=ContextAuthority::new_root(RootAuthoritySpec {
        trace_id:"trace:spatial-test".into(), operation_id:OperationId::parse("operation:spatial-test")?,
        principal:"operator:spatial-test".into(), capabilities:vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
        deadline:None,priority:10,budgets:BudgetVector::default(),privacy_scope:"privacy:internal".into(),
        retention_scope:"retention:ephemeral".into(),anchor_universe:ContentDigest::sha256(b"spatial test"),generation:1,
    })?;
    let cx=ReplayCx::new(ReplayIoAuthority::from_context_authority(&authority,directory.0.join("scratch"))?);
    drop(ReferenceDeployment::open(&directory.0.join("deployment"),"site:spatial-test",&cx)?);
    cx.drain_and_finalize(); Ok(())
}
#[test]
fn native_pose_checks_reject_reflection_and_translation_confused_with_center() {
    validate(&baseline(),"site:spatial-test").unwrap();
    for(path,value)in [
        (vec!["sensors","0","pose","rotation"],"[[-1,0,0],[0,0,-1],[0,1,0]]"),
        (vec!["sensors","0","position"],"[-3,2,-5]"),
        (vec!["sensors","0","intrinsics","imageDomain"],"\"raw-distorted\""),
        (vec!["sensors","0","intrinsics","fx"],"0"),
    ]{let mut v=baseline();replace(&mut v,&path,parse(value).unwrap());assert!(validate(&v,"site:spatial-test").is_err());}
}
#[test]
fn unknown_redacted_or_unobservable_sensor_never_exposes_coordinates() {
    for state in ["unknown","redacted","not_observable"] {
        let mut v=baseline();replace(&mut v,&["sensors","0","knowledge"],Value::Text(state.into()));
        assert!(validate(&v,"site:spatial-test").is_err());
        replace(&mut v,&["sensors","0","pose"],Value::Null);replace(&mut v,&["sensors","0","position"],Value::Null);
        assert!(validate(&v,"site:spatial-test").is_ok());
    }
}
#[test]
fn scene_refuses_wrong_site_duplicate_sensor_unknown_keys_and_invalid_mesh() {
    assert!(validate(&baseline(),"site:other").is_err());
    let mut v=baseline();if let Value::Object(m)=&mut v{m.insert("cameraUrl".into(),Value::Text("https://not-used.invalid".into()));}
    assert!(validate(&v,"site:spatial-test").is_err());
    let mut v=baseline();let s=field(&v,"sensors").unwrap().clone();if let Value::Array(mut a)=s{a.push(a[0].clone());replace(&mut v,&["sensors"],Value::Array(a));}
    assert!(validate(&v,"site:spatial-test").is_err());
    let mut mesh=field(&baseline(),"mesh").unwrap().clone();replace(&mut mesh,&["triangles","0","0"],Value::Number("3".into()));
    assert!(validate_mesh(&mesh).is_err());
    assert!(parse(r#"{"site":"first","site":"second"}"#).is_err());
}
#[test]
fn paths_are_sibling_names_not_urls_traversal_or_arbitrary_tree_reads() -> Test {
    let dir=Directory::new()?;
    assert_eq!(member(&dir.0,"front-01.preview.png")?,dir.0.join("front-01.preview.png"));
    for name in ["../x","/etc/passwd","https://camera/stream",".secret","a/b","a\\b","","a:stream"] {assert!(member(&dir.0,name).is_err());}
    Ok(())
}
#[test]
fn bounded_reader_refuses_large_files_and_never_creates_absent_files() -> Test {
    let dir=Directory::new()?;let path=dir.0.join("source");let lease=Lease::new(10);
    assert!(read_file(&path,3,&lease).is_err());assert!(!path.exists());
    fs::write(&path,b"1234")?;assert!(read_file(&path,3,&lease).is_err());assert_eq!(read_file(&path,4,&lease)?,b"1234");
    assert!(read_file(&path,4,&Lease::new(0)).is_err());Ok(())
}
#[cfg(unix)]
#[test]
fn preview_and_scene_leaf_symlinks_are_refused() -> Test {
    let dir=Directory::new()?;let source=dir.0.join("source");fs::write(&source,b"bytes")?;
    let alias=dir.0.join("alias");std::os::unix::fs::symlink(&source,&alias)?;
    assert!(read_file(&alias,99,&Lease::new(10)).is_err());Ok(())
}
#[test]
fn pixel_header_gate_refuses_nonimages_and_oversized_decoded_dimensions() {
    let mut png=vec![0u8;33];png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");png[11]=13;png[12..16].copy_from_slice(b"IHDR");
    png[16..20].copy_from_slice(&640u32.to_be_bytes());png[20..24].copy_from_slice(&480u32.to_be_bytes());
    assert_eq!(image_kind(&png).unwrap(),"image/png");
    png[16..20].copy_from_slice(&4097u32.to_be_bytes());assert!(image_kind(&png).is_err());
    assert!(image_kind(b"<svg onload='alert(1)'></svg>").is_err());
    assert!(image_kind(b"not an image").is_err());
    assert_eq!(image_kind(&[255,216,255,192,0,8,8,1,224,2,128,3]).unwrap(),"image/jpeg");
    assert!(image_kind(&[255,216,255,192,0,8,8,255,255,255,255,3]).is_err());
}
#[test]
fn composite_native_read_preserves_empty_deployment_and_strips_private_filename() -> Test {
    let dir=Directory::new()?;deployment(&dir)?;let opt=options(&dir);let mut v=baseline();
    let f=parse(&format!(r#"{{"file":"private-preview.png","digest":"{}","sourceDigest":"{}","capturedAtUnixMs":"1789398500000","privacy":"operator-approved-redacted-preview"}}"#,ContentDigest::sha256(b"pixels"),ContentDigest::sha256(b"source")))?;
    replace(&mut v,&["sensors","0","frame"],f);fs::write(opt.scene.as_ref().unwrap(),json(&v))?;
    let root=opt.root.as_ref().unwrap();let ledger=fs::read(root.join("ledger/journal.fssj"))?;let effects=fs::read(root.join("effects/journal.fssj"))?;
    let result=read(&opt,&Lease::new(10))?;let decoded=parse(&result)?;
    assert_eq!(field(field(&decoded,"metadata")?,"demo")?.boolean(),Some(false));
    assert_eq!(field(field(&decoded,"metadata")?,"events")?.array().unwrap().len(),0);
    assert!(!result.contains("private-preview.png"));assert!(!result.contains("event:demo:"));
    assert_eq!(ledger,fs::read(root.join("ledger/journal.fssj"))?);assert_eq!(effects,fs::read(root.join("effects/journal.fssj"))?);
    assert!(frame(&opt,&Lease::new(10),0,"pin").is_err());
    let mut allowed=opt.clone();allowed.allow_frames=true;let pin=load(&allowed,&Lease::new(10))?.1.to_text();
    assert!(frame(&allowed,&Lease::new(10),0,&pin).is_err(),"unretained source must not authorize a preview");
    Ok(())
}
fn wire_twin() -> Vec<u8> {
    fn text(b:&mut Vec<u8>,s:&str){b.extend_from_slice(&(s.len()as u16).to_le_bytes());b.extend_from_slice(s.as_bytes());}
    let mut b=ContentDigest::sha256(b"exact authoring scene").bytes().to_vec();
    text(&mut b,"property fixture");text(&mut b,"epoch:fixture");b.push(2);
    for n in [2.0f64,0.1,-1.0]{b.extend_from_slice(&n.to_le_bytes());}
    for n in [1u32,1,3,1]{b.extend_from_slice(&n.to_le_bytes());}
    text(&mut b,"feature:ground");b.push(1);text(&mut b,"object:ground");b.extend_from_slice(&0u32.to_le_bytes());b.extend_from_slice(&[1,0]);
    for p in [[3.0f64,0.0,0.0],[5.0,0.0,0.0],[3.0,2.0,0.0]]{for n in p{b.extend_from_slice(&n.to_le_bytes());}}
    for n in [0u32,1,2,0]{b.extend_from_slice(&n.to_le_bytes());}
    let mut bytes=b"FSSTWIN1".to_vec();bytes.extend_from_slice(&(b.len()as u64).to_le_bytes());bytes.extend(b);
    let sum=ContentDigest::sha256(&bytes).bytes();bytes.extend_from_slice(&sum);bytes
}
#[test]
fn native_twin_import_keeps_source_coordinates_and_scale_evidence_and_rejects_wrong_pin() -> Test {
    let dir=Directory::new()?;let bytes=wire_twin();fs::write(dir.0.join("property.fsstwin"),&bytes)?;
    let mut source=parse(&format!(r#"{{"file":"property.fsstwin","packageDigest":"{}","sourceSceneDigest":"{}","property":1,"revision":1}}"#,ContentDigest::sha256(&bytes),ContentDigest::sha256(b"exact authoring scene")))?;
    let projected=project_native(&source,&dir.0,&Lease::new(10))?;
    assert_eq!(num(field(field(&projected,"scale")?,"metresPerUnit")?)?,2.0);
    assert_eq!(vec3(&rows(field(field(&projected,"mesh")?,"vertices")?,99)?[0])?,[3.0,0.0,0.0]);
    replace(&mut source,&["packageDigest"],Value::Text(ContentDigest::sha256(b"wrong pin").to_text()));
    assert!(project_native(&source,&dir.0,&Lease::new(10)).is_err());Ok(())
}
