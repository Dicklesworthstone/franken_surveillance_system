#![forbid(unsafe_code)]
//! Bounded operator-local visualization input. Never a geometry activation or camera authority.
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use fss_cli::agent_json::{object, string};
use fss_cli::json_input::{Value, parse};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryBasis, PinholeIntrinsics, RigidPose, WorkBudget};
use super::{Lease, Options, snapshot};

const MAX_INPUT: usize = 1024 * 1024;
const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_FRAME: usize = 4 * 1024 * 1024;
fn bad() -> io::Error { io::Error::other("spatial input unavailable, stale, malformed, or over its bound") }
fn field<'a>(v: &'a Value, key: &str) -> io::Result<&'a Value> { v.object().and_then(|o| o.get(key)).ok_or_else(bad) }
fn text(v: &Value) -> io::Result<&str> { v.text().filter(|s| !s.is_empty() && s.len() <= 512).ok_or_else(bad) }
fn num(v: &Value) -> io::Result<f64> {
    if let Value::Number(s) = v { let n: f64 = s.parse().map_err(|_| bad())?; if n.is_finite() && n.abs() <= 1e6 { return Ok(n); } }
    Err(bad())
}
fn natural(v: &Value, max: usize) -> io::Result<usize> {
    v.integer().and_then(|n| usize::try_from(n).ok()).filter(|n| *n <= max).ok_or_else(bad)
}
fn vec3(v: &Value) -> io::Result<[f64; 3]> {
    let a = v.array().filter(|a| a.len() == 3).ok_or_else(bad)?;
    Ok([num(&a[0])?, num(&a[1])?, num(&a[2])?])
}
fn rows(v: &Value, max: usize) -> io::Result<&[Value]> { v.array().filter(|a| a.len() <= max).ok_or_else(bad) }
fn digest(v: &Value) -> io::Result<ContentDigest> {
    let d = ContentDigest::parse(text(v)?).map_err(|_| bad())?;
    if d.algorithm() != DigestAlgorithm::Sha256 { return Err(bad()); }
    Ok(d)
}
fn choice(v: &Value, choices: &[&str]) -> io::Result<()> { if choices.contains(&text(v)?) { Ok(()) } else { Err(bad()) } }
fn nullable(v: &Value) -> bool { matches!(v, Value::Null) }
fn keys(v: &Value, allowed: &[&str]) -> io::Result<()> {
    if v.object().ok_or_else(bad)?.keys().any(|k| !allowed.contains(&k.as_str())) { return Err(bad()); }
    Ok(())
}
fn timestamp(v: &Value) -> io::Result<()> {
    let s = text(v)?;
    if s.len() > 16 || !s.bytes().all(|b| b.is_ascii_digit()) || s.parse::<u64>().map_err(|_| bad())? > 9_007_199_254_740_991 { return Err(bad()); }
    Ok(())
}
fn value_number(n: f64) -> Value { Value::Number(n.to_string()) }
fn value_vec(v: [f64;3]) -> Value { Value::Array(v.into_iter().map(value_number).collect()) }
fn json(v: &Value) -> String {
    match v {
        Value::Null => "null".into(), Value::Bool(b) => b.to_string(),
        Value::Number(s) => s.clone(), Value::Text(s) => string(s),
        Value::Array(a) => format!("[{}]", a.iter().map(json).collect::<Vec<_>>().join(",")),
        Value::Object(o) => format!("{{{}}}", o.iter().map(|(k,v)| format!("{}:{}",string(k),json(v))).collect::<Vec<_>>().join(",")),
    }
}
fn read_file(path: &Path, limit: usize, lease: &Lease) -> io::Result<Vec<u8>> {
    lease.check()?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() > limit as u64 { return Err(bad()); }
    let mut bytes=Vec::new(); File::open(path)?.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    lease.check()?;
    if bytes.len() > limit { return Err(bad()); }
    Ok(bytes)
}
// Inputs may name only a sibling file; never a URL, absolute path, traversal or arbitrary tree.
fn member(parent: &Path, name: &str) -> io::Result<PathBuf> {
    if name.is_empty() || name.len() > 180 || name.starts_with('.') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b'-'|b'_'|b'.')) { return Err(bad()); }
    if !fs::symlink_metadata(parent)?.file_type().is_dir() { return Err(bad()); }
    Ok(parent.join(name))
}
fn load(options: &Options, lease: &Lease) -> io::Result<(Value, ContentDigest)> {
    let path=options.scene.as_ref().ok_or_else(bad)?;
    let bytes=read_file(path,MAX_INPUT,lease)?;
    let pin=ContentDigest::sha256(&bytes);
    let value=parse(std::str::from_utf8(&bytes).map_err(|_|bad())?).map_err(|_|bad())?;
    Ok((value,pin))
}
const KNOWLEDGE: &[&str] = &["observed","inferred","conflicted","unknown","not_observable","redacted","stale"];
fn validate(v: &Value, site: &str) -> io::Result<()> {
    keys(v,&["format","site","frame","scale","ledgerRoot","mesh","nativeTwin","sensors","placements"])?;
    if text(field(v,"format")?)? != "fss.operator_scene.v1" || text(field(v,"site")?)? != site { return Err(bad()); }
    text(field(v,"frame")?)?;
    let scale=field(v,"scale")?; keys(scale,&["kind","metresPerUnit","error"])?;
    choice(field(scale,"kind")?,&["relative","estimated","measured"])?;
    if text(field(scale,"kind")?)? != "relative" && num(field(scale,"metresPerUnit")?)? <= 0.0 { return Err(bad()); }
    let anchor=field(v,"ledgerRoot")?; if !nullable(anchor) { digest(anchor)?; }
    let mut ids=BTreeSet::new();
    for s in rows(field(v,"sensors")?,64)? {
        keys(s,&["id","label","kind","status","knowledge","basis","position","pose","intrinsics","frame","reading"])?;
        if !ids.insert(text(field(s,"id")?)?) { return Err(bad()); }
        text(field(s,"label")?)?; text(field(s,"basis")?)?;
        choice(field(s,"kind")?,&["camera","motion","contact","temperature","smoke","audio","other"])?;
        choice(field(s,"status")?,&["available","offline","unknown","redacted"])?;
        choice(field(s,"knowledge")?,KNOWLEDGE)?;
        let p=field(s,"position")?; if !nullable(p) { vec3(p)?; }
        let pose=field(s,"pose")?;
        if !nullable(pose) {
            if text(field(s,"kind")?)? != "camera" { return Err(bad()); }
            keys(pose,&["rotation","translation"])?;
            let r=rows(field(pose,"rotation")?,3)?; if r.len()!=3 { return Err(bad()); }
            let pose=RigidPose::new([vec3(&r[0])?,vec3(&r[1])?,vec3(&r[2])?],vec3(field(pose,"translation")?)?).map_err(|_|bad())?;
            if !nullable(p) && vec3(p)?.iter().zip(pose.center()).any(|(a,b)| (a-b).abs()>1e-6) { return Err(bad()); }
            let k=field(s,"intrinsics")?; keys(k,&["width","height","fx","fy","cx","cy","imageDomain"])?;
            if text(field(k,"imageDomain")?)? != "undistorted_pinhole" { return Err(bad()); }
            PinholeIntrinsics::new(natural(field(k,"width")?,8192)? as u32,natural(field(k,"height")?,8192)? as u32,num(field(k,"fx")?)?,num(field(k,"fy")?)?,num(field(k,"cx")?)?,num(field(k,"cy")?)?).map_err(|_|bad())?;
        }
        if matches!(text(field(s,"knowledge")?)?,"unknown"|"not_observable"|"redacted") && (!nullable(p) || !nullable(field(s,"pose")?)) { return Err(bad()); }
        let f=field(s,"frame")?;
        if !nullable(f) {
            keys(f,&["file","digest","sourceDigest","capturedAtUnixMs","privacy"])?;
            if text(field(s,"kind")?)? != "camera" { return Err(bad()); }
            text(field(f,"file")?)?;digest(field(f,"digest")?)?;digest(field(f,"sourceDigest")?)?;timestamp(field(f,"capturedAtUnixMs")?)?;
            if text(field(f,"privacy")?)? != "operator-approved-redacted-preview" { return Err(bad()); }
        }
        let reading=field(s,"reading")?;
        if !nullable(reading) { keys(reading,&["value","unit","observedAtUnixMs"])?;num(field(reading,"value")?)?;text(field(reading,"unit")?)?;timestamp(field(reading,"observedAtUnixMs")?)?; }
    }
    let mut events=BTreeSet::new();
    for p in rows(field(v,"placements")?,256)? {
        keys(p,&["eventId","revisionDigest","knowledge","severity","shape","basis","observedAtUnixMs","validForMs","hypotheses"])?;
        if !events.insert(text(field(p,"eventId")?)?) { return Err(bad()); }
        digest(field(p,"revisionDigest")?)?;choice(field(p,"knowledge")?,KNOWLEDGE)?;
        choice(field(p,"severity")?,&["low","medium","high","critical"])?;
        choice(field(p,"shape")?,&["person","animal","vehicle","unknown"])?;
        text(field(p,"basis")?)?;timestamp(field(p,"observedAtUnixMs")?)?;natural(field(p,"validForMs")?,3_600_000)?;
        let hypotheses=rows(field(p,"hypotheses")?,8)?;
        if matches!(text(field(p,"knowledge")?)?,"unknown"|"not_observable"|"redacted") && !hypotheses.is_empty() { return Err(bad()); }
        for h in hypotheses { keys(h,&["position","radii"])?;vec3(field(h,"position")?)?;if vec3(field(h,"radii")?)?.iter().any(|r| *r<0.0||*r>1000.0) { return Err(bad()); } }
    }
    if !rows(field(v,"placements")?,256)?.is_empty() && nullable(anchor) { return Err(bad()); }
    Ok(())
}
fn validate_mesh(mesh: &Value) -> io::Result<()> {
    keys(mesh,&["vertices","triangles","materials"])?;
    let vertices=rows(field(mesh,"vertices")?,65_536)?;
    for v in vertices { vec3(v)?; }
    let materials=rows(field(mesh,"materials")?,32)?;
    for m in materials { keys(m,&["name","role","color"])?;text(field(m,"name")?)?;text(field(m,"role")?)?;if vec3(field(m,"color")?)?.iter().any(|n| !(0.0..=1.0).contains(n)) { return Err(bad()); } }
    for t in rows(field(mesh,"triangles")?,100_000)? {
        let t=rows(t,4)?;if t.len()!=4||vertices.is_empty()||materials.is_empty(){return Err(bad());}
        for v in &t[..3] { natural(v,vertices.len()-1)?; } natural(&t[3],materials.len()-1)?;
    }
    Ok(())
}
fn project_native(v: &Value, parent: &Path, lease: &Lease) -> io::Result<Value> {
    keys(v,&["file","packageDigest","sourceSceneDigest","property","revision"])?;
    let expected=digest(field(v,"packageDigest")?)?;
    let bytes=read_file(&member(parent,text(field(v,"file")?)?)?,16*1024*1024,lease)?;
    let twin=fss_twin::import_twin(&bytes,fss_twin::ImportExpectation {
        package_sha256:expected.bytes(), source_scene_sha256:digest(field(v,"sourceSceneDigest")?)?.bytes(),
        basis:GeometryBasis::new(natural(field(v,"property")?,usize::MAX)? as u64,natural(field(v,"revision")?,usize::MAX)? as u64).map_err(|_|bad())?,
    },fss_twin::ImportLimits{bytes:16*1024*1024,vertices:65_536,triangles:100_000,..fss_twin::ImportLimits::default()},&mut WorkBudget::new(100_000_000)).map_err(|_|bad())?;
    lease.check()?;
    let vertices=Value::Array(twin.vertices().iter().map(|v|value_vec(*v)).collect());
    let triangles=Value::Array(twin.triangles().iter().enumerate().map(|(i,t)| {
        let (_,feature)=twin.triangle_identity(i).expect("validated twin has triangle identities");
        let material=match feature.surface { fss_twin::SurfaceKind::Grass=>1, fss_twin::SurfaceKind::PedestrianPath=>2, fss_twin::SurfaceKind::Structure=>3, _=>0 };
        Value::Array(t.vertices.iter().map(|v| Value::Number(v.to_string())).chain([Value::Number(material.to_string())]).collect())
    }).collect());
    let materials=parse(r#"[{"name":"Imported surface","role":"surface","color":[0.38,0.46,0.50]},{"name":"Grass","role":"terrain","color":[0.19,0.34,0.28]},{"name":"Path","role":"path","color":[0.52,0.54,0.51]},{"name":"Structure","role":"structure","color":[0.63,0.67,0.64]}]"#).map_err(|_|bad())?;
    let (kind,factor,error)=match twin.scale() {
        fss_twin::ScaleEvidence::Relative => ("relative",None,None),
        fss_twin::ScaleEvidence::Estimated{metres_per_unit,error} => ("estimated",Some(metres_per_unit),error),
        fss_twin::ScaleEvidence::MeasuredAnchor{metres_per_unit,error} => ("measured",Some(metres_per_unit),error),
    };
    let scale=Value::Object([("kind".into(),Value::Text(kind.into())),("metresPerUnit".into(),factor.map_or(Value::Null,value_number)),("error".into(),error.map_or(Value::Null,value_number))].into());
    Ok(Value::Object([("mesh".into(),Value::Object([("vertices".into(),vertices),("triangles".into(),triangles),("materials".into(),materials)].into())),("scale".into(),scale)].into()))
}
fn sanitized(mut v: Value, path: &Path, lease: &Lease) -> io::Result<Value> {
    let o=v.object().ok_or_else(bad)?;
    if o.contains_key("nativeTwin") == o.contains_key("mesh") { return Err(bad()); }
    if let Some(native)=o.get("nativeTwin") {
        let projected=project_native(native,path.parent().ok_or_else(bad)?,lease)?;
        if let Value::Object(ref mut map)=v { map.remove("nativeTwin");map.insert("mesh".into(),field(&projected,"mesh")?.clone());map.insert("scale".into(),field(&projected,"scale")?.clone()); }
    }
    validate_mesh(field(&v,"mesh")?)?;
    if let Value::Object(ref mut map)=v {
        if let Some(Value::Array(sensors))=map.get_mut("sensors") { for sensor in sensors { if let Value::Object(s)=sensor {
            if let Some(Value::Object(f))=s.get_mut("frame") { f.remove("file"); }
        } } }
    }
    Ok(v)
}

pub(super) fn read(options: &Options, lease: &Lease) -> io::Result<String> {
    let metadata=snapshot::read(options,lease)?;
    let (scene,pin)=if options.demo {
        ("null".to_owned(),ContentDigest::sha256(b"explicit synthetic property fixture v1"))
    } else if let Some(path)=&options.scene {
        let (v,pin)=load(options,lease)?;validate(&v,options.site.as_deref().ok_or_else(bad)?)?;
        (json(&sanitized(v,path,lease)?),pin)
    } else { ("null".into(),ContentDigest::sha256(b"no operator scene")) };
    lease.check()?;
    let output=object(&[("format",string("fss.spatial_dashboard.v1")),("metadata",metadata),("scene",scene),("sceneDigest",string(&pin.to_text())),("framesAuthorized",options.allow_frames.to_string())]);
    if output.len()>MAX_OUTPUT{return Err(bad());}Ok(output)
}

// Image bytes are explicitly approved local previews, not authenticated live streams.
// Every request rechecks the current scene pin, native import inventory and exact image digest.
pub(super) fn frame(options: &Options, lease: &Lease, index: usize, pin: &str) -> io::Result<(&'static str,Vec<u8>)> {
    if options.demo || !options.allow_frames { return Err(bad()); }
    let (v,current)=load(options,lease)?;if current.to_text()!=pin{return Err(bad());}
    validate(&v,options.site.as_deref().ok_or_else(bad)?)?;
    let metadata=snapshot::read(options,lease)?;let meta=parse(&metadata).map_err(|_|bad())?;
    if field(&v,"ledgerRoot")?.text()!=field(&meta,"ledgerRoot")?.text(){return Err(bad());}
    let sensor=rows(field(&v,"sensors")?,64)?.get(index).ok_or_else(bad)?;
    if text(field(sensor,"status")?)? != "available" || text(field(sensor,"knowledge")?)? == "redacted" {return Err(bad());}
    let frame=field(sensor,"frame")?;let source=digest(field(frame,"sourceDigest")?)?.to_text();
    if !field(&meta,"imports")?.array().ok_or_else(bad)?.iter().any(|v| v.text()==Some(&source)) { return Err(bad()); }
    let path=member(options.scene.as_ref().and_then(|p|p.parent()).ok_or_else(bad)?,text(field(frame,"file")?)?)?;
    let bytes=read_file(&path,MAX_FRAME,lease)?;
    if ContentDigest::sha256(&bytes)!=digest(field(frame,"digest")?)?{return Err(bad());}
    let mime=image_kind(&bytes)?;
    // A replacement/deletion while reading does not authorize stale pixels in a new response.
    let (_,after)=load(options,lease)?;if after!=current||snapshot::read(options,lease)?!=metadata{return Err(bad());}
    Ok((mime,bytes))
}
fn image_kind(b: &[u8]) -> io::Result<&'static str> {
    let dimensions=|w:u32,h:u32| -> io::Result<()> { if w==0||h==0||w>4096||h>4096||u64::from(w)*u64::from(h)>4_194_304{Err(bad())}else{Ok(())} };
    if b.len()>=33 && b.starts_with(b"\x89PNG\r\n\x1a\n") && &b[12..16]==b"IHDR" && b[8..12]==[0,0,0,13] {
        dimensions(u32::from_be_bytes(b[16..20].try_into().map_err(|_|bad())?),u32::from_be_bytes(b[20..24].try_into().map_err(|_|bad())?))?;
        return Ok("image/png");
    }
    if b.len()>4&&b[..2]==[0xff,0xd8]{let mut i=2;while i+4<=b.len(){if b[i]!=0xff{return Err(bad());}let marker=b[i+1];if marker==0xff{i+=1;continue;}if marker==0xda||marker==0xd9{return Err(bad());}let size=u16::from_be_bytes([b[i+2],b[i+3]])as usize;if size<2||i+2+size>b.len(){return Err(bad());}if matches!(marker,0xc0|0xc1|0xc2){if size<8||b[i+4]!=8{return Err(bad());}dimensions(u16::from_be_bytes([b[i+7],b[i+8]]).into(),u16::from_be_bytes([b[i+5],b[i+6]]).into())?;return Ok("image/jpeg");}i+=2+size;}}
    Err(bad())
}

#[cfg(test)]
#[path = "scene_tests.rs"]
mod tests;
