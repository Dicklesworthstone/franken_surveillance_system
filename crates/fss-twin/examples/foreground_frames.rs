#![forbid(unsafe_code)]
//! Owner-operated, read-only replay of decoded full-range pinhole luma files.
//! This is not a native codec, camera service or registered fss/1 command.
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::foreground::*;
use fss_twin::localization::ImageIdentity;

#[path = "foreground_frames/tracking.rs"]
mod tracking;
#[path = "foreground_frames/zones.rs"]
mod zones;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
struct Row { query: bool, exposure: [u8;32], capture: [u64;2], pixels: PathBuf,
    pixels_hash: [u8;32], mask: PathBuf, mask_hash: [u8;32] }
struct Loaded { source: ForegroundSource, pixels: Vec<u8>, allowed: Vec<u8> }
fn bytes(path:&Path, limit:usize)->Result<Vec<u8>> {
    let file=File::open(path)?;
    if file.metadata()?.len()>limit as u64 {return Err("input exceeds byte limit".into());}
    let mut b=Vec::new();b.try_reserve_exact(limit+1)?;
    file.take(limit as u64+1).read_to_end(&mut b)?;
    if b.len()>limit {return Err("input exceeds byte limit".into());}Ok(b)
}
fn hash(s:&str)->Result<[u8;32]> {
    if s.len()!=64 || !s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
        return Err("expected lowercase SHA-256".into());
    }
    let mut h=[0;32];for (i,v) in h.iter_mut().enumerate() {*v=u8::from_str_radix(&s[2*i..2*i+2],16)?;}
    if h==[0;32] {return Err("zero source identity".into());}Ok(h)
}
fn confined(root:&Path,name:&str)->Result<PathBuf> {
    let p=Path::new(name);
    if p.components().next().is_none() || p.components().any(|c|!matches!(c,Component::Normal(_))) {
        return Err("file path must stay below the manifest directory".into());
    }
    let actual=root.join(p).canonicalize()?;
    if !actual.starts_with(root) || !actual.is_file() {return Err("file outside manifest directory".into());}Ok(actual)
}
fn hex(h:[u8;32])->String {h.iter().map(|b|format!("{b:02x}")).collect()}
fn run()->Result<()> {
    let mut args=std::env::args_os().skip(1);
    let file=PathBuf::from(args.next().ok_or("usage: foreground_frames MANIFEST")?).canonicalize()?;
    if args.next().is_some() {return Err("expected one manifest".into());}
    let root=file.parent().ok_or("manifest has no parent")?;
    let config=String::from_utf8(bytes(&file,65536)?)?;
    let mut lines=config.lines().filter(|s|!s.trim().is_empty()&&!s.trim_start().starts_with('#'));
    let (tracking_enabled, zones_enabled) = match lines.next() {
        Some("FSS_FOREGROUND_FRAMES_1") => (false, false),
        Some("FSS_FOREGROUND_TRACKING_1") => (true, false),
        Some("FSS_FOREGROUND_ZONES_1") => (true, true),
        _ => return Err("unsupported replay manifest".into()),
    };
    let names=["width","height","camera","clock","calibration","image_domain","valid_from","valid_until",
        "selection_evidence","maximum_spread","minimum_change","minimum_area","maximum_regions","widespread_per_mille","work_units"];
    let mut settings=BTreeMap::new();let mut rows=Vec::new();let mut saw_query=false;
    for line in lines {
        if let Some((key,value))=line.split_once('=') {
            if !(names.contains(&key) || tracking_enabled && tracking::SETTINGS.contains(&key)
                || zones_enabled && zones::SETTINGS.contains(&key))
                || settings.insert(key,value).is_some() {return Err("unknown/duplicate setting".into());}
        } else {
            let p:Vec<_>=line.split_whitespace().collect();
            if p.len()!=8 || !["reference","query"].contains(&p[0]) || rows.len()>=128 {return Err("invalid/too many frame rows".into());}
            let query=p[0]=="query";if !query&&saw_query {return Err("references must precede queries".into());}saw_query|=query;
            let capture=[p[2].parse()?,p[3].parse()?];
            if capture[0]>capture[1] {return Err("reversed capture interval".into());}
            rows.push(Row{query,exposure:hash(p[1])?,capture,pixels:confined(root,p[4])?,pixels_hash:hash(p[5])?,
                mask:confined(root,p[6])?,mask_hash:hash(p[7])?});
        }
    }
    if settings.len()!=names.len()+(if tracking_enabled {tracking::SETTINGS.len()} else {0})
        +(if zones_enabled {zones::SETTINGS.len()} else {0}) || !saw_query {return Err("missing settings or query frames".into());}
    let get=|k|settings.get(k).copied().ok_or("missing setting");
    let width:u32=get("width")?.parse()?;let height:u32=get("height")?.parse()?;
    if width==0||height==0||width>4096||height>4096 {return Err("invalid dimensions".into());}
    let count=width as usize*height as usize;
    if count>MAX_FOREGROUND_PIXELS {return Err("image exceeds limit".into());}
    let camera=get("camera")?.parse()?;let clock=get("clock")?.parse()?;
    let calibration=hash(get("calibration")?)?;let domain=hash(get("image_domain")?)?;
    let bp=BackgroundPolicy{selection_evidence:hash(get("selection_evidence")?)?,validity:[get("valid_from")?.parse()?,get("valid_until")?.parse()?],
        maximum_spread:get("maximum_spread")?.parse()?};
    let fp=ForegroundPolicy{minimum_change:get("minimum_change")?.parse()?,minimum_area:get("minimum_area")?.parse()?,
        maximum_regions:get("maximum_regions")?.parse()?,widespread_per_mille:get("widespread_per_mille")?.parse()?};
    let mut budget=WorkBudget::new(get("work_units")?.parse()?);
    let mut tracker = if tracking_enabled { Some(tracking::configure(&settings, &mut budget)?) } else { None };
    let mut zone_monitor = if zones_enabled {
        let basis = fss_twin::image_zones::ImageZoneBasis { camera, clock, calibration,
            image_domain: domain, dimensions: [width, height] };
        Some(zones::configure(&settings, tracker.as_ref().ok_or("zone mode requires tracking")?, basis, &mut budget)?)
    } else { None };
    let refs=rows.iter().take_while(|r|!r.query).count();
    if !(3..=MAX_BACKGROUND_FRAMES).contains(&refs) {return Err("reference count outside 3..31".into());}
    let load=|r:&Row|->Result<Loaded> {
        let pixels=bytes(&r.pixels,count)?;let allowed=bytes(&r.mask,count)?;
        if pixels.len()!=count||allowed.len()!=count||ContentDigest::sha256(&pixels).bytes()!=r.pixels_hash
            ||ContentDigest::sha256(&allowed).bytes()!=r.mask_hash {return Err("frame or mask binding mismatch".into());}
        Ok(Loaded{source:ForegroundSource{image:ImageIdentity{exposure:r.exposure,pixels:r.pixels_hash,
            image_domain:domain,dimensions:[width,height]},camera,calibration,clock,capture:r.capture},pixels,allowed})
    };
    let loaded:Vec<_>=rows[..refs].iter().map(load).collect::<Result<_>>()?;
    let mut frames=Vec::new();
    for f in &loaded {frames.push(ForegroundFrame::new(f.source,&f.pixels,&f.allowed,&mut budget)?);}
    let model=BackgroundModel::build(&frames,bp,&mut budget)?;
    drop(frames);drop(loaded);
    let stdout=std::io::stdout();
    let mut out=std::io::BufWriter::new(stdout.lock());let mut completed=0;
    if let Some(monitor) = &zone_monitor { zones::write_configuration(&mut out, monitor)?; }
    for row in &rows[refs..] {
        let f=load(row)?;let query=ForegroundFrame::new(f.source,&f.pixels,&f.allowed,&mut budget)?;
        let r=model.detect(&query,fp,&mut budget)?;
        let tracked = tracker.as_mut().map(|t| t.update_foreground(&r, &mut budget)).transpose()?;
        write!(out,"{{\"kind\":\"frame\",\"exposure\":\"{}\",\"report\":\"{}\",\"assessment\":\"{:?}\",\"comparable\":{},\"changed\":{},\"small_components\":{},\"small_pixels\":{},\"regions\":[",
            hex(row.exposure),hex(r.digest()),r.assessment(),r.comparable_pixels(),r.changed_pixels(),r.small_component_count(),r.small_component_pixels())?;
        for (i,region) in r.regions().iter().enumerate() {
            if i!=0 {write!(out,",")?;}
            write!(out,"{{\"id\":{},\"area\":{},\"min\":{:?},\"max\":{:?},\"unknown_boundary\":{},\"image_edge\":{}}}",
                region.id,region.area,region.min,region.max,region.touches_unknown,region.touches_edge)?;
        }
        writeln!(out,"]}}")?;
        if let (Some(tracker), Some(report)) = (&tracker, &tracked) {
            tracking::write_report(&mut out, tracker, report)?;
            if let Some(monitor) = &mut zone_monitor {
                match monitor.observe(tracker, report, &mut budget) {
                    Ok(zone_report) => zones::write_report(&mut out, zone_report)?,
                    Err(error) => {
                        writeln!(out, "{{\"kind\":\"zone_incomplete\",\"tracking\":\"{}\",\"error\":\"{:?}\"}}",
                            hex(report.digest()), error)?;
                        out.flush()?;
                        return Err(error.into());
                    }
                }
            }
        }
        out.flush()?;completed+=1;
    }
    writeln!(out,"{{\"kind\":\"complete\",\"frames\":{},\"work_units\":{}}}",completed,budget.used())?;out.flush()?;Ok(())
}
fn main() {
    if let Err(e)=run() {eprintln!("foreground replay failed: {e}");std::process::exit(1);}
}
