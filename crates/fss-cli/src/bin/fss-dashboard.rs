#![forbid(unsafe_code)]
//! Loopback-only operator visualization of retained deployments and explicit local scene inputs.
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};
#[path = "fss-dashboard/server.rs"] mod server;
#[path = "fss-dashboard/snapshot.rs"] mod snapshot;
#[path = "fss-dashboard/scene.rs"] mod scene;
const HELP: &str = "FSS Observatory — local 3D property, sensor wall and evidence workspace\n\n\
  fss-dashboard --demo\n\
  fss-dashboard --root /absolute/deployment --site SITE --allow-local-metadata yes\n\
    [--scene /absolute/operator-scene.json] [--allow-local-frames yes]\n\n\
  Optional: --port 7474 (0 chooses a free port); --serve-seconds 28800 (1..86400).\n\
  --snapshot prints the bounded retained metadata, without opening a socket.\n\
  Open the printed http://127.0.0.1:PORT address. /evidence keeps the metadata explorer.\n\
  Scene: right-handed Z-up evaluated mesh or a pinned native FSSTWIN1 package,\n\
  camera world-to-camera rotations/translations, exact intrinsics and sensor inventory.\n\
  Event positions must pin the latest revision and ledger root. Unknown stays unplaced.\n\
  Local frame permission exposes ONLY explicitly named, hash-checked PNG/JPEG previews\n\
  of retained imports. These must be owner-approved redacted previews, not credentials,\n\
  URLs or original unrestricted media. They are stills, never authenticated live feeds.\n\
  Scene and preview files must be in one directory; file members cannot contain paths.\n\
  Local processes can read this acknowledged metadata. No privacy transform is added.\n\
  Never proxy or forward this listener. Ctrl-C stops it; the finite lease also expires.\n\
  Demo is synthetic and never reads a deployment. Real reads never fall back to demo.\n\
  No camera connections, repairs, secret loading, deployment writes or effect authority.\n\
  Metadata: 256 events; 64 revisions/event; 16 MiB/journal; 2 MiB/object; 4 MiB/report.\n\
  Scene: 1 MiB JSON; 16 MiB native twin; 65536 vertices; 100000 triangles; 64 sensors;\n\
  256 event localizations, at most 8 spatial alternatives each; 8 MiB composite response.\n\
  Preview: 4 MiB encoded and 4 megapixels. See docs/dashboard_spatial.md.\n\
  The 5-second metadata read deadline is cooperative around bounded filesystem work.\n";
#[derive(Clone, Debug, PartialEq, Eq)]
struct Options { root: Option<PathBuf>, site: Option<String>, scene: Option<PathBuf>, allow_frames: bool, demo: bool, snapshot: bool, port: u16, seconds: u64 }
impl Options {
    fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len()>20||args.iter().any(|s|s.as_encoded_bytes().len()>4096){return Err("argument bound exceeded");}
        let mut result=Self{root:None,site:None,scene:None,allow_frames:false,demo:false,snapshot:false,port:7474,seconds:28_800};
        let mut seen=BTreeSet::new();let mut authorized=false;let mut i=0;
        while i<args.len(){let key=args[i].to_str().ok_or("option is not UTF-8")?;if !seen.insert(key){return Err("duplicate option");}i+=1;
            match key {
                "--demo"=>result.demo=true,"--snapshot"=>result.snapshot=true,
                "--root"|"--site"|"--scene"|"--allow-local-metadata"|"--allow-local-frames"|"--port"|"--serve-seconds"=>{
                    let value=args.get(i).ok_or("missing option value")?;i+=1;if value.is_empty(){return Err("empty option value");}
                    if key=="--root"{result.root=Some(PathBuf::from(value));continue;}
                    if key=="--scene"{let path=PathBuf::from(value);if !path.is_absolute(){return Err("scene path must be absolute");}result.scene=Some(path);continue;}
                    let value=value.to_str().ok_or("value is not UTF-8")?;
                    match key {
                        "--site"=>{if value.len()>256||fss_reference::reference_deployment::validate_site_lineage(value).is_err(){return Err("invalid site lineage");}result.site=Some(value.into());}
                        "--allow-local-metadata"|"--allow-local-frames"=>{if value!="yes"{return Err("acknowledgement must be yes");}if key=="--allow-local-metadata"{authorized=true;}else{result.allow_frames=true;}}
                        _=>{if !value.bytes().all(|b|b.is_ascii_digit()){return Err("expected unsigned decimal integer");}let n:u64=value.parse().map_err(|_|"integer overflow")?;if key=="--port"{result.port=u16::try_from(n).map_err(|_|"port out of range")?;}else{if !(1..=86_400).contains(&n){return Err("lease out of range");}result.seconds=n;}}
                    }
                }
                _=>return Err("unknown option"),
            }
        }
        if result.demo {if result.root.is_some()||result.site.is_some()||result.scene.is_some()||authorized||result.allow_frames{return Err("demo cannot authorize local inputs");}}
        else if !authorized||result.site.is_none()||result.root.as_ref().is_none_or(|p|!p.is_absolute()){return Err("require absolute --root, --site and --allow-local-metadata yes");}
        if result.allow_frames&&result.scene.is_none(){return Err("frames require an explicit scene");}
        if result.snapshot&&(seen.contains("--port")||seen.contains("--serve-seconds")||result.scene.is_some()||result.allow_frames){return Err("metadata snapshot mode cannot select listener, scene or frame options");}
        Ok(result)
    }
}
struct Lease { deadline: Instant }
impl Lease {
    fn new(seconds:u64)->Self{Self{deadline:Instant::now()+Duration::from_secs(seconds)}}
    fn check(&self)->io::Result<()>{if Instant::now()>=self.deadline{Err(io::ErrorKind::TimedOut.into())}else{Ok(())}}
}
fn main()->ExitCode{
    let args:Vec<_>=std::env::args_os().skip(1).take(21).collect();
    if args.is_empty()||(args.len()==1&&matches!(args[0].to_str(),Some("--help"|"-h"|"help"))){return match io::stdout().lock().write_all(HELP.as_bytes()){Ok(())=>ExitCode::SUCCESS,Err(_)=>ExitCode::FAILURE};}
    let options=match Options::parse(&args){Ok(v)=>v,Err(reason)=>{eprintln!("{}: {reason}. Use --help.",fss_cli::ERR_CLI_MALFORMED_VALUE);return ExitCode::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code);}};
    let lease=Lease::new(if options.snapshot{5}else{options.seconds});
    let result=if options.snapshot{snapshot::read(&options,&lease).and_then(|body|{let mut out=io::stdout().lock();out.write_all(body.as_bytes())?;out.write_all(b"\n")})}else{server::run(&options,&lease)};
    match result{Ok(())=>ExitCode::SUCCESS,Err(_)=>{eprintln!("{}: dashboard stopped or selected inputs could not be read within their bounds; no deployment writes requested.",fss_cli::ERR_CLI_RUNTIME_FAILURE);ExitCode::FAILURE}}
}
#[cfg(test)]mod tests{
    use super::*;
    fn parse(args:&[&str])->Result<Options,&'static str>{Options::parse(&args.iter().map(OsString::from).collect::<Vec<_>>())}
    #[test]fn demo_and_snapshot_are_explicit_and_pure(){assert!(parse(&["--demo","--snapshot"]).unwrap().snapshot);assert_eq!(parse(&["--demo","--port","0"]).unwrap().port,0);for a in [vec!["--demo","--root","/abs"],vec!["--demo","--allow-local-metadata","yes"],vec!["--demo","--snapshot","--port","0"],vec!["--demo","--scene","/abs"],vec!["--demo","--allow-local-frames","yes"]]{assert!(parse(&a).is_err());}}
    #[test]fn unbounded_ambiguous_or_missing_authority_refuses(){for args in [vec![],vec!["--demo","--demo"],vec!["--demo","--host","0.0.0.0"],vec!["--demo","--port","65536"],vec!["--demo","--serve-seconds","0"],vec!["--demo","--port","-1"],vec!["--root","/abs","--site","site:test"]]{assert!(parse(&args).is_err(),"{args:?}");}}
    #[test]fn frame_authority_requires_scene_and_cannot_hide_in_snapshot(){let base=["--root","/abs","--site","site:test","--allow-local-metadata","yes"];let mut a=base.to_vec();a.extend(["--allow-local-frames","yes"]);assert!(parse(&a).is_err());a.extend(["--scene","/scene.json"]);assert!(parse(&a).unwrap().allow_frames);a.push("--snapshot");assert!(parse(&a).is_err());}
}
