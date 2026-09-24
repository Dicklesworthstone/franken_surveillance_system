#![forbid(unsafe_code)]
//! Read-only detector and tracking operations for fss-infer.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use fss_core::{BudgetVector, ContentDigest, OperationId, PrincipalId};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::recorded_decode::{ComponentInterpretation, DecodeLimits, RecordedDecodeRequest};
use fss_reference::ingest::detections::{BoxEncoding, CoordinateSpace, DetectionBudget, DetectionContract, DetectionFrame, DetectionSpec};
use fss_reference::ingest::tracking::{AssociationBudget, LocalBoxTracker, TrackEnd, TrackingConfig, TrackingUpdate};
use super::{Values, RunResult, value, text, number, digest, export};

const MAX_FRAMES: usize = 128;
const MAX_RUN_LIST_BYTES: usize = 65536;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const HELP: &str = "fss-infer detect|track [options]\n\
  All: --root DIR --site SITE --import-id sha256:HEX --interpretation gray|ycbcr\n\
       --model-digest sha256:HEX --output-port NAME --labels CLASS0,CLASS1\n\
       --box-format xyxy|cxcywh --coordinates pixels|normalized\n\
       [--minimum-score-ppm N] [--nms-iou-ppm N]\n\
       [--maximum-rows N] [--maximum-detections N] [--work-units N]\n\
       [--principal ID] [--report-out FILE]\n\
  detect: --segment N --run-id sha256:HEX\n\
  track: --runs FILE (one SEGMENT SHA256_RUN_ID per line, increasing segments)\n\
       [--minimum-iou-ppm N] [--confirmation-hits N] [--maximum-missed-frames N]\n\
       [--maximum-tracks N] [--association-work-units N]\n\
  Output must be [N,6] or [1,N,6]: four box values, score in [0,1], integer class.\n\
  No implicit resizing, letterbox reversal, logits, class inference, model downloads or alerts.\n\
  Reports are JSON with explicit incomplete results and source proofs. A missed box is not\n\
  absence. Track IDs are local hypotheses. Reconstruct history by replaying the full run list.\n";

#[derive(Debug)]
enum Selection { Single(usize, ContentDigest), List(PathBuf) }
#[derive(Debug)]
struct Options {
    root: PathBuf, site: String, principal: String, source: RecordedDecodeRequest,
    spec: DetectionSpec, contract: DetectionContract, tracking: Option<TrackingConfig>,
    selection: Selection, detector_work: u64, association_work: u64, report: Option<PathBuf>,
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    let tracking = args.first().and_then(|s| s.to_str()) == Some("track");
    let common = ["--root","--site","--import-id","--interpretation","--model-digest","--output-port",
        "--labels","--box-format","--coordinates","--minimum-score-ppm","--nms-iou-ppm",
        "--maximum-rows","--maximum-detections","--work-units","--principal","--report-out"];
    let track_flags = ["--runs","--minimum-iou-ppm","--confirmation-hits","--maximum-missed-frames","--maximum-tracks","--association-work-units"];
    let mut values = Values::new(); let mut i = 1;
    while i < args.len() {
        let key = args[i].to_str().ok_or("option names must be UTF-8")?;
        if !(common.contains(&key) || (tracking && track_flags.contains(&key))
            || (!tracking && matches!(key,"--segment" | "--run-id"))) {
            return Err("unknown or inapplicable detector option".into());
        }
        if values.contains_key(key) { return Err(format!("duplicate {key}")); }
        let v = args.get(i+1).ok_or_else(|| format!("missing value for {key}"))?;
        if v.is_empty() || v.to_str().is_some_and(|s| s.starts_with("--")) { return Err(format!("missing value for {key}")); }
        values.insert(key.to_owned(),v.clone()); i += 2;
    }
    let site = text(&values,"--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site).map_err(|_| "invalid site lineage")?;
    let principal = values.get("--principal").map(|v| v.to_str().ok_or("principal must be UTF-8"))
        .transpose()?.unwrap_or("principal:local-operator").to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let interpretation = match text(&values,"--interpretation")? {
        "gray" => ComponentInterpretation::Grayscale, "ycbcr" => ComponentInterpretation::YCbCr,
        _ => return Err("explicit gray or ycbcr interpretation required".into()),
    };
    let spec = DetectionSpec {
        model_digest:digest(&values,"--model-digest")?,output_port:text(&values,"--output-port")?.to_owned(),
        labels:text(&values,"--labels")?.split(',').map(str::to_owned).collect(),
        encoding:match text(&values,"--box-format")? { "xyxy" => BoxEncoding::Xyxy,"cxcywh" => BoxEncoding::CenterSize,
            _ => return Err("box format must be xyxy or cxcywh".into()) },
        coordinates:match text(&values,"--coordinates")? { "pixels" => CoordinateSpace::Pixels,"normalized" => CoordinateSpace::Normalized,
            _ => return Err("coordinates must be pixels or normalized".into()) },
        minimum_score_ppm:number(&values,"--minimum-score-ppm",Some(500_000))?,
        nms_iou_ppm:number(&values,"--nms-iou-ppm",Some(500_000))?,
        maximum_rows:number(&values,"--maximum-rows",Some(4096))?,
        maximum_detections:number(&values,"--maximum-detections",Some(256))?,
    };
    let contract = DetectionContract::new(spec.clone()).map_err(|e| e.to_string())?;
    let track_config = if tracking {
        let c = TrackingConfig { minimum_iou_ppm:number(&values,"--minimum-iou-ppm",Some(300_000))?,
            confirmation_hits:number(&values,"--confirmation-hits",Some(2))?,
            maximum_missed_frames:number(&values,"--maximum-missed-frames",Some(2))?,
            maximum_tracks:number(&values,"--maximum-tracks",Some(128))? };
        c.digest().map_err(|e| e.to_string())?; Some(c)
    } else { None };
    Ok(Options { root:PathBuf::from(value(&values,"--root")?),site,principal,
        source:RecordedDecodeRequest { import_identity:digest(&values,"--import-id")?,segment_index:0,
            interpretation,read_limits:RetainedReadLimits::default(),decode_limits:DecodeLimits::default() },
        selection:if tracking { Selection::List(PathBuf::from(value(&values,"--runs")?)) }
            else { Selection::Single(number(&values,"--segment",None)?,digest(&values,"--run-id")?) },
        spec,contract,tracking:track_config,
        detector_work:number(&values,"--work-units",Some(10_000_000))?,
        association_work:number(&values,"--association-work-units",Some(10_000_000))?,
        report:values.get("--report-out").map(PathBuf::from) })
}
fn run_list(text: &str) -> RunResult<Vec<(usize,ContentDigest)>> {
    if text.len() > MAX_RUN_LIST_BYTES { return Err(io::Error::other("run list exceeds byte bound").into()); }
    let mut entries = Vec::new(); let mut previous = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let segment: usize = fields.next().ok_or_else(|| io::Error::other("empty run-list line"))?.parse()?;
        let id = ContentDigest::parse(fields.next().ok_or_else(|| io::Error::other("run identity required"))?)?;
        if fields.next().is_some() || id.algorithm()!=fss_core::DigestAlgorithm::Sha256
            || previous.is_some_and(|p| p >= segment) || entries.len() == MAX_FRAMES {
            return Err(io::Error::other("run list requires at most 128 strictly increasing SEGMENT SHA256 pairs").into());
        }
        entries.push((segment,id)); previous=Some(segment);
    }
    if entries.is_empty() { return Err(io::Error::other("empty run list").into()); }
    Ok(entries)
}
fn load_selection(selection: &Selection) -> RunResult<Vec<(usize,ContentDigest)>> {
    match selection {
        Selection::Single(segment,id) => Ok(vec![(*segment,*id)]),
        Selection::List(path) => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.file_type().is_file() || metadata.len() > MAX_RUN_LIST_BYTES as u64 {
                return Err(io::Error::other("run list must be a bounded regular file, not a symlink").into());
            }
            let file=fs::File::open(path)?;
            if !file.metadata()?.file_type().is_file() { return Err(io::Error::other("run list is not regular").into()); }
            let mut bytes=Vec::new(); file.take(MAX_RUN_LIST_BYTES as u64+1).read_to_end(&mut bytes)?;
            run_list(std::str::from_utf8(&bytes)?)
        }
    }
}
fn json_string(value: &str) -> String {
    let mut result=String::from("\"");
    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""), '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"), '\r' => result.push_str("\\r"), '\t' => result.push_str("\\t"),
            c if c <= '\u{1f}' => {
                const HEX: &[u8;16]=b"0123456789abcdef";
                result.push_str("\\u00"); result.push(HEX[(c as usize)>>4] as char); result.push(HEX[(c as usize)&15] as char);
            }
            c => result.push(c),
        }
    }
    result.push('"'); result
}
fn render_frame(frame: &DetectionFrame, update: Option<&TrackingUpdate>) -> RunResult<String> {
    let c=frame.capsule(); let [rows,filtered,suppressed]=frame.counts();
    let mut s=String::new();
    write!(s,"{{\"detection_digest\":\"{}\",\"run_id\":\"{}\",\"frame_root\":\"{}\",\"segment\":{},\"capsule_id\":{},\"sensor_id\":{},\"stream_id\":{},\"sequence\":{},",
        frame.digest()?,frame.run_identity(),frame.frame_root(),frame.segment_index(),
        json_string(c.capsule_id.as_str()),json_string(c.sensor_id.as_str()),json_string(c.stream_id.as_str()),c.sequence)?;
    write!(s,"\"capture\":{{\"earliest_ns\":\"{}\",\"latest_ns\":\"{}\",\"clock_basis\":\"{}\",\"gap_before\":{}}},\"dimensions\":{:?},\"rows\":{},\"filtered\":{},\"suppressed\":{},\"work_units\":{},\"detections\":[",
        c.capture.earliest.0,c.capture.latest.0,c.clock_basis.as_str(),c.gap_before,frame.dimensions(),rows,filtered,suppressed,frame.work_units())?;
    for (i,d) in frame.detections().iter().enumerate() {
        if i!=0 { s.push(','); }
        write!(s,"{{\"row\":{},\"class_index\":{},\"score\":{},\"bounds_subpixel\":{:?}}}",d.row(),d.class_index(),d.score(),d.bounds().coordinates())?;
    }
    s.push_str("],\"tracking\":");
    if let Some(update)=update {
        let predecessor=update.predecessor.map_or("null".to_owned(),|d|format!("\"{d}\""));
        write!(s,"{{\"digest\":\"{}\",\"predecessor\":{},\"config_digest\":\"{}\",\"association_is_hypothesis\":true,\"eligible_edges\":{},\"work_units\":{},\"resets\":[",
            update.digest()?,predecessor,update.config_digest,update.eligible_edges,update.work_units)?;
        for (i,r) in update.resets.iter().enumerate() { if i!=0 { s.push(','); } s.push_str(&json_string(r.as_str())); }
        s.push_str("],\"tracks\":[");
        for (i,t) in update.tracks.iter().enumerate() {
            if i!=0 { s.push(','); }
            let row=t.observed_row.map_or("null".into(),|r|r.to_string());
            write!(s,"{{\"id\":\"{}\",\"class_index\":{},\"bounds_subpixel\":{:?},\"score\":{},\"observed_row\":{},\"first_sequence\":{},\"last_seen_sequence\":{},\"observations\":{},\"consecutive_hits\":{},\"missed_frames\":{},\"confirmed\":{},\"ambiguous\":{}}}",
                t.id,t.class_index,t.bounds,f32::from_bits(t.score_bits),row,t.first_sequence,t.last_seen_sequence,t.observations,t.consecutive_hits,t.missed_frames,t.confirmed,t.ambiguous)?;
        }
        s.push_str("],\"retired\":[");
        for (i,t) in update.retired.iter().enumerate() {
            if i!=0 { s.push(','); }
            write!(s,"{{\"id\":\"{}\",\"reason\":\"{}\"}}",t.id,match t.reason { TrackEnd::Reset=>"reset",TrackEnd::MissedLimit=>"missed_limit" })?;
        }
        s.push_str("]}");
    } else { s.push_str("null"); }
    s.push('}'); Ok(s)
}
fn run(options: Options, out: &mut impl Write) -> RunResult<bool> {
    let entries=load_selection(&options.selection)?;
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?.file_type().is_file() {
        return Err(io::Error::other("existing non-symlink deployment required").into());
    }
    let auth=ContextAuthority::new_root(RootAuthoritySpec {
        trace_id:"trace:detector-cli".into(),operation_id:OperationId::parse("operation:detector-cli")?,
        principal:options.principal,capabilities:vec!["ADP-REPLAY-001".into()],deadline:None,priority:10,
        budgets:BudgetVector::builder().bytes(64*1024*1024).build()?,
        privacy_scope:"privacy:local-authorized-files".into(),retention_scope:"retention:existing-deployment-policy".into(),
        anchor_universe:ContentDigest::sha256(options.site.as_bytes()),generation:1,
    })?;
    auth.validate()?;
    let cx=ReplayCx::from_context_authority(&auth,options.root.clone())?;
    let result=(|| -> RunResult<bool> {
        let deployment=ReferenceDeployment::open(&options.root,&options.site,&cx)?;
        let mut tracker=options.tracking.map(LocalBoxTracker::new).transpose()?;
        let mut detection_budget=DetectionBudget::new(options.detector_work);
        let mut association_budget=AssociationBudget::new(options.association_work);
        let spec=&options.spec;
        let mut report=String::new();
        write!(report,"{{\"schema\":\"fss.detector_track_report.v1\",\"operation\":\"{}\",\"source_import\":\"{}\",\"contract_digest\":\"{}\",\"contract\":{{\"model_digest\":\"{}\",\"output_port\":{},\"box_format\":\"{}\",\"coordinates\":\"{}\",\"box_subpixels\":256,\"minimum_score_ppm\":{},\"nms_iou_ppm\":{},\"maximum_rows\":{},\"maximum_detections\":{},\"labels\":[",
            if tracker.is_some(){"track"}else{"detect"},options.source.import_identity,options.contract.digest(),spec.model_digest,
            json_string(&spec.output_port),match spec.encoding { BoxEncoding::Xyxy=>"xyxy",BoxEncoding::CenterSize=>"cxcywh" },
            match spec.coordinates { CoordinateSpace::Pixels=>"pixels",CoordinateSpace::Normalized=>"normalized" },
            spec.minimum_score_ppm,spec.nms_iou_ppm,spec.maximum_rows,spec.maximum_detections)?;
        for (i,label) in spec.labels.iter().enumerate() { if i!=0 {report.push(',');} report.push_str(&json_string(label)); }
        report.push_str("]},\"tracking_config\":");
        if let Some(c)=options.tracking {
            write!(report,"{{\"minimum_iou_ppm\":{},\"confirmation_hits\":{},\"maximum_missed_frames\":{},\"maximum_tracks\":{}}}",
                c.minimum_iou_ppm,c.confirmation_hits,c.maximum_missed_frames,c.maximum_tracks)?;
        } else {report.push_str("null");}
        report.push_str(",\"model_outputs\":\"uncalibrated\",\"absence_certifiable\":false,\"effects_authorized\":false,\"frames\":[");
        let mut completed=0; let mut failure:Option<String>=None;
        for (segment,id) in &entries {
            let mut source=options.source.clone(); source.segment_index = *segment;
            let frame=match DetectionFrame::read(&deployment,*id,&source,&options.contract,&mut detection_budget,&cx) {
                Ok(frame)=>frame,Err(error)=>{failure=Some(error.to_string());break;}
            };
            let update=match tracker.as_mut().map(|t|t.observe(&frame,&mut association_budget,&cx)).transpose() {
                Ok(update)=>update,Err(error)=>{failure=Some(error.to_string());break;}
            };
            let record=render_frame(&frame,update.as_ref())?;
            if report.len().checked_add(record.len()+1024).is_none_or(|n|n>MAX_REPORT_BYTES) {
                failure=Some("report byte capacity exceeded".into());break;
            }
            if completed!=0 {report.push(',');} report.push_str(&record);completed+=1;
        }
        let complete=failure.is_none();
        let next=entries.get(completed).map_or("null".to_owned(),|(s,_)|s.to_string());
        let next_entry=if complete {"null".into()}else{completed.to_string()};
        writeln!(report,"],\"complete\":{},\"completed_entries\":{},\"requested_entries\":{},\"next_entry\":{},\"next_segment\":{},\"error\":{},\"detector_units_used\":{},\"association_units_used\":{},\"tracking_resume_requires_full_history\":true}}",
            complete,completed,entries.len(),next_entry,next,failure.as_deref().map_or("null".into(),json_string),detection_budget.used(),association_budget.used())?;
        cx.checkpoint("detector_cli:report")?;
        if let Some(path)=&options.report {export(path,report.as_bytes(),&options.root,&cx)?;}
        out.write_all(report.as_bytes())?; Ok(complete)
    })();
    cx.drain_and_finalize();result
}
/// Handles only the two registered local operator subcommands, preserving existing run/read/replay parsing.
pub(super) fn dispatch(args: &[OsString], out: &mut impl Write) -> Option<ExitCode> {
    if !matches!(args.first().and_then(|s|s.to_str()),Some("detect" | "track")) {return None;}
    if args.len()==2 && matches!(args[1].to_str(),Some("--help" | "-h" | "help")) {
        return Some(ExitCode::from(if out.write_all(HELP.as_bytes()).is_ok(){0}else{1}));
    }
    Some(match parse(args) {
        Ok(options)=>match run(options,out) {
            Ok(true)=>ExitCode::from(0),Ok(false)=>ExitCode::from(1),
            Err(e)=>{eprintln!("{}: {e}",fss_cli::ERR_CLI_RUNTIME_FAILURE);ExitCode::from(1)}
        },
        Err(reason)=>{eprintln!("{}: {reason}; use fss-infer detect --help",fss_cli::ERR_CLI_MALFORMED_VALUE);ExitCode::from(2)}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(action: &str) -> Vec<OsString> {
        let mut v=vec![action,"--root","unused","--site","site:test","--import-id",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111","--interpretation","gray","--model-digest",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222","--output-port","detections",
            "--labels","vehicle,animal","--box-format","xyxy","--coordinates","normalized"];
        if action=="detect" {v.extend(["--segment","0","--run-id","sha256:3333333333333333333333333333333333333333333333333333333333333333"]);}
        else {v.extend(["--runs","runs.txt"]);}
        v.into_iter().map(OsString::from).collect()
    }
    #[test]
    fn strict_contract_and_command_specific_options() {
        assert!(parse(&args("detect")).is_ok());assert!(parse(&args("track")).is_ok());
        for extra in [["--runs","x"],["--box-format","xyxy"],["--minimum-score-ppm","1000001"],["--maximum-rows","0"],["--minimum-iou-ppm","1"]] {
            let mut a=args("detect");a.extend(extra.into_iter().map(OsString::from));assert!(parse(&a).is_err());
        }
        let mut a=args("track");a.extend(["--confirmation-hits","0"].into_iter().map(OsString::from));assert!(parse(&a).is_err());
    }
    #[test]
    fn run_manifest_is_exact_bounded_and_ordered() -> Result<(),Box<dyn std::error::Error>> {
        let id=ContentDigest::sha256(b"run");
        assert_eq!(run_list(&format!("0 {id}\n2 {id}\n"))?.len(),2);
        for bad in [String::new(),format!("0 {id} extra"),format!("2 {id}\n1 {id}"),format!("0 {id}\n0 {id}"),format!("0 {id}\n\n"),"0 latest".into()] {
            assert!(run_list(&bad).is_err());
        }
        let big=(0..129).map(|i|format!("{i} {id}\n")).collect::<String>();assert!(run_list(&big).is_err());Ok(())
    }
    #[test]
    fn report_string_escaping_is_json_not_debug_escaping() {
        assert_eq!(json_string("\"\\\n\r\t\0\u{1f}"),"\"\\\"\\\\\\n\\r\\t\\u0000\\u001f\"");
    }
    #[cfg(unix)]
    #[test]
    fn report_paths_preserve_native_os_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let mut a=args("detect");a.push("--report-out".into());a.push(OsString::from_vec(b"report-\xff.json".to_vec()));
        assert!(parse(&a).is_ok());
    }
}
