#![forbid(unsafe_code)]
//! Owner-driven recorded-RTP import, publication and verified readback. No sockets.
//! cargo run --locked -p fss-reference --example ingest_rtpdump -- \
//!   FILE DEPLOYMENT SENSOR STREAM GENERATION SSRC PT RECEIVE_NS PRINCIPAL

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    StreamId, TimestampNs,
};
use fss_packet::{H264Limits, H264Mode, PacketLimits, RtcpMode, StreamKey};
use fss_reference::ingest::rtpdump::{
    RtpDumpLimits,
    import::{ImportEnd, RtpImportError, RtpImportLimits, load_rtp_import},
    replay::RtpReplayConfig,
};
use fss_reference::ingest::{
    ADP_FILE_ROW_ID, FileFormatHint, FileIngestAdapter, FileIngestRequest,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rtpdump import refused: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).take(10).collect();
    if args.len() != 9 {
        return Err(
            "use FILE DEPLOYMENT SENSOR STREAM GENERATION SSRC PT RECEIVE_NS PRINCIPAL".into(),
        );
    }
    let arg = |i: usize| -> Result<&str> {
        args[i]
            .to_str()
            .filter(|s| s.len() <= 4096)
            .ok_or_else(|| "invalid or overlong argument".into())
    };
    let source = std::path::PathBuf::from(&args[0]);
    let root = std::path::PathBuf::from(&args[1]);
    let sensor = SensorId::parse(arg(2)?)?;
    let stream = StreamId::parse(arg(3)?)?;
    let generation = arg(4)?.parse()?;
    let ssrc = match arg(5)?.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16)?,
        None => arg(5)?.parse()?,
    };
    let payload_type = arg(6)?.parse()?;
    let receive_time = TimestampNs(arg(7)?.parse()?);
    // This local reference command acts under the invoking owner's explicit scope;
    // constructing a context is not authentication of a remote camera or sender.
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtpdump-import".into(),
        operation_id: OperationId::parse("operation:rtpdump-import")?,
        principal: arg(8)?.to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.into(), ADP_FILE_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: ContentDigest::try_sha256(b"reference-rtpdump-import")?,
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, &root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-rtp", &cx)
        .map_err(RtpImportError::Reference)?;
    let config = RtpReplayConfig {
        key: StreamKey {
            ingress: 1,
            generation,
            ssrc,
        },
        payload_type,
        mode: H264Mode::NonInterleaved,
        dump: RtpDumpLimits::default(),
        packet: PacketLimits::default(),
        codec: H264Limits::default(),
        rtcp: RtcpMode::Compound,
    };
    let mut request =
        FileIngestRequest::new(source, sensor, stream).with_format_hint(FileFormatHint::RtpPlay);
    request.receive_time = Some(receive_time);
    let receipt = FileIngestAdapter::ingest_rtp(
        request,
        config,
        RtpImportLimits::default(),
        &cx,
        &mut deployment,
    )?;
    let verified = load_rtp_import(&receipt, &cx, &deployment)?;
    let report = verified.report();
    // Surface refusals and probation as well as successful reconstruction. The
    // Debug spellings below contain only closed, payload-free enum variants.
    for (index, record) in report.records().iter().enumerate() {
        println!(
            "{{\"kind\":\"rtpdump_record\",\"ordinal\":{index},\"disposition\":\"{:?}\",\"source_start\":{},\"source_end\":{},\"continuity_fenced\":{},\"expired_fragment\":{},\"discarded_fragment\":{}}}",
            record.disposition,
            record.source.start,
            record.source.end,
            record.gap_before,
            record.expired.is_some(),
            record.discarded.is_some()
        );
    }
    for (index, nal) in report.nals().iter().enumerate() {
        println!(
            "{{\"kind\":\"source_linked_nal\",\"ordinal\":{index},\"digest\":\"{}\",\"source_digest\":\"{}\",\"source_spans\":{},\"decoded_frames\":0}}",
            nal.digest,
            nal.capsule.source_digest,
            nal.spans.len()
        );
    }
    println!(
        "{{\"kind\":\"rtpdump_import_verified\",\"root\":\"{}\",\"source_digest\":\"{}\",\"source_bytes\":{},\"records\":{},\"nals\":{},\"container_eof\":{},\"unfinished_fragment\":{},\"decoded_frames\":0,\"absence_certifiable\":false}}",
        receipt.root(),
        report.input_digest(),
        report.input_bytes(),
        report.records().len(),
        report.nals().len(),
        matches!(report.end(), ImportEnd::Ended),
        report.final_discard().is_some()
    );
    Ok(())
}
