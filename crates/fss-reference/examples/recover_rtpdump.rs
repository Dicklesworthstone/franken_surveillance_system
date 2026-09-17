#![forbid(unsafe_code)]
//! Inspect or explicitly resume one retained RTP root without its source file.
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};
use fss_reference::ingest::{ADP_FILE_ROW_ID, rtpdump::recovery::{inspect_rtp_import, RtpRecoveryPolicy, RtpRecoveryState}};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => { eprintln!("RTP recovery refused: {error}"); std::process::ExitCode::FAILURE }
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).take(5).collect();
    if args.len() != 4 { return Err("use inspect|resume DEPLOYMENT ROOT_DIGEST PRINCIPAL".into()); }
    let text = |i: usize| -> Result<&str> {
        args[i].to_str().filter(|s| s.len() <= 4096).ok_or_else(|| "invalid argument".into())
    };
    let resume = match text(0)? { "inspect" => false, "resume" => true, _ => return Err("use inspect or resume".into()) };
    let directory = std::path::PathBuf::from(&args[1]);
    if !directory.join("LAYOUT").is_file() { return Err("existing deployment required".into()); }
    let root: ContentDigest = text(2)?.parse()?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtpdump-recovery".into(), operation_id: OperationId::parse("operation:rtpdump-recovery")?,
        principal: text(3)?.to_owned(), capabilities: vec![ADP_REPLAY_ROW_ID.into(), ADP_FILE_ROW_ID.into()],
        deadline: None, priority: 10, budgets: BudgetVector::default(), privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(), anchor_universe: root, generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, &directory)?;
    let mut deployment = ReferenceDeployment::reopen(&directory, "site:recorded-rtp", &cx)?;
    let recovered = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &deployment)?;
    let state = match recovered.state() { RtpRecoveryState::Complete { .. } => "complete", RtpRecoveryState::LedgerPending { .. } => "ledger_pending" };
    println!("{{\"kind\":\"rtpdump_root_verified\",\"root\":\"{}\",\"state\":\"{state}\",\"source_bytes\":{},\"nals\":{},\"absence_certifiable\":false}}",
        root, recovered.source().len(), recovered.report().nals().len());
    if resume {
        let receipt = recovered.resume(&cx, &mut deployment)?;
        println!("{{\"kind\":\"rtpdump_resume_complete\",\"root\":\"{}\",\"commit_sequence\":{}}}", receipt.root(), receipt.anchor().commit_sequence);
    }
    Ok(())
}
