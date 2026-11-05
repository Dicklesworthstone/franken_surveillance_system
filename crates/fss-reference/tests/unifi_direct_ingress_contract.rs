#![forbid(unsafe_code)]
//! Actual loopback TCP-to-extended-FLV ownership and failure contracts.

use asupersync::{net::TcpListener, runtime::RuntimeBuilder, time::timeout};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::extended_flv::{
    self, Limits, Parse, Tag, avc,
    stream::{Framer, RecordKind, SearchMode, SourceRecord},
};
use fss_reference::unifi_direct::ingress::{DirectIngress, Error as DirectError, Retirement, Step};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    tcp_ingress::TcpIngress,
};
use std::{error::Error, io::Write, time::Duration};

type TestResult = Result<(), Box<dyn Error>>;

fn root() -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn Error>> {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 16 * 1024 * 1024;
    budget.network_bytes = 16 * 1024 * 1024;
    let spec = RootAuthoritySpec {
        trace_id: "trace:direct-ingress".into(),
        operation_id: OperationId::parse("operation:direct-ingress")?,
        principal: "principal:owner".into(),
        capabilities: vec![
            RuntimeGrant::AdapterNet.as_str().into(),
            RuntimeGrant::ReadMedia.as_str().into(),
        ],
        deadline: Some(TimestampNs(100)),
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy:local".into(),
        retention_scope: "retention:approved".into(),
        anchor_universe: ContentDigest::sha256(b"direct ingress contract"),
        generation: 1,
    };
    Ok(AuthorityCx::root(
        spec,
        RegionId::new("region:direct")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?)
}

fn tag(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = vec![
        kind,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    out.extend_from_slice(payload);
    out.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    out
}

fn source() -> Vec<u8> {
    let mut wire = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    wire.extend_from_slice(&tag(
        9,
        0,
        &[
            0x17, 0, 0, 0, 0, 1, 100, 0, 31, 0xff, 0xe1, 0, 3, 0x67, 0x64, 0x1f, 1, 0, 2, 0x68,
            0xaa,
        ],
    ));
    wire.extend_from_slice(&[0x77; 5]);
    wire.extend_from_slice(&tag(9, 40, &[0x17, 1, 0, 0, 0, 0, 0, 0, 2, 0x65, 0x42]));
    wire.extend_from_slice(&[0x77; 3]);
    wire
}

fn receive_case(
    wire: Vec<u8>,
    chunk_size: usize,
    max_buffer: usize,
    expect_limit: bool,
) -> Result<(Vec<SourceRecord>, Retirement), Box<dyn Error>> {
    receive_case_mode(
        wire,
        chunk_size,
        max_buffer,
        expect_limit,
        SearchMode::Conservative,
    )
}

fn receive_case_mode(
    wire: Vec<u8>,
    chunk_size: usize,
    max_buffer: usize,
    expect_limit: bool,
    mode: SearchMode,
) -> Result<(Vec<SourceRecord>, Retirement), Box<dyn Error>> {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let max_total = wire.len() as u64 + 1;
    let run = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let spec = TaskSpec {
            task_id: TaskId::new("task:direct")?,
            started_at: TimestampNs(2),
        };
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            spec,
            &cx,
            async |owner, runtime_cx| {
                let result: Result<(Vec<SourceRecord>, Retirement), String> = async {
                    owner
                        .checkpoint_for(
                            RuntimeGrant::AdapterNet,
                            "fixture:direct",
                            TimestampNs(3),
                            &BudgetVector::ZERO,
                        )
                        .map_err(|e| e.to_string())?;
                    let listener = TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| e.to_string())?;
                    let address = listener.local_addr().map_err(|e| e.to_string())?;
                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
                        socket.write_all(&wire)
                    });
                    let (socket, _) =
                        timeout(runtime_cx.now(), Duration::from_secs(5), listener.accept())
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| e.to_string())?;
                    let tcp = TcpIngress::new(socket, "fixture:direct", chunk_size, max_total)
                        .map_err(|e| e.to_string())?;
                    let framer = Framer::with_mode(Limits::default(), max_buffer, mode)
                        .map_err(|e| e.to_string())?;
                    let mut ingress = DirectIngress::new(tcp, framer);
                    let mut records = Vec::new();
                    let mut terminal = false;
                    for _ in 0..2048 {
                        let next = timeout(
                            runtime_cx.now(),
                            Duration::from_secs(5),
                            ingress.step(owner, runtime_cx, TimestampNs(4)),
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        match next {
                            Ok(Step::Record(record)) => records.push(record),
                            Ok(Step::Progress { appended }) if appended > 0 => {}
                            Ok(Step::Eof) if !expect_limit => {
                                terminal = true;
                                break;
                            }
                            Err(DirectError::Framing(extended_flv::stream::Error::BufferLimit))
                                if expect_limit =>
                            {
                                terminal = true;
                                break;
                            }
                            other => return Err(format!("unexpected progress: {other:?}")),
                        }
                    }
                    if !terminal {
                        return Err("source did not reach expected terminal".into());
                    }
                    sender
                        .join()
                        .map_err(|_| "sender panicked".to_string())?
                        .map_err(|e| e.to_string())?;
                    Ok((records, ingress.retire()))
                }
                .await;
                let outcome = if result.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("ingress fixture failed".into())
                };
                TaskCompletion {
                    output: result,
                    outcome,
                    completed_at: TimestampNs(5),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    let output = run.output?;
    run.receipt?;
    Ok(output)
}

#[test]
fn actual_tcp_chunks_reach_flv_and_avc_with_exact_source_offsets() -> TestResult {
    let wire = source();
    let (records, retirement) = receive_case(wire.clone(), 7, 64, false)?;
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].kind(), RecordKind::Header);
    assert!(matches!(
        records[2].kind(),
        RecordKind::Candidate {
            trailer_bytes: 5,
            timestamp_ms: 40,
            ..
        }
    ));
    assert!(retirement.buffered.is_none());
    assert_eq!(retirement.framing.bytes(), &[0x77; 3]);
    assert_eq!(retirement.source.received as usize, wire.len());
    let mut reassembled = Vec::new();
    for record in &records {
        assert_eq!(record.offset() as usize, reassembled.len());
        reassembled.extend_from_slice(record.bytes());
    }
    reassembled.extend_from_slice(retirement.framing.bytes());
    assert_eq!(reassembled, wire);
    let Parse::Complete(config_tag) = Tag::parse(records[1].bytes(), Limits::default())? else {
        return Err("missing configuration".into());
    };
    let config = avc::VideoTag::parse(config_tag)?.configuration(avc::Limits::default())?;
    let tag_range = records[2].tag_range().ok_or("missing tag range")?;
    let Parse::Complete(video_tag) =
        Tag::parse(&records[2].bytes()[tag_range.clone()], Limits::default())?
    else {
        return Err("missing video".into());
    };
    let nal_units = avc::VideoTag::parse(video_tag)?.nal_units(&config, avc::Limits::default())?;
    let nal = nal_units.iter().next().ok_or("missing NAL")?;
    let offset = records[2].offset() as usize + tag_range.start + nal.range().start;
    assert_eq!(&wire[offset..offset + nal.bytes().len()], &[0x65, 0x42]);
    Ok(())
}

#[test]
fn buffer_exhaustion_returns_the_complete_received_source_prefix() -> TestResult {
    let wire = source();
    let (records, retirement) = receive_case(wire.clone(), 64, 13, true)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind(), RecordKind::Header);
    let mut recovered = records[0].bytes().to_vec();
    assert_eq!(retirement.framing.offset as usize, recovered.len());
    recovered.extend_from_slice(retirement.framing.bytes());
    if let Some(buffered) = &retirement.buffered {
        recovered.extend_from_slice(&buffered.source.bytes()[buffered.appended..]);
    }
    if let Some(chunk) = &retirement.source.pending {
        recovered.extend_from_slice(chunk.bytes());
    }
    assert_eq!(recovered.len() as u64, retirement.source.received);
    assert_eq!(recovered, wire[..recovered.len()]);
    Ok(())
}

#[test]
#[ignore = "owner-authorized live camera bytes must be supplied on stdin"]
fn owner_camera_live_ingress() -> TestResult {
    use std::io::Read;
    let mut wire = Vec::new();
    std::io::stdin()
        .lock()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut wire)?;
    if wire.len() > 8 * 1024 * 1024 || !wire.starts_with(b"FLV\x01") {
        return Err("invalid bounded laboratory input".into());
    }
    let (records, retirement) = receive_case_mode(
        wire.clone(),
        32 * 1024,
        8 * 1024 * 1024,
        false,
        SearchMode::Provisional,
    )?;
    let mut position = 0_usize;
    let mut video = 0_usize;
    let mut avc_samples = 0_usize;
    let mut provisional = 0_usize;
    let mut skipped = 0_usize;
    for record in &records {
        if record.offset() as usize != position
            || wire.get(position..position + record.bytes().len()) != Some(record.bytes())
        {
            return Err("source record mismatch".into());
        }
        position += record.bytes().len();
        if let RecordKind::Candidate {
            provisional: is_provisional,
            earlier_incomplete,
            ..
        } = record.kind()
        {
            provisional += usize::from(is_provisional);
            skipped += usize::from(earlier_incomplete);
        }
        if let Some(range) = record.tag_range() {
            let Parse::Complete(tag) = Tag::parse(&record.bytes()[range], Limits::default())?
            else {
                return Err("incomplete record".into());
            };
            if tag.kind() == 9 {
                video += 1;
                if let Ok(v) = avc::VideoTag::parse(tag)
                    && v.packet_type() == avc::PacketType::NalUnits
                {
                    avc_samples += 1;
                }
            }
        }
    }
    if retirement.buffered.is_some()
        || retirement.source.pending.is_some()
        || wire.get(position..) != Some(retirement.framing.bytes())
        || retirement.source.received as usize != wire.len()
    {
        return Err("incomplete source recovery".into());
    }
    println!(
        "source_bytes={} records={} video_tags={} avc_sample_tags={} provisional_records={} incomplete_candidate_skips={} tail_bytes={}",
        wire.len(),
        records.len(),
        video,
        avc_samples,
        provisional,
        skipped,
        retirement.framing.bytes().len()
    );
    println!(
        "evidence=passive_g4_midstream_synthetic_header_replayed_through_native_asupersync_loopback_no_live_controller"
    );
    if avc_samples == 0 {
        return Err("no AVC samples observed".into());
    }
    Ok(())
}
