#![forbid(unsafe_code)]
//! Explicitly invoked owner-camera recording laboratory; no media is persisted.

use asupersync::{net::TcpListener, runtime::RuntimeBuilder, time::timeout};
use fss_container::{
    demux::{AvcMp4, DemuxLimits},
    flv_avc::SourceKey,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::extended_flv::{
    Limits as FlvLimits, avc,
    stream::{Framer, Remainder, SearchMode, SourceRecord},
};
use fss_reference::unifi_direct::{
    evidence::{Limits as EvidenceLimits, Prepared},
    ingress::{DirectIngress, TrackedIngress, TrackedStep},
    metered::MeteredClock,
    pipeline,
    recording::{Limits, Push, Recorder, SourceDisposition},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    tcp_ingress::TcpIngress,
};
use std::{
    error::Error,
    io::{Read, Write},
    time::Duration,
};

fn tcp_records(wire: Vec<u8>) -> Result<(Vec<SourceRecord>, Remainder), Box<dyn Error>> {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 16 * 1024 * 1024;
    budget.network_bytes = 16 * 1024 * 1024;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:g4-segment-lab".into(),
            operation_id: OperationId::parse("operation:g4-segment-lab")?,
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(100)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:lab".into(),
            anchor_universe: ContentDigest::sha256(
                b"owner authorized passive camera segment laboratory",
            )
            .with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:g4-segment-lab")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let maximum = u64::try_from(wire.len())?
        .checked_add(1)
        .ok_or("input size overflow")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:g4-segment-lab")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |owner, runtime_cx| {
                let output: Result<(Vec<SourceRecord>, Remainder), String> = async {
                    owner
                        .checkpoint_for(
                            RuntimeGrant::AdapterNet,
                            "fixture:g4-segment",
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
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.write_all(&wire)
                    });
                    let (socket, _) =
                        timeout(runtime_cx.now(), Duration::from_secs(5), listener.accept())
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| e.to_string())?;
                    let tcp = TcpIngress::new(socket, "fixture:g4-segment", 32 * 1024, maximum)
                        .map_err(|e| e.to_string())?;
                    let framer = Framer::with_mode(
                        FlvLimits::default(),
                        8 * 1024 * 1024,
                        SearchMode::StructuredTrailer16,
                    )
                    .map_err(|e| e.to_string())?;
                    let mut ingress = TrackedIngress::new(
                        DirectIngress::new(tcp, framer),
                        FlvLimits::default(),
                        avc::Limits::default(),
                    );
                    let mut records = Vec::new();
                    let mut done = false;
                    for _ in 0..4096 {
                        match timeout(
                            runtime_cx.now(),
                            Duration::from_secs(5),
                            ingress.step(owner, runtime_cx, TimestampNs(4)),
                        )
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?
                        {
                            TrackedStep::Record {
                                source,
                                interpretation,
                            } => {
                                interpretation.map_err(|e| e.to_string())?;
                                records.push(source);
                            }
                            TrackedStep::Progress { appended } if appended > 0 => {}
                            TrackedStep::Eof => {
                                done = true;
                                break;
                            }
                            _ => return Err("unexpected source outcome".into()),
                        }
                    }
                    if !done {
                        return Err("source work limit reached".into());
                    }
                    sender
                        .join()
                        .map_err(|_| "source sender panicked".to_owned())?
                        .map_err(|e| e.to_string())?;
                    let retired = ingress.retire();
                    if retired.buffered.is_some() || retired.source.pending.is_some() {
                        return Err("untransferred TCP source".into());
                    }
                    Ok((records, retired.framing))
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("camera segment replay failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(5),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output.map_err(Into::into)
    })
}

fn check_source(
    wire: &[u8],
    offset: &mut usize,
    source: &SourceRecord,
) -> Result<(), Box<dyn Error>> {
    let end = offset
        .checked_add(source.bytes().len())
        .ok_or("source offset overflow")?;
    if source.offset() != *offset as u64 || wire.get(*offset..end) != Some(source.bytes()) {
        return Err("original source mismatch".into());
    }
    *offset = end;
    Ok(())
}

#[test]
#[ignore = "owner-authorized passive camera bytes and a synthetic configuration are required on stdin"]
fn owner_camera_segment_replay() -> Result<(), Box<dyn Error>> {
    let mut wire = Vec::new();
    std::io::stdin()
        .lock()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut wire)?;
    if wire.len() > 8 * 1024 * 1024 || !wire.starts_with(b"FLV\x01") {
        return Err("invalid bounded laboratory input".into());
    }
    let (records, remainder) = tcp_records(wire.clone())?;
    let mut recorder = Recorder::new(
        SourceKey {
            connection: 1,
            generation: 1,
        },
        Limits::default(),
    )?;
    let mut initialization = None;
    let mut configuration = None;
    let mut source_offset = 0_usize;
    let mut segments = 0_usize;
    let mut samples = 0_usize;
    let mut frames = 0_usize;
    for record in records {
        match recorder.push(record).map_err(|error| error.reason)? {
            Push::Source {
                record,
                disposition,
            } => {
                check_source(&wire, &mut source_offset, &record)?;
                if disposition == SourceDisposition::Configuration {
                    initialization = Some(
                        recorder
                            .initialization()
                            .ok_or("missing initialization")?
                            .bytes()
                            .to_vec(),
                    );
                    configuration = Some(record);
                }
            }
            Push::Buffered => {}
            Push::Segment(segment) => {
                let plan = Prepared::new(
                    &segment,
                    configuration
                        .as_ref()
                        .ok_or("missing source configuration")?,
                    recorder.initialization().ok_or("missing initialization")?,
                    ContentDigest::sha256(b"owner-authorized in-memory laboratory"),
                    EvidenceLimits::default(),
                )?;
                let mut object_count = 0_usize;
                plan.visit_objects(|digest, bytes| {
                    assert_eq!(digest, ContentDigest::sha256(bytes));
                    assert!(plan.manifest().children().contains(&digest));
                    object_count += 1;
                });
                if object_count < 5 {
                    return Err("incomplete evidence graph".into());
                }
                for record in segment.source() {
                    check_source(&wire, &mut source_offset, record)?;
                }
                let mut witness_offset = source_offset;
                if segment.lookahead_copies().is_empty() {
                    return Err("missing source boundary witness".into());
                }
                for record in segment.lookahead_copies() {
                    check_source(&wire, &mut witness_offset, record)?;
                }
                for mapping in segment.fragment().nals() {
                    let start = usize::try_from(mapping.source.start)?;
                    let end = usize::try_from(mapping.source.end)?;
                    if wire.get(start..end)
                        != segment.fragment().bytes().get(mapping.target.clone())
                    {
                        return Err("source mapping mismatch".into());
                    }
                }
                let mut mp4 = initialization
                    .as_ref()
                    .ok_or("missing configuration")?
                    .clone();
                mp4.extend_from_slice(segment.fragment().bytes());
                let movie = AvcMp4::parse(&mp4, None, DemuxLimits::default())?;
                let count = movie.samples().len().min(3);
                if count < 3 {
                    return Err("segment contained too few samples".into());
                }
                let annex = movie.annex_b(0, count)?;
                let limits = fss_codec_h264::DecoderLimits {
                    max_pictures: 8,
                    ..fss_codec_h264::DecoderLimits::default()
                };
                let mut decoder = fss_codec_h264::Decoder::new(limits)?;
                let mut decoded = decoder.decode_annex_b(annex.bytes())?;
                decoded.extend(decoder.finish()?);
                if decoded.len() != count
                    || decoded
                        .iter()
                        .any(|picture| (picture.width(), picture.height()) != (1280, 720))
                {
                    return Err("segment decode did not produce expected frames".into());
                }
                segments += 1;
                samples += movie.samples().len();
                frames += decoded.len();
            }
        }
    }
    let tail = recorder.retire();
    for record in &tail.pending {
        check_source(&wire, &mut source_offset, record)?;
    }
    if source_offset as u64 != remainder.offset
        || wire.get(source_offset..) != Some(remainder.bytes())
    {
        return Err("unparsed source tail mismatch".into());
    }
    if segments == 0 {
        return Err("no complete IDR-delimited segment".into());
    }
    println!(
        "segments={segments} samples={samples} decoded_frames={frames} dimensions=1280x720 unclosed_records={} unparsed_tail_bytes={} source=passive_g4 replay=asupersync_tcp_loopback configuration=synthetic_from_separate_recording idr_start=synthetically_selected evidence_graph=prepared_in_memory authenticity=unverified media_persisted=no",
        tail.pending.len(),
        remainder.bytes().len()
    );
    Ok(())
}

#[test]
#[ignore = "owner-authorized passive camera bytes and a synthetic configuration are required on stdin"]
fn owner_camera_pipeline_replay() -> Result<(), Box<dyn Error>> {
    let mut wire = Vec::new();
    std::io::stdin()
        .lock()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut wire)?;
    if wire.len() > 8 * 1024 * 1024 || !wire.starts_with(b"FLV\x01") {
        return Err("invalid bounded laboratory input".into());
    }
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 16 * 1024 * 1024;
    budget.network_bytes = 16 * 1024 * 1024;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:g4-pipeline-lab".into(),
            operation_id: OperationId::parse("operation:g4-pipeline-lab")?,
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(90_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:lab".into(),
            anchor_universe: ContentDigest::sha256(
                b"owner authorized passive camera pipeline laboratory",
            )
            .with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:g4-pipeline-lab")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime context")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:g4-pipeline-lab")?,started_at:TimestampNs(2)},&cx,async |task,cx| {
            let output: Result<(usize,usize,usize,usize),Box<dyn Error>>=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?;
                let address=listener.local_addr()?;
                let original=wire.clone();
                let maximum=u64::try_from(wire.len())?.checked_add(1).ok_or("input limit overflow")?;
                let sender=std::thread::spawn(move || -> std::io::Result<()> {
                    let mut socket=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;
                    socket.write_all(&wire)
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let clock=MeteredClock::new(task,cx,TimestampNs(3))?;
                let tcp=TcpIngress::new(socket,"fixture:g4-pipeline",32*1024,maximum)?;
                let framer=Framer::with_mode(FlvLimits::default(),8*1024*1024,SearchMode::StructuredTrailer16)?;
                let recorder=Recorder::new(SourceKey {connection:1,generation:1},Limits::default())?;
                let mut pipeline=pipeline::Pipeline::new(DirectIngress::new(tcp,framer),recorder);
                let (mut offset,mut segments,mut samples,mut frames)=(0usize,0usize,0usize,0usize);
                let mut ended=false;
                for _ in 0..8192 {
                    match timeout(cx.now(),Duration::from_secs(10),pipeline.step(task,cx,clock.now()?)).await?? {
                        pipeline::Step::Recording(Push::Source {record,..})=>check_source(&original,&mut offset,&record)?,
                        pipeline::Step::Recording(Push::Buffered)|pipeline::Step::Progress {..}=>(),
                        pipeline::Step::Recording(Push::Segment(segment))=>{
                            for record in segment.source() { check_source(&original,&mut offset,record)?; }
                            let mut movie=pipeline.initialization().ok_or("missing initialization")?.bytes().to_vec();
                            movie.extend_from_slice(segment.fragment().bytes());
                            let movie=AvcMp4::parse(&movie,None,DemuxLimits::default())?;
                            let count=movie.samples().len().min(3);
                            if count<3 { return Err("segment contained too few samples".into()); }
                            let annex=movie.annex_b(0,count)?;
                            let mut decoder=fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits {max_pictures:8,..Default::default()})?;
                            let mut decoded=decoder.decode_annex_b(annex.bytes())?;decoded.extend(decoder.finish()?);
                            if decoded.len()!=count || decoded.iter().any(|p|(p.width(),p.height())!=(1280,720)) { return Err("unexpected decoded frames".into()); }
                            segments+=1;samples+=movie.samples().len();frames+=decoded.len();
                        }
                        pipeline::Step::Eof=>{ended=true;break;}
                        pipeline::Step::LimitReached=>return Err("unexpected source limit".into()),
                    }
                }
                if !ended {return Err("pipeline work limit".into());}
                sender.join().map_err(|_|"sender panic")??;
                let retired=pipeline.retire();
                if retired.ingress.buffered.is_some() || retired.ingress.source.pending.is_some() {return Err("pending source chunk".into());}
                for record in &retired.recorder.pending {check_source(&original,&mut offset,record)?;}
                if offset as u64!=retired.ingress.framing.offset || original.get(offset..)!=Some(retired.ingress.framing.bytes()) {return Err("unparsed tail mismatch".into());}
                if segments==0 {return Err("no complete segment".into());}
                Ok((segments,samples,frames,retired.ingress.framing.bytes().len()))
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Success}else{TaskOutcome::Failed("camera pipeline replay failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(89_000_000_000)}
        }).await?;
        result.receipt?;
        let (segments,samples,frames,tail)=result.output?;
        println!("segments={segments} samples={samples} decoded_frames={frames} dimensions=1280x720 unparsed_tail_bytes={tail} source=passive_g4 replay=asupersync_tcp_loopback configuration=synthetic_from_separate_recording idr_start=synthetically_selected authenticity=unverified media_persisted=no");
        Ok::<(),Box<dyn Error>>(())
    })
}
