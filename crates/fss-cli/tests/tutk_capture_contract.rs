#![forbid(unsafe_code)]
//! Contract tests for `fss-capture-tutk` (`bind_ip` defaulting/validation),
//! zero-orphan TUTK root-last sealing (eliminating the 186-object
//! `objects.unreferenced` leak on normal completion and cancellation), and
//! unified File + RTSP + TUTK discovery in `query --target footage` and `orient`.

use std::collections::BTreeSet;
use std::fs;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse as parse_json};
use fss_container::TimedAvcPicture;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    AgentView, BudgetVector, ContentDigest, OperationId, PrincipalId, SensorId, StreamId,
    TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_packet::avc::{
    AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll, AvcReceiver, parse_pps,
    parse_sps,
};
use fss_packet::{H264Mode, StreamKey};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::agent_footage::{
    FootageQueryFilter, FootageQueryLimits, FootageQueryRequest, query_footage,
};
use fss_reference::agent_orient::{
    OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use fss_reference::doctor::{DoctorReport, DoctorValue, DoctorVerdict, inspect_deployment};
use fss_reference::ingest::file_publication::STAGE_FILE_PART_PREFLIGHT;
use fss_reference::ingest::rtsp_import::{
    RtspImportAuthority, RtspImportCodec, RtspImportRequest, import_rtsp,
};
use fss_reference::ingest::tutk::{
    ADAPTER as TUTK_ADAPTER, ADAPTER_FAMILY as TUTK_ADAPTER_FAMILY, AcquisitionState, AudioPolicy,
    TutkIngest, TutkIngestConfig, TutkIngestLimits,
};
use fss_reference::ingest::{
    ADP_FILE_ROW_ID, FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits, split_annexb,
};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording::{RecordingPacket, RecordingScope, prepare_recording};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_tutk::av::{
    self, AV_VERSION, CHANNEL_I_VIDEO, FRAMEINFO_LEN, MAGIC_AV_LOGIN_RESP, MAGIC_IOCTRL, build_hl,
};
use fss_tutk::chacha::{aead_decrypt, aead_encrypt};
use fss_tutk::digest::Sha256;
use fss_tutk::dtls::{DTLS12, pack_handshake, pack_record, parse_records, prf};
use fss_tutk::session::{AssembledFrame, SessionConfig, SessionEvent};
use fss_tutk::wire::{CHANNEL_MAIN, CMD_DISCOVERY, CMD_DTLS, NewProto, derive_psk};
use fss_tutk::x25519::{x25519, x25519_base};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SITE: &str = "site:tutk-capture-contract";
const MOCK_UID: &str = "SIMCAMSIMCAMSIMCAM11";
const MOCK_ENR: &str = "sim-enr-16byte!!";
const MOCK_MAC: &str = "00AA11BB22CC";
const MOCK_GENERATION: &str = "HL_CAM4/4.52.17.26";

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TestResult<Self> {
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "fss-tutk-contract-{label}-{}-{}",
                std::process::id(),
                DIR_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base)?;
        Ok(Self(base))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root unavailable")?
        .to_path_buf())
}

fn test_cx(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:tutk-capture-contract".to_owned(),
        operation_id: OperationId::parse("operation:tutk-capture-contract")?,
        principal: "principal:tutk-capture-contract".to_owned(),
        capabilities: vec![
            "ADP-FILE-001".to_owned(),
            "ADP-REPLAY-001".to_owned(),
            "ADP-WYZE-V4-LAB-001".to_owned(),
            "CAP-READ-MEDIA-001".to_owned(),
            "CAP-OBJECT-STAGE-001".to_owned(),
            "CAP-OBJECT-PUBLISH-001".to_owned(),
            "CAP-RETENTION-COMMIT-001".to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:owner-authorized-lan".to_owned(),
        retention_scope: "retention:contract-test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&authority, root)?)
}

fn doctor_unreferenced_count(report: &DoctorReport) -> TestResult<i64> {
    let check = report
        .check("objects.unreferenced")
        .ok_or("missing objects.unreferenced check")?;
    match check.fields.get("counts") {
        Some(DoctorValue::Object(map)) => match map.get("unreferenced_objects") {
            Some(DoctorValue::Number(count)) => Ok(*count),
            other => Err(format!("unexpected unreferenced_objects value: {other:?}").into()),
        },
        other => Err(format!("unexpected counts field: {other:?}").into()),
    }
}

fn clean_h264_aus(cx: &ReplayCx) -> TestResult<Vec<Vec<u8>>> {
    let path = repo_root()?.join("tests/fixtures/media/h264/clean.264");
    let bytes = fs::read(path)?;
    let scan = split_annexb(&bytes, Default::default(), cx)?;
    let mut aus = Vec::with_capacity(scan.access_units.len());
    for au in &scan.access_units {
        aus.push(bytes[au.span.offset..au.span.offset + au.span.len].to_vec());
    }
    if aus.is_empty() {
        return Err("clean.264 yielded zero access units".into());
    }
    Ok(aus)
}

fn make_tutk_ingest(sensor: &str, stream: &str, seed: u64) -> TestResult<TutkIngest> {
    Ok(TutkIngest::new(TutkIngestConfig {
        session: SessionConfig {
            uid: MOCK_UID.to_owned(),
            enr: MOCK_ENR.to_owned(),
            mac: MOCK_MAC.to_owned(),
            audio: false,
            psk_truncated: false,
            seed,
            entropy: None,
            known_tuples: vec![("HL_CAM4".to_owned(), "4.52.17.26".to_owned())],
        },
        sensor_id: SensorId::parse(sensor)?,
        stream_id: StreamId::parse(stream)?,
        site_lineage: SITE.to_owned(),
        audio: AudioPolicy::Disabled,
        limits: TutkIngestLimits::default(),
        known_tuples: vec![("HL_CAM4".to_owned(), "4.52.17.26".to_owned())],
    })?)
}

fn feed_synthetic_h264_frames(
    ing: &mut TutkIngest,
    base_aus: &[Vec<u8>],
    frame_count: u32,
) -> Vec<Vec<u8>> {
    ing.handle_event(
        SessionEvent::KAuthComplete {
            camera_info: r#"{"connectionRes":"1","cameraInfo":{"basicInfo":{"model":"HL_CAM4","firmware":"4.52.17.26","type":"normal"}}}"#.to_owned(),
        },
        1_000,
    );
    ing.handle_event(
        SessionEvent::StreamStarted {
            payload: b"k10011-ok".to_vec(),
        },
        2_000,
    );
    let mut emitted = Vec::with_capacity(frame_count as usize);
    for idx in 0..frame_count {
        // Keep each synthetic AU distinct and valid Annex-B so every frame
        // produces a distinct SHA-256 digest (reproducing the 186-object case).
        let mut au = base_aus[(idx as usize) % base_aus.len()].clone();
        // Append an Annex-B filler/SEI-like trailing payload marker to ensure
        // unique content digests across repeated fixture frames.
        au.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x0C]);
        au.extend_from_slice(&idx.to_be_bytes());
        au.push(0x80);
        let first_ns = 10_000_000_000 + u64::from(idx) * 33_333_333;
        let last_ns = first_ns + 500_000;
        ing.handle_event(
            SessionEvent::Frame(AssembledFrame {
                channel: CHANNEL_I_VIDEO,
                frame_no: idx,
                au: au.clone(),
                info: Some(av::FrameInfo {
                    codec_id: 0x4E,
                    codec: av::Codec::H264,
                    is_keyframe: idx % 30 == 0,
                    framerate: 30,
                    payload_size: au.len() as u32,
                    frame_no: idx,
                    timestamp_us: idx * 33_333,
                }),
                first_recv_ns: first_ns,
                last_recv_ns: last_ns,
                packets: 1,
                gap_before: false,
            }),
            last_ns,
        );
        emitted.push(au);
    }
    emitted
}

// ---------------------------------------------------------------------------
// Minimal deterministic pure-Rust loopback TUTK 0xCC51 + DTLS 1.2 PSK server
// ---------------------------------------------------------------------------

fn dtls_nonce(iv: &[u8; 12], epoch: u16, seq: u64) -> [u8; 12] {
    let mut seq64 = [0u8; 8];
    seq64[..2].copy_from_slice(&epoch.to_be_bytes());
    seq64[2..].copy_from_slice(&seq.to_be_bytes()[2..]);
    let mut out = [0u8; 12];
    for i in 0..12 {
        out[i] = iv[i] ^ if i < 4 { 0 } else { seq64[i - 4] };
    }
    out
}

fn dtls_aad(epoch: u16, seq: u64, ct: u8, plain_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(13);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes()[2..]);
    out.push(ct);
    out.extend_from_slice(&DTLS12);
    out.extend_from_slice(&(plain_len as u16).to_be_bytes());
    out
}

fn build_mock_camera_ioctrl(wseq: u16, hl: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32 + hl.len()];
    out[0..2].copy_from_slice(&MAGIC_IOCTRL.to_le_bytes());
    out[4..6].copy_from_slice(&wseq.to_le_bytes());
    out[32..].copy_from_slice(hl);
    out
}

fn build_mock_av_video_packet(frame_no: u32, au: &[u8], keyframe: bool) -> Vec<u8> {
    let mut fi = [0u8; FRAMEINFO_LEN];
    fi[0..2].copy_from_slice(&0x004Eu16.to_le_bytes()); // H.264
    fi[2] = u8::from(keyframe);
    fi[5] = 30;
    fi[8..12].copy_from_slice(&(frame_no * 33_333).to_le_bytes());
    fi[16..20].copy_from_slice(&(au.len() as u32).to_le_bytes());
    fi[20..24].copy_from_slice(&frame_no.to_le_bytes());

    let payload_len = au.len() + FRAMEINFO_LEN;
    let mut hdr = [0u8; 28];
    hdr[0] = CHANNEL_I_VIDEO;
    hdr[1] = 0x01; // 28-byte header + END marker
    hdr[12..14].copy_from_slice(&1u16.to_le_bytes()); // pkt_total = 1
    hdr[14..16].copy_from_slice(&0u16.to_le_bytes()); // pkt_idx = 0
    hdr[16..18].copy_from_slice(&(payload_len as u16).to_le_bytes());
    hdr[24..28].copy_from_slice(&frame_no.to_le_bytes());

    let mut out = Vec::with_capacity(28 + payload_len);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(au);
    out.extend_from_slice(&fi);
    out
}

struct MockTutkServer {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for MockTutkServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Spawn a complete deterministic pure-Rust TUTK 0xCC51 mock camera that runs
/// discovery → DTLS 1.2 ECDHE_PSK → AV Login → K10000/10001/10002/10003 →
/// K10010/10011 → H.264 Annex-B video frames over loopback UDP.
fn spawn_mock_camera(frames: Vec<Vec<u8>>) -> TestResult<MockTutkServer> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    let port = sock.local_addr()?.port();
    sock.set_read_timeout(Some(Duration::from_millis(20)))?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        let Some(proto) = NewProto::new(MOCK_UID, MOCK_ENR, MOCK_MAC) else {
            return;
        };
        let psk = derive_psk(MOCK_ENR);
        let ticket: u16 = 0x0042;
        let mut session_id = [0u8; 8];
        let server_secret = [0x37u8; 32];
        let server_pub = x25519_base(&server_secret);
        let server_random = [0x5Au8; 32];

        let mut client_random = [0u8; 32];
        let mut transcript = Vec::new();
        let mut master_secret: Option<Vec<u8>> = None;
        let mut c_key = [0u8; 32];
        let mut s_key = [0u8; 32];
        let mut c_iv = [0u8; 12];
        let mut s_iv = [0u8; 12];
        let mut dtls_ready = false;
        let mut server_seq0: u64 = 0;
        let mut server_seq1: u64 = 0;
        let mut wseq: u16 = 1;
        let mut login_replied = false;
        let mut k10001_sent = false;
        let mut k10003_sent = false;
        let mut streamed = false;

        let encrypt_record =
            |ct: u8, plain: &[u8], s_key: &[u8; 32], s_iv: &[u8; 12], seq1: &mut u64| -> Vec<u8> {
                let nonce = dtls_nonce(s_iv, 1, *seq1);
                let aad = dtls_aad(1, *seq1, ct, plain.len());
                let (ciphertext, tag) = aead_encrypt(s_key, &nonce, &aad, plain);
                let mut sealed = ciphertext;
                sealed.extend_from_slice(&tag);
                let rec = pack_record(ct, 1, *seq1, &sealed);
                *seq1 += 1;
                rec
            };

        let send_appdata = |sock: &UdpSocket,
                            peer: std::net::SocketAddr,
                            plain: &[u8],
                            s_key: &[u8; 32],
                            s_iv: &[u8; 12],
                            seq1: &mut u64,
                            sid: &[u8; 8]| {
            let rec = encrypt_record(23, plain, s_key, s_iv, seq1);
            let wrapped = proto.wrap_dtls(&rec, ticket, sid, CHANNEL_MAIN);
            let _ = sock.send_to(&wrapped, peer);
        };

        let mut buf = [0u8; 65535];
        let deadline = Instant::now() + Duration::from_secs(15);
        while !stop_flag.load(Ordering::Relaxed) && Instant::now() < deadline {
            let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                continue;
            };
            let pkt = &buf[..n];
            match NewProto::peek_command(pkt) {
                Some(CMD_DISCOVERY) => {
                    if let Ok(disc) = proto.parse_discovery(pkt) {
                        session_id = disc.session_id;
                        let reply_seq = if disc.seq == 0 { 1 } else { 3 };
                        let resp = proto.build_discovery_response(reply_seq, ticket, &session_id);
                        let _ = sock.send_to(&resp, peer);
                    }
                }
                Some(CMD_DTLS) => {
                    let Ok((dtls_bytes, auth_ok, _)) = proto.unwrap_dtls(pkt, false) else {
                        continue;
                    };
                    if !auth_ok {
                        continue;
                    }
                    let Ok(records) = parse_records(dtls_bytes) else {
                        continue;
                    };
                    for rec in records {
                        if !dtls_ready {
                            if rec.content_type == 22 && rec.epoch == 0 && rec.payload.len() >= 12 {
                                let mtype = rec.payload[0];
                                let body = &rec.payload[12..];
                                if mtype == 1 && body.len() >= 34 {
                                    client_random.copy_from_slice(&body[2..34]);
                                    transcript.clear();
                                    transcript.extend_from_slice(&rec.payload);

                                    let mut sh = Vec::with_capacity(38);
                                    sh.extend_from_slice(&DTLS12);
                                    sh.extend_from_slice(&server_random);
                                    sh.push(0);
                                    sh.extend_from_slice(&0xCCACu16.to_be_bytes());
                                    sh.push(0);
                                    let sh_msg = pack_handshake(2, 0, &sh);

                                    let mut ske = Vec::with_capacity(38);
                                    ske.extend_from_slice(&0u16.to_be_bytes());
                                    ske.push(3);
                                    ske.extend_from_slice(&0x001Du16.to_be_bytes());
                                    ske.push(32);
                                    ske.extend_from_slice(&server_pub);
                                    let ske_msg = pack_handshake(12, 1, &ske);

                                    let shd_msg = pack_handshake(14, 2, &[]);

                                    transcript.extend_from_slice(&sh_msg);
                                    transcript.extend_from_slice(&ske_msg);
                                    transcript.extend_from_slice(&shd_msg);

                                    let mut flight = Vec::new();
                                    for msg in [&sh_msg, &ske_msg, &shd_msg] {
                                        flight.extend_from_slice(&pack_record(
                                            22,
                                            0,
                                            server_seq0,
                                            msg,
                                        ));
                                        server_seq0 += 1;
                                    }
                                    let wrapped =
                                        proto.wrap_dtls(&flight, ticket, &session_id, CHANNEL_MAIN);
                                    let _ = sock.send_to(&wrapped, peer);
                                } else if mtype == 16 && body.len() >= 3 {
                                    transcript.extend_from_slice(&rec.payload);
                                    let id_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                                    if body.len() >= 2 + id_len + 33 {
                                        let mut c_pub = [0u8; 32];
                                        c_pub.copy_from_slice(
                                            &body[2 + id_len + 1..2 + id_len + 33],
                                        );
                                        let shared = x25519(&server_secret, &c_pub);
                                        let mut premaster = Vec::new();
                                        premaster.extend_from_slice(
                                            &(shared.len() as u16).to_be_bytes(),
                                        );
                                        premaster.extend_from_slice(&shared);
                                        premaster
                                            .extend_from_slice(&(psk.len() as u16).to_be_bytes());
                                        premaster.extend_from_slice(&psk);
                                        let mut mseed = Vec::with_capacity(64);
                                        mseed.extend_from_slice(&client_random);
                                        mseed.extend_from_slice(&server_random);
                                        let master = prf(&premaster, b"master secret", &mseed, 48);
                                        let mut kseed = Vec::with_capacity(64);
                                        kseed.extend_from_slice(&server_random);
                                        kseed.extend_from_slice(&client_random);
                                        let kb = prf(&master, b"key expansion", &kseed, 88);
                                        c_key.copy_from_slice(&kb[0..32]);
                                        s_key.copy_from_slice(&kb[32..64]);
                                        c_iv.copy_from_slice(&kb[64..76]);
                                        s_iv.copy_from_slice(&kb[76..88]);
                                        master_secret = Some(master);
                                    }
                                }
                            } else if rec.content_type == 22
                                && rec.epoch == 1
                                && rec.payload.len() >= 16
                            {
                                let Some(master) = &master_secret else {
                                    continue;
                                };
                                let (ct, tag_slice) = rec.payload.split_at(rec.payload.len() - 16);
                                let mut tag = [0u8; 16];
                                tag.copy_from_slice(tag_slice);
                                let nonce = dtls_nonce(&c_iv, 1, rec.seq);
                                let aad = dtls_aad(1, rec.seq, 22, ct.len());
                                let Some(plain) = aead_decrypt(&c_key, &nonce, &aad, ct, &tag)
                                else {
                                    continue;
                                };
                                transcript.extend_from_slice(&plain);
                                let verify = prf(
                                    master,
                                    b"server finished",
                                    &Sha256::digest(&transcript),
                                    12,
                                );
                                let fin_msg = pack_handshake(20, 3, &verify);
                                let mut resp = pack_record(20, 0, server_seq0, &[1]);
                                server_seq0 += 1;
                                resp.extend_from_slice(&encrypt_record(
                                    22,
                                    &fin_msg,
                                    &s_key,
                                    &s_iv,
                                    &mut server_seq1,
                                ));
                                let wrapped =
                                    proto.wrap_dtls(&resp, ticket, &session_id, CHANNEL_MAIN);
                                let _ = sock.send_to(&wrapped, peer);
                                dtls_ready = true;
                            }
                        } else if rec.content_type == 23
                            && rec.epoch == 1
                            && rec.payload.len() >= 16
                        {
                            let (ct, tag_slice) = rec.payload.split_at(rec.payload.len() - 16);
                            let mut tag = [0u8; 16];
                            tag.copy_from_slice(tag_slice);
                            let nonce = dtls_nonce(&c_iv, 1, rec.seq);
                            let aad = dtls_aad(1, rec.seq, 23, ct.len());
                            let Some(app) = aead_decrypt(&c_key, &nonce, &aad, ct, &tag) else {
                                continue;
                            };
                            if app.len() < 4 {
                                continue;
                            }
                            let magic = u16::from_le_bytes([app[0], app[1]]);
                            if (magic == 0x0000 || magic == 0x2000) && !login_replied {
                                login_replied = true;
                                let mut resp = vec![0u8; 44];
                                resp[0..2].copy_from_slice(&MAGIC_AV_LOGIN_RESP.to_le_bytes());
                                resp[2..4].copy_from_slice(&AV_VERSION.to_le_bytes());
                                resp[4] = 0x10;
                                resp[16..20].copy_from_slice(&20u32.to_le_bytes());
                                send_appdata(
                                    &sock,
                                    peer,
                                    &resp,
                                    &s_key,
                                    &s_iv,
                                    &mut server_seq1,
                                    &session_id,
                                );
                            } else if let Some(hl_pos) = app.windows(2).position(|w| w == b"HL") {
                                let hl = &app[hl_pos..];
                                if hl.len() >= 8 {
                                    let cmd = u16::from_le_bytes([hl[4], hl[5]]);
                                    match cmd {
                                        10000 if !k10001_sent => {
                                            k10001_sent = true;
                                            let mut p = vec![0u8; 17];
                                            p[0] = 1; // usable status (default key mode)
                                            p[1..17].copy_from_slice(&[0x42u8; 16]);
                                            let io = build_mock_camera_ioctrl(
                                                wseq,
                                                &build_hl(10001, &p),
                                            );
                                            wseq += 1;
                                            send_appdata(
                                                &sock,
                                                peer,
                                                &io,
                                                &s_key,
                                                &s_iv,
                                                &mut server_seq1,
                                                &session_id,
                                            );
                                        }
                                        10002 if !k10003_sent => {
                                            k10003_sent = true;
                                            let info = br#"{"connectionRes":"1","cameraInfo":{"basicInfo":{"model":"HL_CAM4","firmware":"4.52.17.26","type":"normal"}}}"#;
                                            let io = build_mock_camera_ioctrl(
                                                wseq,
                                                &build_hl(10003, info),
                                            );
                                            wseq += 1;
                                            send_appdata(
                                                &sock,
                                                peer,
                                                &io,
                                                &s_key,
                                                &s_iv,
                                                &mut server_seq1,
                                                &session_id,
                                            );
                                        }
                                        10010 if !streamed => {
                                            streamed = true;
                                            let io = build_mock_camera_ioctrl(
                                                wseq,
                                                &build_hl(10011, b"ok"),
                                            );
                                            wseq += 1;
                                            send_appdata(
                                                &sock,
                                                peer,
                                                &io,
                                                &s_key,
                                                &s_iv,
                                                &mut server_seq1,
                                                &session_id,
                                            );
                                            for (idx, au) in frames.iter().enumerate() {
                                                let pkt = build_mock_av_video_packet(
                                                    idx as u32,
                                                    au,
                                                    idx == 0,
                                                );
                                                send_appdata(
                                                    &sock,
                                                    peer,
                                                    &pkt,
                                                    &s_key,
                                                    &s_iv,
                                                    &mut server_seq1,
                                                    &session_id,
                                                );
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });

    Ok(MockTutkServer {
        port,
        stop,
        handle: Some(handle),
    })
}

// ---------------------------------------------------------------------------
// Minimal deterministic native RTSP recording fixture for unified query test
// ---------------------------------------------------------------------------

struct AllowRtsp;

impl RtspImportAuthority for AllowRtsp {
    fn permit(&self, _: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
        destination.site_lineage() == SITE
    }
}

fn split_nals(bytes: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            starts.push((i, i + 3));
            i += 3;
        } else if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 0 && bytes[i + 3] == 1 {
            starts.push((i, i + 4));
            i += 4;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::new();
    for (idx, &(_, payload_start)) in starts.iter().enumerate() {
        let end = starts.get(idx + 1).map_or(bytes.len(), |&(s, _)| s);
        if payload_start < end {
            out.push(&bytes[payload_start..end]);
        }
    }
    out
}

fn make_rtp_packet(seq: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + payload.len());
    pkt.push(0x80);
    pkt.push(if marker { 0x80 | 96 } else { 96 });
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&(u32::from(seq) * 3600).to_be_bytes());
    pkt.extend_from_slice(&7u32.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

fn seed_rtsp_import(
    archive_dir: &Path,
    deployment: &mut ReferenceDeployment,
    cx: &ReplayCx,
) -> TestResult<fss_reference::ingest::rtsp_import::RtspImportReceipt> {
    let avc_bytes =
        fs::read(repo_root()?.join("crates/fss-packet/tests/fixtures/avc/baseline.264"))?;
    let nals = split_nals(&avc_bytes);
    let limits = AvcReceiveLimits::default();
    let sps = parse_sps(nals.first().ok_or("missing SPS")?, limits.syntax)?;
    let pps = parse_pps(nals.get(1).ok_or("missing PPS")?, &sps, limits.syntax)?;
    let key = StreamKey {
        ingress: 901,
        generation: 1,
        ssrc: 7,
    };
    let mut receiver = AvcReceiver::new(key, 96, H264Mode::NonInterleaved, limits, (sps, pps))?;
    receiver.ingest(key, &make_rtp_packet(0, false, nals[0]), 0)?;

    let mut pictures: Vec<AvcPictureGroup> = Vec::new();
    let mut packets: Vec<(u64, u64, Vec<u8>)> = Vec::new();
    for (idx, nal) in nals.into_iter().enumerate() {
        let seq = 1u16 + idx as u16;
        let vcl = matches!(nal[0] & 31, 1 | 5);
        let wire = make_rtp_packet(seq, vcl, nal);
        receiver.ingest(key, &wire, u64::from(seq))?;
        packets.push((u64::from(seq), u64::from(seq), wire));
        for _ in 0..1024 {
            match receiver.poll(u64::from(seq))? {
                AvcReceivePoll::Source { .. } => {}
                AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
                    if let Some(pic) = output.picture {
                        pictures.push(pic);
                    }
                }
                AvcReceivePoll::Picture(pic) => pictures.push(pic),
                AvcReceivePoll::Pending { .. } => break,
                other => return Err(format!("unexpected AVC poll outcome: {other:?}").into()),
            }
        }
        if vcl {
            break;
        }
    }
    let scope = RecordingScope {
        sensor: SensorId::parse("sensor:rtsp-driveway")?,
        stream: StreamId::parse("stream:rtsp-main")?,
        generation: 1,
        anchor: ContentDigest::sha256(b"rtsp-owner-anchor"),
        receive_clock: ContentDigest::sha256(b"rtsp-host-clock"),
    };
    let timed: Vec<_> = pictures
        .iter()
        .enumerate()
        .map(|(i, picture)| TimedAvcPicture {
            picture,
            decode_time: i as u64 * 3600,
            duration: 3600,
            composition_offset: 0,
        })
        .collect();
    let source_packets: Vec<_> = packets
        .iter()
        .map(|(s, r, b)| RecordingPacket {
            sequence: *s,
            received_ns: *r,
            bytes: b,
        })
        .collect();
    let prepared = prepare_recording(scope.clone(), 90_000, &timed, &source_packets)?;

    let pub_limits = LocalPublicationLimits::new(
        16,
        512,
        16,
        256,
        SpoolLimits::new(256, 128 * 1024 * 1024, 32 * 1024 * 1024, 256),
    );
    let mut publisher = LocalRootPublisher::open(archive_dir, pub_limits)?;
    let slot = SlotName::parse("rtsp-win-0001")?;
    let mut publication = RecordingPublication::new(
        &prepared,
        &mut publisher,
        slot.clone(),
        prepared.byte_len(),
        100,
    )?;
    for at in 0..4 {
        assert!(matches!(
            publication.step(at, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        publication.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    drop(publication);

    let req = RtspImportRequest {
        codec: RtspImportCodec::Avc,
        slot,
        root: prepared.manifest().root(),
        source: scope,
        receive_time: TimestampNs(5_000_000_000),
        capture_origin: None,
        max_frames: 64,
        max_original_bytes: 16 * 1024 * 1024,
        max_media_bytes: 16 * 1024 * 1024,
    };
    let mut work = WorkBudget::new(256 * 1024 * 1024);
    Ok(import_rtsp(
        &publisher, deployment, &req, &AllowRtsp, cx, &mut work,
    )?)
}

fn json_string_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    match value.object().and_then(|obj| obj.get(key)) {
        Some(Value::Text(s)) => Ok(s.as_str()),
        other => Err(format!("missing string field {key}: {other:?}").into()),
    }
}

// ---------------------------------------------------------------------------
// Contract Tests
// ---------------------------------------------------------------------------

#[test]
fn cli_empty_whitespace_and_invalid_bind_ip_contract() -> TestResult {
    let dir = TempDir::new("cli-bind-ip")?;
    let split_cx = test_cx(dir.path())?;
    let base_aus = clean_h264_aus(&split_cx)?;

    // 1. Non-empty invalid bind_ip must fail closed with typed refusal.
    let bad_cfg = dir.path().join("bad_bind.json");
    let bad_root = dir.path().join("bad_root");
    fs::write(
        &bad_cfg,
        format!(
            "{{\"uid\":\"{MOCK_UID}\",\"enr\":\"{MOCK_ENR}\",\"mac\":\"{MOCK_MAC}\",\"camera_ip\":\"127.0.0.1\",\"camera_port\":32761,\"bind_ip\":\"not-an-ip\"}}"
        ),
    )?;
    let bad_out = Command::new(env!("CARGO_BIN_EXE_fss-capture-tutk"))
        .args(["--root"])
        .arg(&bad_root)
        .args(["--cfg"])
        .arg(&bad_cfg)
        .args(["--secs", "1", "--site", SITE, "--owner-authorized"])
        .output()?;
    assert!(
        !bad_out.status.success(),
        "invalid bind_ip must fail closed"
    );
    let bad_err = String::from_utf8(bad_out.stderr)?;
    assert!(
        bad_err.contains("ERR-TUTK-CAPTURE-CONFIG-004"),
        "expected ERR-TUTK-CAPTURE-CONFIG-004, got: {bad_err}"
    );

    // 2. Empty ("") and whitespace ("   ") bind_ip default cleanly to 0.0.0.0,
    //    complete capture against the pure-Rust loopback TUTK mock server, and
    //    produce a doctor-Healthy deployment visible in footage + orient.
    let mut mock_frames = Vec::new();
    for i in 0..8usize {
        let mut au = base_aus[i % base_aus.len()].clone();
        au.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x0C, i as u8, 0x80]);
        mock_frames.push(au);
    }

    for (label, bind_ip_json) in [("empty", ""), ("whitespace", "   ")] {
        let server = spawn_mock_camera(mock_frames.clone())?;
        let cfg_path = dir.path().join(format!("cam_{label}.json"));
        let dep_root = dir.path().join(format!("dep_{label}"));
        fs::write(
            &cfg_path,
            format!(
                "{{\"uid\":\"{MOCK_UID}\",\"enr\":\"{MOCK_ENR}\",\"mac\":\"{MOCK_MAC}\",\"camera_ip\":\"127.0.0.1\",\"camera_port\":{},\"bind_ip\":\"{bind_ip_json}\"}}",
                server.port
            ),
        )?;

        let capture_out = Command::new(env!("CARGO_BIN_EXE_fss-capture-tutk"))
            .args(["--root"])
            .arg(&dep_root)
            .args(["--cfg"])
            .arg(&cfg_path)
            .args([
                "--secs",
                "1",
                "--site",
                SITE,
                "--sensor-id",
                "sensor:tutk:porch:01",
                "--stream-id",
                "stream:tutk:porch:main",
                "--owner-authorized",
            ])
            .output()?;
        let stdout = String::from_utf8(capture_out.stdout)?;
        let stderr = String::from_utf8(capture_out.stderr)?;
        assert!(
            capture_out.status.success(),
            "fss-capture-tutk failed for bind_ip={label:?}: stderr={stderr} stdout={stdout}"
        );
        let parsed = parse_json(&stdout)?;
        assert_eq!(
            json_string_field(&parsed, "schema")?,
            "fss.tutk_capture_cli.v1"
        );

        // `fss doctor --json` must report Healthy and 0 unreferenced objects.
        let doc_out = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["doctor", "--json", "--root"])
            .arg(&dep_root)
            .output()?;
        let doc_stdout = String::from_utf8(doc_out.stdout)?;
        assert!(
            doc_out.status.success(),
            "fss doctor failed for {label}: {doc_stdout}"
        );
        let doc_json = parse_json(&doc_stdout)?;
        assert_eq!(json_string_field(&doc_json, "verdict")?, "healthy");
        let report = inspect_deployment(&dep_root);
        assert_eq!(report.verdict, DoctorVerdict::Healthy);
        assert_eq!(doctor_unreferenced_count(&report)?, 0);

        // `fss query --json --target footage` must admit the TUTK capture directly.
        let query_out = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["query", "--json", "--target", "footage", "--root"])
            .arg(&dep_root)
            .args(["--max-entries", "32"])
            .output()?;
        let query_stdout = String::from_utf8(query_out.stdout)?;
        assert!(
            query_out.status.success(),
            "fss query --target footage failed: {query_stdout}"
        );
        assert!(
            query_stdout.contains("adapter_id=ADP-WYZE-V4-LAB-001"),
            "missing TUTK adapter_id in footage output: {query_stdout}"
        );
        assert!(
            query_stdout.contains("Other-adapter completed imports outside this scope: 0."),
            "TUTK was excluded into other_adapter_imports: {query_stdout}"
        );

        // `fss orient --json` must succeed and report the completed import.
        let orient_out = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["orient", "--json", "--root"])
            .arg(&dep_root)
            .output()?;
        let orient_stdout = String::from_utf8(orient_out.stdout)?;
        assert!(
            orient_out.status.success(),
            "fss orient failed: {orient_stdout}"
        );
        let snap = read_deployment(&dep_root, &OrientLimits::default())?;
        assert_eq!(snap.completed_imports.len(), 1);
        assert_eq!(snap.doctor_verdict, DoctorVerdict::Healthy);

        println!(
            "{{\"event\":\"tutk_cli_bind_ip_verified\",\"case\":\"{label}\",\"verdict\":\"healthy\",\"unreferenced\":0,\"completed_imports\":{}}}",
            snap.completed_imports.len()
        );
    }

    Ok(())
}

#[test]
fn tutk_186_frame_normal_completion_and_mid_capture_cancellation_zero_orphans() -> TestResult {
    let dir = TempDir::new("186-and-cancel")?;
    let split_cx = test_cx(dir.path())?;
    let base_aus = clean_h264_aus(&split_cx)?;

    // 1. Normal 186-frame completion (exact regression for the 186-object orphan leak).
    let root_186 = dir.path().join("normal_186");
    let cx_186 = test_cx(&root_186)?;
    let mut dep_186 = ReferenceDeployment::open(&root_186, SITE, &cx_186)?;
    let mut ing_186 = make_tutk_ingest("sensor:tutk:wyze:01", "stream:tutk:wyze:main", 186)?;
    let emitted = feed_synthetic_h264_frames(&mut ing_186, &base_aus, 186);
    assert!(matches!(
        ing_186.state(),
        AcquisitionState::ContinuityVerified { .. }
    ));
    let seal = ing_186.seal_acquisition(&mut dep_186, MOCK_GENERATION, &cx_186)?;
    assert_eq!(seal.capsule_count, 186);

    // RetainedFileImport opens and reconstructs every segment byte-for-byte.
    let retained = RetainedFileImport::open(
        &dep_186,
        seal.import_identity,
        RetainedReadLimits::default(),
        &cx_186,
    )?;
    assert_eq!(retained.manifest().capsule_ids.len(), 186);
    assert_eq!(
        retained.read_segment(&dep_186, 0, RetainedReadLimits::default(), &cx_186)?,
        emitted[0]
    );
    assert_eq!(
        retained.read_segment(&dep_186, 185, RetainedReadLimits::default(), &cx_186)?,
        emitted[185]
    );
    assert_eq!(
        retained.verify_source(&dep_186, RetainedReadLimits::default(), &cx_186)?,
        retained.manifest().input_sha256
    );
    drop(dep_186);

    let report_186 = inspect_deployment(&root_186);
    assert_eq!(
        report_186.verdict,
        DoctorVerdict::Healthy,
        "186-frame doctor report: {}",
        report_186.to_json()
    );
    assert_eq!(doctor_unreferenced_count(&report_186)?, 0);

    // 2. Mid-capture cancellation (partial-import finalized seal path).
    let root_partial = dir.path().join("cancel_partial");
    let cx_partial = test_cx(&root_partial)?;
    let mut dep_partial = ReferenceDeployment::open(&root_partial, SITE, &cx_partial)?;
    let mut ing_partial = make_tutk_ingest("sensor:tutk:wyze:02", "stream:tutk:wyze:main", 42)?;
    let _ = feed_synthetic_h264_frames(&mut ing_partial, &base_aus, 25);
    ing_partial.cancel();
    assert_eq!(ing_partial.state(), &AcquisitionState::Cancelled);
    let partial_seal =
        ing_partial.seal_acquisition(&mut dep_partial, MOCK_GENERATION, &cx_partial)?;
    assert_eq!(partial_seal.capsule_count, 25);
    drop(dep_partial);

    let report_partial = inspect_deployment(&root_partial);
    assert_eq!(report_partial.verdict, DoctorVerdict::Healthy);
    assert_eq!(doctor_unreferenced_count(&report_partial)?, 0);

    // 3. Mid-capture cancellation (request->drain->finalize abort before staging).
    let root_abort = dir.path().join("cancel_abort");
    let cx_abort = test_cx(&root_abort)?;
    let mut dep_abort = ReferenceDeployment::open(&root_abort, SITE, &cx_abort)?;
    let mut ing_abort = make_tutk_ingest("sensor:tutk:wyze:03", "stream:tutk:wyze:main", 43)?;
    let _ = feed_synthetic_h264_frames(&mut ing_abort, &base_aus, 25);
    cx_abort.set_cancel_at_checkpoint_occurrence(STAGE_FILE_PART_PREFLIGHT, 1);
    assert!(
        ing_abort
            .seal_acquisition(&mut dep_abort, MOCK_GENERATION, &cx_abort)
            .is_err()
    );
    ing_abort.discard_unsealed();
    cx_abort.drain_and_finalize();
    drop(dep_abort);

    let report_abort = inspect_deployment(&root_abort);
    assert_eq!(report_abort.verdict, DoctorVerdict::Healthy);
    assert_eq!(doctor_unreferenced_count(&report_abort)?, 0);

    println!(
        "{{\"event\":\"tutk_zero_orphan_verified\",\"normal_frames\":186,\"normal_unreferenced\":0,\"cancel_partial_frames\":25,\"cancel_partial_unreferenced\":0,\"cancel_abort_unreferenced\":0}}"
    );
    Ok(())
}

#[test]
fn unified_footage_and_orient_index_file_rtsp_and_tutk() -> TestResult {
    let dir = TempDir::new("unified-index")?;
    let root = dir.path().join("deployment");
    let rtsp_archive = dir.path().join("rtsp_archive");
    let cx = test_cx(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;

    // 1. File import (ADP-FILE-001)
    let file_req = FileIngestRequest::new(
        repo_root()?.join("tests/fixtures/media/h264/clean.264"),
        SensorId::parse("sensor:file-garage")?,
        StreamId::parse("stream:file-main")?,
    )
    .with_format_hint(FileFormatHint::AnnexB)
    .with_receive_time(TimestampNs(2_000_000_000));
    let file_receipt = FileIngestAdapter::ingest(file_req, &cx, &mut deployment)?;

    // 2. Native RTSP recording import (ADP-RTSP-RECORDING-ARCHIVE-001)
    let rtsp_receipt = seed_rtsp_import(&rtsp_archive, &mut deployment, &cx)?;

    // 3. TUTK live acquisition import (ADP-WYZE-V4-LAB-001 / tutk_p2p)
    let base_aus = clean_h264_aus(&cx)?;
    let mut ing = make_tutk_ingest("sensor:tutk-front-door", "stream:tutk-main", 999)?;
    let _ = feed_synthetic_h264_frames(&mut ing, &base_aus, 6);
    let tutk_seal = ing.seal_acquisition(&mut deployment, MOCK_GENERATION, &cx)?;

    // Verify RetainedFileImport opens the TUTK import cleanly.
    let retained_tutk = RetainedFileImport::open(
        &deployment,
        tutk_seal.import_identity,
        RetainedReadLimits::default(),
        &cx,
    )?;
    assert_eq!(retained_tutk.manifest().adapter_id, TUTK_ADAPTER);
    drop(deployment);

    // Doctor must report Healthy with zero unreferenced objects across all 3 imports.
    let report = inspect_deployment(&root);
    assert_eq!(
        report.verdict,
        DoctorVerdict::Healthy,
        "unified doctor report: {}",
        report.to_json()
    );
    assert_eq!(doctor_unreferenced_count(&report)?, 0);

    // Unified `query_footage` must return File + RTSP + TUTK with exact provenance.
    let req = FootageQueryRequest {
        filter: FootageQueryFilter::default(),
        principal: PrincipalId::parse("principal:unified-operator")?,
        max_entries: 32,
        expected_anchor: None,
        continuation: None,
    };
    let page = query_footage(&root, &req, &FootageQueryLimits::default(), &mut |_| true)?;
    let expected_total = file_receipt.capsule_count + rtsp_receipt.frames + tutk_seal.capsule_count;
    assert_eq!(page.other_adapter_imports, 0);
    assert_eq!(page.scanned_capsules, expected_total);
    assert_eq!(page.matched_capsules, expected_total);

    let families: BTreeSet<&str> = page.rows.iter().map(|r| r.adapter_family()).collect();
    assert_eq!(
        families,
        BTreeSet::from(["file", "rtsp", TUTK_ADAPTER_FAMILY])
    );

    let adapters: BTreeSet<&str> = page.rows.iter().map(|r| r.adapter_id.as_str()).collect();
    assert!(adapters.contains(ADP_FILE_ROW_ID));
    assert!(adapters.contains(fss_reference::ingest::rtsp_import::ADAPTER));
    assert!(adapters.contains(TUTK_ADAPTER));

    let tutk_rows: Vec<_> = page
        .rows
        .iter()
        .filter(|r| r.adapter_id == TUTK_ADAPTER)
        .collect();
    assert_eq!(tutk_rows.len(), 6);
    for row in &tutk_rows {
        assert_eq!(row.capsule.sensor_id.as_str(), "sensor:tutk-front-door");
        assert_eq!(row.capsule.stream_id.as_str(), "stream:tutk-main");
        assert_eq!(row.adapter_family(), TUTK_ADAPTER_FAMILY);
        assert_eq!(row.adapter_generation, MOCK_GENERATION);
        assert_eq!(row.import_root, tutk_seal.import_root);
        assert_eq!(row.import_identity, tutk_seal.import_identity);
        assert!(row.capsule.capture.earliest.0 >= 10_000_000_000);
    }

    // `read_deployment` + `orient_deployment` sees all 3 completed imports cleanly.
    let orient_limits = OrientLimits::default();
    let snapshot = read_deployment(&root, &orient_limits)?;
    assert_eq!(snapshot.doctor_verdict, DoctorVerdict::Healthy);
    assert_eq!(snapshot.completed_imports.len(), 3);
    assert!(
        snapshot
            .completed_imports
            .contains(&tutk_seal.manifest_digest)
    );
    let orient_req = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:unified-operator")?,
        budget_tokens: None,
    };
    let oriented = orient_deployment(&snapshot, &orient_req, &orient_limits)?;
    assert!(
        oriented.capsule().frame.knowledge_cells.iter().any(|cell| {
            cell.claim_id() == fss_reference::agent_orient::CLAIM_IMPORTS
                && cell.evidence_digests().contains(&tutk_seal.manifest_digest)
        }),
        "orient CLAIM_IMPORTS cell must reference the TUTK import manifest"
    );

    println!(
        "{{\"event\":\"unified_footage_orient_verified\",\"verdict\":\"healthy\",\"unreferenced\":0,\"other_adapter_imports\":{},\"scanned_capsules\":{},\"completed_imports\":{},\"families\":[\"file\",\"rtsp\",\"tutk_p2p\"]}}",
        page.other_adapter_imports,
        page.scanned_capsules,
        snapshot.completed_imports.len()
    );
    Ok(())
}
