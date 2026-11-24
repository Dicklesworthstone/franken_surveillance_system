#![forbid(unsafe_code)]
//! Real-Hardware & Deterministic Replay E2E Suite (`fss-x4a.31.3.7` / `C7`).
//!
//! 100% offline, deterministic loopback/fixture end-to-end tests reproducing real field hardware
//! behaviors without touching unauthorized live networks or storing secrets:
//! 1. **Scenario 1 — Wyze SmolRTSP Direct -> Import -> OSD-Masked Watch -> YOLOX-Nano Cascade**:
//!    - Loopback SmolRTSP server (SDP without `sprop-parameter-sets`, in-band H.264 SPS/PPS/IDR
//!      via STAP-A, companion audio track SETUP/drain/TEARDOWN, Latin-1 vendor headers).
//!    - Real `fss-capture-rtsp` -> `fss-import-rtsp` -> `fss-file verify/decode` ->
//!      `fss-infer activity` -> `fss-infer package-detect` (YOLOX-Nano).
//!    - Real `fss-event watch --ignore-rect` proving 0 false-positive OSD clock alerts when only
//!      the timestamp corner ticks, while genuine scene motion outside the OSD rect IS detected.
//!    - In-process `ResidentModelPool` + `TwoStageCascade` (`ModelPoolEngine`) loaded ONCE with
//!      real `models/yolox-nano/yolox_nano.fmpk` over retained RGB frames (`loads == 1`).
//! 2. **Scenario 2 — Wyze TUTK Direct Capture -> Unified `fss query --target footage` -> `fss doctor`**:
//!    - Loopback pure-Rust mock TUTK 0xCC51 + DTLS 1.2 PSK server -> real `fss-capture-tutk`
//!      with empty `bind_ip` defaulting to `0.0.0.0`.
//!    - Asserts `fss doctor --json` reports `"healthy"` with `objects.unreferenced == 0`, and
//!      `fss query --target footage` surfaces `tutk_p2p` with `other_adapter_imports == 0`.
//! 3. **Scenario 3 — 4MP `2688x1512` 4:4:4 UniFi G4 JPEG Pipeline**:
//!    - Generates a genuine full-resolution `2688x1512` 4:4:4 YCbCr JPEG using
//!      `fss_codec_jpeg_encode` matching the UniFi G4 Doorbell Pro / Bullet geometry that
//!      previously hit `ERR-CODEC-MJPEG-BUDGET-001`.
//!    - Verifies default `fss-file decode` (zero manual budget flags) and default
//!      `fss-infer package-detect` (`yolox_nano.fmpk`, zero manual budget flags) succeed cleanly.
//!    - Verifies default `fss-infer activity` (`fss_activity_v1.fmpk`, zero manual budget flags)
//!      succeeds on a 16:9 1MP (`1280x720`) 4:4:4 YCbCr UniFi sub-stream pair without hitting the
//!      old hardcoded 20M work-unit ceiling.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse as parse_json};
use fss_codec_jpeg_encode::{
    EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg as encode_rgb_jpeg,
};
use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, OperationId, PrincipalId, SensorId, TimestampNs,
};
use fss_reference::agent_footage::{
    FootageQueryFilter, FootageQueryLimits, FootageQueryRequest, query_footage,
};
use fss_reference::doctor::{DoctorReport, DoctorValue, DoctorVerdict, inspect_deployment};
use fss_reference::executor_activity_package::ACTIVITY_PACKAGE_V1_SHA256;
use fss_reference::ingest::model_pool::{
    CameraPriorityTier, CascadePolicyConfig, FairShareScheduler, FramePixelInput, ModelPoolEngine,
    PoolBudgetConfig, ResidentModelPool, StageDecision, StreamFrameInput, StreamRegistration,
    TwoStageCascade, WorkerPoolConfig, WorkerPoolExecutor,
};
use fss_reference::ingest::osd_mask::ImageRect;
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits, split_annexb};
use fss_reference::media_fixture::jpeg::{
    JpegConfig, Subsampling, encode_jpeg as encode_gray_jpeg,
};
use fss_reference::{KernelBackend, ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_tutk::av::{
    AV_VERSION, CHANNEL_I_VIDEO, FRAMEINFO_LEN, MAGIC_AV_LOGIN_RESP, MAGIC_IOCTRL, build_hl,
};
use fss_tutk::chacha::{aead_decrypt, aead_encrypt};
use fss_tutk::digest::Sha256;
use fss_tutk::dtls::{DTLS12, pack_handshake, pack_record, parse_records, prf};
use fss_tutk::wire::{CHANNEL_MAIN, CMD_DISCOVERY, CMD_DTLS, NewProto, derive_psk};
use fss_tutk::x25519::{x25519, x25519_base};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const YOLOX_PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const WYZE_SENSOR: &str = "sensor:wyze-cam-v4-51";
const WYZE_STREAM: &str = "stream:wyze-main";
const WYZE_SITE: &str = "site:real-hw-wyze";

const TUTK_SITE: &str = "site:real-hw-tutk";
const MOCK_UID: &str = "SIMCAMSIMCAMSIMCAM11";
const MOCK_ENR: &str = "sim-enr-16byte!!";
const MOCK_MAC: &str = "00AA11BB22CC";

const UNIFI_SITE: &str = "site:real-hw-unifi-4mp";
const UNIFI_SENSOR: &str = "sensor:unifi-g4-177";
const UNIFI_STREAM: &str = "stream:unifi-main";

const WYZE_SMOLRTSP_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 127.0.0.1\r\n",
    "s=SmolRTSP\r\n",
    "t=0 0\r\n",
    "a=control:*\r\n",
    "m=video 0 RTP/AVP 96\r\n",
    "a=rtpmap:96 H264/90000\r\n",
    "a=control:track1\r\n",
    "m=audio 0 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=control:track2\r\n",
);

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TestResult<Self> {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fss-real-hw-{label}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        builder.create(&path)?;
        Ok(Self(path))
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

fn yolox_package_path() -> TestResult<PathBuf> {
    Ok(repo_root()?.join("models/yolox-nano/yolox_nano.fmpk"))
}

fn digest_text(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn ok_stdout(output: Output, label: &str) -> TestResult<String> {
    if !output.status.success() {
        return Err(format!(
            "{label} failed ({:?}): stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn json_val<'a>(node: &'a Value, key: &str) -> TestResult<&'a Value> {
    node.object()
        .and_then(|map| map.get(key))
        .ok_or_else(|| format!("missing JSON key {key}").into())
}

fn json_text<'a>(node: &'a Value, key: &str) -> TestResult<&'a str> {
    json_val(node, key)?
        .text()
        .ok_or_else(|| format!("JSON key {key} is not a string").into())
}

fn json_int(node: &Value, key: &str) -> TestResult<i128> {
    json_val(node, key)?
        .integer()
        .ok_or_else(|| format!("JSON key {key} is not an integer").into())
}

fn json_bool(node: &Value, key: &str) -> TestResult<bool> {
    json_val(node, key)?
        .boolean()
        .ok_or_else(|| format!("JSON key {key} is not a boolean").into())
}

fn test_replay_cx(root: &Path, site: &str) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:{site}"),
        operation_id: OperationId::parse("operation:real-hw-replay-e2e")?,
        principal: "principal:real-hw-replay".to_owned(),
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
        retention_scope: "retention:e2e-test".to_owned(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
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

// ===========================================================================
// Scenario 1 helpers: Loopback Wyze SmolRTSP server + OSD MJPEG generator
// ===========================================================================

type H264FixtureNals = (&'static [u8], &'static [u8], &'static [u8], &'static [u8]);

fn fixture_h264_nals() -> TestResult<H264FixtureNals> {
    let bytes: &'static [u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut nals = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if prefix == 0 {
            at += 1;
            continue;
        }
        if let Some(begin) = start {
            let mut end = at;
            while end > begin && bytes[end - 1] == 0 {
                end -= 1;
            }
            if begin < end {
                nals.push(&bytes[begin..end]);
            }
        }
        start = Some(at + prefix);
        at += prefix;
    }
    if let Some(begin) = start
        && begin < bytes.len()
    {
        nals.push(&bytes[begin..]);
    }
    let sps = *nals
        .iter()
        .find(|n| n[0] & 31 == 7)
        .ok_or("missing fixture SPS")?;
    let pps = *nals
        .iter()
        .find(|n| n[0] & 31 == 8)
        .ok_or("missing fixture PPS")?;
    let idr = *nals
        .iter()
        .find(|n| n[0] & 31 == 5)
        .ok_or("missing fixture IDR")?;
    let p_slice = *nals
        .iter()
        .find(|n| n[0] & 31 == 1)
        .ok_or("missing fixture P slice")?;
    Ok((sps, pps, idr, p_slice))
}

fn interleaved_rtp(
    channel: u8,
    seq: u16,
    ts: u32,
    marker: bool,
    ssrc: u32,
    pt: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + payload.len());
    pkt.push(0x80);
    pkt.push(pt | if marker { 0x80 } else { 0 });
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&ts.to_be_bytes());
    pkt.extend_from_slice(&ssrc.to_be_bytes());
    pkt.extend_from_slice(payload);
    let mut framed = Vec::with_capacity(4 + pkt.len());
    framed.push(b'$');
    framed.push(channel);
    framed.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    framed.extend_from_slice(&pkt);
    framed
}

fn stap_a(units: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0x78]; // F=0, NRI=3, Type=24
    for unit in units {
        out.extend_from_slice(&(unit.len() as u16).to_be_bytes());
        out.extend_from_slice(unit);
    }
    out
}

fn read_rtsp_request(peer: &mut TcpStream) -> TestResult<Option<(String, String, u32, String)>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0_u8; 1];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("EOF mid-request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8(bytes)?;
            let first = text.split("\r\n").next().unwrap_or("");
            let mut parts = first.split_ascii_whitespace();
            let method = parts.next().ok_or("missing method")?.to_owned();
            let uri = parts.next().ok_or("missing uri")?.to_owned();
            let cseq = text
                .split("\r\n")
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    k.eq_ignore_ascii_case("cseq").then_some(v.trim())
                })
                .ok_or("missing CSeq")?
                .parse()?;
            return Ok(Some((method, uri, cseq, text)));
        }
    }
    Err("RTSP request exceeded 8 KiB".into())
}

fn write_rtsp_response_raw(
    peer: &mut TcpStream,
    cseq: u32,
    extra_headers: &[u8],
    body: &[u8],
) -> TestResult {
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(extra_headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    peer.write_all(&out)?;
    Ok(())
}

fn serve_wyze_smolrtsp(listener: TcpListener) -> TestResult<Vec<String>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(format!("accept timeout: {e}").into()),
        }
    };
    peer.set_nonblocking(false)?;
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    peer.set_nodelay(true)?;

    let mut methods = Vec::new();
    // Reproduce real non-UTF-8 Latin-1 vendor header bytes seen on embedded RTSP cameras.
    let latin1_header: &[u8] = b"Server: Cam\xe9ra-SmolRTSP/1.0\r\nX-Vendor: wyze-lab-caf\xe9\r\n";

    // 1. DESCRIBE (SDP intentionally omits sprop-parameter-sets, matching real Wyze SmolRTSP).
    let (method, _, cseq, _) = read_rtsp_request(&mut peer)?.ok_or("no DESCRIBE")?;
    assert_eq!(method, "DESCRIBE");
    methods.push(method);
    let mut desc_hdrs = Vec::new();
    desc_hdrs.extend_from_slice(latin1_header);
    desc_hdrs.extend_from_slice(b"Content-Type: application/sdp\r\n");
    write_rtsp_response_raw(&mut peer, cseq, &desc_hdrs, WYZE_SMOLRTSP_SDP.as_bytes())?;

    // 2. Video SETUP (track1, interleaved=0-1).
    let (method, uri, cseq, raw) = read_rtsp_request(&mut peer)?.ok_or("no video SETUP")?;
    assert_eq!(method, "SETUP");
    assert!(uri.ends_with("/track1"), "unexpected video URI: {uri}");
    assert!(raw.contains("interleaved=0-1"), "missing 0-1: {raw}");
    methods.push(method);
    let mut setup_v = Vec::new();
    setup_v.extend_from_slice(latin1_header);
    setup_v.extend_from_slice(
        b"Session: wyze-51;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007\r\n",
    );
    write_rtsp_response_raw(&mut peer, cseq, &setup_v, b"")?;

    // 3. Companion audio SETUP (track2, interleaved=2-3).
    let (method, uri, cseq, raw) = read_rtsp_request(&mut peer)?.ok_or("no audio SETUP")?;
    assert_eq!(method, "SETUP");
    assert!(uri.ends_with("/track2"), "unexpected audio URI: {uri}");
    assert!(raw.contains("Session: wyze-51"), "missing Session: {raw}");
    assert!(raw.contains("interleaved=2-3"), "missing 2-3: {raw}");
    methods.push(method);
    let mut setup_a = Vec::new();
    setup_a.extend_from_slice(latin1_header);
    setup_a.extend_from_slice(
        b"Session: wyze-51;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3;ssrc=DEADBEEF\r\n",
    );
    write_rtsp_response_raw(&mut peer, cseq, &setup_a, b"")?;

    // 4. PLAY.
    let (method, _, cseq, _) = read_rtsp_request(&mut peer)?.ok_or("no PLAY")?;
    assert_eq!(method, "PLAY");
    methods.push(method);
    let mut play_hdrs = Vec::new();
    play_hdrs.extend_from_slice(latin1_header);
    play_hdrs.extend_from_slice(b"Session: wyze-51\r\n");
    write_rtsp_response_raw(&mut peer, cseq, &play_hdrs, b"")?;

    // 5. Interleaved video + companion audio stream: 3 pre-sync P-frames, companion audio RTP/RTCP,
    //    then STAP-A(SPS+PPS+IDR), audio RTP, and follow-up P-frame.
    let (sps, pps, idr, p_slice) = fixture_h264_nals()?;
    let mut media = Vec::new();
    for i in 0..3_u16 {
        media.extend_from_slice(&interleaved_rtp(
            0,
            10 + i,
            9000 + u32::from(i) * 3600,
            true,
            7,
            96,
            p_slice,
        ));
        media.extend_from_slice(&interleaved_rtp(
            2,
            100 + i,
            8000 + u32::from(i) * 160,
            false,
            0xDEAD_BEEF,
            0,
            &[0x7f; 160],
        ));
    }
    media.extend_from_slice(&[b'$', 3, 0, 8, 0x80, 0xc9, 0, 1, 0xde, 0xad, 0xbe, 0xef]);
    let stap = stap_a(&[sps, pps, idr]);
    media.extend_from_slice(&interleaved_rtp(0, 13, 19800, true, 7, 96, &stap));
    media.extend_from_slice(&interleaved_rtp(
        2,
        103,
        8480,
        false,
        0xDEAD_BEEF,
        0,
        &[0x55; 160],
    ));
    media.extend_from_slice(&interleaved_rtp(0, 14, 23400, true, 7, 96, p_slice));
    let _ = peer.write_all(&media);

    // 6. Wait for clean TEARDOWN.
    for _ in 0..8 {
        let Some((method, _, cseq, _)) = read_rtsp_request(&mut peer)? else {
            break;
        };
        methods.push(method.clone());
        if method == "TEARDOWN" {
            let _ = write_rtsp_response_raw(&mut peer, cseq, b"Session: wyze-51\r\n", b"");
            break;
        }
    }
    Ok(methods)
}

/// Builds a 14-frame `96x48` grayscale MJPEG stream with a simulated ticking Wyze timestamp OSD
/// in `0,0,24,12` and optional genuine scene motion traversing `door:64,0,32,32`.
fn build_wyze_osd_mjpeg_scene(include_genuine_motion: bool) -> TestResult<Vec<u8>> {
    const W: u32 = 96;
    const H: u32 = 48;
    const FRAMES: usize = 14;
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (W * H) as usize];
        // Ticking Wyze corner clock OSD strictly inside (0,0,24,12): flips digits every frame.
        let osd_luma = if index % 2 == 0 { 240_u8 } else { 15_u8 };
        for y in 1..11 {
            for x in 1..23 {
                let digit_bar = ((x + index) % 4) != 0;
                pixels[y * W as usize + x] = if digit_bar { osd_luma } else { 40 };
            }
        }
        // Optional genuine moving subject strictly outside the OSD rect (entering door:64,0,32,32).
        if include_genuine_motion && index >= 3 {
            let left = (index - 3) * 8;
            for y in 16..32 {
                for x in left..left + 16 {
                    if x < W as usize {
                        pixels[y * W as usize + x] = 225;
                    }
                }
            }
        }
        stream.extend(encode_gray_jpeg(W, H, &pixels, &config)?);
    }
    Ok(stream)
}

fn import_mjpeg_cli(
    root: &Path,
    site: &str,
    sensor: &str,
    stream: &str,
    path: &Path,
    bytes: &[u8],
) -> TestResult<String> {
    fs::write(path, bytes)?;
    let out = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["import", "--root"])
            .arg(root)
            .args(["--site", site, "--input"])
            .arg(path)
            .args([
                "--sensor",
                sensor,
                "--stream",
                stream,
                "--receive-time-ns",
                "5000000000",
                "--media-format",
                "mjpeg",
            ])
            .output()?,
        "fss-file import",
    )?;
    let _ = fs::remove_file(path);
    let import_id = out
        .lines()
        .find_map(|l| l.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("missing import_identity")?;
    Ok(import_id)
}

// ===========================================================================
// Scenario 2 helpers: Loopback pure-Rust mock TUTK 0xCC51 + DTLS 1.2 PSK server
// ===========================================================================

fn dtls_nonce(iv: &[u8; 12], epoch: u16, seq: u64) -> [u8; 12] {
    let mut seq64 = [0_u8; 8];
    seq64[..2].copy_from_slice(&epoch.to_be_bytes());
    seq64[2..].copy_from_slice(&seq.to_be_bytes()[2..]);
    let mut out = [0_u8; 12];
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
    let mut out = vec![0_u8; 32 + hl.len()];
    out[0..2].copy_from_slice(&MAGIC_IOCTRL.to_le_bytes());
    out[4..6].copy_from_slice(&wseq.to_le_bytes());
    out[32..].copy_from_slice(hl);
    out
}

fn build_mock_av_video_packet(frame_no: u32, au: &[u8], keyframe: bool) -> Vec<u8> {
    let mut fi = [0_u8; FRAMEINFO_LEN];
    fi[0..2].copy_from_slice(&0x004E_u16.to_le_bytes()); // H.264
    fi[2] = u8::from(keyframe);
    fi[5] = 30;
    fi[8..12].copy_from_slice(&(frame_no * 33_333).to_le_bytes());
    fi[16..20].copy_from_slice(&(au.len() as u32).to_le_bytes());
    fi[20..24].copy_from_slice(&frame_no.to_le_bytes());

    let payload_len = au.len() + FRAMEINFO_LEN;
    let mut hdr = [0_u8; 28];
    hdr[0] = CHANNEL_I_VIDEO;
    hdr[1] = 0x01; // 28-byte header + END marker
    hdr[12..14].copy_from_slice(&1_u16.to_le_bytes());
    hdr[14..16].copy_from_slice(&0_u16.to_le_bytes());
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

fn spawn_mock_tutk_camera(frames: Vec<Vec<u8>>) -> TestResult<MockTutkServer> {
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
        let mut session_id = [0_u8; 8];
        let server_secret = [0x37_u8; 32];
        let server_pub = x25519_base(&server_secret);
        let server_random = [0x5A_u8; 32];

        let mut client_random = [0_u8; 32];
        let mut transcript = Vec::new();
        let mut master_secret: Option<Vec<u8>> = None;
        let mut c_key = [0_u8; 32];
        let mut s_key = [0_u8; 32];
        let mut c_iv = [0_u8; 12];
        let mut s_iv = [0_u8; 12];
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
                            peer: SocketAddr,
                            plain: &[u8],
                            s_key: &[u8; 32],
                            s_iv: &[u8; 12],
                            seq1: &mut u64,
                            sid: &[u8; 8]| {
            let rec = encrypt_record(23, plain, s_key, s_iv, seq1);
            let wrapped = proto.wrap_dtls(&rec, ticket, sid, CHANNEL_MAIN);
            let _ = sock.send_to(&wrapped, peer);
        };

        let mut buf = [0_u8; 65535];
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
                                    sh.extend_from_slice(&0xCCAC_u16.to_be_bytes());
                                    sh.push(0);
                                    let sh_msg = pack_handshake(2, 0, &sh);

                                    let mut ske = Vec::with_capacity(38);
                                    ske.extend_from_slice(&0_u16.to_be_bytes());
                                    ske.push(3);
                                    ske.extend_from_slice(&0x001D_u16.to_be_bytes());
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
                                        let mut c_pub = [0_u8; 32];
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
                                let mut tag = [0_u8; 16];
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
                            let mut tag = [0_u8; 16];
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
                                let mut resp = vec![0_u8; 44];
                                resp[0..2].copy_from_slice(&MAGIC_AV_LOGIN_RESP.to_le_bytes());
                                resp[2..4].copy_from_slice(&AV_VERSION.to_le_bytes());
                                resp[4] = 0x10;
                                resp[16..20].copy_from_slice(&20_u32.to_le_bytes());
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
                                            let mut p = vec![0_u8; 17];
                                            p[0] = 1;
                                            p[1..17].copy_from_slice(&[0x42_u8; 16]);
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

// ===========================================================================
// Scenario 3 helpers: 4MP 2688x1512 & 1MP 1280x720 4:4:4 YCbCr JPEG encoder
// ===========================================================================

fn encode_unifi_444_jpeg(width: u32, height: u32, bright_block: bool) -> TestResult<Vec<u8>> {
    let w = width as usize;
    let h = height as usize;
    let mut rgb = vec![0_u8; w * h * 3];
    // Synthetic driveway gradient + optional high-contrast subject block.
    for y in 0..h {
        let row_r = ((y * 160) / h.max(1)) as u8;
        let row_b = 200_u8.saturating_sub(row_r);
        let row_off = y * w * 3;
        for x in 0..w {
            let px = row_off + x * 3;
            let in_subject =
                bright_block && x >= w / 3 && x < (w * 2) / 3 && y >= h / 3 && y < (h * 2) / 3;
            if in_subject {
                rgb[px] = 235;
                rgb[px + 1] = 220;
                rgb[px + 2] = 40;
            } else {
                rgb[px] = row_r;
                rgb[px + 1] = 96;
                rgb[px + 2] = row_b;
            }
        }
    }
    let limits = EncodeLimits::default();
    let config = EncodeConfig {
        quality: 80,
        format: PixelFormat::Rgb,
    };
    let mut budget = EncodeBudget::new(limits.work_bound(PixelFormat::Rgb));
    let digest = ContentDigest::sha256(&rgb).bytes();
    let encoded = encode_rgb_jpeg(width, height, &rgb, digest, config, &limits, &mut budget)?;
    assert_eq!(encoded.receipt().dimensions, [width, height]);
    assert_eq!(encoded.receipt().format, PixelFormat::Rgb);
    Ok(encoded.into_bytes())
}

// ===========================================================================
// Scenario 1: Wyze SmolRTSP Direct -> Import -> OSD-Masked Watch -> YOLOX-Nano
// ===========================================================================

#[test]
fn scenario_1_wyze_smolrtsp_import_osd_watch_and_yolox_cascade() -> TestResult {
    let dir = TempDir::new("scen1-wyze")?;
    let archive_root = dir.path().join("archive");
    let pins_root = dir.path().join("pins");
    let deployment_root = dir.path().join("deployment");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;

    // 1. Preview & approve real `fss-capture-rtsp` with Wyze in-band SPS/PPS + companion audio.
    let anchor = digest_text("wyze-e2e-anchor");
    let recv_clock = digest_text("wyze-e2e-receive-clock");
    let timing_ev = digest_text("wyze-e2e-timing-evidence");
    let journal_id = digest_text("wyze-e2e-journal-id");

    let mut capture_args: Vec<OsString> = [
        "--root",
        archive_root.to_str().ok_or("archive path")?,
        "--pins",
        pins_root.to_str().ok_or("pins path")?,
        "--peer",
        &addr.to_string(),
        "--authority",
        &addr.to_string(),
        "--presentation",
        "/stream1",
        "--control-root",
        "/",
        "--sensor-id",
        WYZE_SENSOR,
        "--stream-id",
        WYZE_STREAM,
        "--generation",
        "1",
        "--ingress",
        "1",
        "--ssrc",
        "7",
        "--anchor",
        &anchor,
        "--receive-clock",
        &recv_clock,
        "--timing-evidence",
        &timing_ev,
        "--journal-id",
        &journal_id,
        "--frame-duration-ticks",
        "3600",
        "--stop-after-pictures",
        "2",
        "--owner-authorized",
        "yes",
        "--plaintext",
        "yes",
        "--retain-originals",
        "yes",
        "--allow-inband-parameter-sets",
        "yes",
        "--setup-companion-tracks",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();

    let preview_out = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-capture-rtsp"))
            .args(&capture_args)
            .stdin(Stdio::null())
            .output()?,
        "fss-capture-rtsp preview",
    )?;
    let preview_json = parse_json(&preview_out)?;
    capture_args.push(OsString::from("--approve"));
    capture_args.push(OsString::from(json_text(&preview_json, "approval")?));

    let (capture_out, methods) = thread::scope(|scope| -> TestResult<(Output, Vec<String>)> {
        let srv = scope.spawn(move || serve_wyze_smolrtsp(listener));
        let out = Command::new(env!("CARGO_BIN_EXE_fss-capture-rtsp"))
            .args(&capture_args)
            .stdin(Stdio::null())
            .output()?;
        let transcript = srv
            .join()
            .map_err(|_| "SmolRTSP server thread panicked")??;
        Ok((out, transcript))
    })?;
    let capture_stdout = ok_stdout(capture_out, "fss-capture-rtsp execute")?;
    assert_eq!(
        methods,
        vec!["DESCRIBE", "SETUP", "SETUP", "PLAY", "TEARDOWN"]
    );

    let mut rows = Vec::new();
    for line in capture_stdout.lines() {
        rows.push(parse_json(line)?);
    }
    let find_detail = |kind: &str| -> TestResult<&Value> {
        let row = rows
            .iter()
            .find(|r| r.object().and_then(|m| m.get("kind")).and_then(Value::text) == Some(kind))
            .ok_or_else(|| format!("missing capture row kind {kind}"))?;
        json_val(row, "detail")
    };
    let terminal = find_detail("terminal")?;
    assert!(json_bool(terminal, "complete")?);
    assert_eq!(json_text(terminal, "parameter_set_origin")?, "inband_rtp");
    assert_eq!(json_int(terminal, "pre_sync_discarded")?, 3);
    assert!(json_int(terminal, "companion_packets_discarded")? >= 4);
    assert_eq!(json_int(terminal, "durable_pictures")?, 2);

    let window = find_detail("window_durable")?;
    let window_slot = json_text(window, "slot")?;
    let window_root = json_text(window, "root")?;

    // 2. Import captured SmolRTSP archive window into deployment via `fss-import-rtsp`.
    let mut import_args: Vec<OsString> = [
        "--archive",
        archive_root.to_str().ok_or("archive path")?,
        "--root",
        deployment_root.to_str().ok_or("deployment path")?,
        "--site",
        WYZE_SITE,
        "--window-slot",
        window_slot,
        "--window-root",
        window_root,
        "--codec",
        "avc",
        "--sensor-id",
        WYZE_SENSOR,
        "--stream-id",
        WYZE_STREAM,
        "--generation",
        "1",
        "--anchor",
        &anchor,
        "--receive-clock",
        &recv_clock,
        "--receive-time-ns",
        "5000000000",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let imp_preview = parse_json(&ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
            .args(&import_args)
            .output()?,
        "fss-import-rtsp preview",
    )?)?;
    import_args.push(OsString::from("--approve"));
    import_args.push(OsString::from(json_text(&imp_preview, "approval_digest")?));
    let imported = parse_json(&ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
            .args(&import_args)
            .output()?,
        "fss-import-rtsp execute",
    )?)?;
    assert_eq!(json_int(&imported, "frames")?, 2);
    let rtsp_import_id = json_text(&imported, "import_identity")?.to_owned();

    // 3. Run real `fss-infer activity` on the retained Wyze H.264 import.
    let activity_out = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-infer"))
            .args(["activity", "--root"])
            .arg(&deployment_root)
            .args([
                "--site",
                WYZE_SITE,
                "--import-id",
                &rtsp_import_id,
                "--reference-segment",
                "0",
                "--segment",
                "1",
                "--sensor",
                WYZE_SENSOR,
                "--stream",
                WYZE_STREAM,
                "--job",
                "job:wyze-rtsp-activity",
                "--interpretation",
                "ycbcr",
                "--package-digest",
                ACTIVITY_PACKAGE_V1_SHA256,
                "--policy-generation",
                "1",
                "--threshold-bits",
                "3c23d70a",
                "--execution-macs",
                "10000000",
                "--execution-bytes",
                "16777216",
            ])
            .output()?,
        "fss-infer activity on Wyze RTSP",
    )?;
    let activity_json = parse_json(&activity_out)?;
    assert_eq!(
        json_text(&activity_json, "format")?,
        "fss.recorded_activity_report.v1"
    );
    assert_eq!(json_text(&activity_json, "media_format")?, "mp4avc");
    assert!(json_bool(&activity_json, "reference_only")?);
    assert!(!json_bool(&activity_json, "effects_authorized")?);

    // 4. OSD-Masked `fss-event watch` with explicit `--ignore-rect`:
    //    (a) Ticking Wyze OSD corner ONLY -> 0 false-positive alerts when masked (vs foreground
    //        activity when unmasked).
    //    (b) Ticking Wyze OSD corner + genuine scene motion -> detected when masked.
    let osd_only_id = import_mjpeg_cli(
        &deployment_root,
        WYZE_SITE,
        "sensor:wyze-osd-only",
        "stream:osd-only",
        &dir.path().join("osd_only.mjpeg"),
        &build_wyze_osd_mjpeg_scene(false)?,
    )?;
    let osd_unmasked = parse_json(&ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["watch", "--root"])
            .arg(&deployment_root)
            .args([
                "--site",
                WYZE_SITE,
                "--import-id",
                &osd_only_id,
                "--interpretation",
                "gray",
                "--zone",
                "osd_corner:0,0,32,24",
            ])
            .output()?,
        "fss-event watch unmasked OSD",
    )?)?;
    assert!(
        json_int(&osd_unmasked, "foreground_boxes")? > 0,
        "unmasked ticking Wyze OSD must generate foreground motion boxes"
    );

    let osd_masked = parse_json(&ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["watch", "--root"])
            .arg(&deployment_root)
            .args([
                "--site",
                WYZE_SITE,
                "--import-id",
                &osd_only_id,
                "--interpretation",
                "gray",
                "--zone",
                "osd_corner:0,0,32,24",
                "--ignore-rect",
                "0,0,24,12",
            ])
            .output()?,
        "fss-event watch masked OSD",
    )?)?;
    assert_eq!(
        json_int(&osd_masked, "foreground_boxes")?,
        0,
        "OSD-masked watch must emit 0 foreground boxes on clock-only ticks"
    );
    assert_eq!(
        json_int(&osd_masked, "candidate_count")?,
        0,
        "OSD-masked watch must emit 0 false-positive alerts on clock-only ticks"
    );

    let osd_plus_motion_id = import_mjpeg_cli(
        &deployment_root,
        WYZE_SITE,
        "sensor:wyze-osd-motion",
        "stream:osd-motion",
        &dir.path().join("osd_motion.mjpeg"),
        &build_wyze_osd_mjpeg_scene(true)?,
    )?;
    let motion_masked = parse_json(&ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["watch", "--root"])
            .arg(&deployment_root)
            .args([
                "--site",
                WYZE_SITE,
                "--import-id",
                &osd_plus_motion_id,
                "--interpretation",
                "gray",
                "--zone",
                "door:64,0,32,32",
                "--ignore-rect",
                "0,0,24,12",
            ])
            .output()?,
        "fss-event watch masked OSD + genuine motion",
    )?)?;
    assert_eq!(
        json_int(&motion_masked, "candidate_count")?,
        1,
        "genuine motion outside OSD ignore-rect must produce 1 candidate"
    );
    let candidates = json_val(&motion_masked, "candidates")?
        .array()
        .ok_or("missing candidates array")?;
    assert_eq!(candidates.len(), 1);
    assert_eq!(json_text(&candidates[0], "zone_id")?, "door");
    assert_eq!(json_text(&candidates[0], "status")?, "prepared");

    // 5. ResidentModelPool + TwoStageCascade with real `yolox_nano.fmpk` on retained RGB frames:
    //    verifies zero weight reloads (loads == 1), OSD corner ignored on frames 0..=3, and
    //    genuine motion on frame 4 runs YOLOX-Nano RGB inference cleanly.
    let pkg_path = yolox_package_path()?;
    let pkg_bytes = fs::read(&pkg_path)?;
    let pkg_digest = ContentDigest::parse(YOLOX_PACKAGE_SHA256)?;
    let replay_cx = test_replay_cx(&deployment_root, WYZE_SITE)?;
    let scalar_cx = ScalarExecCx::new();

    let deployment = ReferenceDeployment::open(&deployment_root, WYZE_SITE, &replay_cx)?;
    let retained_motion = RetainedFileImport::open(
        &deployment,
        ContentDigest::parse(&osd_plus_motion_id)?,
        RetainedReadLimits::default(),
        &replay_cx,
    )?;
    let dims = [96_u32, 48_u32];
    let sensor = SensorId::parse("sensor:wyze-osd-motion")?;
    let mut cascade_inputs = Vec::new();
    // Segments 0, 1, 2 have OSD clock ticks only; segment 4 has genuine motion outside OSD rect.
    for (ord, seg_idx) in [0_usize, 1, 2, 4].into_iter().enumerate() {
        let jpeg_bytes = retained_motion.read_segment(
            &deployment,
            seg_idx,
            RetainedReadLimits::default(),
            &replay_cx,
        )?;
        let src_digest = ContentDigest::sha256(&jpeg_bytes);
        let decoded = decode_rgb(
            &jpeg_bytes,
            src_digest.bytes(),
            ComponentInterpretation::Grayscale,
            RgbDecodeLimits::default(),
            &mut DecodeBudget::new(RgbDecodeLimits::default().baseline_rgb_work_bound()),
        )?;
        assert_eq!(decoded.dimensions(), dims);
        let t_ns = 10_000_000_000_i128 + (ord as i128) * 100_000_000;
        cascade_inputs.push(StreamFrameInput {
            sensor_id: sensor.clone(),
            frame_sequence: ord as u64,
            capture_interval: CaptureInterval::new(
                TimestampNs(t_ns),
                TimestampNs(t_ns + 5_000_000),
            )?,
            source_digest: src_digest,
            dimensions: dims,
            is_keyframe: ord == 0,
            pixels: FramePixelInput::Rgb {
                pixels: decoded.pixels().to_vec(),
            },
        });
    }
    drop(deployment);

    let pool = ResidentModelPool::default_bounded();
    let yolox_t0 = Instant::now();
    let resident_model = pool.load_or_get_rgb_detector(
        &pkg_bytes,
        pkg_digest,
        1 << 36,
        KernelBackend::OptimizedCpuV1,
        None,
        &replay_cx,
        &scalar_cx,
    )?;
    assert!(resident_model.is_rgb_detector());
    // Second load must hit cache with zero weight reload.
    let cached = pool.load_or_get_rgb_detector(
        &pkg_bytes,
        pkg_digest,
        1 << 36,
        KernelBackend::OptimizedCpuV1,
        None,
        &replay_cx,
        &scalar_cx,
    )?;
    assert_eq!(cached.key(), resident_model.key());
    assert_eq!(pool.metrics_snapshot().loads, 1);
    assert!(pool.metrics_snapshot().cache_hits >= 1);

    let mut policy = CascadePolicyConfig::default_for_dimensions(dims);
    policy.quiescent_keyframe_only = false;
    policy.sentinel_on_first_keyframe = false;
    policy.sentinel_interval_frames = 100;
    policy.min_foreground_pixels_trigger = 16;
    let mut cascade = TwoStageCascade::new(policy)?;
    cascade.register_stream(StreamRegistration {
        sensor_id: sensor,
        stream_order: 0,
        priority: CameraPriorityTier::HighConsequenceZone,
        dimensions: dims,
        ignore_regions: vec![ImageRect::new(0, 0, 24, 12)?],
    })?;
    let mut engine = ModelPoolEngine::new(
        cascade,
        FairShareScheduler::new(PoolBudgetConfig::default())?,
        WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(2)?)?,
    );
    let (batch, _) = engine.process_epoch(
        &pool,
        resident_model.key(),
        1,
        &cascade_inputs,
        Some(&replay_cx),
        &scalar_cx,
    )?;
    let yolox_cascade_ms = yolox_t0.elapsed().as_millis();
    // Frames 0, 1, 2 (OSD clock ticks only) MUST NOT trigger Stage-2 YOLOX; frame 3 (seg 4) MUST.
    assert_eq!(batch.frames_motion_triggered, 1);
    assert_eq!(
        batch.frames[3].stage_decision,
        StageDecision::MotionTriggered
    );
    assert!(!batch.frames[0].stage_decision.ran_ml_inference());
    assert!(!batch.frames[1].stage_decision.ran_ml_inference());
    assert!(!batch.frames[2].stage_decision.ran_ml_inference());
    assert_eq!(pool.metrics_snapshot().loads, 1);
    assert!(!batch.absence_certifiable);
    assert!(!batch.effects_authorized);

    // 6. Verify deployment doctor stays Healthy with 0 unreferenced objects.
    let doc_report = inspect_deployment(&deployment_root);
    assert_eq!(
        doc_report.verdict,
        DoctorVerdict::Healthy,
        "Scenario 1 doctor: {}",
        doc_report.to_json()
    );
    assert_eq!(doctor_unreferenced_count(&doc_report)?, 0);

    eprintln!(
        "METRIC scenario_1_wyze: rtsp_methods=5 osd_false_alerts=0 motion_candidates=1 pool_loads=1 yolox_cascade_ms={yolox_cascade_ms} doctor=healthy orphans=0"
    );
    Ok(())
}

// ===========================================================================
// Scenario 2: Wyze TUTK Direct Capture -> Unified Footage Query -> Doctor
// ===========================================================================

#[test]
fn scenario_2_wyze_tutk_direct_capture_unified_footage_and_doctor_healthy() -> TestResult {
    let dir = TempDir::new("scen2-tutk")?;
    let split_cx = test_replay_cx(dir.path(), TUTK_SITE)?;
    let clean_bytes = fs::read(repo_root()?.join("tests/fixtures/media/h264/clean.264"))?;
    let scan = split_annexb(&clean_bytes, Default::default(), &split_cx)?;
    let base_aus: Vec<Vec<u8>> = scan
        .access_units
        .iter()
        .map(|au| clean_bytes[au.span.offset..au.span.offset + au.span.len].to_vec())
        .collect();
    assert!(!base_aus.is_empty());

    let mut mock_frames = Vec::new();
    for i in 0..10_usize {
        let mut au = base_aus[i % base_aus.len()].clone();
        au.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x0C, i as u8, 0x80]);
        mock_frames.push(au);
    }

    let server = spawn_mock_tutk_camera(mock_frames)?;
    let cfg_path = dir.path().join("wyze_tutk_cam.json");
    let dep_root = dir.path().join("tutk_deployment");
    // Empty `bind_ip` MUST default cleanly to `0.0.0.0` (regression for live Wyze .39/.51 capture).
    fs::write(
        &cfg_path,
        format!(
            "{{\"uid\":\"{MOCK_UID}\",\"enr\":\"{MOCK_ENR}\",\"mac\":\"{MOCK_MAC}\",\"camera_ip\":\"127.0.0.1\",\"camera_port\":{},\"bind_ip\":\"\"}}",
            server.port
        ),
    )?;

    let capture_stdout = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-capture-tutk"))
            .args(["--root"])
            .arg(&dep_root)
            .args(["--cfg"])
            .arg(&cfg_path)
            .args([
                "--secs",
                "1",
                "--site",
                TUTK_SITE,
                "--sensor-id",
                "sensor:wyze-39-tutk",
                "--stream-id",
                "stream:wyze-39-main",
                "--owner-authorized",
            ])
            .output()?,
        "fss-capture-tutk",
    )?;
    let capture_json = parse_json(&capture_stdout)?;
    assert_eq!(
        json_text(&capture_json, "schema")?,
        "fss.tutk_capture_cli.v1"
    );

    // 1. `fss doctor --json` reports "healthy" with `objects.unreferenced == 0`.
    let doc_stdout = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["doctor", "--json", "--root"])
            .arg(&dep_root)
            .output()?,
        "fss doctor",
    )?;
    let doc_json = parse_json(&doc_stdout)?;
    assert_eq!(json_text(&doc_json, "verdict")?, "healthy");
    let report = inspect_deployment(&dep_root);
    assert_eq!(report.verdict, DoctorVerdict::Healthy);
    assert_eq!(doctor_unreferenced_count(&report)?, 0);

    // 2. Unified `fss query --json --target footage` surfaces `tutk_p2p` with
    //    `other_adapter_imports == 0`.
    let query_stdout = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["query", "--json", "--target", "footage", "--root"])
            .arg(&dep_root)
            .args(["--max-entries", "32"])
            .output()?,
        "fss query --target footage",
    )?;
    assert!(
        query_stdout.contains("ADP-WYZE-V4-LAB-001"),
        "expected TUTK adapter ID in footage query: {query_stdout}"
    );
    assert!(
        query_stdout.contains("Other-adapter completed imports outside this scope: 0."),
        "TUTK capture must not be relegated to other_adapter_imports: {query_stdout}"
    );

    let page = query_footage(
        &dep_root,
        &FootageQueryRequest {
            filter: FootageQueryFilter::default(),
            principal: PrincipalId::parse("principal:real-hw-operator")?,
            max_entries: 32,
            expected_anchor: None,
            continuation: None,
        },
        &FootageQueryLimits::default(),
        &mut |_| true,
    )?;
    assert_eq!(page.other_adapter_imports, 0);
    assert!(!page.rows.is_empty());
    assert!(page.rows.iter().all(|r| r.adapter_family() == "tutk_p2p"));

    eprintln!(
        "METRIC scenario_2_tutk: verdict=healthy unreferenced=0 tutk_capsules={} other_adapter_imports={}",
        page.rows.len(),
        page.other_adapter_imports
    );
    Ok(())
}

// ===========================================================================
// Scenario 3: 4MP 2688x1512 4:4:4 UniFi G4 JPEG Pipeline
// ===========================================================================

#[test]
fn scenario_3_unifi_g4_4mp_444_jpeg_default_decode_detect_and_activity() -> TestResult {
    let dir = TempDir::new("scen3-unifi-4mp")?;
    let root = dir.path().join("deployment");

    // 1. Encode a genuine full-resolution 2688x1512 4:4:4 YCbCr JPEG (exact UniFi G4 geometry).
    let encode_t0 = Instant::now();
    let jpeg_4mp = encode_unifi_444_jpeg(2688, 1512, true)?;
    let encode_ms = encode_t0.elapsed().as_millis();
    assert!(jpeg_4mp.starts_with(&[0xFF, 0xD8]));
    assert!(jpeg_4mp.ends_with(&[0xFF, 0xD9]));

    let import_4mp = import_mjpeg_cli(
        &root,
        UNIFI_SITE,
        UNIFI_SENSOR,
        UNIFI_STREAM,
        &dir.path().join("unifi_g4_2688x1512_444.jpg"),
        &jpeg_4mp,
    )?;

    // 2. Default `fss-file decode` (ZERO manual `--work-units` flags!) must succeed cleanly on 4MP.
    let decode_t0 = Instant::now();
    let decode_stdout = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["decode", "--root"])
            .arg(&root)
            .args([
                "--site",
                UNIFI_SITE,
                "--import-id",
                &import_4mp,
                "--segment",
                "0",
                "--interpretation",
                "ycbcr",
            ])
            .output()?,
        "fss-file decode default 4MP",
    )?;
    let decode_4mp_ms = decode_t0.elapsed().as_millis();
    assert!(decode_stdout.contains("width=2688\n"), "{decode_stdout}");
    assert!(decode_stdout.contains("height=1512\n"), "{decode_stdout}");
    assert!(
        decode_stdout.contains("decode_complete=true\n"),
        "{decode_stdout}"
    );
    let decode_work: u64 = decode_stdout
        .lines()
        .find_map(|l| l.strip_prefix("this_request_decode_work_units="))
        .ok_or("missing this_request_decode_work_units")?
        .parse()?;
    // 2688x1512 4:4:4 uses ~789M luma work units (far exceeding old 100M/500M ceilings).
    assert!(
        decode_work > 700_000_000,
        "unexpectedly low 4MP 4:4:4 work units: {decode_work}"
    );

    // 3. Default `fss-infer package-detect` with `yolox_nano.fmpk` (ZERO manual `--jpeg-work-units`!)
    //    must succeed cleanly on 4MP 2688x1512 4:4:4 without hitting ERR-CODEC-MJPEG-BUDGET-001.
    let detect_t0 = Instant::now();
    let detect_stdout = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-infer"))
            .args(["package-detect", "--root"])
            .arg(&root)
            .args([
                "--site",
                UNIFI_SITE,
                "--import-id",
                &import_4mp,
                "--first-segment",
                "0",
                "--frames",
                "1",
                "--interpretation",
                "ycbcr",
                "--package-digest",
                YOLOX_PACKAGE_SHA256,
                "--threads",
                "auto",
            ])
            .arg("--package")
            .arg(yolox_package_path()?)
            .output()?,
        "fss-infer package-detect default 4MP",
    )?;
    let detect_4mp_ms = detect_t0.elapsed().as_millis();
    let detect_json = parse_json(&detect_stdout)?;
    assert_eq!(
        json_text(&detect_json, "schema")?,
        "fss.package_detection_report.v1"
    );
    assert!(json_bool(&detect_json, "complete")?);
    assert!(
        detect_stdout.contains("\"width\":2688,\"height\":1512")
            || detect_stdout.contains("[2688,1512]"),
        "expected 2688x1512 dimensions in package-detect report: {detect_stdout}"
    );

    // 4. Default `fss-infer activity` (ZERO manual `--max-decode-work` flags!) on a 2-frame
    //    16:9 UniFi 4:4:4 YCbCr sub-stream pair (1280x720 = 921,600 px, within the explicit 1MP
    //    `MAX_ACTIVITY_MODEL_PIXELS` bound) succeeds without hitting the old 20M work ceiling.
    let sub_a = encode_unifi_444_jpeg(1280, 720, false)?;
    let sub_b = encode_unifi_444_jpeg(1280, 720, true)?;
    let mut sub_clip = Vec::with_capacity(sub_a.len() + sub_b.len());
    sub_clip.extend_from_slice(&sub_a);
    sub_clip.extend_from_slice(&sub_b);
    let import_sub = import_mjpeg_cli(
        &root,
        UNIFI_SITE,
        "sensor:unifi-g4-177-sub",
        "stream:unifi-sub-720p",
        &dir.path().join("unifi_g4_1280x720_444.mjpeg"),
        &sub_clip,
    )?;

    let act_t0 = Instant::now();
    let act_stdout = ok_stdout(
        Command::new(env!("CARGO_BIN_EXE_fss-infer"))
            .args(["activity", "--root"])
            .arg(&root)
            .args([
                "--site",
                UNIFI_SITE,
                "--import-id",
                &import_sub,
                "--reference-segment",
                "0",
                "--segment",
                "1",
                "--sensor",
                "sensor:unifi-g4-177-sub",
                "--stream",
                "stream:unifi-sub-720p",
                "--job",
                "job:unifi-sub-444-activity",
                "--interpretation",
                "ycbcr",
                "--package-digest",
                ACTIVITY_PACKAGE_V1_SHA256,
                "--policy-generation",
                "1",
                "--threshold-bits",
                "3c23d70a",
                "--execution-macs",
                "10000000",
                "--execution-bytes",
                "16777216",
            ])
            .output()?,
        "fss-infer activity default 1280x720 4:4:4",
    )?;
    let act_ms = act_t0.elapsed().as_millis();
    let act_json = parse_json(&act_stdout)?;
    assert_eq!(
        json_text(&act_json, "format")?,
        "fss.recorded_activity_report.v1"
    );
    assert_eq!(json_text(&act_json, "outcome")?, "activity");
    let act_decode_work = json_int(&act_json, "decode_work")?;
    assert!(
        act_decode_work > 500_000_000,
        "expected >500M default work units for two 1280x720 4:4:4 frames, got {act_decode_work}"
    );

    // 5. Verify doctor stays Healthy with 0 orphans after full 4MP + 720p pipeline.
    let doc_report = inspect_deployment(&root);
    assert_eq!(doc_report.verdict, DoctorVerdict::Healthy);
    assert_eq!(doctor_unreferenced_count(&doc_report)?, 0);

    eprintln!(
        "METRIC scenario_3_unifi_4mp: encode_ms={encode_ms} decode_4mp_ms={decode_4mp_ms} decode_work={decode_work} detect_4mp_ms={detect_4mp_ms} activity_720p_444_ms={act_ms} activity_decode_work={act_decode_work} orphans=0"
    );
    Ok(())
}
