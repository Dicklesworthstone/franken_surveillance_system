#![forbid(unsafe_code)]
//! Real approved capture processes, killed after acknowledged pre-picture source custody.
//! No camera, synthetic success, injected network error, or post-kill finalization.

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_packet::StreamKey;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveLimits, DatagramPin, DatagramScope,
};
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const OUTPUT: u64 = 2 * 1024 * 1024;
const COUNT: usize = 32;
const BYTES: u64 = 1024 * 1024;
const MAX_SOURCE: u64 = 67_108_864;
const AVC: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n";
const HEVC: &str = concat!(
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n",
    "m=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\n",
    "a=fmtp:98 sprop-vps=QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA;",
    "sprop-sps=QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=;",
    "sprop-pps=RAHAc8CJ\r\na=control:trackID=0\r\n"
);
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..256 {
            let p = std::env::temp_dir().join(format!(
                "fss-source-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process {
    child: Child,
    out: PathBuf,
    err: PathBuf,
    deadline: Instant,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn binary() -> PathBuf {
    std::env::var_os("FSS_CAPTURE_RTSP_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_fss-capture-rtsp")))
}
impl Process {
    fn start(dir: &Directory, args: &[OsString]) -> Test<Self> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let out = dir.0.join(format!("stdout-{n}"));
        let err = dir.0.join(format!("stderr-{n}"));
        let child = Command::new(binary())
            .args(args)
            .stdin(Stdio::null())
            .stdout(File::create_new(&out)?)
            .stderr(File::create_new(&err)?)
            .spawn()?;
        Ok(Self {
            child,
            out,
            err,
            deadline: Instant::now() + Duration::from_secs(25),
        })
    }
    fn read(path: &Path) -> Test<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)?.take(OUTPUT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > OUTPUT {
            return Err("process output bound".into());
        }
        Ok(bytes)
    }
    fn check(&self) -> Test {
        if Instant::now() >= self.deadline
            || fs::metadata(&self.out)?.len() > OUTPUT
            || fs::metadata(&self.err)?.len() > OUTPUT
        {
            return Err("process time/output bound".into());
        }
        Ok(())
    }
    fn rows(&self) -> Test<Vec<Value>> {
        let bytes = Self::read(&self.out)?;
        let end = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        std::str::from_utf8(&bytes[..end])?
            .lines()
            .map(|s| parse(s).map_err(Into::into))
            .collect()
    }
    fn wait_rows(&mut self, kind: &str, count: usize) -> Test<Vec<Value>> {
        loop {
            self.check()?;
            let rows = self.rows()?;
            if details(&rows, kind)?.len() >= count {
                return Ok(rows);
            }
            if self.child.try_wait()?.is_some() {
                return Err(format!(
                    "capture ended before {count} {kind}: stdout={} stderr={}",
                    String::from_utf8_lossy(&Self::read(&self.out)?),
                    String::from_utf8_lossy(&Self::read(&self.err)?)
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn finish(&mut self) -> Test<Output> {
        let status = loop {
            self.check()?;
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        Ok(Output {
            status,
            stdout: Self::read(&self.out)?,
            stderr: Self::read(&self.err)?,
        })
    }
    fn kill(&mut self) -> Test {
        self.child.kill()?;
        assert!(!self.child.wait()?.success());
        Ok(())
    }
}
fn field<'a>(v: &'a Value, key: &str) -> Test<&'a Value> {
    v.object()
        .and_then(|o| o.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(v: &'a Value, key: &str) -> Test<&'a str> {
    field(v, key)?
        .text()
        .ok_or_else(|| format!("non-text {key}").into())
}
fn number(v: &Value, key: &str) -> Test<i128> {
    field(v, key)?
        .integer()
        .ok_or_else(|| format!("non-number {key}").into())
}
fn details<'a>(rows: &'a [Value], kind: &str) -> Test<Vec<&'a Value>> {
    rows.iter()
        .filter(|r| text(r, "kind").ok() == Some(kind))
        .map(|r| field(r, "detail"))
        .collect()
}
fn unique<'a>(rows: &'a [Value], kind: &str) -> Test<&'a Value> {
    let found = details(rows, kind)?;
    assert_eq!(found.len(), 1, "{kind}");
    Ok(found[0])
}
fn rows(out: &Output) -> Test<Vec<Value>> {
    std::str::from_utf8(&out.stdout)?
        .lines()
        .map(|s| parse(s).map_err(Into::into))
        .collect()
}
fn digest(s: &str) -> String {
    ContentDigest::sha256(s.as_bytes()).to_text()
}
fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(i) = args.iter().position(|s| s == key) {
        args[i + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}
fn args(dir: &Directory, peer: SocketAddr, codec: &str) -> Vec<OsString> {
    let mut args: Vec<_> = vec!["retain-source".into()];
    args.extend(
        [
            ("--root", dir.0.join("media").display().to_string()),
            ("--pins", dir.0.join("pins").display().to_string()),
            ("--source-root", dir.0.join("source").display().to_string()),
            (
                "--source-retention-evidence",
                digest("explicit fixture RTP and RTCP retention"),
            ),
            ("--max-datagrams", COUNT.to_string()),
            ("--source-storage-bytes", BYTES.to_string()),
            ("--peer", peer.to_string()),
            ("--authority", peer.to_string()),
            ("--presentation", "/live/".into()),
            ("--control-root", "/live".into()),
            ("--sensor-id", "sensor:source-cli".into()),
            ("--stream-id", "stream:source-cli".into()),
            ("--generation", "1".into()),
            ("--ingress", "71".into()),
            ("--ssrc", "7".into()),
            ("--anchor", digest("source owner")),
            ("--receive-clock", digest("source clock")),
            ("--timing-evidence", digest("source timing")),
            ("--journal-id", digest("source pins")),
            (
                "--frame-duration-ticks",
                if codec == "hevc" { "18000" } else { "3600" }.into(),
            ),
            ("--stop-after-pictures", "10".into()),
            ("--owner-authorized", "yes".into()),
            ("--plaintext", "yes".into()),
            ("--retain-originals", "yes".into()),
            ("--timeout-ms", "20000".into()),
            ("--drain-timeout-ms", "2000".into()),
            ("--response-timeout-ms", "5000".into()),
            ("--max-report-bytes", "1048576".into()),
            ("--codec", codec.into()),
            (
                "--payload-type",
                if codec == "hevc" { "98" } else { "96" }.into(),
            ),
            ("--read-bytes", "7".into()),
        ]
        .into_iter()
        .flat_map(|(k, v)| [k.into(), v.into()]),
    );
    args
}
fn preview(dir: &Directory, args: &[OsString]) -> Test<Value> {
    let out = Process::start(dir, args)?.finish()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(parse(std::str::from_utf8(&out.stdout)?)?)
}
fn approve(dir: &Directory, args: &[OsString]) -> Test<Vec<OsString>> {
    let plan = preview(dir, args)?;
    let mut args = args.to_vec();
    set(&mut args, "--approve", text(&plan, "approval")?);
    Ok(args)
}
fn listen() -> Test<TcpListener> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    l.set_nonblocking(true)?;
    Ok(l)
}
fn no_connection(l: &TcpListener) -> Test {
    match l.accept() {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err("unexpected connection".into()),
    }
}
fn request(peer: &mut TcpStream) -> Test<(String, u32)> {
    let mut bytes = Vec::new();
    for _ in 0..8192 {
        let mut b = [0];
        peer.read_exact(&mut b)?;
        bytes.push(b[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            let s = String::from_utf8(bytes)?;
            assert!(!s.to_ascii_lowercase().contains("authorization:"));
            let method = s
                .split_ascii_whitespace()
                .next()
                .ok_or("method")?
                .to_owned();
            let cseq = s
                .lines()
                .find_map(|s| {
                    let (k, v) = s.split_once(':')?;
                    k.eq_ignore_ascii_case("cseq").then_some(v.trim())
                })
                .ok_or("cseq")?
                .parse()?;
            return Ok((method, cseq));
        }
    }
    Err("request bound".into())
}
fn response(peer: &mut TcpStream, cseq: u32, headers: &str, body: &str) -> Test {
    peer.write_all(
        format!(
            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    Ok(())
}
fn playing(l: &TcpListener, codec: &str) -> Test<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut peer = loop {
        match l.accept() {
            Ok((p, _)) => break p,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e.into()),
        }
    };
    peer.set_nodelay(true)?;
    peer.set_read_timeout(Some(Duration::from_secs(8)))?;
    peer.set_write_timeout(Some(Duration::from_secs(8)))?;
    for (expected, headers, body) in [
        (
            "DESCRIBE",
            "Content-Type: application/sdp\r\n",
            if codec == "hevc" { HEVC } else { AVC },
        ),
        (
            "SETUP",
            "Session: source;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
            "",
        ),
        ("PLAY", "Session: source\r\n", ""),
    ] {
        let (method, cseq) = request(&mut peer)?;
        assert_eq!(method, expected);
        response(&mut peer, cseq, headers, body)?;
    }
    Ok(peer)
}
fn packet(pt: u8, seq: u16, timestamp: u32, payload: &[u8], marker: bool) -> Vec<u8> {
    let mut p = vec![0x80, pt | if marker { 128 } else { 0 }];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&timestamp.to_be_bytes());
    p.extend_from_slice(&7_u32.to_be_bytes());
    p.extend_from_slice(payload);
    p
}
fn send(peer: &mut TcpStream, channel: u8, payload: &[u8]) -> Test {
    let mut wire = vec![b'$', channel];
    wire.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
    wire.extend_from_slice(payload);
    peer.write_all(&wire)?;
    Ok(())
}
fn pin(v: &Value) -> Test<DatagramPin> {
    Ok(DatagramPin {
        scope: ContentDigest::parse(text(v, "scope")?)?,
        head: ContentDigest::parse(text(v, "head")?)?,
        datagrams: u64::try_from(number(v, "datagrams")?)?,
        payload_bytes: u64::try_from(number(v, "payload_bytes")?)?,
    })
}
fn limits(count: usize) -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        count,
        2,
        count,
        2 * count + 16,
        SpoolLimits::new(3 * count + 16, BYTES, 65536, 3 * count + 16),
    )
}
fn cold(
    dir: &Directory,
    address: SocketAddr,
    pin: DatagramPin,
    expected: &[(u8, Vec<u8>)],
    count: usize,
) -> Test {
    let p = LocalRootPublisher::open(dir.0.join("source"), limits(count))?;
    let scope = DatagramScope {
        binding: TcpBinding::new(
            StreamKey {
                ingress: 71,
                generation: 1,
                ssrc: 7,
            },
            address,
            &address.to_string(),
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        channels: (0, 1),
        receive_clock: ContentDigest::sha256(b"source clock"),
        retention_evidence: ContentDigest::sha256(b"explicit fixture RTP and RTCP retention"),
    };
    let mut work = WorkBudget::new(1_000_000_000);
    let a = DatagramArchive::recover(
        &p,
        scope.clone(),
        DatagramArchiveLimits {
            max_datagrams: count,
            max_payload_bytes: MAX_SOURCE,
            max_scan_roots: 2 * count + 16,
            max_spool_object_bytes: 65536,
        },
        Some(pin),
        &NeverCancel,
        &mut work,
    )?;
    assert_eq!(a.pin(), pin);
    assert_eq!(pin.datagrams as usize, expected.len());
    let mut previous = scope.digest()?;
    for (i, (channel, payload)) in expected.iter().enumerate() {
        let r = a.read(i as u64 + 1, &p, &NeverCancel, &mut work)?;
        assert_eq!(r.payload(), payload);
        assert_eq!(r.record().channel, *channel);
        assert_eq!(r.record().prior.head, previous);
        previous = r.record().pin.head;
    }
    assert_eq!(previous, pin.head);
    Ok(())
}
fn no_effects(dir: &Directory, l: &TcpListener) -> Test {
    for name in ["source", "media", "pins"] {
        assert!(!dir.0.join(name).exists(), "{name}");
    }
    no_connection(l)
}

#[test]
fn source_preview_is_pure_and_does_not_reuse_the_native_approval() -> Test {
    let dir = Directory::new()?;
    let l = listen()?;
    let a = args(&dir, l.local_addr()?, "avc");
    let plan = preview(&dir, &a)?;
    no_effects(&dir, &l)?;
    assert_eq!(text(&plan, "mode")?, "retain-source");
    let native = text(field(&plan, "capture_plan")?, "approval")?;
    assert_ne!(text(&plan, "approval")?, native);
    let mut stale = a.clone();
    set(&mut stale, "--approve", native);
    let out = Process::start(&dir, &stale)?.finish()?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ERR-CAPTURE-RTSP-APPROVAL-001"));
    no_effects(&dir, &l)?;
    Ok(())
}

#[test]
fn every_source_effect_and_bound_changes_approval_before_any_io() -> Test {
    let dir = Directory::new()?;
    let l = listen()?;
    let a = args(&dir, l.local_addr()?, "avc");
    let base = preview(&dir, &a)?;
    let approval = text(&base, "approval")?;
    for (k, v) in [
        (
            "--source-root",
            dir.0.join("other-source").display().to_string(),
        ),
        (
            "--source-retention-evidence",
            digest("different privacy decision"),
        ),
        ("--max-datagrams", "33".into()),
        ("--source-storage-bytes", "2097152".into()),
        ("--source-work", "99999999".into()),
    ] {
        let mut changed = a.clone();
        set(&mut changed, k, &v);
        let plan = preview(&dir, &changed)?;
        assert_ne!(text(&plan, "approval")?, approval, "{k}");
        set(&mut changed, "--approve", approval);
        assert!(!Process::start(&dir, &changed)?.finish()?.status.success());
        no_effects(&dir, &l)?;
    }
    Ok(())
}

#[test]
fn source_arguments_refuse_missing_evidence_duplicates_and_unbounded_work() -> Test {
    let dir = Directory::new()?;
    let l = listen()?;
    let a = args(&dir, l.local_addr()?, "avc");
    for (k, v) in [
        (
            "--source-retention-evidence",
            format!("sha256:{}", "0".repeat(64)),
        ),
        ("--source-work", "0".into()),
        ("--max-datagrams", "65537".into()),
        ("--source-storage-bytes", "0".into()),
        (
            "--source-root",
            dir.0.join("media/subdirectory").display().to_string(),
        ),
    ] {
        let mut bad = a.clone();
        set(&mut bad, k, &v);
        assert!(!Process::start(&dir, &bad)?.finish()?.status.success());
    }
    let mut duplicate = a.clone();
    duplicate.extend(["--max-datagrams".into(), "4".into()]);
    assert!(!Process::start(&dir, &duplicate)?.finish()?.status.success());
    let mut missing = a;
    let at = missing
        .iter()
        .position(|s| s == "--source-retention-evidence")
        .ok_or("evidence")?;
    missing.drain(at..at + 2);
    assert!(!Process::start(&dir, &missing)?.finish()?.status.success());
    no_effects(&dir, &l)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn canonical_source_alias_refuses_before_creating_either_archive() -> Test {
    let dir = Directory::new()?;
    let l = listen()?;
    fs::create_dir(dir.0.join("real"))?;
    std::os::unix::fs::symlink(dir.0.join("real"), dir.0.join("alias"))?;
    let mut a = args(&dir, l.local_addr()?, "avc");
    set(
        &mut a,
        "--root",
        &dir.0.join("real/media").display().to_string(),
    );
    set(
        &mut a,
        "--source-root",
        &dir.0.join("alias/media").display().to_string(),
    );
    let approved = approve(&dir, &a)?;
    let out = Process::start(&dir, &approved)?.finish()?;
    assert!(!out.status.success());
    assert!(!dir.0.join("real/media").exists());
    no_effects(&dir, &l)?;
    Ok(())
}

#[test]
fn kill_after_durable_incomplete_rtp_preserves_both_codecs_and_rtcp() -> Test {
    for codec in ["avc", "hevc"] {
        let dir = Directory::new()?;
        let l = listen()?;
        let address = l.local_addr()?;
        let approved = approve(&dir, &args(&dir, address, codec))?;
        let mut process = Process::start(&dir, &approved)?;
        let mut peer = playing(&l, codec)?;
        // Valid RTCP RR, then sequence probation followed by only the START of a
        // fragmented slice. No complete picture can exist in either codec.
        let pt = if codec == "avc" { 96 } else { 98 };
        let fragment = if codec == "avc" {
            vec![0x7c, 0x85, 0xaa]
        } else {
            vec![98, 1, 0x94, 0xaa]
        };
        let expected = vec![
            (1, vec![0x80, 201, 0, 1, 0, 0, 0, 7]),
            (0, packet(pt, 0, 0, &fragment, false)),
            (0, packet(pt, 1, 0, &fragment, false)),
        ];
        for (i, (channel, bytes)) in expected.iter().enumerate() {
            send(&mut peer, *channel, bytes)?;
            process.wait_rows("datagram_durable", i + 1)?;
        }
        // A partial interleaved frame is deliberately outside the acknowledged
        // prefix. SIGKILL cannot cause a Drop/publication or EOF completion.
        peer.write_all(&[b'$', 0, 0, 40, 0x80, pt])?;
        let rows = process.rows()?;
        let receipts = details(&rows, "datagram_durable")?;
        assert_eq!(receipts.len(), expected.len());
        assert!(details(&rows, "window_durable")?.is_empty());
        let prefix = pin(field(receipts.last().ok_or("receipt")?, "prefix")?)?;
        for r in receipts {
            assert_eq!(field(r, "picture_complete")?.boolean(), Some(false));
        }
        process.kill()?;
        drop(peer);
        assert!(details(&process.rows()?, "terminal")?.is_empty());
        cold(&dir, address, prefix, &expected, COUNT)?;
        no_connection(&l)?;
        let p = LocalRootPublisher::open(
            dir.0.join("media"),
            LocalPublicationLimits::new(
                128,
                1024,
                128,
                1024,
                SpoolLimits::new(1024, 16 * 1024 * 1024, 2 * 1024 * 1024, 1024),
            ),
        )?;
        assert_eq!(
            p.visible_roots().count(),
            0,
            "source custody must not fabricate a recording"
        );
    }
    Ok(())
}

#[test]
fn source_count_exhaustion_stops_capture_without_discarding_acknowledged_prefix() -> Test {
    for codec in ["avc", "hevc"] {
        let dir = Directory::new()?;
        let l = listen()?;
        let address = l.local_addr()?;
        let mut a = args(&dir, address, codec);
        set(&mut a, "--max-datagrams", "2");
        let approved = approve(&dir, &a)?;
        let mut process = Process::start(&dir, &approved)?;
        let mut peer = playing(&l, codec)?;
        let rr = vec![0x80, 201, 0, 1, 0, 0, 0, 7];
        for i in 1..=2 {
            send(&mut peer, 1, &rr)?;
            process.wait_rows("datagram_durable", i)?;
        }
        send(&mut peer, 1, &rr)?;
        let out = process.finish()?;
        assert!(!out.status.success());
        let rows = rows(&out)?;
        let t = unique(&rows, "terminal")?;
        assert_eq!(text(t, "error_id")?, "ERR-CAPTURE-RTSP-STORAGE-001");
        assert_eq!(number(t, "collected_pictures")?, 0);
        assert_eq!(field(t, "complete")?.boolean(), Some(false));
        let custody = field(t, "datagram_source")?;
        assert_eq!(
            field(custody, "source_custody_refused")?.boolean(),
            Some(true)
        );
        let prefix = pin(field(custody, "last_local_durable_prefix")?)?;
        assert_eq!(details(&rows, "datagram_durable")?.len(), 2);
        drop(peer);
        cold(&dir, address, prefix, &[(1, rr.clone()), (1, rr)], 2)?;
        no_connection(&l)?;
    }
    Ok(())
}

#[test]
fn malformed_datagram_is_retained_but_not_converted_to_a_picture() -> Test {
    for codec in ["avc", "hevc"] {
        let dir = Directory::new()?;
        let l = listen()?;
        let address = l.local_addr()?;
        let approved = approve(&dir, &args(&dir, address, codec))?;
        let mut process = Process::start(&dir, &approved)?;
        let mut peer = playing(&l, codec)?;
        let bad = vec![0, 1, 2];
        send(&mut peer, 0, &bad)?;
        let rows = process.wait_rows("datagram_durable", 1)?;
        let r = unique(&rows, "datagram_durable")?;
        let prefix = pin(field(r, "prefix")?)?;
        // Whether the protocol stops or keeps diagnosing this malformed source,
        // it never needs a valid picture to commit the original datagram.
        if process.child.try_wait()?.is_none() {
            process.kill()?;
        }
        drop(peer);
        cold(&dir, address, prefix, &[(0, bad)], COUNT)?;
        assert!(details(&rows, "window_durable")?.is_empty());
    }
    Ok(())
}

#[test]
fn authentication_challenge_never_enters_the_source_spool() -> Test {
    let dir = Directory::new()?;
    let l = listen()?;
    let address = l.local_addr()?;
    let approved = approve(&dir, &args(&dir, address, "avc"))?;
    let mut process = Process::start(&dir, &approved)?;
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut peer = loop {
        match l.accept() {
            Ok((p, _)) => break p,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(8)))?;
    let (method, cseq) = request(&mut peer)?;
    assert_eq!(method, "DESCRIBE");
    write!(
        peer,
        "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"fixture\", nonce=\"not-a-secret\"\r\nContent-Length: 4\r\n\r\n$\0\0\0"
    )?;
    let out = process.finish()?;
    assert!(!out.status.success());
    let rows = rows(&out)?;
    assert!(details(&rows, "datagram_durable")?.is_empty());
    let t = unique(&rows, "terminal")?;
    let prefix = pin(field(
        field(t, "datagram_source")?,
        "last_local_durable_prefix",
    )?)?;
    cold(&dir, address, prefix, &[], COUNT)?;
    Ok(())
}

fn complete_video(codec: &str) -> Test<Vec<Vec<u8>>> {
    if codec == "hevc" {
        let nals: Vec<Vec<u8>> =
            include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
                .lines()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    (0..s.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
                        .collect::<Test<Vec<_>>>()
                })
                .collect::<Test<Vec<_>>>()?;
        // The following VCL establishes the first HEVC picture's real boundary.
        let mut packets = vec![packet(98, 0, 0, &nals[0], false)];
        for (i, nal) in nals.iter().take(5).enumerate() {
            packets.push(packet(
                98,
                (i + 1) as u16,
                if i == 4 { 18000 } else { 0 },
                nal,
                true,
            ));
        }
        return Ok(packets);
    }
    let bytes = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
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
    if let Some(begin) = start {
        if begin < bytes.len() {
            nals.push(&bytes[begin..]);
        }
    }
    let end = nals
        .iter()
        .position(|n| n[0] & 31 == 5)
        .ok_or("fixture IDR")?;
    let mut packets = vec![packet(96, 0, 0, nals[0], false)];
    for (i, nal) in nals.iter().take(end + 1).enumerate() {
        packets.push(packet(96, (i + 1) as u16, 0, nal, nal[0] & 31 == 5));
    }
    Ok(packets)
}

#[test]
fn source_first_mode_still_completes_native_recording_for_both_codecs() -> Test {
    for codec in ["avc", "hevc"] {
        let dir = Directory::new()?;
        let l = listen()?;
        let address = l.local_addr()?;
        let mut a = args(&dir, address, codec);
        set(&mut a, "--stop-after-pictures", "1");
        let approved = approve(&dir, &a)?;
        let mut process = Process::start(&dir, &approved)?;
        let mut peer = playing(&l, codec)?;
        let expected: Vec<_> = complete_video(codec)?.into_iter().map(|p| (0, p)).collect();
        for (i, (channel, bytes)) in expected.iter().enumerate() {
            send(&mut peer, *channel, bytes)?;
            process.wait_rows("datagram_durable", i + 1)?;
        }
        let out = process.finish()?;
        assert!(
            out.status.success(),
            "{} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let rows = rows(&out)?;
        let t = unique(&rows, "terminal")?;
        assert_eq!(field(t, "complete")?.boolean(), Some(true));
        assert_eq!(number(t, "durable_pictures")?, 1);
        assert_eq!(field(t, "peer_eof")?.boolean(), Some(false));
        assert_eq!(
            text(t, "control_and_rtcp_retention")?,
            "control_omitted_rtcp_in_separate_source_prefix"
        );
        let custody = field(t, "datagram_source")?;
        let prefix = pin(field(custody, "last_local_durable_prefix")?)?;
        assert_eq!(
            field(custody, "complete_input_retained")?.boolean(),
            Some(false)
        );
        let window = unique(&rows, "window_durable")?;
        let _ = unique(&rows, "catalog_published")?;
        drop(peer);
        cold(&dir, address, prefix, &expected, COUNT)?;
        let p = LocalRootPublisher::open(
            dir.0.join("media"),
            LocalPublicationLimits::new(
                128,
                1024,
                128,
                1024,
                SpoolLimits::new(1024, 16 * 1024 * 1024, 2 * 1024 * 1024, 1024),
            ),
        )?;
        let scope = fss_reference::rtsp::recording::RecordingScope {
            sensor: fss_core::SensorId::parse("sensor:source-cli")?,
            stream: fss_core::StreamId::parse("stream:source-cli")?,
            generation: 1,
            anchor: ContentDigest::sha256(b"source owner"),
            receive_clock: ContentDigest::sha256(b"source clock"),
        };
        let slot = fss_publication::SlotName::parse(text(window, "slot")?)?;
        let root = ContentDigest::parse(text(window, "root")?)?;
        if codec == "avc" {
            assert_eq!(
                fss_reference::rtsp::recording::local::load_recording(
                    &p,
                    &slot,
                    root,
                    &scope,
                    &NeverCancel
                )?
                .summary()
                .samples,
                1
            );
        } else {
            assert_eq!(
                fss_reference::rtsp::recording::hevc::local::load_hevc_recording(
                    &p,
                    &slot,
                    root,
                    &scope,
                    &NeverCancel
                )?
                .samples()
                .len(),
                1
            );
        }
        // Original source is committed before the recording derivative/window.
        let first_window = rows
            .iter()
            .position(|r| text(r, "kind").ok() == Some("window_durable"))
            .ok_or("window order")?;
        assert!(
            rows.iter()
                .enumerate()
                .filter(|(_, r)| text(r, "kind").ok() == Some("datagram_durable"))
                .all(|(i, _)| i < first_window)
        );
    }
    Ok(())
}
