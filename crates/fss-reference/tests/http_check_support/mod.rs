#![forbid(unsafe_code)]
//! Synthetic canonical wire-root fixtures, NOT a claim of live camera capture or EOF.
use std::path::{Path, PathBuf};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, SlotName};
use fss_reference::ingest::http_replay::check::{HttpCheckDecode, HttpCheckRequest, HttpCheckSource};
pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const JPEG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fss-codec-mjpeg/tests/fixtures/gray.jpg"));
pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new() -> Test<Self> {
        for n in 0..128 {
            let path = std::env::temp_dir().join(format!("fss-http-check-{}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory bound".into())
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
pub fn open(root: &Path) -> Test<LocalRootPublisher> {
    Ok(LocalRootPublisher::open(root, LocalPublicationLimits::new(128, 128, 128, 1024,
        SpoolLimits::new(1024, 16 * 1024 * 1024, 65536, 1024)))?)
}
pub struct Fixture { pub request: HttpCheckRequest, pub wire_digest: ContentDigest }
pub fn fixture(root: &Path, close: bool, images: &[&[u8]]) -> Test<Fixture> {
    let mut p = open(root)?;
    let source = HttpCheckSource { source: ContentDigest::sha256(b"synthetic original stream"), generation: 1,
        receive_clock: ContentDigest::sha256(b"fixture receive clock"), retention_evidence: ContentDigest::sha256(b"fixture retention") };
    let scope = source.scope()?.digest()?;
    let mut body = Vec::new();
    for image in images {
        body.extend_from_slice(format!("--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", image.len()).as_bytes());
        body.extend_from_slice(image); body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fss--\r\n");
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n".to_vec();
    if !close { wire.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes()); }
    wire.extend_from_slice(b"\r\n"); wire.extend_from_slice(&body);
    assert!(wire.len() <= 65536);
    let raw = p.stage_object(&wire)?;
    // Canonical v1 wire fixture: independently build the public format rather than
    // minting an HttpWireRead or using a false live-camera/termination receipt.
    let mut e = CanonicalEncoder::new(); e.text("fss.http_camera_wire.v1"); e.digest(scope); e.digest(scope);
    e.u64(0); e.u64(0); e.digest(source.source); e.u64(source.generation);
    e.u64(0); e.u64(wire.len() as u64); e.digest(raw); e.u64(1);
    let metadata = p.stage_object(&e.finish_checked()?)?;
    let manifest = ObjectManifest::new("http_camera_wire_v1", [raw], Some(metadata))?;
    let mut e = CanonicalEncoder::new(); e.text("fss.http_wire_namespace.v1"); e.digest(source.source); e.u64(source.generation);
    let namespace = ContentDigest::sha256(&e.finish_checked()?).to_text();
    let slot = SlotName::parse(&format!("fsshw1-{}-00000001", namespace.strip_prefix("sha256:").ok_or("algorithm")?))?;
    p.publish(&slot, &manifest)?;
    Ok(Fixture { request: HttpCheckRequest { source, head: manifest.root(), reads: 1, bytes: wire.len() as u64,
        completion: None, decode: HttpCheckDecode::Grayscale }, wire_digest: raw })
}
