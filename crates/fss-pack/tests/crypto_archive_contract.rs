#![forbid(unsafe_code)]
//! Comprehensive contract, adversarial tamper, zero-rewrite KEK rotation, cryptographic erasure,
//! loopback S3 archival/audit/restore E2E, and secret canary-leak tests for bead `fss-x4a.31.1.6` (`A6`).

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs,
};
use fss_pack::{
    AEAD_FRAME_HEADER_LEN, AeadRecordContext, ColdArchivePolicy, ColdAuditConfig,
    ColdPackArchiveManifest, ColdProviderKind, ColdRetrievabilityVerdict, ColdS3Credentials,
    ColdS3Endpoint, ColdS3Limits, ColdStorageTier, ColdUploadMode, DataEncryptionKey, DekId,
    DurabilityMode, ERR_CRYPTO_AUTH_FAILED_001, ERR_CRYPTO_KEY_ERASED_001, EncryptedPackReader,
    EncryptedPackWriter, EncryptedStreamKind, KeyEncryptionKey, KeyEnvelopeCatalog, KeyEpoch,
    PACK_KIND_MEDIA_CHUNK, PACK_KIND_OBJECT_MANIFEST, PackConfig, PackError, PackId,
    PackObjectInput, PackStore, S3CompatiblePackTransport, SCHEMA_EPOCH_PACKFILE,
    archive_sealed_pack, audit_cold_pack_retrievability, decrypt_aead_frame,
    decrypt_and_verify_ledger_epoch_segment, decrypt_and_verify_pack_bytes,
    decrypt_and_verify_pack_file, encrypt_aead_frame, encrypt_ledger_epoch_segment,
    encrypt_pack_file, evict_local_sealed_pack, fetch_cold_pack_manifest, restore_cold_pack,
};
use fss_vault::{
    AdapterFamily, CAP_SECRET_READ_001, CAP_SECRET_WRITE_001, CanaryLeakScanner, KdfParams,
    LabEntropy, LocalEncryptedVault, OsEntropy, SecretAccessCx, SecretBytes, SecretId, SecretScope,
    SecretStore,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-pack-crypto-archive-{label}-{}-{id}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn kek_scope(site: &str) -> Result<SecretScope, Box<dyn std::error::Error>> {
    Ok(SecretScope::new(
        AdapterFamily::StorageKek,
        site,
        "local-pack-store",
    )?)
}

fn s3_scope(bucket: &str) -> Result<SecretScope, Box<dyn std::error::Error>> {
    Ok(SecretScope::new(
        AdapterFamily::ArchiveS3,
        "cold-tier",
        bucket,
    )?)
}

fn make_kek(
    epoch: u32,
    site: &str,
    seed_byte: u8,
) -> Result<KeyEncryptionKey, Box<dyn std::error::Error>> {
    let mut raw = [0_u8; 32];
    for (idx, b) in raw.iter_mut().enumerate() {
        *b = seed_byte
            .wrapping_add((idx as u8).wrapping_mul(11))
            .wrapping_add(epoch as u8);
    }
    let secret = SecretBytes::from_slice(&raw)?;
    Ok(KeyEncryptionKey::from_secret_bytes(
        KeyEpoch::new(epoch)?,
        kek_scope(site)?,
        secret,
    )?)
}

fn shannon_entropy_bits_per_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for &b in data {
        counts[usize::from(b)] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn make_secret_cx(
    scope: SecretScope,
    caps: Vec<String>,
    now: TimestampNs,
    cancelled: bool,
) -> Result<SecretAccessCx, Box<dyn std::error::Error>> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:a6:test".to_owned(),
        operation_id: OperationId::parse("op:a6:test")?,
        principal: "principal:operator:test".to_owned(),
        capabilities: caps,
        deadline: Some(TimestampNs(now.0 + 60_000_000_000)),
        priority: 1,
        budgets: BudgetVector::ZERO,
        privacy_scope: "privacy:owner".to_owned(),
        retention_scope: "retention:hot-cold".to_owned(),
        anchor_universe: ContentDigest::sha256(b"test-universe"),
        generation: 1,
    })?;
    let mut cx = SecretAccessCx::new(authority, scope, now)?;
    if cancelled {
        cx = cx.with_cancelled("operator cancelled");
    }
    Ok(cx)
}

// =========================================================================
// Pure-Rust in-process HTTP/1.1 Loopback S3 Mock Server
// =========================================================================

#[derive(Clone, Debug)]
struct RecordedS3Request {
    method: String,
    path: String,
    query: String,
    has_sigv4: bool,
    body_sha256_verified: bool,
}

#[derive(Default)]
struct MockS3State {
    objects: BTreeMap<String, (Vec<u8>, String)>,
    multiparts: BTreeMap<String, (String, BTreeMap<u32, Vec<u8>>)>,
    requests: Vec<RecordedS3Request>,
    next_upload_seq: u64,
    force_redirect_on_key: Option<String>,
    mislabel_ranges: bool,
}

struct LoopbackS3Server {
    addr: SocketAddr,
    state: Arc<Mutex<MockS3State>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl LoopbackS3Server {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(MockS3State::default()));
        let stop = Arc::new(AtomicBool::new(false));

        let state_bg = Arc::clone(&state);
        let stop_bg = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        let _ = handle_mock_s3_connection(&mut stream, &state_bg);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            state,
            stop,
            handle: Some(handle),
        })
    }

    fn requests(&self) -> Vec<RecordedS3Request> {
        self.state
            .lock()
            .map(|g| g.requests.clone())
            .unwrap_or_default()
    }

    fn stored_bytes(&self, bucket: &str, key: &str) -> Option<Vec<u8>> {
        let full_path = format!("/{bucket}/{key}");
        self.state
            .lock()
            .ok()
            .and_then(|g| g.objects.get(&full_path).map(|(b, _)| b.clone()))
    }

    fn flip_byte_in_object(&self, bucket: &str, key: &str, offset: usize) -> bool {
        let full_path = format!("/{bucket}/{key}");
        if let Ok(mut g) = self.state.lock()
            && let Some((bytes, _etag)) = g.objects.get_mut(&full_path)
            && offset < bytes.len()
        {
            bytes[offset] ^= 0x80;
            return true;
        }
        false
    }

    fn delete_object(&self, bucket: &str, key: &str) -> bool {
        let full_path = format!("/{bucket}/{key}");
        self.state
            .lock()
            .map(|mut g| g.objects.remove(&full_path).is_some())
            .unwrap_or(false)
    }

    fn set_force_redirect(&self, bucket: &str, key: Option<&str>) {
        if let Ok(mut g) = self.state.lock() {
            g.force_redirect_on_key = key.map(|k| format!("/{bucket}/{k}"));
        }
    }
}

impl Drop for LoopbackS3Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_mock_s3_connection(
    stream: &mut TcpStream,
    state: &Arc<Mutex<MockS3State>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 8192];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&buf[..n]);
    };

    let head = std::str::from_utf8(&raw[..header_end - 4])?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let target = parts.next().unwrap_or("");
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (target.to_owned(), String::new()),
    };

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let content_len: usize = headers
        .get("content-length")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut body = raw[header_end..].to_vec();
    while body.len() < content_len {
        let need = (content_len - body.len()).min(buf.len());
        let n = stream.read(&mut buf[..need])?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_len);

    // Verify AWS SigV4 header presence & exact x-amz-content-sha256 binding
    let has_sigv4 = headers.get("authorization").is_some_and(|a| {
        a.starts_with("AWS4-HMAC-SHA256 Credential=")
            && a.contains("/s3/aws4_request,SignedHeaders=")
            && a.contains(",Signature=")
    }) && headers.contains_key("x-amz-date");

    let actual_sha_hex = hex_bytes(&ContentDigest::sha256(&body).bytes());
    let body_sha256_verified = headers
        .get("x-amz-content-sha256")
        .is_some_and(|declared| declared == &actual_sha_hex);

    let mut guard = state.lock().map_err(|_| "mock S3 state lock poisoned")?;
    guard.requests.push(RecordedS3Request {
        method: method.clone(),
        path: path.clone(),
        query: query.clone(),
        has_sigv4,
        body_sha256_verified,
    });

    if !has_sigv4 || !body_sha256_verified {
        let reply = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(reply.as_bytes())?;
        return Ok(());
    }

    if guard.force_redirect_on_key.as_deref() == Some(path.as_str()) {
        let reply = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/evil\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(reply.as_bytes())?;
        return Ok(());
    }

    let query_params = parse_query(&query);

    match method.as_str() {
        "POST" if query == "uploads=" => {
            guard.next_upload_seq += 1;
            let upload_id = format!("upload-{}", guard.next_upload_seq);
            guard
                .multiparts
                .insert(upload_id.clone(), (path.clone(), BTreeMap::new()));
            let (bucket, key) = split_bucket_key(&path);
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{bucket}</Bucket><Key>{key}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>"
            );
            write_http_reply(stream, 200, "OK", &[], xml.as_bytes())?;
        }
        "POST" if query_params.contains_key("uploadId") => {
            let upload_id = query_params.get("uploadId").cloned().unwrap_or_default();
            if let Some((obj_path, parts_map)) = guard.multiparts.remove(&upload_id) {
                let mut assembled = Vec::new();
                for part_bytes in parts_map.values() {
                    assembled.extend_from_slice(part_bytes);
                }
                let etag = format!(
                    "\"mp-{}-{}\"",
                    &hex_bytes(&ContentDigest::sha256(&assembled).bytes())[..16],
                    parts_map.len()
                );
                guard
                    .objects
                    .insert(obj_path.clone(), (assembled, etag.clone()));
                let (bucket, key) = split_bucket_key(&obj_path);
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{bucket}</Bucket><Key>{key}</Key><ETag>{etag}</ETag></CompleteMultipartUploadResult>"
                );
                write_http_reply(stream, 200, "OK", &[], xml.as_bytes())?;
            } else {
                write_http_reply(stream, 404, "Not Found", &[], b"")?;
            }
        }
        "PUT"
            if query_params.contains_key("partNumber") && query_params.contains_key("uploadId") =>
        {
            let upload_id = query_params.get("uploadId").cloned().unwrap_or_default();
            let part_num: u32 = query_params
                .get("partNumber")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if let Some((_obj_path, parts_map)) = guard.multiparts.get_mut(&upload_id) {
                let part_etag = format!("\"part-{part_num}-{}\"", &actual_sha_hex[..12]);
                parts_map.insert(part_num, body);
                write_http_reply(stream, 200, "OK", &[("ETag", &part_etag)], b"")?;
            } else {
                write_http_reply(stream, 404, "Not Found", &[], b"")?;
            }
        }
        "PUT" => {
            let etag = format!("\"{}\"", &actual_sha_hex[..24]);
            guard.objects.insert(path, (body, etag.clone()));
            write_http_reply(stream, 200, "OK", &[("ETag", &etag)], b"")?;
        }
        "DELETE" if query_params.contains_key("uploadId") => {
            let upload_id = query_params.get("uploadId").cloned().unwrap_or_default();
            guard.multiparts.remove(&upload_id);
            write_http_reply(stream, 204, "No Content", &[], b"")?;
        }
        "GET" => {
            if let Some((data, etag)) = guard.objects.get(&path).cloned() {
                if let Some(range_val) = headers.get("range") {
                    if let Some(spec) = range_val.strip_prefix("bytes=")
                        && let Some((s, e)) = spec.split_once('-')
                        && let (Ok(start), Ok(end)) = (s.parse::<usize>(), e.parse::<usize>())
                        && start <= end
                        && end < data.len()
                    {
                        let slice = &data[start..=end];
                        let content_range = if guard.mislabel_ranges {
                            format!("bytes 0-0/{}", data.len())
                        } else {
                            format!("bytes {start}-{end}/{}", data.len())
                        };
                        write_http_reply(
                            stream,
                            206,
                            "Partial Content",
                            &[("ETag", &etag), ("Content-Range", &content_range)],
                            slice,
                        )?;
                    } else {
                        write_http_reply(stream, 416, "Range Not Satisfiable", &[], b"")?;
                    }
                } else {
                    write_http_reply(stream, 200, "OK", &[("ETag", &etag)], &data)?;
                }
            } else {
                write_http_reply(stream, 404, "Not Found", &[], b"")?;
            }
        }
        _ => {
            write_http_reply(stream, 405, "Method Not Allowed", &[], b"")?;
        }
    }
    Ok(())
}

fn write_http_reply(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str("Connection: close\r\n\r\n");
    stream.write_all(resp.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    Ok(())
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_owned(), v.to_owned());
        }
    }
    map
}

fn split_bucket_key(path: &str) -> (&str, &str) {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    trimmed.split_once('/').unwrap_or((trimmed, ""))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

// =========================================================================
// Verification Test 1: Plaintext Confidentiality & High Shannon Entropy
// =========================================================================

#[test]
fn plaintext_confidentiality_zero_markers_and_high_shannon_entropy() -> TestResult {
    let dir = TempDir::new("confidentiality")?;
    let mut entropy = LabEntropy::from_seed([0x11; 32]);
    let kek = make_kek(1, "site-alpha", 0x33)?;
    let mut catalog = KeyEnvelopeCatalog::open_or_create(
        dir.path.join("key-catalog.fskc"),
        KeyEpoch(1),
        kek.scope(),
        DurabilityMode::Fsync,
    )?;

    let pack_id = PackId::new(1, 1);
    let (dek, _env) =
        catalog.create_and_wrap_dek(&kek, &mut entropy, &[pack_id], TimestampNs(100))?;

    let jpeg_marker = b"\xff\xd8\xff\xe1CAMERA-FRONT-DOOR-SECRET-MARKER-JPEG-PAYLOAD-9876543210";
    let manifest_marker = b"FSS-MANIFEST-CAM-DRIVEWAY-SENSITIVE-EVENT-RECORD-001";

    let mut jpeg_frame = Vec::with_capacity(32 * 1024);
    for _ in 0..400 {
        jpeg_frame.extend_from_slice(jpeg_marker);
    }
    let mut manifest_blob = Vec::with_capacity(16 * 1024);
    for _ in 0..250 {
        manifest_blob.extend_from_slice(manifest_marker);
    }
    let plain_entropy = shannon_entropy_bits_per_byte(&jpeg_frame);
    assert!(
        plain_entropy < 5.5,
        "synthetic JPEG marker plaintext should have low entropy (got {plain_entropy:.2})"
    );

    let enc_path = dir.path.join("pack-00000001-000000000001.fsep");
    let mut writer = EncryptedPackWriter::create(
        &enc_path,
        pack_id,
        EncryptedStreamKind::PackRecords,
        SCHEMA_EPOCH_PACKFILE,
        dek,
        KeyEpoch(1),
        DurabilityMode::Fsync,
    )?;
    let r1 = writer.write_record(&jpeg_frame, &mut entropy)?;
    let r2 = writer.write_record(&manifest_blob, &mut entropy)?;
    let receipt = writer.finish()?;

    assert_eq!(receipt.frame_count, 2);
    assert_eq!(r1.plaintext_digest, ContentDigest::sha256(&jpeg_frame));
    assert_eq!(r2.plaintext_digest, ContentDigest::sha256(&manifest_blob));

    let on_disk = fs::read(&enc_path)?;
    assert!(!contains_subslice(&on_disk, jpeg_marker));
    assert!(!contains_subslice(&on_disk, b"CAMERA-FRONT-DOOR"));
    assert!(!contains_subslice(&on_disk, manifest_marker));
    assert!(!contains_subslice(&on_disk, b"CAM-DRIVEWAY-SENSITIVE"));

    let cipher_entropy = shannon_entropy_bits_per_byte(&on_disk);
    assert!(
        cipher_entropy >= 7.80,
        "encrypted packfile must have high Shannon entropy (>= 7.80 bits/byte), got {cipher_entropy:.3}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(&enc_path)?.mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "encrypted packfile must enforce 0600 mode");
    }

    let reader = EncryptedPackReader::open(&enc_path)?;
    let (h1, dec1) = reader.read_frame_with_catalog(r1.record_offset, &catalog, &kek)?;
    let (h2, dec2) = reader.read_frame_with_catalog(r2.record_offset, &catalog, &kek)?;
    assert_eq!(dec1, jpeg_frame);
    assert_eq!(dec2, manifest_blob);
    assert_eq!(h1.plaintext_digest(), r1.plaintext_digest);
    assert_eq!(h2.plaintext_digest(), r2.plaintext_digest);
    Ok(())
}

// =========================================================================
// Verification Test 2: Round-Trip & Nonce Uniqueness Across 250 Objects
// =========================================================================

#[test]
fn round_trip_encrypt_decrypt_and_nonce_uniqueness_across_250_objects() -> TestResult {
    let dir = TempDir::new("nonce-250")?;
    let mut os_entropy = OsEntropy::new();
    let kek = make_kek(1, "site-nonce", 0x55)?;
    let mut catalog = KeyEnvelopeCatalog::open_or_create(
        dir.path.join("key-catalog.fskc"),
        KeyEpoch(1),
        kek.scope(),
        DurabilityMode::Fsync,
    )?;

    let pack_id = PackId::new(1, 7);
    let (dek, _env) =
        catalog.create_and_wrap_dek(&kek, &mut os_entropy, &[pack_id], TimestampNs(200))?;

    let enc_path = dir.path.join("pack-250.fsep");
    let mut writer = EncryptedPackWriter::create(
        &enc_path,
        pack_id,
        EncryptedStreamKind::PackRecords,
        SCHEMA_EPOCH_PACKFILE,
        dek.clone(),
        KeyEpoch(1),
        DurabilityMode::Fsync,
    )?;

    let mut expected: Vec<(u64, ContentDigest, Vec<u8>)> = Vec::with_capacity(250);
    let mut nonces = HashSet::with_capacity(250);
    for idx in 0_usize..250 {
        let len = match idx % 5 {
            0 => 0,
            1 => 17,
            2 => 256,
            3 => 1024,
            _ => 4096,
        };
        let payload: Vec<u8> = (0..len)
            .map(|i| ((idx * 31 + i * 7) & 0xff) as u8)
            .collect();
        let digest = ContentDigest::sha256(&payload);
        let rec = writer.write_record(&payload, &mut os_entropy)?;
        assert_eq!(rec.plaintext_digest, digest);
        assert!(
            nonces.insert(rec.nonce),
            "nonce collision detected at record {idx}"
        );
        expected.push((rec.record_offset, digest, payload));
    }
    let receipt = writer.finish()?;
    assert_eq!(receipt.frame_count, 250);
    assert_eq!(nonces.len(), 250);

    let reader = EncryptedPackReader::open(&enc_path)?;
    let all = reader.decrypt_all_records(&catalog, &kek)?;
    assert_eq!(all.len(), 250);
    for (idx, ((offset, exp_digest, exp_bytes), (got_digest, got_bytes))) in
        expected.iter().zip(all.iter()).enumerate()
    {
        assert_eq!(got_digest, exp_digest, "digest mismatch at {idx}");
        assert_eq!(got_bytes, exp_bytes, "plaintext mismatch at {idx}");
        let (hdr, pos_bytes) = reader.read_frame_with_catalog(*offset, &catalog, &kek)?;
        assert_eq!(hdr.plaintext_digest(), *exp_digest);
        assert_eq!(pos_bytes, *exp_bytes);
    }

    // Also prove ledger epoch segment round-trip & domain isolation
    let ledger_plain = b"FSSE-v2-epoch-segment-canonical-delta-batch-payload-0001".repeat(64);
    let (ledger_ct, ledger_rec) = encrypt_ledger_epoch_segment(
        42,
        2,
        &ledger_plain,
        &dek,
        KeyEpoch(1),
        1024,
        &mut os_entropy,
    )?;
    assert!(!contains_subslice(&ledger_ct, b"FSSE-v2-epoch-segment"));
    let (ledger_dec, dec_rec) =
        decrypt_and_verify_ledger_epoch_segment(&ledger_ct, 42, 2, &catalog, &kek)?;
    assert_eq!(ledger_dec, ledger_plain);
    assert_eq!(dec_rec.plaintext_sha256, ledger_rec.plaintext_sha256);

    // Cross-epoch / cross-stream-kind decryption MUST fail with ERR-CRYPTO-AUTH-FAILED-001
    let wrong_epoch = decrypt_and_verify_ledger_epoch_segment(&ledger_ct, 43, 2, &catalog, &kek);
    assert_eq!(
        wrong_epoch.err().and_then(|e| e.stable_error_id()),
        Some(ERR_CRYPTO_AUTH_FAILED_001)
    );
    let wrong_kind = decrypt_and_verify_pack_bytes(
        &ledger_ct,
        PackId::new(2, 42),
        EncryptedStreamKind::SealedPackChunks,
        SCHEMA_EPOCH_PACKFILE,
        &catalog,
        &kek,
    );
    assert_eq!(
        wrong_kind.err().and_then(|e| e.stable_error_id()),
        Some(ERR_CRYPTO_AUTH_FAILED_001)
    );
    Ok(())
}

// =========================================================================
// Verification Test 3: Adversarial AEAD Tamper Matrix
// =========================================================================

#[test]
fn adversarial_aead_tamper_matrix_all_cases_fail_with_err_crypto_auth_failed_001() -> TestResult {
    let dir = TempDir::new("tamper-matrix")?;
    let mut entropy = LabEntropy::from_seed([0x22; 32]);
    let dek = DataEncryptionKey::generate(&mut entropy)?;
    let ctx = AeadRecordContext::new(PackId::new(1, 9), 48, SCHEMA_EPOCH_PACKFILE);
    let plaintext = b"authentic camera H.265 IDR frame payload 0123456789abcdef";

    let (_hdr, frame) = encrypt_aead_frame(ctx, &dek, KeyEpoch(1), plaintext, &mut entropy)?;
    // Sanity check clean decrypt
    let (_ok_hdr, ok_plain) = decrypt_aead_frame(ctx, &dek, &frame, Some(KeyEpoch(1)))?;
    assert_eq!(ok_plain, plaintext);

    fn assert_auth_failed<T: std::fmt::Debug>(
        label: &str,
        res: Result<T, PackError>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match res {
            Ok(_) => Err(format!("tamper case '{label}' unexpectedly succeeded").into()),
            Err(err) => {
                assert_eq!(
                    err.stable_error_id(),
                    Some(ERR_CRYPTO_AUTH_FAILED_001),
                    "tamper case '{label}' returned unexpected error: {err:?}"
                );
                Ok(())
            }
        }
    }

    // 1. Bit flip in ciphertext body
    let mut tampered = frame.clone();
    tampered[AEAD_FRAME_HEADER_LEN + 5] ^= 0x01;
    assert_auth_failed(
        "ciphertext bit flip",
        decrypt_aead_frame(ctx, &dek, &tampered, None),
    )?;

    // 2. Bit flip in Poly1305 tag (last 16 bytes)
    let mut tampered = frame.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert_auth_failed(
        "poly1305 tag bit flip",
        decrypt_aead_frame(ctx, &dek, &tampered, None),
    )?;

    // 3. Bit flip in 96-bit nonce (bytes 32..44)
    let mut tampered = frame.clone();
    tampered[35] ^= 0x04;
    assert_auth_failed(
        "nonce bit flip",
        decrypt_aead_frame(ctx, &dek, &tampered, None),
    )?;

    // 4. Bit flip in key_epoch header field (bytes 8..12)
    let mut tampered = frame.clone();
    tampered[11] ^= 0x02;
    assert_auth_failed(
        "key_epoch bit flip",
        decrypt_aead_frame(ctx, &dek, &tampered, None),
    )?;

    // 5. Bit flip in schema_epoch header field (bytes 12..16)
    let mut tampered = frame.clone();
    tampered[15] ^= 0x02;
    assert_auth_failed(
        "schema_epoch bit flip",
        decrypt_aead_frame(ctx, &dek, &tampered, None),
    )?;

    // 6. Bit flip in dek_id header field (bytes 16..32)
    let mut tampered = frame.clone();
    tampered[20] ^= 0x10;
    assert_auth_failed(
        "dek_id bit flip",
        decrypt_aead_frame(ctx, &dek, &tampered, None),
    )?;

    // 7. Bit flip in plaintext_sha256 header field (bytes 52..84)
    let mut tampered = frame.clone();
    tampered[60] ^= 0x01;
    assert_auth_failed(
        "plaintext_sha256 bit flip",
        decrypt_aead_frame(ctx, &dek, &tampered, None),
    )?;

    // 8. Bit flip in magic / version / cipher_id / reserved_flags / plaintext_len
    for (name, byte_idx) in [
        ("magic", 0_usize),
        ("version", 5),
        ("cipher_id", 6),
        ("reserved_flags", 7),
        ("plaintext_len", 51),
    ] {
        let mut tampered = frame.clone();
        tampered[byte_idx] ^= 0x01;
        assert_auth_failed(name, decrypt_aead_frame(ctx, &dek, &tampered, None))?;
    }

    // 9. Moving valid frame to another pack_id
    let wrong_pack_ctx = AeadRecordContext::new(PackId::new(1, 10), 48, SCHEMA_EPOCH_PACKFILE);
    assert_auth_failed(
        "moved to another pack_id",
        decrypt_aead_frame(wrong_pack_ctx, &dek, &frame, None),
    )?;

    // 10. Moving valid frame to another record_offset
    let wrong_offset_ctx = AeadRecordContext::new(PackId::new(1, 9), 512, SCHEMA_EPOCH_PACKFILE);
    assert_auth_failed(
        "moved to another record_offset",
        decrypt_aead_frame(wrong_offset_ctx, &dek, &frame, None),
    )?;

    // 11. Swapping two valid equal-length records between offsets in an on-disk .fsep file
    let kek = make_kek(1, "site-swap", 0x44)?;
    let mut catalog = KeyEnvelopeCatalog::open_or_create(
        dir.path.join("swap-catalog.fskc"),
        KeyEpoch(1),
        kek.scope(),
        DurabilityMode::Fsync,
    )?;
    let pack_id = PackId::new(1, 99);
    let (swap_dek, _env) =
        catalog.create_and_wrap_dek(&kek, &mut entropy, &[pack_id], TimestampNs(300))?;
    let swap_path = dir.path.join("swap.fsep");
    let mut writer = EncryptedPackWriter::create(
        &swap_path,
        pack_id,
        EncryptedStreamKind::PackRecords,
        SCHEMA_EPOCH_PACKFILE,
        swap_dek,
        KeyEpoch(1),
        DurabilityMode::Fsync,
    )?;
    let rec_a = writer.write_record(&[0xAA_u8; 128], &mut entropy)?;
    let rec_b = writer.write_record(&[0xBB_u8; 128], &mut entropy)?;
    let _ = writer.finish()?;
    assert_eq!(rec_a.frame_len, rec_b.frame_len);

    let mut raw = fs::read(&swap_path)?;
    let a0 = usize::try_from(rec_a.record_offset)?;
    let b0 = usize::try_from(rec_b.record_offset)?;
    let flen = usize::try_from(rec_a.frame_len)?;
    let slice_a = raw[a0..a0 + flen].to_vec();
    let slice_b = raw[b0..b0 + flen].to_vec();
    raw[a0..a0 + flen].copy_from_slice(&slice_b);
    raw[b0..b0 + flen].copy_from_slice(&slice_a);
    fs::write(&swap_path, &raw)?;

    let reader = EncryptedPackReader::open(&swap_path)?;
    assert_auth_failed(
        "swapped frame A positional read",
        reader.read_frame_with_catalog(rec_a.record_offset, &catalog, &kek),
    )?;
    assert_auth_failed(
        "swapped frame B positional read",
        reader.read_frame_with_catalog(rec_b.record_offset, &catalog, &kek),
    )?;
    assert_auth_failed(
        "swapped frames full stream decrypt",
        reader.decrypt_all_records(&catalog, &kek),
    )?;
    Ok(())
}

// =========================================================================
// Verification Test 4: Zero-Rewrite KEK Rotation + Vault Cx Enforcement
// =========================================================================

#[test]
fn zero_rewrite_kek_rotation_leaves_pack_untouched_and_revokes_old_kek() -> TestResult {
    let dir = TempDir::new("kek-rotation")?;
    let mut entropy = LabEntropy::from_seed([0x44; 32]);
    let now = TimestampNs(1_700_000_000_000_000_000);

    // Load KEKs through real fss-vault LocalEncryptedVault + explicit SecretAccessCx!
    let vault_dir = dir.path.join("vault");
    let passphrase = SecretBytes::from_slice(b"operator-site-master-passphrase")?;
    let mut vault = LocalEncryptedVault::open_with_entropy(
        &vault_dir,
        KdfParams::for_testing(1)?,
        LabEntropy::from_seed([0x45; 32]),
    );
    vault.initialize(&passphrase)?;
    let scope = kek_scope("site-home")?;
    let cx_rw = make_secret_cx(
        scope.clone(),
        vec![
            CAP_SECRET_WRITE_001.to_owned(),
            CAP_SECRET_READ_001.to_owned(),
        ],
        now,
        false,
    )?;
    let kek1_id = SecretId::new("storage", "site-kek-v1")?;
    let kek2_id = SecretId::new("storage", "site-kek-v2")?;
    vault.store(&cx_rw, &kek1_id, SecretBytes::from_slice(&[0x1A_u8; 32])?)?;
    vault.store(&cx_rw, &kek2_id, SecretBytes::from_slice(&[0x2B_u8; 32])?)?;

    // Cancelled SecretAccessCx and wrong AdapterFamily scope MUST be refused!
    let cancelled_cx = make_secret_cx(
        scope.clone(),
        vec![CAP_SECRET_READ_001.to_owned()],
        now,
        true,
    )?;
    assert!(matches!(
        KeyEncryptionKey::from_vault(&vault, &cancelled_cx, &kek1_id, KeyEpoch(1)),
        Err(PackError::Cancelled)
    ));
    let wrong_family_cx = make_secret_cx(
        SecretScope::new(AdapterFamily::Rtsp, "cam-01", "rtsp://127.0.0.1")?,
        vec![CAP_SECRET_READ_001.to_owned()],
        now,
        false,
    )?;
    assert!(matches!(
        KeyEncryptionKey::from_vault(&vault, &wrong_family_cx, &kek1_id, KeyEpoch(1)),
        Err(PackError::CryptoAuthority { .. })
    ));

    let kek_v1 = KeyEncryptionKey::from_vault(&vault, &cx_rw, &kek1_id, KeyEpoch(1))?;
    let kek_v2 = KeyEncryptionKey::from_vault(&vault, &cx_rw, &kek2_id, KeyEpoch(2))?;

    let catalog_path = dir.path.join("key-catalog.fskc");
    let mut catalog = KeyEnvelopeCatalog::open_or_create(
        &catalog_path,
        KeyEpoch(1),
        &scope,
        DurabilityMode::Fsync,
    )?;

    // Build real sealed pack P1 via PackStore and encrypt under KEK v1
    let store = PackStore::open(
        dir.path.join("store"),
        PackConfig {
            target_pack_bytes: 2048,
            durability: DurabilityMode::Fsync,
            ..PackConfig::default()
        },
    )?;
    let p1_obj_a = b"pack-1-camera-clip-A-bytes".repeat(40);
    let p1_obj_b = b"pack-1-camera-clip-B-bytes".repeat(40);
    let p1_digest_a = ContentDigest::sha256(&p1_obj_a);
    let p1_digest_b = ContentDigest::sha256(&p1_obj_b);
    let _ = store.append_batch(&[
        PackObjectInput::new(PACK_KIND_MEDIA_CHUNK, 0, &p1_obj_a),
        PackObjectInput::new(PACK_KIND_MEDIA_CHUNK, 0, &p1_obj_b),
    ])?;
    let sealed_p1 = store.seal_active_pack()?.ok_or("expected sealed pack P1")?;

    let (dek_p1, _env1) =
        catalog.create_and_wrap_dek(&kek_v1, &mut entropy, &[sealed_p1.pack_id], now)?;
    let p1_src = store.packs_dir().join(sealed_p1.pack_id.file_name());
    let p1_enc = dir.path.join("p1.fsep");
    let p1_enc_rec = encrypt_pack_file(
        &p1_src,
        &p1_enc,
        sealed_p1.pack_id,
        SCHEMA_EPOCH_PACKFILE,
        dek_p1,
        KeyEpoch(1),
        1024,
        &mut entropy,
        DurabilityMode::Fsync,
    )?;
    let p1_bytes_before = fs::read(&p1_enc)?;
    let p1_hash_before = ContentDigest::sha256(&p1_bytes_before);
    let p1_mtime_before = fs::metadata(&p1_enc)?.modified()?;

    // Rotate KEK v1 -> KEK v2 with ZERO rewrite of P1!
    let rot_receipt = catalog.rotate_kek(
        &kek_v1,
        &kek_v2,
        KeyEpoch(2),
        &mut entropy,
        TimestampNs(now.0 + 1_000),
    )?;
    assert_eq!(rot_receipt.old_epoch, KeyEpoch(1));
    assert_eq!(rot_receipt.new_epoch, KeyEpoch(2));
    assert_eq!(rot_receipt.rewrapped_dek_count, 1);

    // Assert P1 on disk is 100% UNTOUCHED (identical bytes, hash, and mtime)
    let p1_bytes_after = fs::read(&p1_enc)?;
    assert_eq!(p1_bytes_after, p1_bytes_before);
    assert_eq!(ContentDigest::sha256(&p1_bytes_after), p1_hash_before);
    assert_eq!(fs::metadata(&p1_enc)?.modified()?, p1_mtime_before);

    // Write sealed pack P2 under KEK v2
    let p2_obj = b"pack-2-post-rotation-evidence-frame".repeat(50);
    let _ = store.append_batch(&[PackObjectInput::new(PACK_KIND_MEDIA_CHUNK, 0, &p2_obj)])?;
    let sealed_p2 = store.seal_active_pack()?.ok_or("expected sealed pack P2")?;
    let (dek_p2, _env2) = catalog.create_and_wrap_dek(
        &kek_v2,
        &mut entropy,
        &[sealed_p2.pack_id],
        TimestampNs(now.0 + 2_000),
    )?;
    let p2_src = store.packs_dir().join(sealed_p2.pack_id.file_name());
    let p2_enc = dir.path.join("p2.fsep");
    let p2_enc_rec = encrypt_pack_file(
        &p2_src,
        &p2_enc,
        sealed_p2.pack_id,
        SCHEMA_EPOCH_PACKFILE,
        dek_p2,
        KeyEpoch(2),
        1024,
        &mut entropy,
        DurabilityMode::Fsync,
    )?;

    // Reload catalog from disk to verify durable atomic persistence across restart
    let reloaded = KeyEnvelopeCatalog::open_existing(&catalog_path, DurabilityMode::Fsync)?;
    assert_eq!(reloaded.active_kek_epoch(), KeyEpoch(2));
    assert!(reloaded.is_epoch_revoked(KeyEpoch(1)));

    // Both P1 (created under v1) and P2 (created under v2) decrypt cleanly under KEK v2!
    let p1_restored = dir.path.join("p1-restored.fssp");
    let p2_restored = dir.path.join("p2-restored.fssp");
    let dec1 = decrypt_and_verify_pack_file(
        &p1_enc,
        &p1_restored,
        sealed_p1.pack_id,
        SCHEMA_EPOCH_PACKFILE,
        &reloaded,
        &kek_v2,
        DurabilityMode::Fsync,
    )?;
    let dec2 = decrypt_and_verify_pack_file(
        &p2_enc,
        &p2_restored,
        sealed_p2.pack_id,
        SCHEMA_EPOCH_PACKFILE,
        &reloaded,
        &kek_v2,
        DurabilityMode::Fsync,
    )?;
    assert_eq!(dec1.plaintext_sha256, p1_enc_rec.plaintext_sha256);
    assert_eq!(dec2.plaintext_sha256, p2_enc_rec.plaintext_sha256);
    assert_eq!(fs::read(&p1_restored)?, fs::read(&p1_src)?);
    assert_eq!(fs::read(&p2_restored)?, fs::read(&p2_src)?);
    assert_eq!(store.read_verified(&p1_digest_a)?, p1_obj_a);
    assert_eq!(store.read_verified(&p1_digest_b)?, p1_obj_b);

    // Old revoked KEK v1 MUST be rejected for both P1 and P2!
    let old_p1 = decrypt_and_verify_pack_file(
        &p1_enc,
        dir.path.join("nope1.fssp"),
        sealed_p1.pack_id,
        SCHEMA_EPOCH_PACKFILE,
        &reloaded,
        &kek_v1,
        DurabilityMode::Fsync,
    );
    assert_eq!(
        old_p1.err().and_then(|e| e.stable_error_id()),
        Some(ERR_CRYPTO_AUTH_FAILED_001)
    );
    let old_p2 = reloaded.unwrap_dek(p2_enc_rec.dek_id, &kek_v1);
    assert_eq!(
        old_p2.err().and_then(|e| e.stable_error_id()),
        Some(ERR_CRYPTO_AUTH_FAILED_001)
    );
    Ok(())
}

// =========================================================================
// Verification Test 5: Cryptographic Erasure (--crypto-erase)
// =========================================================================

#[test]
fn cryptographic_erasure_destroys_dek_and_isolates_unrelated_packs() -> TestResult {
    let dir = TempDir::new("crypto-erase")?;
    let mut entropy = LabEntropy::from_seed([0x66; 32]);
    let kek = make_kek(1, "site-erase", 0x77)?;
    let catalog_path = dir.path.join("key-catalog.fskc");
    let mut catalog = KeyEnvelopeCatalog::open_or_create(
        &catalog_path,
        KeyEpoch(1),
        kek.scope(),
        DurabilityMode::Fsync,
    )?;

    let p1_id = PackId::new(1, 101);
    let p2_id = PackId::new(1, 102);
    let p3_id = PackId::new(1, 103);
    let (dek1, env1) =
        catalog.create_and_wrap_dek(&kek, &mut entropy, &[p1_id], TimestampNs(500))?;
    let (dek2, _env2) =
        catalog.create_and_wrap_dek(&kek, &mut entropy, &[p2_id], TimestampNs(501))?;
    let (dek3, _env3) =
        catalog.create_and_wrap_dek(&kek, &mut entropy, &[p3_id], TimestampNs(502))?;

    let wrapped_dek1_bytes = env1.wrapped_dek_ciphertext.clone();
    assert!(contains_subslice(
        &fs::read(&catalog_path)?,
        &wrapped_dek1_bytes
    ));

    let p1_path = dir.path.join("p1.fsep");
    let p2_path = dir.path.join("p2.fsep");
    let mut w1 = EncryptedPackWriter::create(
        &p1_path,
        p1_id,
        EncryptedStreamKind::PackRecords,
        SCHEMA_EPOCH_PACKFILE,
        dek1,
        KeyEpoch(1),
        DurabilityMode::Fsync,
    )?;
    let r1 = w1.write_record(b"sensitive-pack-1-footage", &mut entropy)?;
    let _ = w1.finish()?;

    let mut w2 = EncryptedPackWriter::create(
        &p2_path,
        p2_id,
        EncryptedStreamKind::PackRecords,
        SCHEMA_EPOCH_PACKFILE,
        dek2,
        KeyEpoch(1),
        DurabilityMode::Fsync,
    )?;
    let r2 = w2.write_record(b"retained-pack-2-footage", &mut entropy)?;
    let _ = w2.finish()?;

    // Execute signed --crypto-erase on DEK 1
    let receipt = catalog.crypto_erase_dek_signed(
        env1.dek_id,
        &kek,
        "owner-right-to-erasure-ticket-77",
        "operator:jeff",
        TimestampNs(999_000),
    )?;
    assert!(receipt.cryptographic_erasure);
    assert_eq!(receipt.dek_id, env1.dek_id);
    assert_eq!(receipt.affected_pack_ids, vec![p1_id]);
    assert_eq!(receipt.erased_at_ns, TimestampNs(999_000));
    receipt.verify_digest()?;
    receipt.verify_kek_signature(&kek)?;

    // Also test unsigned 4-argument crypto_erase_dek on DEK 3
    let receipt3 = catalog.crypto_erase_dek(
        dek3.dek_id(),
        "policy-retention-crypto-erase",
        "policy:ring",
        TimestampNs(999_500),
    )?;
    assert!(receipt3.cryptographic_erasure);
    assert!(!receipt3.signed_with_kek);
    receipt3.verify_digest()?;

    // Verify DEK 1 wrapped ciphertext bytes are 100% GONE from the on-disk catalog file!
    let catalog_disk_after = fs::read(&catalog_path)?;
    assert!(
        !contains_subslice(&catalog_disk_after, &wrapped_dek1_bytes),
        "erased DEK wrapped ciphertext must not remain in key-catalog.fskc"
    );

    // Reload from disk and verify P1 fails with ERR-CRYPTO-KEY-ERASED-001 while P2 remains 100% readable!
    let reloaded = KeyEnvelopeCatalog::open_existing(&catalog_path, DurabilityMode::Fsync)?;
    assert_eq!(reloaded.active_dek_count(), 1);
    assert_eq!(reloaded.erased_dek_count(), 2);

    let reader1 = EncryptedPackReader::open(&p1_path)?;
    let err_pos = reader1.read_frame_with_catalog(r1.record_offset, &reloaded, &kek);
    assert_eq!(
        err_pos.err().and_then(|e| e.stable_error_id()),
        Some(ERR_CRYPTO_KEY_ERASED_001)
    );
    let err_all = reader1.decrypt_all_records(&reloaded, &kek);
    assert_eq!(
        err_all.err().and_then(|e| e.stable_error_id()),
        Some(ERR_CRYPTO_KEY_ERASED_001)
    );

    let reader2 = EncryptedPackReader::open(&p2_path)?;
    let (_h2, dec2) = reader2.read_frame_with_catalog(r2.record_offset, &reloaded, &kek)?;
    assert_eq!(dec2, b"retained-pack-2-footage");
    Ok(())
}

// =========================================================================
// Verification Test 6: Cold-Tier Loopback S3 E2E (Single PUT, Multipart,
// Root-Last Manifest, Evict, Retrievability Audit Clean/Tampered/Missing, Restore)
// =========================================================================

#[test]
fn cold_tier_loopback_s3_e2e_archive_audit_tamper_evict_and_restore() -> TestResult {
    let dir = TempDir::new("cold-s3-e2e")?;
    let server = LoopbackS3Server::start()?;
    let mut entropy = LabEntropy::from_seed([0x88; 32]);
    let now = TimestampNs(1_730_000_000_000_000_000);

    let kek = make_kek(1, "site-cold", 0x99)?;
    let mut catalog = KeyEnvelopeCatalog::open_or_create(
        dir.path.join("key-catalog.fskc"),
        KeyEpoch(1),
        kek.scope(),
        DurabilityMode::Fsync,
    )?;

    let bucket = "fss-cold-archive-bucket";
    let endpoint = ColdS3Endpoint::new_local_approved(
        ColdProviderKind::CloudflareR2,
        server.addr,
        &format!("127.0.0.1:{}", server.addr.port()),
        "auto",
        bucket,
        ContentDigest::sha256(b"operator-approved-local-r2-emulator"),
    )?;
    let creds = ColdS3Credentials::new(
        "AKIAFSSCOLDTEST0001",
        SecretBytes::from_slice(b"SuperSecretColdS3Key-NeverLogMe-99887766")?,
        None,
        s3_scope(bucket)?,
    )?;
    let mut transport = S3CompatiblePackTransport::new(endpoint, creds, ColdS3Limits::default())?;

    // Create a PackStore with two sealed packs: P1 (small -> SinglePut) and P2 (larger -> Multipart)
    let store_dir = dir.path.join("hot-store");
    let store_cfg = PackConfig {
        target_pack_bytes: 64 * 1024,
        durability: DurabilityMode::Fsync,
        ..PackConfig::default()
    };
    let store = PackStore::open(&store_dir, store_cfg)?;

    let p1_objects: Vec<(ContentDigest, Vec<u8>)> = (0_u8..4)
        .map(|i| {
            let mut v = format!("CAMERA-YARD-MARKER-P1-OBJ-{i}-").into_bytes();
            v.extend_from_slice(&vec![i.wrapping_mul(19).wrapping_add(3); 1024]);
            (ContentDigest::sha256(&v), v)
        })
        .collect();
    let p1_inputs: Vec<PackObjectInput<'_>> = p1_objects
        .iter()
        .map(|(d, b)| PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, b, *d))
        .collect();
    let _ = store.append_batch(&p1_inputs)?;
    let sealed_p1 = store.seal_active_pack()?.ok_or("expected sealed pack P1")?;

    let p2_objects: Vec<(ContentDigest, Vec<u8>)> = (0_u8..6)
        .map(|i| {
            let mut v = format!("CAMERA-GARAGE-MARKER-P2-OBJ-{i}-").into_bytes();
            v.extend_from_slice(&vec![i.wrapping_mul(29).wrapping_add(7); 4096]);
            (ContentDigest::sha256(&v), v)
        })
        .collect();
    let p2_inputs: Vec<PackObjectInput<'_>> = p2_objects
        .iter()
        .map(|(d, b)| PackObjectInput::with_digest(PACK_KIND_OBJECT_MANIFEST, 1, b, *d))
        .collect();
    let _ = store.append_batch(&p2_inputs)?;
    let sealed_p2 = store.seal_active_pack()?.ok_or("expected sealed pack P2")?;

    // Enforce whole-pack archival sizing: production 64 MiB minimum rejects small test pack!
    let prod_policy = ColdArchivePolicy::production_default(ColdStorageTier::CloudflareR2);
    assert!(matches!(
        archive_sealed_pack(
            store.packs_dir(),
            sealed_p1.pack_id,
            &prod_policy,
            &mut catalog,
            &kek,
            &mut transport,
            &mut entropy,
            None,
            DurabilityMode::Fsync,
            now,
        ),
        Err(PackError::InvalidConfig { .. })
    ));

    // Configure test policy: min 2 KiB, multipart threshold 16 KiB, part size 8 KiB
    let policy = ColdArchivePolicy::for_testing(
        2 * 1024,
        16 * 1024,
        8 * 1024,
        ColdStorageTier::CloudflareR2,
    )?;
    let local_manifests_dir = dir.path.join("cold-manifests");

    // Archive P1 (SinglePut) and P2 (Multipart)
    let arch_p1 = archive_sealed_pack(
        store.packs_dir(),
        sealed_p1.pack_id,
        &policy,
        &mut catalog,
        &kek,
        &mut transport,
        &mut entropy,
        Some(&local_manifests_dir),
        DurabilityMode::Fsync,
        now,
    )?;
    assert_eq!(arch_p1.upload_mode, ColdUploadMode::SinglePut);
    assert_eq!(arch_p1.manifest.part_count, 1);

    let arch_p2 = archive_sealed_pack(
        store.packs_dir(),
        sealed_p2.pack_id,
        &policy,
        &mut catalog,
        &kek,
        &mut transport,
        &mut entropy,
        Some(&local_manifests_dir),
        DurabilityMode::Fsync,
        TimestampNs(now.0 + 1_000),
    )?;
    match arch_p2.upload_mode {
        ColdUploadMode::Multipart { part_count } => assert!(part_count >= 3),
        ColdUploadMode::SinglePut => {
            return Err("expected Multipart upload for P2".into());
        }
    }

    // Verify SigV4 + root-last ordering on loopback S3 request log!
    let reqs = server.requests();
    assert!(!reqs.is_empty());
    for req in &reqs {
        assert!(req.has_sigv4, "request missing SigV4: {req:?}");
        assert!(
            req.body_sha256_verified,
            "request body SHA-256 mismatch: {req:?}"
        );
    }
    let p1_pack_put_idx = reqs
        .iter()
        .position(|r| r.method == "PUT" && r.path.ends_with(&arch_p1.manifest.object_key))
        .ok_or("missing P1 pack PUT")?;
    let p1_manifest_put_idx = reqs
        .iter()
        .position(|r| r.method == "PUT" && r.path.ends_with(&arch_p1.manifest_object_key))
        .ok_or("missing P1 manifest PUT")?;
    assert!(
        p1_pack_put_idx < p1_manifest_put_idx,
        "root-last violated for P1: pack PUT ({p1_pack_put_idx}) must precede manifest PUT ({p1_manifest_put_idx})"
    );

    let p2_complete_idx = reqs
        .iter()
        .position(|r| {
            r.method == "POST"
                && r.path.ends_with(&arch_p2.manifest.object_key)
                && r.query.starts_with("uploadId=")
        })
        .ok_or("missing P2 CompleteMultipartUpload")?;
    let p2_manifest_put_idx = reqs
        .iter()
        .position(|r| r.method == "PUT" && r.path.ends_with(&arch_p2.manifest_object_key))
        .ok_or("missing P2 manifest PUT")?;
    assert!(
        p2_complete_idx < p2_manifest_put_idx,
        "root-last violated for P2: CompleteMultipartUpload must precede manifest PUT"
    );

    // Verify remote stored ciphertext has ZERO plaintext markers
    let remote_p1 = server
        .stored_bytes(bucket, &arch_p1.manifest.object_key)
        .ok_or("missing remote P1 object")?;
    assert!(!contains_subslice(&remote_p1, b"CAMERA-YARD-MARKER"));
    let remote_manifest_raw = server
        .stored_bytes(bucket, &arch_p1.manifest_object_key)
        .ok_or("missing remote P1 manifest")?;
    let parsed_remote_manifest =
        ColdPackArchiveManifest::from_canonical_bytes(&remote_manifest_raw)?;
    assert_eq!(parsed_remote_manifest, arch_p1.manifest);

    // Retry a complete archive of the same sealed pack with a fresh DEK. Both receipts
    // must still independently recover their pinned remote roots after the second PUT.
    let republished = archive_sealed_pack(
        store.packs_dir(),
        sealed_p1.pack_id,
        &policy,
        &mut catalog,
        &kek,
        &mut transport,
        &mut entropy,
        None,
        DurabilityMode::Fsync,
        now,
    )?;
    assert_eq!(
        republished.manifest.plaintext_pack_sha256,
        arch_p1.manifest.plaintext_pack_sha256
    );
    assert_ne!(republished.manifest_object_key, arch_p1.manifest_object_key);
    for publication in [&arch_p1, &republished] {
        assert_eq!(
            fetch_cold_pack_manifest(
                &mut transport,
                &publication.manifest_object_key,
                publication.manifest.manifest_digest,
                now,
            )?,
            publication.manifest
        );
    }

    // Partial-only audit MUST NEVER upgrade to Verified!
    let partial_cfg = ColdAuditConfig {
        verify_whole_pack: false,
        sample_range_bytes: 256,
        ..ColdAuditConfig::default()
    };
    let partial_audit = audit_cold_pack_retrievability(
        &mut transport,
        &arch_p1.manifest,
        &partial_cfg,
        TimestampNs(now.0 + 2_000),
    )?;
    assert_eq!(partial_audit.verdict, ColdRetrievabilityVerdict::Unknown);
    assert!(!partial_audit.whole_pack_sha256_verified);
    assert_eq!(partial_audit.range_samples_verified, 3);
    partial_audit.verify_digest()?;

    // Eviction requiring Verified audit MUST refuse a partial Unknown audit!
    assert!(matches!(
        evict_local_sealed_pack(
            store.packs_dir(),
            &arch_p1.manifest,
            Some(&partial_audit),
            true,
            DurabilityMode::Fsync,
        ),
        Err(PackError::ArchiveIntegrity { .. })
    ));

    // Full Range-GET + whole-pack SHA-256 retrievability audit -> Verified!
    let full_audit_cfg = ColdAuditConfig {
        verify_whole_pack: true,
        sample_range_bytes: 512,
        ..ColdAuditConfig::default()
    };
    // Return exactly the expected bytes and ETag with the wrong range identity.
    server
        .state
        .lock()
        .map_err(|_| "mock state poisoned")?
        .mislabel_ranges = true;
    let wrong_range =
        audit_cold_pack_retrievability(&mut transport, &arch_p1.manifest, &full_audit_cfg, now)?;
    assert_eq!(wrong_range.verdict, ColdRetrievabilityVerdict::Corrupted);
    assert_eq!(wrong_range.range_samples_verified, 0);
    assert_eq!(wrong_range.bytes_verified, 0);
    assert!(!wrong_range.whole_pack_sha256_verified);
    assert!(wrong_range.requires_repair_obligation);
    wrong_range.verify_digest()?;
    server
        .state
        .lock()
        .map_err(|_| "mock state poisoned")?
        .mislabel_ranges = false;

    let audit_p1 = audit_cold_pack_retrievability(
        &mut transport,
        &arch_p1.manifest,
        &full_audit_cfg,
        TimestampNs(now.0 + 3_000),
    )?;
    assert_eq!(audit_p1.verdict, ColdRetrievabilityVerdict::Verified);
    assert!(audit_p1.whole_pack_sha256_verified);
    assert!(!audit_p1.requires_repair_obligation);
    assert_eq!(audit_p1.range_samples_verified, 3);
    audit_p1.verify_digest()?;

    let audit_p2 = audit_cold_pack_retrievability(
        &mut transport,
        &arch_p2.manifest,
        &full_audit_cfg,
        TimestampNs(now.0 + 4_000),
    )?;
    assert_eq!(audit_p2.verdict, ColdRetrievabilityVerdict::Verified);
    assert!(audit_p2.whole_pack_sha256_verified);

    // Evict BOTH local hot sealed packs after Verified audits, reopen PackStore, prove evicted!
    let packs_dir = store.packs_dir().to_path_buf();
    drop(store);
    let ev1 = evict_local_sealed_pack(
        &packs_dir,
        &arch_p1.manifest,
        Some(&audit_p1),
        true,
        DurabilityMode::Fsync,
    )?;
    let ev2 = evict_local_sealed_pack(
        &packs_dir,
        &arch_p2.manifest,
        Some(&audit_p2),
        true,
        DurabilityMode::Fsync,
    )?;
    assert!(ev1.evicted_bytes > 0 && ev2.evicted_bytes > 0);

    let reopened = PackStore::open(&store_dir, store_cfg)?;
    assert!(matches!(
        reopened.read_verified(&p1_objects[0].0),
        Err(PackError::MissingObject(_))
    ));
    assert!(matches!(
        reopened.read_verified(&p2_objects[0].0),
        Err(PackError::MissingObject(_))
    ));

    // Lose all local archive manifests and recover both roots from independent retained pins.
    fs::remove_dir_all(&local_manifests_dir)?;
    let recovered_p1 = fetch_cold_pack_manifest(
        &mut transport,
        &arch_p1.manifest_object_key,
        arch_p1.manifest.manifest_digest,
        now,
    )?;
    let recovered_p2 = fetch_cold_pack_manifest(
        &mut transport,
        &arch_p2.manifest_object_key,
        arch_p2.manifest.manifest_digest,
        now,
    )?;
    assert_eq!(recovered_p1, arch_p1.manifest);
    assert_eq!(recovered_p2, arch_p2.manifest);

    let manifest_requests = server.requests().len();
    for invalid_pin in [
        ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0; 32]),
        ContentDigest::new(fss_core::DigestAlgorithm::Blake3, [1; 32]),
    ] {
        assert!(
            fetch_cold_pack_manifest(
                &mut transport,
                &arch_p1.manifest_object_key,
                invalid_pin,
                now
            )
            .is_err()
        );
    }
    assert!(
        fetch_cold_pack_manifest(&mut transport, "", arch_p1.manifest.manifest_digest, now)
            .is_err()
    );
    assert_eq!(server.requests().len(), manifest_requests);
    assert!(matches!(
        fetch_cold_pack_manifest(
            &mut transport,
            &arch_p1.manifest_object_key,
            arch_p2.manifest.manifest_digest,
            now,
        ),
        Err(PackError::DigestMismatch { .. })
    ));

    let original_manifest = arch_p1.manifest.to_canonical_bytes()?;
    let mut corrupt_manifest = original_manifest.clone();
    corrupt_manifest[0] ^= 1;
    let mut suffixed_manifest = original_manifest.clone();
    suffixed_manifest.push(0);
    for bytes in [
        corrupt_manifest,
        suffixed_manifest,
        arch_p2.manifest.to_canonical_bytes()?,
        vec![0; fss_pack::MAX_COLD_MANIFEST_DOWNLOAD_BYTES + 1],
    ] {
        server
            .state
            .lock()
            .map_err(|_| "S3 state poisoned")?
            .objects
            .insert(
                format!("/{bucket}/{}", arch_p1.manifest_object_key),
                (bytes, "\"untrusted-manifest-etag\"".to_owned()),
            );
        let before = server.requests().len();
        assert!(
            fetch_cold_pack_manifest(
                &mut transport,
                &arch_p1.manifest_object_key,
                arch_p1.manifest.manifest_digest,
                now,
            )
            .is_err()
        );
        let requests = server.requests();
        assert_eq!(requests.len(), before + 1);
        assert!(
            requests[before]
                .path
                .ends_with(&arch_p1.manifest_object_key)
        );
    }
    server
        .state
        .lock()
        .map_err(|_| "S3 state poisoned")?
        .objects
        .insert(
            format!("/{bucket}/{}", arch_p1.manifest_object_key),
            (original_manifest, "\"recovered-manifest-etag\"".to_owned()),
        );
    assert_eq!(
        fetch_cold_pack_manifest(
            &mut transport,
            &arch_p1.manifest_object_key,
            arch_p1.manifest.manifest_digest,
            now,
        )?,
        recovered_p1
    );

    let before = server.requests().len();
    assert!(matches!(
        restore_cold_pack(
            &mut transport,
            &recovered_p1,
            &catalog,
            &kek,
            &reopened,
            recovered_p1.ciphertext_bytes as usize - 1,
            now,
        ),
        Err(PackError::ObjectTooLarge { .. })
    ));
    assert_eq!(server.requests().len(), before);

    // Restore BOTH cold packs from loopback S3 -> verify EVERY inner object's SHA-256 + bytes!
    let rest_p1 = restore_cold_pack(
        &mut transport,
        &recovered_p1,
        &catalog,
        &kek,
        &reopened,
        64 * 1024 * 1024,
        TimestampNs(now.0 + 5_000),
    )?;
    assert_eq!(rest_p1.restored_object_count, p1_objects.len());
    let rest_p2 = restore_cold_pack(
        &mut transport,
        &recovered_p2,
        &catalog,
        &kek,
        &reopened,
        64 * 1024 * 1024,
        TimestampNs(now.0 + 6_000),
    )?;
    assert_eq!(rest_p2.restored_object_count, p2_objects.len());

    for (digest, expected_bytes) in p1_objects.iter().chain(p2_objects.iter()) {
        assert_eq!(reopened.read_verified(digest)?, *expected_bytes);
    }

    // HTTP 302 redirect MUST fail closed -> audit emits Unknown (never follows redirect)
    server.set_force_redirect(bucket, Some(&arch_p1.manifest.object_key));
    let redirect_audit = audit_cold_pack_retrievability(
        &mut transport,
        &arch_p1.manifest,
        &full_audit_cfg,
        TimestampNs(now.0 + 6_500),
    )?;
    assert_eq!(redirect_audit.verdict, ColdRetrievabilityVerdict::Unknown);
    server.set_force_redirect(bucket, None);

    // Flip 1 bit in remote P1 -> audit MUST emit Corrupted & require repair obligation!
    assert!(server.flip_byte_in_object(bucket, &arch_p1.manifest.object_key, 200));
    let tampered_audit = audit_cold_pack_retrievability(
        &mut transport,
        &arch_p1.manifest,
        &full_audit_cfg,
        TimestampNs(now.0 + 7_000),
    )?;
    assert_eq!(tampered_audit.verdict, ColdRetrievabilityVerdict::Corrupted);
    assert!(!tampered_audit.whole_pack_sha256_verified);
    assert!(tampered_audit.requires_repair_obligation);
    tampered_audit.verify_digest()?;
    assert!(matches!(
        restore_cold_pack(
            &mut transport,
            &arch_p1.manifest,
            &catalog,
            &kek,
            &reopened,
            64 * 1024 * 1024,
            TimestampNs(now.0 + 7_500),
        ),
        Err(PackError::ArchiveIntegrity { .. })
    ));

    // Delete remote P2 -> audit MUST emit Missing & require repair obligation!
    assert!(server.delete_object(bucket, &arch_p2.manifest.object_key));
    let missing_audit = audit_cold_pack_retrievability(
        &mut transport,
        &arch_p2.manifest,
        &full_audit_cfg,
        TimestampNs(now.0 + 8_000),
    )?;
    assert_eq!(missing_audit.verdict, ColdRetrievabilityVerdict::Missing);
    assert!(missing_audit.requires_repair_obligation);
    missing_audit.verify_digest()?;
    Ok(())
}

// =========================================================================
// Verification Test 7: CanaryLeakScanner Across Logs, Errors, Receipts, Disk
// =========================================================================

#[test]
fn canary_leak_scanner_proves_zero_kek_dek_or_s3_secret_leaks() -> TestResult {
    let dir = TempDir::new("canary-scan")?;
    let mut entropy = LabEntropy::from_seed([0xAB; 32]);
    let now = TimestampNs(1_730_500_000_000_000_000);

    let kek_v1_secret = SecretBytes::from_slice(b"CANARY-KEK-V1-DO-NOT-EXFIL-00001")?;
    let kek_v2_secret = SecretBytes::from_slice(b"CANARY-KEK-V2-DO-NOT-EXFIL-00002")?;
    let dek_secret = SecretBytes::from_slice(b"CANARY-DEK-01-DO-NOT-EXFIL-00003")?;
    let s3_secret = SecretBytes::from_slice(b"CANARY-S3-SECRET-KEY-98765432100")?;

    let mut scanner = CanaryLeakScanner::new();
    scanner.register_secret("kek_v1", &kek_v1_secret)?;
    scanner.register_secret("kek_v2", &kek_v2_secret)?;
    scanner.register_secret("dek_01", &dek_secret)?;
    scanner.register_secret("s3_secret", &s3_secret)?;

    let scope = kek_scope("site-canary")?;
    let kek_v1 = KeyEncryptionKey::from_secret_bytes(KeyEpoch(1), scope.clone(), kek_v1_secret)?;
    let kek_v2 = KeyEncryptionKey::from_secret_bytes(KeyEpoch(2), scope.clone(), kek_v2_secret)?;
    let dek_id = DekId::new([0x42; 16])?;
    let dek = DataEncryptionKey::from_secret_bytes(dek_id, dek_secret)?;

    let catalog_path = dir.path.join("canary-catalog.fskc");
    let mut catalog = KeyEnvelopeCatalog::open_or_create(
        &catalog_path,
        KeyEpoch(1),
        &scope,
        DurabilityMode::Fsync,
    )?;
    let pack_id = PackId::new(1, 55);
    let env = catalog.register_and_wrap_dek(&dek, &kek_v1, &mut entropy, &[pack_id], now)?;

    let enc_path = dir.path.join("canary-pack.fsep");
    let mut writer = EncryptedPackWriter::create(
        &enc_path,
        pack_id,
        EncryptedStreamKind::PackRecords,
        SCHEMA_EPOCH_PACKFILE,
        dek.clone(),
        KeyEpoch(1),
        DurabilityMode::Fsync,
    )?;
    let _ = writer.write_record(b"camera-frame-bytes-for-canary-audit", &mut entropy)?;
    let enc_receipt = writer.finish()?;

    let _rot = catalog.rotate_kek(
        &kek_v1,
        &kek_v2,
        KeyEpoch(2),
        &mut entropy,
        TimestampNs(now.0 + 10),
    )?;
    let old_err = catalog
        .unwrap_dek(dek_id, &kek_v1)
        .err()
        .map(|e| format!("{e} | {e:?}"))
        .unwrap_or_default();
    let erase_receipt = catalog.crypto_erase_dek_signed(
        dek_id,
        &kek_v2,
        "canary-audit-erasure",
        "operator:auditor",
        TimestampNs(now.0 + 20),
    )?;
    let erased_err = catalog
        .unwrap_dek(dek_id, &kek_v2)
        .err()
        .map(|e| format!("{e} | {e:?}"))
        .unwrap_or_default();

    let s3_creds = ColdS3Credentials::new(
        "AKIACANARY0001",
        s3_secret,
        None,
        s3_scope("canary-bucket")?,
    )?;
    let endpoint = ColdS3Endpoint::new_local_approved(
        ColdProviderKind::BackblazeB2,
        SocketAddr::from(([127, 0, 0, 1], 9000)),
        "127.0.0.1:9000",
        "us-west-004",
        "canary-bucket",
        ContentDigest::sha256(b"canary-approval"),
    )?;
    let transport = S3CompatiblePackTransport::new(endpoint, s3_creds, ColdS3Limits::default())?;

    let manifest = ColdPackArchiveManifest::build(
        pack_id,
        KeyEpoch(1),
        dek_id,
        env.envelope_digest(),
        enc_receipt.plaintext_sha256,
        enc_receipt.plaintext_bytes,
        enc_receipt.ciphertext_sha256,
        enc_receipt.ciphertext_bytes,
        "fss-cold/v1/packs/pack-00000001-000000000055-deadbeef.fsep".to_owned(),
        "\"etag-canary\"".to_owned(),
        ColdStorageTier::BackblazeB2,
        1,
        now,
    )?;

    let combined_text_surface = format!(
        "kek1={kek_v1} | {kek_v1:?}\nkek2={kek_v2} | {kek_v2:?}\ndek={dek} | {dek:?}\ntransport={transport:?}\nold_err={old_err}\nerased_err={erased_err}\nerase_json={}\nmanifest_json={}\n",
        erase_receipt.to_canonical_json(),
        manifest.to_canonical_json(),
    );

    scanner.assert_clean(
        "logs_errors_debug_receipts",
        combined_text_surface.as_bytes(),
    )?;
    scanner.assert_clean("key-catalog.fskc", &fs::read(&catalog_path)?)?;
    scanner.assert_clean("canary-pack.fsep", &fs::read(&enc_path)?)?;
    scanner.assert_clean("manifest.fssc", &manifest.to_canonical_bytes()?)?;

    // Verify negative control: OpenOptions append of canary WOULD be caught by scanner
    let leaked_probe = dir.path.join("probe.log");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&leaked_probe)?;
        f.write_all(b"safe-prefix CANARY-S3-SECRET-KEY-98765432100")?;
    }
    assert!(
        scanner
            .assert_clean("probe", &fs::read(&leaked_probe)?)
            .is_err()
    );

    // Emit structured JSONL telemetry line for verification logs (zero secrets!)
    let telemetry_jsonl = format!(
        "{{\"suite\":\"crypto_archive_contract\",\"canaries_checked\":{},\"erase_receipt\":{},\"manifest\":{}}}",
        scanner.canary_count(),
        erase_receipt.to_canonical_json(),
        manifest.to_canonical_json()
    );
    scanner.assert_clean("telemetry_jsonl", telemetry_jsonl.as_bytes())?;
    Ok(())
}
