#![forbid(unsafe_code)]
//! Actual signed loopback GETs under the fresh bounded retrieval owner. Source
//! uploads use a deterministic fixture provider and a real immutable file journal.

use super::*;
use std::sync::Arc;

use fss_object::HostSpoolIo;
use fss_object::multipart::{
    ETag, MultipartRecovery, MultipartTransport, PartReceipt, Reconciliation, UploadId,
    UploadIntent, UploadJournal,
};
use fss_object::planner::PlannedChunk;
use fss_object::upload_journal::FileUploadJournal;
use fss_object::uploader::{
    MAX_RETRIEVAL_RANGE_BYTES, RetrievalObservation, RetrievalOutcome, RetrievalReceipt,
    VerifiedRetrievalBytes,
};

fn budget() -> BudgetVector {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 128 * 1024 * 1024;
    budget.network_bytes = 64 * 1024 * 1024;
    budget.storage_operations = 256;
    budget
}

fn reader_spec() -> RootAuthoritySpec {
    let mut result = spec(budget());
    result.operation_id = OperationId::parse("operation:s3-independent-retrieval").unwrap();
    result.capabilities = [
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::ReadMedia,
    ]
    .into_iter()
    .map(|grant| grant.as_str().to_owned())
    .collect();
    result.deadline = Some(TimestampNs(NOW.0 + 120_000_000_000));
    result
}

fn reader_property(resource: &str) -> (AuthorityCx, AuthorityCx, RegionTree) {
    let mut all = spec(budget());
    all.capabilities
        .push(RuntimeGrant::ReadMedia.as_str().into());
    let (mut root, mut tree) = AuthorityCx::root(
        all.clone(),
        RegionId::new("region:s3-retrieval-process").unwrap(),
        RegionKind::Process,
        budget(),
        NOW,
    )
    .unwrap();
    let mut parent = root
        .scope_down(
            &mut tree,
            RegionId::new("region:s3-retrieval-property").unwrap(),
            RegionKind::Property,
            budget(),
            all,
            NOW,
        )
        .unwrap();
    let mut grants = GrantSet::empty();
    for grant in [
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::ReadMedia,
    ] {
        grants = grants.with_scope(grant, [resource.to_owned()].into_iter().collect());
    }
    parent.narrow_grants(grants).unwrap();
    (root, parent, tree)
}

struct SourceProvider;
impl MultipartTransport for SourceProvider {
    fn initiate(
        &mut self,
        cx: &mut TransportCx<'_>,
        _intent: &UploadIntent,
    ) -> Result<UploadId, String> {
        cx.checkpoint(cx.now()).map_err(|error| error.to_string())?;
        Ok(UploadId("completed-fixture-upload".into()))
    }
    fn upload_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        _upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        digest: ContentDigest,
    ) -> Result<PartReceipt, String> {
        cx.checkpoint(cx.now()).map_err(|error| error.to_string())?;
        assert_eq!(bytes.len() as u64, chunk.len);
        assert_eq!(ContentDigest::sha256(bytes), digest);
        Ok(PartReceipt {
            index: chunk.index,
            content_digest: digest,
            etag: ETag(format!("\"source-part-{}\"", chunk.index)),
        })
    }
    fn complete(
        &mut self,
        cx: &mut TransportCx<'_>,
        _upload: &UploadId,
        _intent: &UploadIntent,
        _parts: &[PartReceipt],
    ) -> Result<(), String> {
        cx.checkpoint(cx.now()).map_err(|error| error.to_string())
    }
    fn abort(
        &mut self,
        _cx: &mut TransportCx<'_>,
        _upload: &UploadId,
        _intent: &UploadIntent,
    ) -> Result<(), String> {
        panic!("retrieval fixture cannot authorize abort")
    }
    fn reconcile(
        &mut self,
        _cx: &mut TransportCx<'_>,
        _intent: &UploadIntent,
    ) -> Result<Reconciliation, String> {
        panic!("retrieval fixture cannot replace completed evidence")
    }
}

struct Source {
    journal: FileUploadJournal,
    recovery: MultipartRecovery,
    _directory: super::durable::Directory,
}

impl Source {
    fn new(endpoint: &S3Endpoint, bytes: &[u8]) -> Self {
        let directory = super::durable::Directory::new();
        let mut journal = FileUploadJournal::create(
            &directory.0,
            super::durable::limits(),
            Arc::new(HostSpoolIo),
        )
        .unwrap();
        let (_root, mut parent, mut tree) = reader_property(endpoint.resource());
        let mut transport = SourceProvider;
        {
            let mut upload = StagedUpload::stage(
                &mut parent,
                &mut tree,
                &mut transport,
                spec(budget()).operation_id,
                bytes.len() as u64,
                ChunkPolicy {
                    part_size: MIN_PART_SIZE,
                },
                // A graph root is deliberately different from the independent
                // whole-object digest supplied to the later reader.
                ContentDigest::sha256(b"independent manifest graph root"),
                spec(budget()),
                endpoint.resource(),
                NOW,
            )
            .unwrap();
            upload.attach_journal(&tree, NOW, &mut journal).unwrap();
            upload
                .upload_chunks(
                    &tree,
                    || NOW,
                    |chunk| {
                        bytes[chunk.offset as usize..(chunk.offset + chunk.len) as usize].to_vec()
                    },
                )
                .unwrap();
            upload.finish(&mut tree, NOW).unwrap();
        }
        let recovery = MultipartRecovery::read(&journal, journal.head().unwrap()).unwrap();
        assert_eq!(recovery.phase(), MultipartPhase::Completed);
        Self {
            journal,
            recovery,
            _directory: directory,
        }
    }

    fn metadata(&self) -> String {
        let intent = self.recovery.intent();
        [
            ("x-amz-meta-fss-intent", intent.digest()),
            ("x-amz-meta-fss-plan", intent.plan_digest()),
            ("x-amz-meta-fss-root", intent.manifest_root()),
            (
                "x-amz-meta-fss-origin",
                self.recovery.origin_binding().unwrap(),
            ),
        ]
        .into_iter()
        .map(|(name, digest)| {
            let hex: String = digest
                .bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            format!("{name}: {hex}\r\n")
        })
        .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplyKind {
    Exact,
    Corrupt,
    Truncated,
    ExtraByte,
    WholeResponse,
    Missing,
    Denied,
    Redirect,
    PreconditionFailed,
    WrongOrigin,
    WrongIntent,
    WrongPlan,
    WrongRoot,
    DuplicateMetadata,
    WrongRange,
    WrongTotal,
    DuplicateRange,
    DuplicateLength,
    NoEtag,
    WeakEtag,
    DuplicateEtag,
    ChangedEtag,
    Encoded,
    DeleteMarker,
    TransferEncoding,
}

fn get_reply(
    listener: &TcpListener,
    metadata: &str,
    source: &[u8],
    offset: usize,
    length: usize,
    kind: ReplyKind,
) {
    let mut socket = accept(listener);
    let (head, body) = request(&mut socket);
    assert!(head.starts_with(&format!("GET {TARGET} HTTP/1.1\r\n")));
    assert!(body.is_empty());
    assert_eq!(
        request_value(&head, "range"),
        format!("bytes={offset}-{}", offset + length - 1)
    );
    assert_eq!(request_value(&head, "accept-encoding"), "identity");
    let signature = request_value(&head, "authorization");
    assert!(signature.contains(";range;"));
    if offset == 0 {
        assert!(!head.contains("if-match:"));
    } else {
        assert_eq!(
            request_value(&head, "if-match"),
            "\"opaque-retrieval-token\""
        );
        assert!(signature.contains(";if-match;"));
    }
    let status = match kind {
        ReplyKind::WholeResponse => 200,
        ReplyKind::Missing => 404,
        ReplyKind::Denied => 403,
        ReplyKind::Redirect => 307,
        ReplyKind::PreconditionFailed => 412,
        _ => 206,
    };
    let mut metadata = metadata.to_owned();
    for (fault, name) in [
        (ReplyKind::WrongOrigin, "x-amz-meta-fss-origin"),
        (ReplyKind::WrongIntent, "x-amz-meta-fss-intent"),
        (ReplyKind::WrongPlan, "x-amz-meta-fss-plan"),
        (ReplyKind::WrongRoot, "x-amz-meta-fss-root"),
    ] {
        if kind == fault {
            let old = request_value(&metadata, name).to_owned();
            metadata = metadata.replace(
                &format!("{name}: {old}"),
                &format!("{name}: {}", "a".repeat(64)),
            );
        }
    }
    if matches!(kind, ReplyKind::DuplicateMetadata) {
        metadata.push_str(&format!("x-amz-meta-fss-origin: {}\r\n", "a".repeat(64)));
    }
    let mut bytes = source[offset..offset + length].to_vec();
    if matches!(kind, ReplyKind::Corrupt) {
        bytes[0] ^= 0xff;
    }
    if matches!(kind, ReplyKind::Truncated) {
        bytes.pop();
    }
    if matches!(kind, ReplyKind::ExtraByte) {
        bytes.push(0xff);
    }
    let reported_length = if matches!(kind, ReplyKind::Truncated) {
        length
    } else {
        bytes.len()
    };
    let mut headers = format!("HTTP/1.1 {status} fixture\r\nContent-Length: {reported_length}\r\n");
    let first = if matches!(kind, ReplyKind::WrongRange) {
        offset + 1
    } else {
        offset
    };
    let total = source.len() + usize::from(matches!(kind, ReplyKind::WrongTotal));
    headers.push_str(&format!(
        "Content-Range: bytes {first}-{}/{total}\r\n",
        offset + length - 1
    ));
    if matches!(kind, ReplyKind::DuplicateRange) {
        headers.push_str(&format!(
            "content-range: bytes {offset}-{}/{total}\r\n",
            offset + length - 1
        ));
    }
    if matches!(kind, ReplyKind::DuplicateLength) {
        headers.push_str(&format!("content-length: {reported_length}\r\n"));
    }
    match kind {
        ReplyKind::NoEtag => {}
        ReplyKind::WeakEtag => headers.push_str("ETag: W/\"opaque-retrieval-token\"\r\n"),
        ReplyKind::ChangedEtag => headers.push_str("ETag: \"replaced-object-token\"\r\n"),
        _ => headers.push_str("ETag: \"opaque-retrieval-token\"\r\n"),
    }
    match kind {
        ReplyKind::DuplicateEtag => headers.push_str("etag: \"another-token\"\r\n"),
        ReplyKind::Encoded => headers.push_str("Content-Encoding: gzip\r\n"),
        ReplyKind::DeleteMarker => headers.push_str("x-amz-delete-marker: true\r\n"),
        ReplyKind::Redirect => headers.push_str("Location: http://127.0.0.1:9/other\r\n"),
        ReplyKind::TransferEncoding => headers.push_str("Transfer-Encoding: chunked\r\n"),
        _ => {}
    }
    headers.push_str(&metadata);
    headers.push_str("Connection: close\r\n\r\n");
    socket.write_all(headers.as_bytes()).unwrap();
    socket.write_all(&bytes).unwrap();
}

fn verify(source: &Source, endpoint: S3Endpoint, expected: ContentDigest) -> RetrievalReceipt {
    let original_pin = source.journal.head();
    let original_record = source.journal.latest().unwrap().to_vec();
    let (_root, mut parent, mut tree) = reader_property(endpoint.resource());
    let mut transport = NativeS3Transport::from_recovery(
        endpoint,
        credentials(),
        S3Limits::default(),
        Clock,
        &source.recovery,
    )
    .unwrap();
    let mut observation = RetrievalObservation::begin(
        &mut parent,
        &mut tree,
        &source.journal,
        &source.recovery,
        source.recovery.intent(),
        expected,
        reader_spec(),
        NOW,
    )
    .unwrap();
    let result = observation.verify(&mut tree, &mut transport, || Ok(NOW));
    let receipt = observation.settle(&mut tree, NOW).unwrap();
    assert_eq!(
        result.is_ok(),
        receipt.outcome() == RetrievalOutcome::Verified
    );
    assert!(
        observation
            .verify(&mut tree, &mut transport, || Ok(NOW))
            .is_err()
    );
    assert_eq!(source.journal.head(), original_pin);
    assert_eq!(source.journal.latest().unwrap(), original_record);
    receipt
}

#[test]
fn native_get_verifies_bytes_under_independent_read_media_authority() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let bytes = b"abc";
    let source = Source::new(&endpoint, bytes);
    let metadata = source.metadata();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            get_reply(
                &listener,
                &metadata,
                bytes,
                0,
                bytes.len(),
                ReplyKind::Exact,
            )
        });
        let receipt = verify(&source, endpoint, ContentDigest::sha256(bytes));
        assert_eq!(receipt.outcome(), RetrievalOutcome::Verified);
        assert_eq!(receipt.expected_bytes(), 3);
        assert_eq!(receipt.bytes_read(), 3);
        assert_eq!(receipt.verified_parts(), 1);
        assert_eq!(receipt.attempted_ranges(), 1);
        server.join().unwrap();
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
    });
}

#[test]
fn large_object_uses_bounded_etag_pinned_ranges_across_original_parts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let bytes: Vec<u8> = (0..MIN_PART_SIZE as usize + 37)
        .map(|index| (index % 251) as u8)
        .collect();
    let source = Source::new(&endpoint, &bytes);
    let metadata = source.metadata();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            for chunk in &source.recovery.plan().chunks {
                let mut within = 0;
                while within < chunk.len {
                    let length = (chunk.len - within).min(MAX_RETRIEVAL_RANGE_BYTES);
                    get_reply(
                        &listener,
                        &metadata,
                        &bytes,
                        (chunk.offset + within) as usize,
                        length as usize,
                        ReplyKind::Exact,
                    );
                    within += length;
                }
            }
        });
        let receipt = verify(&source, endpoint, ContentDigest::sha256(&bytes));
        assert_eq!(receipt.outcome(), RetrievalOutcome::Verified);
        assert_eq!(receipt.bytes_read(), bytes.len() as u64);
        assert_eq!(receipt.verified_parts(), 2);
        assert_eq!(
            receipt.attempted_ranges(),
            MIN_PART_SIZE / MAX_RETRIEVAL_RANGE_BYTES + 1
        );
        server.join().unwrap();
    });
}

#[test]
fn metadata_framing_status_or_validator_conflicts_cannot_prove_retrieval() {
    for kind in [
        ReplyKind::Truncated,
        ReplyKind::ExtraByte,
        ReplyKind::WholeResponse,
        ReplyKind::Missing,
        ReplyKind::Denied,
        ReplyKind::Redirect,
        ReplyKind::PreconditionFailed,
        ReplyKind::WrongOrigin,
        ReplyKind::WrongIntent,
        ReplyKind::WrongPlan,
        ReplyKind::WrongRoot,
        ReplyKind::DuplicateMetadata,
        ReplyKind::WrongRange,
        ReplyKind::WrongTotal,
        ReplyKind::DuplicateRange,
        ReplyKind::DuplicateLength,
        ReplyKind::NoEtag,
        ReplyKind::WeakEtag,
        ReplyKind::DuplicateEtag,
        ReplyKind::Encoded,
        ReplyKind::DeleteMarker,
        ReplyKind::TransferEncoding,
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let bytes = b"abc";
        let source = Source::new(&endpoint, bytes);
        let metadata = source.metadata();
        std::thread::scope(|scope| {
            let server =
                scope.spawn(|| get_reply(&listener, &metadata, bytes, 0, bytes.len(), kind));
            let receipt = verify(&source, endpoint, ContentDigest::sha256(bytes));
            assert_eq!(receipt.outcome(), RetrievalOutcome::Unknown, "{kind:?}");
            assert_eq!(receipt.bytes_read(), 0, "{kind:?}");
            assert_eq!(receipt.attempted_ranges(), 1, "{kind:?}");
            server.join().unwrap();
            assert_eq!(
                listener.accept().err().unwrap().kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
    }
}

#[test]
fn valid_headers_do_not_hide_corruption_or_an_independent_digest_mismatch() {
    for corrupt in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let bytes = b"abc";
        let source = Source::new(&endpoint, bytes);
        let metadata = source.metadata();
        let kind = if corrupt {
            ReplyKind::Corrupt
        } else {
            ReplyKind::Exact
        };
        std::thread::scope(|scope| {
            let server =
                scope.spawn(|| get_reply(&listener, &metadata, bytes, 0, bytes.len(), kind));
            let expected = if corrupt {
                ContentDigest::sha256(bytes)
            } else {
                ContentDigest::sha256(b"different trusted source")
            };
            let receipt = verify(&source, endpoint, expected);
            assert_eq!(receipt.outcome(), RetrievalOutcome::Mismatch);
            assert_eq!(receipt.bytes_read(), 3);
            assert_eq!(receipt.verified_parts(), u64::from(!corrupt));
            server.join().unwrap();
        });
    }
}

#[test]
fn a_changed_representation_between_ranges_stops_before_publication() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let range = MAX_RETRIEVAL_RANGE_BYTES as usize;
    let bytes = vec![b'x'; range + 3];
    let source = Source::new(&endpoint, &bytes);
    let metadata = source.metadata();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            get_reply(&listener, &metadata, &bytes, 0, range, ReplyKind::Exact);
            get_reply(
                &listener,
                &metadata,
                &bytes,
                range,
                3,
                ReplyKind::ChangedEtag,
            );
        });
        let receipt = verify(&source, endpoint, ContentDigest::sha256(&bytes));
        assert_eq!(receipt.outcome(), RetrievalOutcome::Unknown);
        assert_eq!(receipt.bytes_read(), range as u64);
        assert_eq!(receipt.verified_parts(), 0);
        assert_eq!(receipt.attempted_ranges(), 2);
        server.join().unwrap();
    });
}

#[test]
fn insufficient_wire_budget_refuses_before_connect_and_preserves_upload() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let source = Source::new(&endpoint, b"abc");
    let (_root, mut parent, mut tree) = reader_property(endpoint.resource());
    let mut transport = NativeS3Transport::from_recovery(
        endpoint,
        credentials(),
        S3Limits::default(),
        Clock,
        &source.recovery,
    )
    .unwrap();
    let mut child = reader_spec();
    child.budgets.network_bytes = 3;
    let mut observation = RetrievalObservation::begin(
        &mut parent,
        &mut tree,
        &source.journal,
        &source.recovery,
        source.recovery.intent(),
        ContentDigest::sha256(b"abc"),
        child,
        NOW,
    )
    .unwrap();
    assert!(
        observation
            .verify(&mut tree, &mut transport, || Ok(NOW))
            .is_err()
    );
    assert_ne!(
        observation.settle(&mut tree, NOW).unwrap().outcome(),
        RetrievalOutcome::Verified
    );
    assert_eq!(
        listener.accept().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(source.recovery.phase(), MultipartPhase::Completed);
}

fn restore(
    source: &Source,
    endpoint: S3Endpoint,
    expected: ContentDigest,
) -> (Option<VerifiedRetrievalBytes>, RetrievalReceipt) {
    let original_pin = source.journal.head();
    let original_record = source.journal.latest().unwrap().to_vec();
    let original_spend = source.recovery.consumed();
    let (_root, mut parent, mut tree) = reader_property(endpoint.resource());
    let mut transport = NativeS3Transport::from_recovery(
        endpoint,
        credentials(),
        S3Limits::default(),
        Clock,
        &source.recovery,
    )
    .unwrap();
    let mut observation = RetrievalObservation::begin(
        &mut parent,
        &mut tree,
        &source.journal,
        &source.recovery,
        source.recovery.intent(),
        expected,
        reader_spec(),
        NOW,
    )
    .unwrap();
    let result = observation.verify_with_bytes(&mut tree, &mut transport, || Ok(NOW));
    let receipt = observation.settle(&mut tree, NOW).unwrap();
    assert!(observation.is_settled());
    assert_eq!(
        result.is_ok(),
        receipt.outcome() == RetrievalOutcome::Verified
    );
    if let Ok(restored) = &result {
        assert_eq!(restored.receipt(), &receipt);
    }
    assert!(
        observation
            .verify_with_bytes(&mut tree, &mut transport, || Ok(NOW))
            .is_err()
    );
    assert_eq!(source.journal.head(), original_pin);
    assert_eq!(source.journal.latest().unwrap(), original_record);
    assert_eq!(source.recovery.consumed(), original_spend);
    (result.ok(), receipt)
}

#[test]
fn native_restore_returns_exact_complete_media_after_all_parts_and_settlement() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let bytes: Vec<u8> = (0..MIN_PART_SIZE as usize + 37)
        .map(|index| (index % 251) as u8)
        .collect();
    let source = Source::new(&endpoint, &bytes);
    let metadata = source.metadata();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            for chunk in &source.recovery.plan().chunks {
                let mut within = 0;
                while within < chunk.len {
                    let length = (chunk.len - within).min(MAX_RETRIEVAL_RANGE_BYTES);
                    get_reply(
                        &listener,
                        &metadata,
                        &bytes,
                        (chunk.offset + within) as usize,
                        length as usize,
                        ReplyKind::Exact,
                    );
                    within += length;
                }
            }
        });
        let (restored, receipt) = restore(&source, endpoint, ContentDigest::sha256(&bytes));
        let restored = restored.expect("complete verified restore");
        assert_eq!(restored.bytes(), bytes.as_slice());
        assert_eq!(receipt.outcome(), RetrievalOutcome::Verified);
        assert_eq!(receipt.bytes_read(), bytes.len() as u64);
        assert_eq!(receipt.verified_parts(), 2);
        assert_eq!(
            receipt.attempted_ranges(),
            MIN_PART_SIZE / MAX_RETRIEVAL_RANGE_BYTES + 1
        );
        assert_eq!(restored.receipt().source_pin(), source.recovery.head());
        server.join().unwrap();
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
    });
}

#[test]
fn native_restore_discards_corruption_and_changed_provider_representations() {
    for kind in [ReplyKind::Corrupt, ReplyKind::ChangedEtag] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let range = MAX_RETRIEVAL_RANGE_BYTES as usize;
        let bytes = vec![b'x'; range + 3];
        let source = Source::new(&endpoint, &bytes);
        let metadata = source.metadata();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                get_reply(&listener, &metadata, &bytes, 0, range, ReplyKind::Exact);
                get_reply(&listener, &metadata, &bytes, range, 3, kind);
            });
            let (restored, receipt) = restore(&source, endpoint, ContentDigest::sha256(&bytes));
            assert!(restored.is_none(), "partial media escaped for {kind:?}");
            assert_eq!(
                receipt.outcome(),
                if kind == ReplyKind::Corrupt {
                    RetrievalOutcome::Mismatch
                } else {
                    RetrievalOutcome::Unknown
                }
            );
            assert_eq!(receipt.attempted_ranges(), 2);
            assert_eq!(receipt.verified_parts(), 0);
            server.join().unwrap();
            assert_eq!(
                listener.accept().err().unwrap().kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
    }
}
