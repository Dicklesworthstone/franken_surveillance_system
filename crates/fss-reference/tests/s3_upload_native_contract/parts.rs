#![forbid(unsafe_code)]
//! Lost UploadPart acknowledgements are recovered only by positive, bounded
//! evidence for the exact still-pending owner. All sockets are local fixtures.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_object::HostSpoolIo;
use fss_object::multipart::{MultipartRecovery, UploadIntent, UploadJournalPin};
use fss_object::upload_journal::{FileUploadJournal, UploadJournalLimits};

const UPLOAD: &str = "owned/+upload=";
const QUERY: &str = "max-parts=1000&part-number-marker=0&uploadId=owned%2F%2Bupload%3D";
const ETAG: &str = "\"recovered-part-token\"";
const EXPIRED: TimestampNs = TimestampNs(NOW.0 + 60_000_000_000);

#[derive(Clone)]
struct ControlledClock(Arc<AtomicU64>);

impl ControlledClock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(u64::try_from(NOW.0).unwrap())))
    }
}

impl S3Clock for ControlledClock {
    fn now(&mut self, _cx: &TransportCx<'_>) -> Result<TimestampNs, S3Error> {
        Ok(TimestampNs(i128::from(self.0.load(Ordering::SeqCst))))
    }
}

fn journal_limits() -> UploadJournalLimits {
    let mut limits = durable::limits();
    limits.max_records = 512;
    limits.max_total_bytes = 2 * 1024 * 1024;
    limits.max_read_bytes = 8 * 1024 * 1024;
    limits
}

fn inventory() -> String {
    format!(
        "<ListPartsResult><Bucket>archive</Bucket><Key>{KEY}</Key><UploadId>{UPLOAD}</UploadId><PartNumberMarker>0</PartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated><ChecksumAlgorithm>SHA256</ChecksumAlgorithm><ChecksumType>COMPOSITE</ChecksumType><Part><PartNumber>1</PartNumber><Size>3</Size><ChecksumSHA256>{CHECKSUM}</ChecksumSHA256><ETag>{ETAG}</ETag></Part></ListPartsResult>"
    )
}

fn missing_part() -> String {
    let body = inventory();
    let start = body.find("<Part>").unwrap();
    let end = body.find("</Part>").unwrap() + "</Part>".len();
    body[..start].to_owned() + &body[end..]
}

fn create_and_lose_part(listener: &TcpListener) {
    let mut socket = accept(listener);
    let (head, body) = request(&mut socket);
    assert!(head.starts_with(&format!("POST {TARGET}?uploads= HTTP/1.1\r\n")));
    assert!(body.is_empty());
    assert!(!request_value(&head, "x-amz-meta-fss-origin").is_empty());
    reply(
        &mut socket,
        200,
        "",
        &format!(
            "<InitiateMultipartUploadResult><Bucket>archive</Bucket><Key>{KEY}</Key><UploadId>{UPLOAD}</UploadId></InitiateMultipartUploadResult>"
        ),
    );
    drop(socket);
    let mut socket = accept(listener);
    let (head, body) = request(&mut socket);
    assert!(head.starts_with(&format!(
        "PUT {TARGET}?partNumber=1&uploadId=owned%2F%2Bupload%3D HTTP/1.1\r\n"
    )));
    assert_eq!(request_value(&head, "x-amz-checksum-sha256"), CHECKSUM);
    assert_eq!(body, b"abc");
    // The provider retains the exact bytes; only its acknowledgement is lost.
    drop(socket);
}

fn inventory_request(listener: &TcpListener) -> TcpStream {
    let mut socket = accept(listener);
    let (head, body) = request(&mut socket);
    assert!(head.starts_with(&format!("GET {TARGET}?{QUERY} HTTP/1.1\r\n")));
    assert!(body.is_empty());
    assert_eq!(request_value(&head, "content-length"), "0");
    socket
}

fn assert_no_extra_request(listener: TcpListener) {
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn prepare_lost_part(
    directory: &durable::Directory,
    endpoint: &S3Endpoint,
    clock: ControlledClock,
    child_spec: RootAuthoritySpec,
) -> (UploadJournalPin, UploadIntent) {
    let resource = endpoint.resource();
    let mut journal =
        FileUploadJournal::create(&directory.0, journal_limits(), Arc::new(HostSpoolIo))
            .unwrap();
    let (_root, mut parent, mut tree) = property(resource);
    let mut transport =
        NativeS3Transport::new(endpoint.clone(), credentials(), S3Limits::default(), clock)
            .unwrap();
    let mut upload = StagedUpload::stage(
        &mut parent,
        &mut tree,
        &mut transport,
        child_spec.operation_id.clone(),
        3,
        ChunkPolicy {
            part_size: MIN_PART_SIZE,
        },
        ContentDigest::sha256(b"abc"),
        child_spec,
        resource,
        NOW,
    )
    .unwrap();
    let minimum = upload.attach_journal(&tree, NOW, &mut journal).unwrap();
    let expected = upload.intent().clone();
    upload.start(&tree, NOW).unwrap();
    assert!(upload.upload_part(&tree, NOW, 0, b"abc").is_err());
    assert_eq!(
        upload.phase(),
        MultipartPhase::Uncertain(TransportOperation::UploadPart)
    );
    assert_eq!(upload.confirmed_parts(), 0);
    // Every in-memory owner is discarded; only the pinned journal survives.
    (minimum, expected)
}

#[test]
fn lost_part_reconciles_durably_and_cold_completion_never_reuploads_its_bytes() {
    let directory = durable::Directory::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let resource = endpoint.resource().to_owned();
    std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            create_and_lose_part(&listener);
            let mut socket = inventory_request(&listener);
            reply(&mut socket, 200, "", &inventory());
            drop(socket);
            let mut socket = accept(&listener);
            let (head, body) = request(&mut socket);
            assert!(head.starts_with(&format!(
                "POST {TARGET}?uploadId=owned%2F%2Bupload%3D HTTP/1.1\r\n"
            )));
            assert!(head.contains("if-none-match: *\r\n"));
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("<ETag>&quot;recovered-part-token&quot;</ETag>"));
            assert!(body.contains(&format!(
                "<ChecksumSHA256>{CHECKSUM}</ChecksumSHA256>"
            )));
            reply(
                &mut socket,
                200,
                "",
                &format!(
                    "<CompleteMultipartUploadResult><Bucket>archive</Bucket><Key>{KEY}</Key><ETag>whole-token</ETag><ChecksumSHA256>{COMPOSITE}</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
                ),
            );
            drop(socket);
            listener
        });
        let (minimum, expected) =
            prepare_lost_part(&directory, &endpoint, ControlledClock::new(), spec(allowance()));
        let spent = {
            let mut journal = FileUploadJournal::open(
                &directory.0,
                journal_limits(),
                Arc::new(HostSpoolIo),
                minimum,
            )
            .unwrap();
            let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
            assert_eq!(
                recovery.intended_parts().collect::<Vec<_>>(),
                vec![(0, ContentDigest::sha256(b"abc"))]
            );
            assert_eq!(recovery.confirmed_parts(), 0);
            let spent = recovery.consumed();
            let child_spec = spec(recovery.remaining_budget());
            let mut transport = NativeS3Transport::from_recovery(
                endpoint.clone(),
                credentials(),
                S3Limits::default(),
                ControlledClock::new(),
                &recovery,
            )
            .unwrap();
            let (_root, mut parent, mut tree) = property(&resource);
            let mut upload = StagedUpload::recover(
                &mut parent,
                &mut tree,
                &mut transport,
                &mut journal,
                recovery,
                &expected,
                child_spec,
                NOW,
            )
            .unwrap();
            assert_eq!(
                upload.reconcile(&mut tree, NOW).unwrap(),
                MultipartPhase::Uploading
            );
            assert_eq!(upload.confirmed_parts(), 1);
            assert_eq!(tree.get(upload.region()).unwrap().state, RegionState::Active);
            assert_eq!(
                upload.cumulative_consumed().unwrap().storage_operations,
                spent.storage_operations + 1
            );
            upload.cumulative_consumed().unwrap()
        };
        // A positive response is first committed by the protocol; the uncertain
        // adapter is discarded before any subsequent mutation is authorized.
        let mut journal = FileUploadJournal::open(
            &directory.0,
            journal_limits(),
            Arc::new(HostSpoolIo),
            minimum,
        )
        .unwrap();
        let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
        assert_eq!(recovery.phase(), MultipartPhase::Uploading);
        assert_eq!(recovery.confirmed_parts(), 1);
        assert_eq!(recovery.consumed(), spent);
        assert_eq!(recovery.part_receipts().next().unwrap().etag.0, ETAG);
        let child_spec = spec(recovery.remaining_budget());
        let mut transport = NativeS3Transport::from_recovery(
            endpoint,
            credentials(),
            S3Limits::default(),
            ControlledClock::new(),
            &recovery,
        )
        .unwrap();
        let (_root, mut parent, mut tree) = property(&resource);
        let mut upload = StagedUpload::recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            recovery,
            &expected,
            child_spec,
            NOW,
        )
        .unwrap();
        let receipt = upload.finish(&mut tree, NOW).unwrap();
        assert_eq!(receipt.upload.0, UPLOAD);
        assert_eq!(receipt.parts[0].etag.0, ETAG);
        assert_eq!(receipt.parts[0].content_digest, ContentDigest::sha256(b"abc"));
        assert_eq!(tree.get(upload.region()).unwrap().state, RegionState::Closed);
        assert_no_extra_request(server.join().unwrap());
    });
}

#[test]
fn missing_partial_wrong_or_denied_inventory_cannot_authorize_part_replay() {
    let good = inventory();
    let cases = [
        (200, missing_part()),
        (200, good.replace("<IsTruncated>false", "<IsTruncated>true")),
        (200, good.replace(UPLOAD, "some-other-upload")),
        (200, good.replace("<Size>3</Size>", "<Size>4</Size>")),
        (200, good.replace(CHECKSUM, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
        (200, good.replace("<PartNumber>1", "<PartNumber>2")),
        (200, good.replace("<MaxParts>1000", "<MaxParts>1")),
        (200, good.replace("<Size>3</Size>", "<Size>3</Size><Size>3</Size>")),
        (403, "<Error><Code>AccessDenied</Code></Error>".into()),
        (404, "<Error><Code>NoSuchUpload</Code></Error>".into()),
    ];
    for (status, body) in cases {
        let directory = durable::Directory::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let resource = endpoint.resource().to_owned();
        std::thread::scope(|scope| {
            let server = scope.spawn(move || {
                create_and_lose_part(&listener);
                let mut socket = inventory_request(&listener);
                reply(&mut socket, status, "", &body);
                drop(socket);
                listener
            });
            let (minimum, expected) = prepare_lost_part(
                &directory,
                &endpoint,
                ControlledClock::new(),
                spec(allowance()),
            );
            let mut journal = FileUploadJournal::open(
                &directory.0,
                journal_limits(),
                Arc::new(HostSpoolIo),
                minimum,
            )
            .unwrap();
            let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
            let child_spec = spec(recovery.remaining_budget());
            let mut transport = NativeS3Transport::from_recovery(
                endpoint,
                credentials(),
                S3Limits::default(),
                ControlledClock::new(),
                &recovery,
            )
            .unwrap();
            let (_root, mut parent, mut tree) = property(&resource);
            let mut upload = StagedUpload::recover(
                &mut parent,
                &mut tree,
                &mut transport,
                &mut journal,
                recovery,
                &expected,
                child_spec,
                NOW,
            )
            .unwrap();
            let _ = upload.reconcile(&mut tree, NOW);
            assert_eq!(
                upload.phase(),
                MultipartPhase::Uncertain(TransportOperation::UploadPart)
            );
            assert_eq!(upload.confirmed_parts(), 0);
            assert!(upload.upload_part(&tree, NOW, 0, b"abc").is_err());
            assert!(upload.finish(&mut tree, NOW).is_err());
            upload
                .settle_indeterminate(
                    &mut tree,
                    NOW,
                    "ListParts did not prove the exact dispatched part",
                    ContentDigest::sha256(b"unresolved native part fixture"),
                )
                .unwrap();
            assert_no_extra_request(server.join().unwrap());
        });
    }
}

#[derive(Clone, Copy, Debug)]
enum Refusal {
    Cancelled,
    Expired,
    AuthenticationRevoked,
    MemoryFloor,
    WireFloor,
    FinalOperation,
}

#[test]
fn active_part_recovery_preserves_lifetime_grants_and_cleanup_allowance() {
    for refusal in [
        Refusal::Cancelled,
        Refusal::Expired,
        Refusal::AuthenticationRevoked,
        Refusal::MemoryFloor,
        Refusal::WireFloor,
        Refusal::FinalOperation,
    ] {
        let directory = durable::Directory::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let resource = endpoint.resource().to_owned();
        let clock = ControlledClock::new();
        let limits = S3Limits::default();
        let memory = (limits.response_bytes as u64 + limits.header_bytes as u64) * 8 + 32 * 1024;
        let wire = (limits.header_bytes + limits.wire_bytes) as u64;
        let mut child_spec = spec(allowance());
        match refusal {
            Refusal::Expired => child_spec.deadline = Some(EXPIRED),
            // Two prior exchanges plus the source bytes and retained intention
            // leave one byte less than a probe plus its reserved abort.
            Refusal::MemoryFloor => child_spec.budgets.bytes = 4 * memory + 3 + 256 - 1,
            Refusal::WireFloor => child_spec.budgets.network_bytes = 4 * wire + 3 - 1,
            _ => {}
        }
        std::thread::scope(|scope| {
            let server = scope.spawn(move || {
                create_and_lose_part(&listener);
                if matches!(refusal, Refusal::FinalOperation) {
                    for _ in 0..3 {
                        let mut socket = inventory_request(&listener);
                        reply(&mut socket, 200, "", &missing_part());
                    }
                }
                listener
            });
            let (minimum, expected) =
                prepare_lost_part(&directory, &endpoint, clock.clone(), child_spec);
            let mut journal = FileUploadJournal::open(
                &directory.0,
                journal_limits(),
                Arc::new(HostSpoolIo),
                minimum,
            )
            .unwrap();
            let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
            let mut child_spec = spec(recovery.remaining_budget());
            child_spec.deadline = recovery.original_authority().deadline;
            let mut transport = NativeS3Transport::from_recovery(
                endpoint,
                credentials(),
                limits,
                clock.clone(),
                &recovery,
            )
            .unwrap();
            let (_root, mut parent, mut tree) = property(&resource);
            let mut upload = StagedUpload::recover(
                &mut parent,
                &mut tree,
                &mut transport,
                &mut journal,
                recovery,
                &expected,
                child_spec,
                NOW,
            )
            .unwrap();
            let mut now = NOW;
            match refusal {
                Refusal::Cancelled => upload.request_cancellation(&mut tree, NOW).unwrap(),
                Refusal::Expired => {
                    now = EXPIRED;
                    clock.0.store(u64::try_from(now.0).unwrap(), Ordering::SeqCst);
                }
                Refusal::AuthenticationRevoked => {
                    let mut grants = GrantSet::empty();
                    for grant in [
                        RuntimeGrant::ObjectStage,
                        RuntimeGrant::ObjectPublish,
                        RuntimeGrant::AdapterNet,
                    ] {
                        grants = grants.with_scope(grant, [resource.clone()].into_iter().collect());
                    }
                    upload.narrow_grants_durable(&tree, NOW, grants).unwrap();
                }
                Refusal::MemoryFloor => assert!(upload.budget().remaining().bytes < memory * 2),
                Refusal::WireFloor => assert!(upload.budget().remaining().network_bytes < wire * 2),
                Refusal::FinalOperation => {
                    for _ in 0..3 {
                        assert_eq!(
                            upload.reconcile(&mut tree, NOW).unwrap(),
                            MultipartPhase::Uncertain(TransportOperation::UploadPart)
                        );
                    }
                    assert_eq!(upload.budget().remaining().storage_operations, 1);
                }
            }
            assert!(upload.reconcile(&mut tree, now).is_err(), "{refusal:?}");
            assert_eq!(
                upload.phase(),
                MultipartPhase::Uncertain(TransportOperation::UploadPart),
                "{refusal:?}"
            );
            assert_eq!(upload.confirmed_parts(), 0, "{refusal:?}");
            if matches!(refusal, Refusal::FinalOperation) {
                assert_eq!(upload.budget().remaining().storage_operations, 0);
            }
            upload
                .settle_indeterminate(
                    &mut tree,
                    now,
                    "part recovery cannot restore forward authority",
                    ContentDigest::sha256(b"part recovery refused"),
                )
                .unwrap();
            assert_no_extra_request(server.join().unwrap());
        });
    }
}

#[test]
fn deadline_crossed_during_list_parts_cannot_restore_active_uploading() {
    let directory = durable::Directory::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let resource = endpoint.resource().to_owned();
    let clock = ControlledClock::new();
    let mut child_spec = spec(allowance());
    child_spec.deadline = Some(EXPIRED);
    std::thread::scope(|scope| {
        let server_clock = clock.clone();
        let server = scope.spawn(move || {
            create_and_lose_part(&listener);
            let mut socket = inventory_request(&listener);
            server_clock
                .0
                .store(u64::try_from(EXPIRED.0).unwrap(), Ordering::SeqCst);
            let body = inventory();
            let response = format!(
                "HTTP/1.1 200 Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            // The client may close as soon as it observes expiry.
            let _ = socket.write_all(response.as_bytes());
            drop(socket);
            listener
        });
        let (minimum, expected) =
            prepare_lost_part(&directory, &endpoint, clock.clone(), child_spec);
        let mut journal = FileUploadJournal::open(
            &directory.0,
            journal_limits(),
            Arc::new(HostSpoolIo),
            minimum,
        )
        .unwrap();
        let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
        let mut child_spec = spec(recovery.remaining_budget());
        child_spec.deadline = Some(EXPIRED);
        let mut transport = NativeS3Transport::from_recovery(
            endpoint,
            credentials(),
            S3Limits::default(),
            clock,
            &recovery,
        )
        .unwrap();
        let (_root, mut parent, mut tree) = property(&resource);
        let mut upload = StagedUpload::recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            recovery,
            &expected,
            child_spec,
            NOW,
        )
        .unwrap();
        assert!(upload.reconcile(&mut tree, NOW).is_err());
        assert_eq!(
            upload.phase(),
            MultipartPhase::Uncertain(TransportOperation::UploadPart)
        );
        assert_eq!(upload.confirmed_parts(), 0);
        upload
            .settle_indeterminate(
                &mut tree,
                EXPIRED,
                "owner expired before positive inventory became usable",
                ContentDigest::sha256(b"expiry during ListParts"),
            )
            .unwrap();
        assert_no_extra_request(server.join().unwrap());
    });
}
