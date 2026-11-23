#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Native loopback server exercises the real socket, codec, signature and owned
//! multipart and independent retrieval paths. It does not claim MinIO, B2, R2
//! or TLS qualification.

#[cfg(unix)]
#[path = "s3_upload_native_contract/retrieval.rs"]
mod retrieval;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RegionState, RegionTree,
    RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{MultipartPhase, TransportCx, TransportOperation};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE};
use fss_object::uploader::{StagedUpload, minimum_upload_budget};
use fss_reference::s3_upload::{
    NativeS3Transport, S3Clock, S3Credentials, S3Endpoint, S3Error, S3Limits,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;

const NOW: TimestampNs = TimestampNs(1_369_353_600_000_000_000);
const CHECKSUM: &str = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
const COMPOSITE: &str = "T4tCwi3TcptRm6b2jS2nzFstYG0F2u1a1RKMwD5sY1g=-1";
const KEY: &str = "evidence//../a b";
const TARGET: &str = "/archive/evidence//../a%20b";

struct Clock;
impl S3Clock for Clock {
    fn now(&mut self, _cx: &TransportCx<'_>) -> Result<TimestampNs, S3Error> {
        Ok(NOW)
    }
}

fn endpoint(peer: SocketAddr) -> S3Endpoint {
    S3Endpoint::new(
        peer,
        &peer.to_string(),
        "us-east-1",
        "archive",
        KEY,
        ContentDigest::sha256(b"explicit fixture local plaintext approval"),
    )
    .unwrap()
}
fn credentials() -> S3Credentials {
    S3Credentials::from_lines(b"fixture-access\nfixture-secret\n".to_vec()).unwrap()
}
fn allowance() -> BudgetVector {
    let mut result = minimum_upload_budget(
        3,
        ChunkPolicy {
            part_size: MIN_PART_SIZE,
        },
    )
    .unwrap();
    let overhead = S3Limits::default().overhead_budget(1).unwrap();
    result.bytes += overhead.bytes;
    result.network_bytes += overhead.network_bytes;
    result
}
fn spec(allowance: BudgetVector) -> RootAuthoritySpec {
    RootAuthoritySpec {
        trace_id: "trace:s3-native-fixture".into(),
        operation_id: OperationId::parse("operation:s3-native-fixture").unwrap(),
        principal: "principal:s3-native-fixture".into(),
        capabilities: [
            RuntimeGrant::ObjectStage,
            RuntimeGrant::ObjectPublish,
            RuntimeGrant::AdapterNet,
            RuntimeGrant::AdapterAuth,
        ]
        .into_iter()
        .map(|grant| grant.as_str().to_owned())
        .collect(),
        deadline: None,
        priority: 10,
        budgets: allowance,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: ContentDigest::sha256(b"s3-native-contract"),
        generation: 1,
    }
}
fn property(resource: &str) -> (AuthorityCx, AuthorityCx, RegionTree) {
    let allowance = allowance();
    let (mut root, mut tree) = AuthorityCx::root(
        spec(allowance),
        RegionId::new("region:s3-process").unwrap(),
        RegionKind::Process,
        allowance,
        NOW,
    )
    .unwrap();
    let mut parent = root
        .scope_down(
            &mut tree,
            RegionId::new("region:s3-property").unwrap(),
            RegionKind::Property,
            allowance,
            spec(allowance),
            NOW,
        )
        .unwrap();
    let mut grants = GrantSet::empty();
    for grant in [
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
    ] {
        grants = grants.with_scope(grant, [resource.to_owned()].into_iter().collect());
    }
    parent.narrow_grants(grants).unwrap();
    (root, parent, tree)
}

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return socket;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("fixture accept: {error}"),
        }
    }
}

fn request(socket: &mut TcpStream) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut read = [0; 1024];
    let head_end = loop {
        let count = socket.read(&mut read).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&read[..count]);
        assert!(bytes.len() <= 32 * 1024);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let head = String::from_utf8(bytes[..head_end].to_vec()).unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(length < 16384);
    while bytes.len() - head_end < length {
        let count = socket.read(&mut read).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&read[..count]);
    }
    assert_eq!(bytes.len() - head_end, length);
    assert!(
        head.contains(
            "AWS4-HMAC-SHA256 Credential=fixture-access/20130524/us-east-1/s3/aws4_request"
        )
    );
    assert!(!head.contains("fixture-secret"));
    (head, bytes[head_end..].to_vec())
}
fn reply(socket: &mut TcpStream, code: u16, headers: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {code} Fixture\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
        body.len()
    );
    socket.write_all(head.as_bytes()).unwrap();
    socket.write_all(body.as_bytes()).unwrap();
}
#[derive(Clone, Copy)]
enum End {
    Complete,
    Error,
    LostCreate,
    BadChecksum,
    Abort,
    Reconcile(HeadProof),
}

#[derive(Clone, Copy, Debug)]
enum HeadProof {
    Exact,
    Missing,
    Denied,
    Redirect,
    WrongIntent,
    WrongPlan,
    WrongRoot,
    MissingOrigin,
    WrongOrigin,
    WrongChecksum,
    WrongChecksumType,
    WrongSize,
    DuplicateMetadata,
    DuplicateOrigin,
    DuplicateChecksum,
    DuplicateLength,
    Range,
    DeleteMarker,
    MissingEtag,
    UnexpectedBody,
}

fn request_value<'a>(head: &'a str, name: &str) -> &'a str {
    head.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .unwrap()
}

fn head_proof(listener: &TcpListener, metadata: &[String], proof: HeadProof) {
    let mut socket = accept(listener);
    let (head, body) = request(&mut socket);
    assert!(head.starts_with(&format!("HEAD {TARGET} HTTP/1.1\r\n")));
    assert!(body.is_empty());
    assert!(head.contains("x-amz-checksum-mode: ENABLED\r\n"));
    assert!(request_value(&head, "authorization").contains(";x-amz-checksum-mode;"));
    let status = match proof {
        HeadProof::Missing => 404,
        HeadProof::Denied => 403,
        HeadProof::Redirect => 301,
        _ => 200,
    };
    let wrong = "0".repeat(64);
    let mut values: Vec<(&str, String)> = [
        ("x-amz-meta-fss-intent", metadata[0].clone()),
        ("x-amz-meta-fss-plan", metadata[1].clone()),
        ("x-amz-meta-fss-root", metadata[2].clone()),
        ("x-amz-checksum-sha256", COMPOSITE.to_owned()),
        ("x-amz-checksum-type", "COMPOSITE".to_owned()),
        ("Content-Length", "3".to_owned()),
        ("ETag", "\"opaque-whole-token\"".to_owned()),
    ]
    .into_iter()
    .collect();
    match proof {
        HeadProof::WrongIntent => values[0].1 = wrong,
        HeadProof::WrongPlan => values[1].1 = wrong,
        HeadProof::WrongRoot => values[2].1 = wrong,
        HeadProof::WrongChecksum => values[3].1 = CHECKSUM.to_owned(),
        HeadProof::WrongChecksumType => values[4].1 = "FULL_OBJECT".to_owned(),
        HeadProof::WrongSize => values[5].1 = "4".to_owned(),
        HeadProof::DuplicateMetadata => values.push(values[0].clone()),
        HeadProof::DuplicateChecksum => values.push(values[3].clone()),
        HeadProof::DuplicateLength => values.push(values[5].clone()),
        HeadProof::Range => values.push(("Content-Range", "bytes 0-2/3".to_owned())),
        HeadProof::DeleteMarker => values.push(("x-amz-delete-marker", "true".to_owned())),
        HeadProof::MissingEtag => {
            values.pop();
        }
        _ => {}
    }
    if let Some(origin) = metadata.get(3) {
        match proof {
            HeadProof::MissingOrigin => {}
            HeadProof::WrongOrigin => values.push(("x-amz-meta-fss-origin", "0".repeat(64))),
            HeadProof::DuplicateOrigin => {
                values.push(("x-amz-meta-fss-origin", origin.clone()));
                values.push(("x-amz-meta-fss-origin", origin.clone()));
            }
            _ => values.push(("x-amz-meta-fss-origin", origin.clone())),
        }
    }
    let mut response = format!("HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 {status} Fixture\r\n");
    for (name, value) in values {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("Connection: close\r\n\r\n");
    if matches!(proof, HeadProof::UnexpectedBody) {
        response.push_str("not a HEAD body");
    }
    socket.write_all(response.as_bytes()).unwrap();
}

fn server(listener: TcpListener, ending: End) {
    let mut socket = accept(&listener);
    let (head, body) = request(&mut socket);
    assert!(head.starts_with(&format!("POST {TARGET}?uploads= HTTP/1.1\r\n")));
    assert!(body.is_empty());
    let mut metadata: Vec<_> = [
        "x-amz-meta-fss-intent",
        "x-amz-meta-fss-plan",
        "x-amz-meta-fss-root",
    ]
    .into_iter()
    .map(|name| request_value(&head, name).to_owned())
    .collect();
    if let Some(origin) = head
        .lines()
        .find_map(|line| line.strip_prefix("x-amz-meta-fss-origin: "))
    {
        assert_eq!(origin.len(), 64);
        assert!(request_value(&head, "authorization").contains(";x-amz-meta-fss-origin;"));
        metadata.push(origin.to_owned());
    }
    for header in [
        "x-amz-checksum-algorithm: SHA256\r\n",
        "x-amz-checksum-type: COMPOSITE\r\n",
        "x-amz-meta-fss-intent: ",
        "x-amz-meta-fss-plan: ",
        "x-amz-meta-fss-root: ",
    ] {
        assert!(head.contains(header));
    }
    if matches!(ending, End::LostCreate) {
        return;
    }
    reply(
        &mut socket,
        200,
        "",
        &format!(
            "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>archive</Bucket><Key>{KEY}</Key><UploadId>owned/+upload=</UploadId></InitiateMultipartUploadResult>",
        ),
    );
    drop(socket);
    let mut socket = accept(&listener);
    let (head, body) = request(&mut socket);
    assert!(head.starts_with(&format!(
        "PUT {TARGET}?partNumber=1&uploadId=owned%2F%2Bupload%3D HTTP/1.1\r\n",
    )));
    assert!(head.contains(&format!("x-amz-checksum-sha256: {CHECKSUM}\r\n")));
    assert_eq!(body, b"abc");
    let checksum = if matches!(ending, End::BadChecksum) {
        "wrong"
    } else {
        CHECKSUM
    };
    reply(
        &mut socket,
        200,
        &format!("ETag: \"opaque-part-token\"\r\nx-amz-checksum-sha256: {checksum}\r\n"),
        "",
    );
    drop(socket);
    if matches!(ending, End::BadChecksum) {
        return;
    }
    let mut socket = accept(&listener);
    let (head, body) = request(&mut socket);
    if matches!(ending, End::Abort) {
        assert!(head.starts_with(&format!(
            "DELETE {TARGET}?uploadId=owned%2F%2Bupload%3D HTTP/1.1\r\n"
        )));
        assert!(body.is_empty());
        reply(&mut socket, 204, "", "");
        return;
    }
    assert!(head.starts_with(&format!(
        "POST {TARGET}?uploadId=owned%2F%2Bupload%3D HTTP/1.1\r\n"
    )));
    assert!(head.contains("if-none-match: *\r\n"));
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains("<PartNumber>1</PartNumber>"));
    assert!(body.contains("<ETag>&quot;opaque-part-token&quot;</ETag>"));
    assert!(body.contains(&format!("<ChecksumSHA256>{CHECKSUM}</ChecksumSHA256>")));
    if let End::Reconcile(proof) = ending {
        // The provider accepted the exact complete request, but its TCP reply
        // disappears. The only subsequent request allowed is a read-only HEAD.
        drop(socket);
        head_proof(&listener, &metadata, proof);
        return;
    }
    let body = if matches!(ending, End::Error) {
        "<Error><Code>InternalError</Code><Message>not an acknowledgement</Message></Error>"
            .to_owned()
    } else {
        format!(
            "<CompleteMultipartUploadResult><Bucket>archive</Bucket><Key>{KEY}</Key><ETag>\"opaque-whole-token\"</ETag><ChecksumSHA256>{COMPOSITE}</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
        )
    };
    // Exercise interim responses, chunk framing, and processing whitespace
    // before both success and the HTTP-200-embedded Error case.
    socket.write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n \r\n\r\n").unwrap();
    socket
        .write_all(format!("{:X}\r\n{body}\r\n0\r\n\r\n", body.len()).as_bytes())
        .unwrap();
}

fn run(ending: End) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let resource = endpoint.resource().to_owned();
    let (_root, mut parent, mut tree) = property(&resource);
    let mut transport =
        NativeS3Transport::new(endpoint, credentials(), S3Limits::default(), Clock).unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(move || server(listener, ending));
        let mut upload = StagedUpload::stage(
            &mut parent,
            &mut tree,
            &mut transport,
            spec(allowance()).operation_id,
            3,
            ChunkPolicy {
                part_size: MIN_PART_SIZE,
            },
            ContentDigest::sha256(b"abc"),
            spec(allowance()),
            &resource,
            NOW,
        )
        .unwrap();
        let started = upload.start(&tree, NOW);
        if matches!(ending, End::LostCreate) {
            assert!(started.is_err());
            assert_eq!(
                upload.phase(),
                MultipartPhase::Uncertain(TransportOperation::Initiate)
            );
            assert!(upload.start(&tree, NOW).is_err());
            assert_eq!(upload.reconcile(&mut tree, NOW).unwrap(), upload.phase());
            assert!(upload.cancel(&mut tree, NOW).is_err());
        } else {
            started.unwrap();
            let part = upload.upload_part(&tree, NOW, 0, b"abc");
            if matches!(ending, End::BadChecksum) {
                assert!(part.is_err());
                assert_eq!(
                    upload.phase(),
                    MultipartPhase::Uncertain(TransportOperation::UploadPart)
                );
                assert!(upload.finish(&mut tree, NOW).is_err());
                assert!(upload.cancel(&mut tree, NOW).is_err());
            } else {
                assert_eq!(part.unwrap().etag.0, "\"opaque-part-token\"");
                // Confirmed replay stays local and cannot send a fourth request.
                upload.upload_part(&tree, NOW, 0, b"abc").unwrap();
                let region = upload.region().clone();
                if matches!(ending, End::Abort) {
                    upload.request_cancellation(&mut tree, NOW).unwrap();
                    upload.cancel(&mut tree, NOW).unwrap();
                    assert_eq!(upload.phase(), MultipartPhase::Aborted);
                } else if matches!(ending, End::Error) {
                    assert!(upload.finish(&mut tree, NOW).is_err());
                    assert_eq!(
                        upload.phase(),
                        MultipartPhase::Uncertain(TransportOperation::Complete)
                    );
                    let consumed = *upload.budget().consumed();
                    assert_eq!(upload.reconcile(&mut tree, NOW).unwrap(), upload.phase());
                    // Unbound requests never gain positive proof from matching
                    // object metadata and do not even issue a speculative HEAD.
                    assert_eq!(
                        upload.budget().consumed().network_bytes,
                        consumed.network_bytes
                    );
                    assert!(upload.cancel(&mut tree, NOW).is_err());
                } else {
                    let receipt = upload.finish(&mut tree, NOW).unwrap();
                    assert_eq!(
                        receipt.parts[0].content_digest,
                        ContentDigest::sha256(b"abc")
                    );
                    assert_eq!(upload.phase(), MultipartPhase::Completed);
                }
                if matches!(ending, End::Complete | End::Abort) {
                    assert_eq!(tree.get(&region).unwrap().state, RegionState::Closed);
                }
            }
        }
        server.join().unwrap();
    });
}

#[test]
fn native_multipart_success_and_clean_abort_close_real_owned_children() {
    run(End::Complete);
    run(End::Abort);
}

#[test]
fn lost_create_bad_checksum_and_http200_error_preserve_uncertainty() {
    run(End::LostCreate);
    run(End::BadChecksum);
    run(End::Error);
}

#[cfg(unix)]
fn reconcile_lost_completion(proof: HeadProof) {
    use std::sync::Arc;

    use fss_object::HostSpoolIo;
    use fss_object::upload_journal::FileUploadJournal;

    let directory = durable::Directory::new();
    let mut journal =
        FileUploadJournal::create(&directory.0, durable::limits(), Arc::new(HostSpoolIo)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let resource = endpoint.resource().to_owned();
    let (_root, mut parent, mut tree) = property(&resource);
    let mut transport =
        NativeS3Transport::new(endpoint, credentials(), S3Limits::default(), Clock).unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(move || server(listener, End::Reconcile(proof)));
        let mut upload = StagedUpload::stage(
            &mut parent,
            &mut tree,
            &mut transport,
            spec(allowance()).operation_id,
            3,
            ChunkPolicy {
                part_size: MIN_PART_SIZE,
            },
            ContentDigest::sha256(b"abc"),
            spec(allowance()),
            &resource,
            NOW,
        )
        .unwrap();
        upload.attach_journal(&tree, NOW, &mut journal).unwrap();
        upload.start(&tree, NOW).unwrap();
        upload.upload_part(&tree, NOW, 0, b"abc").unwrap();
        assert!(upload.finish(&mut tree, NOW).is_err());
        assert_eq!(
            upload.phase(),
            MultipartPhase::Uncertain(TransportOperation::Complete)
        );
        // Neither ordinary resume nor abort is permitted to repeat the effect.
        assert!(upload.finish(&mut tree, NOW).is_err());
        let consumed = *upload.budget().consumed();
        let reconciled = upload.reconcile(&mut tree, NOW);
        assert_eq!(
            upload.budget().consumed().storage_operations,
            consumed.storage_operations + 1
        );
        assert!(upload.budget().consumed().network_bytes > consumed.network_bytes);
        if matches!(proof, HeadProof::Exact) {
            assert_eq!(reconciled.unwrap(), MultipartPhase::Completed);
            assert_eq!(
                tree.get(upload.region()).unwrap().state,
                RegionState::Closed
            );
            let receipt = upload.finish(&mut tree, NOW).unwrap();
            assert_eq!(receipt.upload.0, "owned/+upload=");
            assert_eq!(
                receipt.parts[0].content_digest,
                ContentDigest::sha256(b"abc")
            );
            assert_eq!(receipt.parts[0].etag.0, "\"opaque-part-token\"");
        } else {
            assert_eq!(
                upload.phase(),
                MultipartPhase::Uncertain(TransportOperation::Complete)
            );
            if matches!(
                proof,
                HeadProof::DuplicateMetadata
                    | HeadProof::DuplicateOrigin
                    | HeadProof::DuplicateChecksum
                    | HeadProof::DuplicateLength
                    | HeadProof::UnexpectedBody
            ) {
                assert!(reconciled.is_err(), "{proof:?}");
            } else {
                assert_eq!(reconciled.unwrap(), upload.phase(), "{proof:?}");
            }
            assert!(upload.finish(&mut tree, NOW).is_err());
            assert!(upload.cancel(&mut tree, NOW).is_err());
            upload
                .settle_indeterminate(
                    &mut tree,
                    NOW,
                    "read-only proof did not establish completion",
                    ContentDigest::sha256(b"independent follow-up reference"),
                )
                .unwrap();
            assert_eq!(
                tree.get(upload.region()).unwrap().state,
                RegionState::Closed
            );
        }
        server.join().unwrap();
    });
}

#[test]
#[cfg(unix)]
fn lost_complete_is_resolved_only_by_exact_read_only_head_proof() {
    reconcile_lost_completion(HeadProof::Exact);
}

#[test]
#[cfg(unix)]
fn missing_denied_redirected_or_conflicting_head_cannot_resolve_completion() {
    for proof in [
        HeadProof::Missing,
        HeadProof::Denied,
        HeadProof::Redirect,
        HeadProof::WrongIntent,
        HeadProof::WrongPlan,
        HeadProof::WrongRoot,
        HeadProof::MissingOrigin,
        HeadProof::WrongOrigin,
        HeadProof::WrongChecksum,
        HeadProof::WrongChecksumType,
        HeadProof::WrongSize,
        HeadProof::Range,
        HeadProof::DeleteMarker,
        HeadProof::MissingEtag,
    ] {
        reconcile_lost_completion(proof);
    }
}

#[test]
#[cfg(unix)]
fn duplicate_integrity_headers_and_unexpected_head_body_preserve_uncertainty() {
    for proof in [
        HeadProof::DuplicateMetadata,
        HeadProof::DuplicateOrigin,
        HeadProof::DuplicateChecksum,
        HeadProof::DuplicateLength,
        HeadProof::UnexpectedBody,
    ] {
        reconcile_lost_completion(proof);
    }
}

#[test]
fn public_plaintext_and_malformed_secret_inputs_refuse_without_io() {
    for peer in [
        "8.8.8.8:80",
        "0.0.0.0:80",
        "[2001:4860:4860::8888]:80",
        "224.0.0.1:80",
    ] {
        assert!(
            S3Endpoint::new(
                peer.parse().unwrap(),
                "store.invalid",
                "us-east-1",
                "archive",
                "key",
                ContentDigest::sha256(b"approval"),
            )
            .is_err()
        );
    }
    for bytes in [
        b"key\nsecret".to_vec(),
        b"key\r\nsecret\n".to_vec(),
        b"key\nsecret\nextra\nfourth\n".to_vec(),
        vec![0xff, b'\n'],
    ] {
        assert!(S3Credentials::from_lines(bytes).is_err());
    }
    let credentials = credentials();
    assert!(!format!("{credentials:?}").contains("fixture"));
}

#[test]
fn secret_revocation_and_wire_budget_refuse_before_connect() {
    for revoke in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let resource = endpoint.resource().to_owned();
        let (_root, mut parent, mut tree) = property(&resource);
        let mut transport =
            NativeS3Transport::new(endpoint, credentials(), S3Limits::default(), Clock).unwrap();
        let mut budget = allowance();
        if !revoke {
            budget.bytes = 3;
        }
        let mut upload = StagedUpload::stage(
            &mut parent,
            &mut tree,
            &mut transport,
            spec(budget).operation_id,
            3,
            ChunkPolicy {
                part_size: MIN_PART_SIZE,
            },
            ContentDigest::sha256(b"abc"),
            spec(budget),
            &resource,
            NOW,
        )
        .unwrap();
        if revoke {
            let mut grants = GrantSet::empty();
            for grant in [
                RuntimeGrant::ObjectStage,
                RuntimeGrant::ObjectPublish,
                RuntimeGrant::AdapterNet,
            ] {
                grants = grants.with_scope(grant, [resource.clone()].into_iter().collect());
            }
            upload.narrow_grants(grants).unwrap();
        }
        assert!(upload.start(&tree, NOW).is_err());
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[cfg(unix)]
mod durable {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use fss_object::HostSpoolIo;
    use fss_object::multipart::{MultipartRecovery, MultipartSession, UploadIo, UploadJournal};
    use fss_object::planner::plan_chunks;
    use fss_object::upload_journal::{FileUploadJournal, UploadJournalLimits};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    pub(super) struct Directory(pub(super) PathBuf);
    impl Directory {
        pub(super) fn new() -> Self {
            for _ in 0..16 {
                let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("fss-native-s3-{}-{ordinal}", std::process::id()));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("fixture directory: {error}"),
                }
            }
            panic!("fixture directory exhausted")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    pub(super) fn limits() -> UploadJournalLimits {
        UploadJournalLimits {
            max_records: 128,
            max_checkpoint_bytes: 16 * 1024,
            max_total_bytes: 512 * 1024,
            max_read_bytes: 2 * 1024 * 1024,
        }
    }

    #[test]
    fn separate_journals_with_identical_intent_cannot_claim_each_others_completion() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let resource = endpoint.resource().to_owned();
        std::thread::scope(|scope| {
            let server = scope.spawn(move || {
                let mut completed_metadata = Vec::new();
                for attempt in 0..2 {
                    let mut socket = accept(&listener);
                    let (head, body) = request(&mut socket);
                    assert!(head.starts_with(&format!("POST {TARGET}?uploads= HTTP/1.1\r\n")));
                    assert!(body.is_empty());
                    let metadata: Vec<_> = [
                        "x-amz-meta-fss-intent",
                        "x-amz-meta-fss-plan",
                        "x-amz-meta-fss-root",
                        "x-amz-meta-fss-origin",
                    ]
                    .into_iter()
                    .map(|name| request_value(&head, name).to_owned())
                    .collect();
                    assert!(
                        request_value(&head, "authorization")
                            .contains(";x-amz-meta-fss-origin;")
                    );
                    if attempt == 0 {
                        completed_metadata = metadata;
                    } else {
                        assert_eq!(metadata[..3], completed_metadata[..3]);
                        assert_ne!(metadata[3], completed_metadata[3]);
                    }
                    reply(
                        &mut socket,
                        200,
                        "",
                        &format!(
                            "<InitiateMultipartUploadResult><Bucket>archive</Bucket><Key>{KEY}</Key><UploadId>attempt-{attempt}</UploadId></InitiateMultipartUploadResult>"
                        ),
                    );
                    drop(socket);
                    let mut socket = accept(&listener);
                    let (head, body) = request(&mut socket);
                    assert!(head.starts_with(&format!(
                        "PUT {TARGET}?partNumber=1&uploadId=attempt-{attempt} HTTP/1.1\r\n"
                    )));
                    assert_eq!(body, b"abc");
                    reply(
                        &mut socket,
                        200,
                        &format!(
                            "ETag: \"opaque-part-token\"\r\nx-amz-checksum-sha256: {CHECKSUM}\r\n"
                        ),
                        "",
                    );
                    drop(socket);
                    let mut socket = accept(&listener);
                    let (head, _) = request(&mut socket);
                    assert!(head.starts_with(&format!(
                        "POST {TARGET}?uploadId=attempt-{attempt} HTTP/1.1\r\n"
                    )));
                    assert!(head.contains("if-none-match: *\r\n"));
                    if attempt == 0 {
                        reply(
                            &mut socket,
                            200,
                            "",
                            &format!(
                                "<CompleteMultipartUploadResult><Bucket>archive</Bucket><Key>{KEY}</Key><ETag>\"opaque-whole-token\"</ETag><ChecksumSHA256>{COMPOSITE}</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
                            ),
                        );
                    } else {
                        // The first object exists and the second upload remains
                        // staged. Matching semantic metadata cannot close it.
                        reply(
                            &mut socket,
                            412,
                            "",
                            "<Error><Code>PreconditionFailed</Code></Error>",
                        );
                        drop(socket);
                        head_proof(&listener, &completed_metadata, HeadProof::Exact);
                    }
                }
            });
            let mut expected = None;
            let mut origins = Vec::new();
            for attempt in 0..2 {
                let directory = Directory::new();
                let mut journal =
                    FileUploadJournal::create(&directory.0, limits(), Arc::new(HostSpoolIo))
                        .unwrap();
                let (_root, mut parent, mut tree) = property(&resource);
                let mut transport = NativeS3Transport::new(
                    endpoint.clone(),
                    credentials(),
                    S3Limits::default(),
                    Clock,
                )
                .unwrap();
                {
                    let mut upload = StagedUpload::stage(
                        &mut parent,
                        &mut tree,
                        &mut transport,
                        spec(allowance()).operation_id,
                        3,
                        ChunkPolicy {
                            part_size: MIN_PART_SIZE,
                        },
                        ContentDigest::sha256(b"abc"),
                        spec(allowance()),
                        &resource,
                        NOW,
                    )
                    .unwrap();
                    if let Some(expected) = &expected {
                        assert_eq!(upload.intent(), expected);
                    } else {
                        expected = Some(upload.intent().clone());
                    }
                    upload.attach_journal(&tree, NOW, &mut journal).unwrap();
                    upload.start(&tree, NOW).unwrap();
                    upload.upload_part(&tree, NOW, 0, b"abc").unwrap();
                    if attempt == 0 {
                        assert_eq!(upload.finish(&mut tree, NOW).unwrap().upload.0, "attempt-0");
                    } else {
                        assert!(upload.finish(&mut tree, NOW).is_err());
                        assert_eq!(
                            upload.reconcile(&mut tree, NOW).unwrap(),
                            MultipartPhase::Uncertain(TransportOperation::Complete)
                        );
                        assert!(upload.finish(&mut tree, NOW).is_err());
                        assert!(upload.cancel(&mut tree, NOW).is_err());
                        upload
                            .settle_indeterminate(
                                &mut tree,
                                NOW,
                                "observed object belongs to a different custody origin",
                                ContentDigest::sha256(b"distinct-attempt follow-up"),
                            )
                            .unwrap();
                    }
                }
                origins.push(journal.origin_binding().unwrap());
            }
            assert_ne!(origins[0], origins[1]);
            server.join().unwrap();
        });
    }

    #[test]
    fn cold_native_owner_preserves_exact_upload_and_confirmed_part() {
        let directory = Directory::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let resource = endpoint.resource().to_owned();
        std::thread::scope(|scope| {
            let server = scope.spawn(move || server(listener, End::Complete));
            let (minimum, expected) = {
                let mut journal =
                    FileUploadJournal::create(&directory.0, limits(), Arc::new(HostSpoolIo))
                        .unwrap();
                let (_root, mut parent, mut tree) = property(&resource);
                let mut transport = NativeS3Transport::new(
                    endpoint.clone(),
                    credentials(),
                    S3Limits::default(),
                    Clock,
                )
                .unwrap();
                let mut upload = StagedUpload::stage(
                    &mut parent,
                    &mut tree,
                    &mut transport,
                    spec(allowance()).operation_id,
                    3,
                    ChunkPolicy {
                        part_size: MIN_PART_SIZE,
                    },
                    ContentDigest::sha256(b"abc"),
                    spec(allowance()),
                    &resource,
                    NOW,
                )
                .unwrap();
                let minimum = upload.attach_journal(&tree, NOW, &mut journal).unwrap();
                let expected = upload.intent().clone();
                upload.start(&tree, NOW).unwrap();
                upload.upload_part(&tree, NOW, 0, b"abc").unwrap();
                // Drop every live handle. Only the independently pinned file
                // journal and the provider outlive this process-shaped scope.
                (minimum, expected)
            };
            let mut journal =
                FileUploadJournal::open(&directory.0, limits(), Arc::new(HostSpoolIo), minimum)
                    .unwrap();
            let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
            assert_eq!(recovery.phase(), MultipartPhase::Uploading);
            assert_eq!(recovery.upload_id().unwrap().0, "owned/+upload=");
            assert_eq!(recovery.confirmed_parts(), 1);
            let child_spec = spec(recovery.remaining_budget());
            let mut transport = NativeS3Transport::from_recovery(
                endpoint,
                credentials(),
                S3Limits::default(),
                Clock,
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
            upload.upload_part(&tree, NOW, 0, b"abc").unwrap();
            let receipt = upload.finish(&mut tree, NOW).unwrap();
            assert_eq!(receipt.upload.0, "owned/+upload=");
            assert_eq!(receipt.parts[0].etag.0, "\"opaque-part-token\"");
            assert_eq!(
                tree.get(upload.region()).unwrap().state,
                RegionState::Closed
            );
            server.join().unwrap();
        });
    }

    #[test]
    fn cold_native_reconciliation_preserves_part_size_identity_and_settles_journal() {
        let directory = Directory::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let resource = endpoint.resource().to_owned();
        std::thread::scope(|scope| {
            let server = scope.spawn(move || server(listener, End::Reconcile(HeadProof::Exact)));
            let (minimum, expected) = {
                let mut journal =
                    FileUploadJournal::create(&directory.0, limits(), Arc::new(HostSpoolIo))
                        .unwrap();
                let (_root, mut parent, mut tree) = property(&resource);
                let mut transport = NativeS3Transport::new(
                    endpoint.clone(),
                    credentials(),
                    S3Limits::default(),
                    Clock,
                )
                .unwrap();
                let mut upload = StagedUpload::stage(
                    &mut parent,
                    &mut tree,
                    &mut transport,
                    spec(allowance()).operation_id,
                    3,
                    ChunkPolicy {
                        part_size: MIN_PART_SIZE,
                    },
                    ContentDigest::sha256(b"abc"),
                    spec(allowance()),
                    &resource,
                    NOW,
                )
                .unwrap();
                let minimum = upload.attach_journal(&tree, NOW, &mut journal).unwrap();
                let expected = upload.intent().clone();
                upload.start(&tree, NOW).unwrap();
                upload.upload_part(&tree, NOW, 0, b"abc").unwrap();
                assert!(upload.finish(&mut tree, NOW).is_err());
                assert_eq!(
                    upload.phase(),
                    MultipartPhase::Uncertain(TransportOperation::Complete)
                );
                (minimum, expected)
            };
            {
                let mut journal =
                    FileUploadJournal::open(&directory.0, limits(), Arc::new(HostSpoolIo), minimum)
                        .unwrap();
                let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
                assert_eq!(
                    recovery.phase(),
                    MultipartPhase::Uncertain(TransportOperation::Complete)
                );
                let consumed = recovery.consumed();
                let child_spec = spec(recovery.remaining_budget());
                let mut transport = NativeS3Transport::from_recovery(
                    endpoint,
                    credentials(),
                    S3Limits::default(),
                    Clock,
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
                    MultipartPhase::Completed
                );
                assert!(
                    upload.cumulative_consumed().unwrap().storage_operations
                        > consumed.storage_operations
                );
                assert_eq!(
                    tree.get(upload.region()).unwrap().state,
                    RegionState::Closed
                );
                assert_eq!(
                    upload.finish(&mut tree, NOW).unwrap().parts[0].etag.0,
                    "\"opaque-part-token\""
                );
            }
            let journal =
                FileUploadJournal::open(&directory.0, limits(), Arc::new(HostSpoolIo), minimum)
                    .unwrap();
            let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
            assert_eq!(recovery.phase(), MultipartPhase::Completed);
            assert!(recovery.completion_receipt().is_ok());
            server.join().unwrap();
        });
    }

    #[test]
    fn protocol_only_durable_context_cannot_bypass_secret_recovery_custody() {
        let directory = Directory::new();
        let mut journal =
            FileUploadJournal::create(&directory.0, limits(), Arc::new(HostSpoolIo)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let resource = endpoint.resource().to_owned();
        let (_root, mut parent, mut tree) = property(&resource);
        let mut child = parent
            .scope_down(
                &mut tree,
                RegionId::new("region:s3-raw-protocol").unwrap(),
                RegionKind::ObjectStore,
                allowance(),
                spec(allowance()),
                NOW,
            )
            .unwrap();
        let mut transport =
            NativeS3Transport::new(endpoint.clone(), credentials(), S3Limits::default(), Clock)
                .unwrap();
        let plan = plan_chunks(
            3,
            ChunkPolicy {
                part_size: MIN_PART_SIZE,
            },
        )
        .unwrap();
        let mut session = MultipartSession::prepare(
            &mut transport,
            &plan,
            ContentDigest::sha256(b"abc"),
            spec(allowance()).operation_id,
            &resource,
            NOW,
        )
        .unwrap();
        let minimum = session
            .attach_journal(
                &mut journal,
                UploadIo {
                    authority: &mut child,
                    tree: &tree,
                    now: NOW,
                },
                Vec::new(),
            )
            .unwrap();
        assert!(
            session
                .start(UploadIo {
                    authority: &mut child,
                    tree: &tree,
                    now: NOW,
                })
                .is_err()
        );
        drop(session);
        let recovery = MultipartRecovery::read(&journal, minimum).unwrap();
        assert!(matches!(
            NativeS3Transport::from_recovery(
                endpoint,
                credentials(),
                S3Limits::default(),
                Clock,
                &recovery,
            ),
            Err(S3Error::Binding)
        ));
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
