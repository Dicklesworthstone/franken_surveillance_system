#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real loopback socket/codec/SigV4 tests for complete object verification.
//! These fixtures establish neither external-provider nor TLS qualification.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RegionTree, RootAuthoritySpec,
    RuntimeGrant, TimestampNs,
};
use fss_reference::s3_upload::verification::{
    MAX_VERIFIED_OBJECT_BYTES, S3ObjectPin, S3ReadClock, S3ReadIo, S3VerificationReceipt,
    verification_budget, verify_s3_object,
};
use fss_reference::s3_upload::{S3Credentials, S3Endpoint, S3Error, S3Limits};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;

const NOW: TimestampNs = TimestampNs(1_369_353_600_000_000_000);
const DEADLINE: TimestampNs = TimestampNs(NOW.0 + 30_000_000_000);
const READ_GRANTS: [RuntimeGrant; 3] = [
    RuntimeGrant::AdapterNet,
    RuntimeGrant::AdapterAuth,
    RuntimeGrant::ReadMedia,
];

struct Clock;
impl S3ReadClock for Clock {
    fn now(&mut self, _: &AuthorityCx) -> Result<TimestampNs, S3Error> {
        Ok(NOW)
    }
}
struct NoClock;
impl S3ReadClock for NoClock {
    fn now(&mut self, _: &AuthorityCx) -> Result<TimestampNs, S3Error> {
        panic!("refused input must not reach a clock or socket boundary")
    }
}
struct ExpireAfterFirstRange;
impl S3ReadClock for ExpireAfterFirstRange {
    fn now(&mut self, owner: &AuthorityCx) -> Result<TimestampNs, S3Error> {
        Ok(if owner.budget().consumed().storage_operations > 1 {
            DEADLINE
        } else {
            NOW
        })
    }
}

fn limits() -> S3Limits {
    S3Limits {
        response_bytes: 1024,
        header_bytes: 4096,
        wire_bytes: 8192,
        io_bytes: 1024,
        connect_timeout_ns: 1_000_000_000,
        io_timeout_ns: 1_000_000_000,
        exchange_timeout_ns: 3_000_000_000,
        ..S3Limits::default()
    }
}
fn pin(bytes: &[u8]) -> S3ObjectPin {
    S3ObjectPin {
        digest: ContentDigest::sha256(bytes),
        bytes: bytes.len() as u64,
    }
}
fn endpoint(peer: SocketAddr) -> S3Endpoint {
    S3Endpoint::new(
        peer,
        &peer.to_string(),
        "us-east-1",
        "archive",
        "evidence//../a b",
        ContentDigest::sha256(b"explicit fixture local plaintext approval"),
    )
    .unwrap()
}
fn credentials() -> S3Credentials {
    S3Credentials::from_lines(b"fixture-access\nfixture-secret\n".to_vec()).unwrap()
}
fn owners(
    endpoint: &S3Endpoint,
    pin: S3ObjectPin,
    allowance: BudgetVector,
    grants: &[RuntimeGrant],
) -> (AuthorityCx, AuthorityCx, AuthorityCx, RegionTree) {
    owners_with_resources(
        pin,
        allowance,
        grants,
        Some(&[endpoint.resource().to_owned()]),
    )
}
fn owners_with_resources(
    pin: S3ObjectPin,
    allowance: BudgetVector,
    grants: &[RuntimeGrant],
    resources: Option<&[String]>,
) -> (AuthorityCx, AuthorityCx, AuthorityCx, RegionTree) {
    let spec = RootAuthoritySpec {
        trace_id: "trace:s3-read-fixture".into(),
        operation_id: OperationId::parse("operation:s3-read-fixture").unwrap(),
        principal: "principal:s3-read-fixture".into(),
        capabilities: grants
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect(),
        deadline: Some(DEADLINE),
        priority: 10,
        budgets: allowance,
        privacy_scope: "privacy:fixture".into(),
        retention_scope: "retention:fixture".into(),
        anchor_universe: pin.digest,
        generation: 1,
    };
    let (mut root, mut tree) = AuthorityCx::root(
        spec.clone(),
        RegionId::new("region:read-process").unwrap(),
        RegionKind::Process,
        allowance,
        NOW,
    )
    .unwrap();
    if let Some(resources) = resources {
        let mut scopes = GrantSet::empty();
        for grant in grants {
            scopes = scopes.with_scope(*grant, resources.iter().cloned().collect());
        }
        root.narrow_grants(scopes).unwrap();
    }
    let mut property = root
        .scope_down(
            &mut tree,
            RegionId::new("region:read-property").unwrap(),
            RegionKind::Property,
            allowance,
            spec.clone(),
            NOW,
        )
        .unwrap();
    let object = property
        .scope_down(
            &mut tree,
            RegionId::new("region:read-object").unwrap(),
            RegionKind::ObjectStore,
            allowance,
            spec,
            NOW,
        )
        .unwrap();
    (root, property, object, tree)
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
fn request(socket: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let count = socket.read(&mut chunk).unwrap();
        assert!(count > 0);
        head.extend_from_slice(&chunk[..count]);
        assert!(head.len() <= 8192);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("GET /archive/evidence//../a%20b HTTP/1.1\r\n"));
    assert!(head.contains("content-length: 0\r\n"));
    assert!(head.contains("accept-encoding: identity\r\n"));
    assert!(
        head.contains(
            "AWS4-HMAC-SHA256 Credential=fixture-access/20130524/us-east-1/s3/aws4_request"
        )
    );
    assert!(!head.contains("fixture-secret"));
    head
}
struct Response {
    status: u16,
    headers: String,
    bytes: Vec<u8>,
}
fn range_response(bytes: &[u8], start: usize, total: usize, etag: &str) -> Response {
    Response {
        status: if total == 0 { 200 } else { 206 },
        headers: format!(
            "Content-Length: {}\r\nETag: {etag}\r\n{}",
            bytes.len(),
            if total == 0 {
                String::new()
            } else {
                format!(
                    "Content-Range: bytes {start}-{}/{total}\r\n",
                    start + bytes.len() - 1
                )
            }
        ),
        bytes: bytes.to_vec(),
    }
}
fn fixture<C: S3ReadClock>(
    pin: S3ObjectPin,
    responses: Vec<Response>,
    clock: &mut C,
) -> (
    Result<S3VerificationReceipt, S3Error>,
    Vec<String>,
    BudgetVector,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let allowance = verification_budget(pin, limits()).unwrap();
    let (mut root, mut property, mut reader, mut tree) =
        owners(&endpoint, pin, allowance, &READ_GRANTS);
    let (result, heads) = std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            responses
                .into_iter()
                .map(|response| {
                    let mut socket = accept(&listener);
                    let head = request(&mut socket);
                    let wire = format!(
                        "HTTP/1.1 {} Fixture\r\n{}Connection: close\r\n\r\n",
                        response.status, response.headers
                    );
                    socket.write_all(wire.as_bytes()).unwrap();
                    socket.write_all(&response.bytes).unwrap();
                    head
                })
                .collect::<Vec<_>>()
        });
        let result = verify_s3_object(
            &endpoint,
            &credentials(),
            limits(),
            clock,
            S3ReadIo {
                authority: &mut reader,
                tree: &tree,
                now: NOW,
            },
            pin,
        );
        (result, server.join().unwrap())
    });
    listener.set_nonblocking(true).unwrap();
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    let consumed = *reader.budget().consumed();
    reader.request_cancellation(&mut tree, DEADLINE).unwrap();
    reader.begin_drain(&mut tree, DEADLINE).unwrap();
    reader.finalize(&mut tree, DEADLINE).unwrap();
    property.release_scope_reservation(&tree, &reader).unwrap();
    property.request_cancellation(&mut tree, DEADLINE).unwrap();
    property.begin_drain(&mut tree, DEADLINE).unwrap();
    property.finalize(&mut tree, DEADLINE).unwrap();
    root.release_scope_reservation(&tree, &property).unwrap();
    root.request_cancellation(&mut tree, DEADLINE).unwrap();
    root.begin_drain(&mut tree, DEADLINE).unwrap();
    root.finalize(&mut tree, DEADLINE).unwrap();
    (result, heads, consumed)
}

#[test]
fn complete_stream_hashes_exact_bytes_and_pins_every_later_signed_range() {
    let bytes: Vec<_> = (0..2561).map(|n| (n % 251) as u8).collect();
    let expected = pin(&bytes);
    let responses = bytes
        .chunks(1024)
        .enumerate()
        .map(|(n, chunk)| range_response(chunk, n * 1024, bytes.len(), "\"stable\""))
        .collect();
    let (result, heads, consumed) = fixture(expected, responses, &mut Clock);
    let receipt = result.unwrap();
    assert_eq!(receipt.object(), expected);
    assert_eq!(receipt.consumed(), consumed);
    assert_eq!(consumed, verification_budget(expected, limits()).unwrap());
    assert_eq!(heads.len(), 3);
    assert!(heads[0].contains("range: bytes=0-1023\r\n"));
    assert!(!heads[0].contains("if-match:"));
    assert!(heads[1].contains("range: bytes=1024-2047\r\n"));
    assert!(heads[2].contains("range: bytes=2048-2560\r\n"));
    for head in &heads[1..] {
        assert!(head.contains("if-match: \"stable\"\r\n"));
        let authorization = head
            .lines()
            .find(|line| line.starts_with("authorization: "))
            .unwrap();
        assert!(authorization.contains(";if-match;"));
        assert!(authorization.contains(";range;"));
    }
    let encoded = receipt.encode().unwrap();
    assert_eq!(S3VerificationReceipt::decode(&encoded).unwrap(), receipt);
    assert_eq!(receipt.digest().unwrap(), ContentDigest::sha256(&encoded));
    assert!(!String::from_utf8_lossy(&encoded).contains("fixture-secret"));
    assert!(!String::from_utf8_lossy(&encoded).contains("evidence//../a b"));
    assert!(S3VerificationReceipt::decode(&encoded[..encoded.len() - 1]).is_err());
    let mut suffixed = encoded;
    suffixed.push(0);
    assert!(S3VerificationReceipt::decode(&suffixed).is_err());
}

#[test]
fn same_length_corruption_never_creates_a_verification_receipt() {
    let (result, _, consumed) = fixture(
        pin(b"abc"),
        vec![range_response(b"abd", 0, 3, "\"stable\"")],
        &mut Clock,
    );
    assert_eq!(result.unwrap_err(), S3Error::Integrity);
    assert_eq!(consumed.storage_operations, 1);
}

#[test]
fn provider_cannot_mix_versions_even_when_it_ignores_if_match() {
    let bytes = vec![b'x'; 2048];
    let (result, heads, _) = fixture(
        pin(&bytes),
        vec![
            range_response(&bytes[..1024], 0, 2048, "\"version-one\""),
            range_response(&bytes[1024..], 1024, 2048, "\"version-two\""),
        ],
        &mut Clock,
    );
    assert!(result.is_err());
    assert!(heads[1].contains("if-match: \"version-one\"\r\n"));
}

#[test]
fn empty_object_is_a_real_exact_zero_length_get() {
    let (result, heads, _) = fixture(
        pin(b""),
        vec![range_response(b"", 0, 0, "\"empty\"")],
        &mut Clock,
    );
    assert_eq!(result.unwrap().object(), pin(b""));
    assert_eq!(heads.len(), 1);
    assert!(!heads[0].contains("range:"));
}

#[test]
fn malformed_range_version_encoding_and_provider_status_cannot_pass() {
    let mutations: [fn(&mut Response); 10] = [
        |r| r.status = 200,
        |r| r.status = 403,
        |r| r.status = 301,
        |r| r.headers = r.headers.replace("bytes 0-2/3", "bytes 1-3/3"),
        |r| r.headers = r.headers.replace("bytes 0-2/3", "bytes 0-2/4"),
        |r| r.headers = r.headers.replace("ETag: \"stable\"", "ETag: W/\"stable\""),
        |r| r.headers.push_str("ETag: \"stable\"\r\n"),
        |r| r.headers.push_str("Content-Encoding: gzip\r\n"),
        |r| r.headers.push_str("x-amz-delete-marker: true\r\n"),
        |r| r.headers.push_str("Content-Range: bytes 0-2/3\r\n"),
    ];
    for mutate in mutations {
        let mut response = range_response(b"abc", 0, 3, "\"stable\"");
        mutate(&mut response);
        let (result, _, _) = fixture(pin(b"abc"), vec![response], &mut Clock);
        assert!(
            result.is_err(),
            "ambiguous provider response created a receipt"
        );
    }
}

#[test]
fn truncated_and_extra_body_bytes_cannot_pass() {
    for bytes in [b"ab".as_slice(), b"abcd".as_slice()] {
        let mut response = range_response(b"abc", 0, 3, "\"stable\"");
        response.bytes = bytes.to_vec();
        if bytes.len() > 3 {
            // Frame all four bytes so refusal cannot depend on TCP packet splitting.
            response.headers = response
                .headers
                .replace("Content-Length: 3", "Content-Length: 4");
        }
        let (result, _, _) = fixture(pin(b"abc"), vec![response], &mut Clock);
        assert!(result.is_err());
    }
}

#[test]
fn the_original_deadline_stops_later_ranges_without_a_new_connection() {
    let bytes = vec![b'x'; 2048];
    let (result, heads, consumed) = fixture(
        pin(&bytes),
        vec![range_response(&bytes[..1024], 0, 2048, "\"stable\"")],
        &mut ExpireAfterFirstRange,
    );
    assert_eq!(result.unwrap_err(), S3Error::Deadline);
    assert_eq!(heads.len(), 1);
    // The admitted second reservation remains charged even though no second GET ran.
    assert_eq!(consumed.storage_operations, 2);
}

fn no_socket(listener: &TcpListener) {
    listener.set_nonblocking(true).unwrap();
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn cancellation_on_an_ancestor_refuses_before_clock_or_network() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let pin = pin(b"abc");
    let allowance = verification_budget(pin, limits()).unwrap();
    let (mut root, _, mut reader, mut tree) = owners(&endpoint, pin, allowance, &READ_GRANTS);
    root.request_cancellation(&mut tree, NOW).unwrap();
    let result = verify_s3_object(
        &endpoint,
        &credentials(),
        limits(),
        &mut NoClock,
        S3ReadIo {
            authority: &mut reader,
            tree: &tree,
            now: NOW,
        },
        pin,
    );
    assert_eq!(result.unwrap_err(), S3Error::Authority);
    assert_eq!(*reader.budget().consumed(), BudgetVector::ZERO);
    no_socket(&listener);
}

#[test]
fn metadata_authority_does_not_authorize_raw_media_reads() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let pin = pin(b"abc");
    let allowance = verification_budget(pin, limits()).unwrap();
    let grants = [
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::ObserveStatus,
    ];
    let (_, _, mut reader, tree) = owners(&endpoint, pin, allowance, &grants);
    let result = verify_s3_object(
        &endpoint,
        &credentials(),
        limits(),
        &mut NoClock,
        S3ReadIo {
            authority: &mut reader,
            tree: &tree,
            now: NOW,
        },
        pin,
    );
    assert_eq!(result.unwrap_err(), S3Error::Authority);
    no_socket(&listener);
}

#[test]
fn unscoped_media_grants_are_refused_before_clock_or_network() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let pin = pin(b"abc");
    let allowance = verification_budget(pin, limits()).unwrap();
    let (_, _, mut reader, tree) = owners_with_resources(pin, allowance, &READ_GRANTS, None);
    let result = verify_s3_object(
        &endpoint,
        &credentials(),
        limits(),
        &mut NoClock,
        S3ReadIo {
            authority: &mut reader,
            tree: &tree,
            now: NOW,
        },
        pin,
    );
    assert_eq!(result.unwrap_err(), S3Error::Authority);
    assert_eq!(*reader.budget().consumed(), BudgetVector::ZERO);
    no_socket(&listener);
}

#[test]
fn multi_object_media_grants_are_refused_before_clock_or_network() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let pin = pin(b"abc");
    let allowance = verification_budget(pin, limits()).unwrap();
    let resources = [
        endpoint.resource().to_owned(),
        "object:unrelated-archive".to_owned(),
    ];
    let (_, _, mut reader, tree) =
        owners_with_resources(pin, allowance, &READ_GRANTS, Some(&resources));
    let result = verify_s3_object(
        &endpoint,
        &credentials(),
        limits(),
        &mut NoClock,
        S3ReadIo {
            authority: &mut reader,
            tree: &tree,
            now: NOW,
        },
        pin,
    );
    assert_eq!(result.unwrap_err(), S3Error::Authority);
    assert_eq!(*reader.budget().consumed(), BudgetVector::ZERO);
    no_socket(&listener);
}

#[test]
fn independent_digest_must_match_the_actual_authority_anchor() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let requested = pin(b"abc");
    let allowance = verification_budget(requested, limits()).unwrap();
    let (_, _, mut reader, tree) = owners(&endpoint, pin(b"abd"), allowance, &READ_GRANTS);
    let result = verify_s3_object(
        &endpoint,
        &credentials(),
        limits(),
        &mut NoClock,
        S3ReadIo {
            authority: &mut reader,
            tree: &tree,
            now: NOW,
        },
        requested,
    );
    assert_eq!(result.unwrap_err(), S3Error::Authority);
    assert_eq!(*reader.budget().consumed(), BudgetVector::ZERO);
    no_socket(&listener);
}

#[test]
fn insufficient_or_already_spent_allowance_refuses_before_io() {
    for already_spent in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let pin = pin(b"abc");
        let mut allowance = verification_budget(pin, limits()).unwrap();
        if !already_spent {
            allowance.network_bytes -= 1;
        }
        let (_, _, mut reader, tree) = owners(&endpoint, pin, allowance, &READ_GRANTS);
        if already_spent {
            let mut cost = BudgetVector::ZERO;
            cost.bytes = 1;
            reader
                .budget_mut(&tree)
                .unwrap()
                .spend_vector(&cost)
                .unwrap();
        }
        let result = verify_s3_object(
            &endpoint,
            &credentials(),
            limits(),
            &mut NoClock,
            S3ReadIo {
                authority: &mut reader,
                tree: &tree,
                now: NOW,
            },
            pin,
        );
        assert_eq!(result.unwrap_err(), S3Error::Limit);
        no_socket(&listener);
    }
}

#[test]
fn object_identity_is_validated_before_any_authority_or_media_work() {
    assert_eq!(
        verification_budget(
            S3ObjectPin {
                digest: ContentDigest::sha256(b"nonempty"),
                bytes: 0,
            },
            limits()
        )
        .unwrap_err(),
        S3Error::Configuration
    );
    assert_eq!(
        verification_budget(
            S3ObjectPin {
                digest: ContentDigest::sha256(b"oversized"),
                bytes: MAX_VERIFIED_OBJECT_BYTES + 1,
            },
            limits()
        )
        .unwrap_err(),
        S3Error::Configuration
    );
}
