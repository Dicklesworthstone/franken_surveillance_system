#![forbid(unsafe_code)]
//! Independently pinned disaster recovery, without an upload journal or owner.

use super::*;
use fss_core::RegionState;
use fss_reference::s3_upload::verification::{
    VerifiedS3ObjectBytes, verification_with_bytes_budget, verify_s3_object_with_bytes,
};

fn retained_fixture<C: S3ReadClock>(
    pin: S3ObjectPin,
    responses: Vec<Response>,
    clock: &mut C,
) -> (
    Result<VerifiedS3ObjectBytes, S3Error>,
    Vec<String>,
    BudgetVector,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let allowance = verification_with_bytes_budget(pin, limits()).unwrap();
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
        let result = verify_s3_object_with_bytes(
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
    no_socket(&listener);
    let consumed = *reader.budget().consumed();
    // Verification never settles a region it does not own. The caller must
    // drain and release the reader even when no verified media can be returned.
    assert_eq!(
        tree.get(reader.region()).unwrap().state,
        RegionState::Active
    );
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
fn standalone_recovery_returns_exact_bytes_only_after_complete_verification() {
    let source = b"private retained evidence material; ".repeat(74);
    let expected = pin(&source);
    let responses = source
        .chunks(1024)
        .enumerate()
        .map(|(n, chunk)| range_response(chunk, n * 1024, source.len(), "\"stable\""))
        .collect();
    let (result, heads, consumed) = retained_fixture(expected, responses, &mut Clock);
    let verified = result.unwrap();
    assert_eq!(verified.bytes(), source);
    assert_eq!(ContentDigest::sha256(verified.bytes()), expected.digest);
    assert_eq!(verified.receipt().object(), expected);
    assert_eq!(verified.receipt().consumed(), consumed);
    assert_eq!(
        consumed,
        verification_with_bytes_budget(expected, limits()).unwrap()
    );
    let mut streaming_cost = consumed;
    streaming_cost.bytes -= expected.bytes;
    assert_eq!(
        streaming_cost,
        verification_budget(expected, limits()).unwrap()
    );
    assert_eq!(heads.len(), source.len().div_ceil(1024));
    assert!(!heads[0].contains("if-match:"));
    for (n, head) in heads.iter().enumerate() {
        let end = ((n + 1) * 1024).min(source.len()) - 1;
        assert!(head.contains(&format!("range: bytes={}-{end}\r\n", n * 1024)));
        if n != 0 {
            assert!(head.contains("if-match: \"stable\"\r\n"));
            assert!(head.contains("SignedHeaders=accept-encoding;host;if-match;range;"));
        }
    }
    let canonical = verified.receipt().encode().unwrap();
    assert_eq!(
        S3VerificationReceipt::decode(&canonical).unwrap(),
        *verified.receipt()
    );
    assert_eq!(
        verified.receipt().digest().unwrap(),
        ContentDigest::sha256(&canonical)
    );
    assert!(
        !canonical
            .windows(16)
            .any(|window| window == b"private retained")
    );
    let debug = format!("{verified:?}");
    assert!(debug.contains(&format!("byte_len: {}", source.len())));
    assert!(!debug.contains("private retained"));
    assert!(!debug.contains("fixture-secret"));
}

#[test]
fn standalone_empty_recovery_retains_empty_bytes_after_one_exact_get() {
    let expected = pin(b"");
    let (result, heads, consumed) = retained_fixture(
        expected,
        vec![range_response(b"", 0, 0, "\"empty\"")],
        &mut Clock,
    );
    let verified = result.unwrap();
    assert!(verified.bytes().is_empty());
    assert_eq!(verified.receipt().object(), expected);
    assert_eq!(consumed, verification_budget(expected, limits()).unwrap());
    assert_eq!(heads.len(), 1);
    assert!(!heads[0].contains("range:"));
    assert!(!heads[0].contains("if-match:"));
}

#[test]
fn complete_retained_buffer_allowance_is_required_before_clock_or_network() {
    for only_streaming in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(listener.local_addr().unwrap());
        let expected = pin(b"recoverable bytes");
        let mut allowance = if only_streaming {
            verification_budget(expected, limits()).unwrap()
        } else {
            verification_with_bytes_budget(expected, limits()).unwrap()
        };
        if !only_streaming {
            allowance.bytes -= 1;
        }
        let (_, _, mut reader, tree) = owners(&endpoint, expected, allowance, &READ_GRANTS);
        let result = verify_s3_object_with_bytes(
            &endpoint,
            &credentials(),
            limits(),
            &mut NoClock,
            S3ReadIo {
                authority: &mut reader,
                tree: &tree,
                now: NOW,
            },
            expected,
        );
        assert_eq!(result.unwrap_err(), S3Error::Limit);
        assert_eq!(*reader.budget().consumed(), BudgetVector::ZERO);
        no_socket(&listener);
    }
}

#[test]
fn corruption_or_version_change_never_exposes_a_verified_prefix() {
    let source = vec![42; 1025];
    let expected = pin(&source);
    for changed_version in [false, true] {
        let tail = if changed_version { 42 } else { 43 };
        let etag = if changed_version {
            "\"replaced\""
        } else {
            "\"stable\""
        };
        let (result, heads, consumed) = retained_fixture(
            expected,
            vec![
                range_response(&source[..1024], 0, source.len(), "\"stable\""),
                range_response(&[tail], 1024, source.len(), etag),
            ],
            &mut Clock,
        );
        assert_eq!(
            result.unwrap_err(),
            if changed_version {
                S3Error::Protocol
            } else {
                S3Error::Integrity
            }
        );
        assert_eq!(heads.len(), 2);
        assert!(heads[1].contains("if-match: \"stable\"\r\n"));
        assert_eq!(
            consumed,
            verification_with_bytes_budget(expected, limits()).unwrap()
        );
    }
}

#[test]
fn truncated_last_range_never_releases_partial_recovery_bytes() {
    let source = vec![42; 1026];
    let expected = pin(&source);
    let mut truncated = range_response(&source[1024..], 1024, source.len(), "\"stable\"");
    truncated.bytes.pop();
    let (result, heads, _) = retained_fixture(
        expected,
        vec![
            range_response(&source[..1024], 0, source.len(), "\"stable\""),
            truncated,
        ],
        &mut Clock,
    );
    assert_eq!(result.unwrap_err(), S3Error::Protocol);
    assert_eq!(heads.len(), 2);
}

#[test]
fn expiry_discards_already_read_media_before_any_later_request() {
    let source = vec![42; 2048];
    let expected = pin(&source);
    let (result, heads, consumed) = retained_fixture(
        expected,
        vec![range_response(
            &source[..1024],
            0,
            source.len(),
            "\"stable\"",
        )],
        &mut ExpireAfterFirstRange,
    );
    assert_eq!(result.unwrap_err(), S3Error::Deadline);
    assert_eq!(heads.len(), 1);
    assert_eq!(
        consumed,
        verification_with_bytes_budget(expected, limits()).unwrap()
    );
}

#[test]
fn standalone_recovery_requires_the_independent_authority_pin_before_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(listener.local_addr().unwrap());
    let expected = pin(b"original independent object");
    let allowance = verification_with_bytes_budget(expected, limits()).unwrap();
    let (_, _, mut reader, tree) =
        owners(&endpoint, pin(b"different object"), allowance, &READ_GRANTS);
    let result = verify_s3_object_with_bytes(
        &endpoint,
        &credentials(),
        limits(),
        &mut NoClock,
        S3ReadIo {
            authority: &mut reader,
            tree: &tree,
            now: NOW,
        },
        expected,
    );
    assert_eq!(result.unwrap_err(), S3Error::Authority);
    assert_eq!(*reader.budget().consumed(), BudgetVector::ZERO);
    no_socket(&listener);
}
