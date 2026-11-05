#![forbid(unsafe_code)]
//! Synthetic bounded Ubiquiti discovery reply and privacy contracts.

use fss_packet::unifi_discovery::{DeviceKind, Error, Reply, V1_QUERY};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn packet(fields: &[(u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (kind, bytes) in fields {
        body.push(*kind);
        body.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(bytes);
    }
    let mut out = vec![1, 0];
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

#[test]
fn camera_candidate_and_multiple_addresses_are_untrusted_bounded_claims() -> TestResult {
    assert_eq!(V1_QUERY, [1, 0, 0, 0]);
    let bytes = packet(&[
        (1, &[0x10, 2, 3, 4, 5, 6]),
        (2, &[0x10, 2, 3, 4, 5, 6, 192, 0, 2, 3]),
        (2, &[0x10, 2, 3, 4, 5, 7, 192, 0, 2, 4]),
        (3, b"UVC.v4.example"),
        (12, b"UVC G4 Instant"),
        (6, b"PRIVATE_USERNAME"),
        (7, b"PRIVATE_CHALLENGE"),
    ]);
    let reply = Reply::parse(&bytes)?;
    assert_eq!(reply.kind(), DeviceKind::CameraCandidate);
    assert_eq!(reply.platform(), Some("UVC G4 Instant"));
    assert_eq!(reply.firmware(), Some("UVC.v4.example"));
    assert_eq!(reply.mac(), Some([0x10, 2, 3, 4, 5, 6]));
    assert_eq!(reply.address_count(), 2);
    let addresses: Vec<_> = reply.addresses().collect();
    assert_eq!(addresses[0].ipv4, [192, 0, 2, 3]);
    assert_eq!(addresses[1].ipv4, [192, 0, 2, 4]);
    assert!(!format!("{reply:?}").contains("PRIVATE"));
    assert!(!format!("{reply:?}").contains("192"));
    assert!(!format!("{:?}", addresses[0]).contains("192"));
    Ok(())
}

#[test]
fn vendor_equipment_and_missing_platform_are_not_camera_claims() -> TestResult {
    for bytes in [
        packet(&[(12, b"U6 Enterprise")]),
        packet(&[(3, b"UVC.fake")]),
        packet(&[]),
    ] {
        assert_eq!(Reply::parse(&bytes)?.kind(), DeviceKind::OtherOrUnknown);
    }
    Ok(())
}

#[test]
fn malformed_lengths_duplicate_identity_and_non_ascii_fail_closed() {
    let valid = packet(&[(12, b"UVC G4 Instant")]);
    for cut in 0..valid.len() {
        assert!(Reply::parse(&valid[..cut]).is_err());
    }
    let mut invalid = valid.clone();
    invalid[0] = 2;
    assert_eq!(Reply::parse(&invalid), Err(Error::Unsupported));
    invalid = valid.clone();
    invalid.extend_from_slice(&[0]);
    assert_eq!(Reply::parse(&invalid), Err(Error::Length));
    assert_eq!(
        Reply::parse(&packet(&[(1, &[1, 2]), (12, b"UVC")])),
        Err(Error::InvalidField)
    );
    assert_eq!(
        Reply::parse(&packet(&[(2, &[1, 2]), (12, b"UVC")])),
        Err(Error::InvalidField)
    );
    assert_eq!(
        Reply::parse(&packet(&[(12, b"UVC"), (12, b"UVC")])),
        Err(Error::InvalidField)
    );
    assert_eq!(
        Reply::parse(&packet(&[(12, b"UVC\x00bad")])),
        Err(Error::InvalidField)
    );
    assert_eq!(
        Reply::parse(&packet(&[(3, &[0xff])])),
        Err(Error::InvalidField)
    );
}

#[test]
fn field_count_and_datagram_bounds_are_enforced() {
    let repeated = vec![(99_u8, &[][..]); 129];
    assert_eq!(Reply::parse(&packet(&repeated)), Err(Error::FieldLimit));
    assert_eq!(Reply::parse(&vec![0; 8193]), Err(Error::Length));
}
