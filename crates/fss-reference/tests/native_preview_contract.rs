#![forbid(unsafe_code)]
//! Real native AVC/HEVC preview derivatives, durable gating and independent reader bounds.

#[path = "recording_support/mod.rs"]
mod avc;
#[path = "hevc_recording_support/mod.rs"]
mod hevc;

use std::cell::Cell;

use fss_core::ContentDigest;
use fss_reference::rtsp::preview::{
    PreviewAuthority, PreviewCodec, PreviewError, PreviewHub, PreviewLimits, PreviewMetadata,
    PreviewRead, PreviewScope, PreviewSkip, PublishOutcome, StageOutcome, SubscriberId,
};
use fss_reference::rtsp::recording::PreparedRecording;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

struct Authority {
    scope: PreviewScope,
    refusal: Cell<Option<PreviewError>>,
    checkpoints: Cell<u64>,
}
impl PreviewAuthority for Authority {
    fn checkpoint(&self, scope: &PreviewScope, _now_ns: u64) -> Result<(), PreviewError> {
        self.checkpoints.set(self.checkpoints.get() + 1);
        if scope != &self.scope {
            return Err(PreviewError::Unauthorized);
        }
        match self.refusal.get() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn scope(recording: &PreparedRecording, codec: PreviewCodec) -> PreviewScope {
    PreviewScope {
        recording: recording.summary().scope.clone(),
        codec,
        time_scale: recording.summary().time_scale,
        decode_clock: ContentDigest::sha256(b"explicit-native-preview-decode-clock"),
        privacy_binding: ContentDigest::sha256(b"approved-local-unredacted-preview-fixture"),
        expires_at_ns: 10_000,
    }
}

fn owner(scope: PreviewScope, limits: PreviewLimits) -> Result<(PreviewHub, Authority), Error> {
    let authority = Authority {
        scope: scope.clone(),
        refusal: Cell::new(None),
        checkpoints: Cell::new(0),
    };
    let hub = PreviewHub::new(scope, limits, 0, &authority)?;
    Ok((hub, authority))
}

fn window(ordinal: u16) -> Result<PreparedRecording, Error> {
    avc::repeated(
        100 + u128::from(ordinal),
        1,
        1 + ordinal * 16,
        u32::from(ordinal) * 3_600,
    )?
    .prepare_at(u64::from(ordinal) * 3_600)
}

fn publish(
    hub: &mut PreviewHub,
    recording: &PreparedRecording,
    now_ns: u64,
    authority: &Authority,
) -> Result<PreviewMetadata, Error> {
    if !matches!(
        hub.stage(recording, now_ns, authority)?,
        StageOutcome::Staged { .. }
    ) {
        return Err("fixture derivative was not newly staged".into());
    }
    match hub.publish_durable(recording.manifest().root(), now_ns, authority)? {
        PublishOutcome::Published(metadata) => Ok(metadata),
        _ => Err("fixture derivative was not newly published".into()),
    }
}

fn read_body(
    hub: &mut PreviewHub,
    id: SubscriberId,
    metadata: &PreviewMetadata,
    now_ns: u64,
    authority: &Authority,
) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    while body.len() < metadata.body_bytes() {
        let before = body.len();
        body.extend_from_slice(hub.chunk(id, metadata.sequence, before, 257, now_ns, authority)?);
        let written = body.len() - before;
        if written == 0 || body.len() > metadata.body_bytes() {
            return Err("preview response made invalid progress".into());
        }
        hub.advance(id, metadata.sequence, written, now_ns, authority)?;
    }
    Ok(body)
}

fn expected_body(recording: &PreparedRecording) -> Vec<u8> {
    let objects = recording.objects();
    [objects.initialization, objects.media].concat()
}

#[test]
fn native_avc_is_invisible_until_matching_durable_root_and_replays_exact_remux() -> TestResult {
    let recording = window(0)?;
    let root = recording.manifest().root();
    let (mut hub, authority) = owner(
        scope(&recording, PreviewCodec::Avc),
        PreviewLimits::default(),
    )?;
    let id = hub.subscribe(100, 0, &authority)?;
    assert_eq!(hub.next(id, 0, &authority)?, PreviewRead::Empty);
    assert_eq!(hub.latest(0, &authority)?, None);
    let source_digest = ContentDigest::sha256(recording.objects().source);
    assert_eq!(
        hub.stage(&recording, 1, &authority)?,
        StageOutcome::Staged {
            root,
            bytes: expected_body(&recording).len()
        }
    );
    assert_eq!(
        hub.stage(&recording, 2, &authority)?,
        StageOutcome::AlreadyStaged { root }
    );
    assert_eq!(hub.latest(2, &authority)?, None);
    assert_eq!(
        hub.chunk(id, 1, 0, 8, 2, &authority),
        Err(PreviewError::Evicted)
    );
    assert_eq!(
        hub.publish_durable(
            ContentDigest::sha256(b"different-source-root"),
            2,
            &authority
        ),
        Err(PreviewError::PublicationMismatch)
    );
    assert_eq!(hub.status().staged, 1);
    let metadata = match hub.publish_durable(root, 3, &authority)? {
        PublishOutcome::Published(metadata) => metadata,
        _ => return Err("durable source root did not publish its derivative".into()),
    };
    assert_eq!(metadata.sequence, 1);
    assert_eq!(metadata.root, root);
    assert_eq!(metadata.admitted_at_ns, 1);
    assert_eq!(metadata.published_at_ns, 3);
    assert_eq!(metadata.mime, "video/mp4; codecs=\"avc1.42C00B\"");
    assert_eq!(metadata.decode_interval, 0..3_600);
    assert_eq!(metadata.time_scale, 90_000);
    assert_eq!(metadata.samples, 1);
    assert_eq!(
        metadata.initialization_digest,
        ContentDigest::sha256(recording.objects().initialization)
    );
    assert_eq!(
        metadata.media_digest,
        ContentDigest::sha256(recording.objects().media)
    );
    assert_eq!(
        hub.next(id, 3, &authority)?,
        PreviewRead::Fragment(metadata.clone())
    );
    assert_eq!(
        read_body(&mut hub, id, &metadata, 3, &authority)?,
        expected_body(&recording)
    );
    assert_eq!(hub.next(id, 3, &authority)?, PreviewRead::Empty);
    assert_eq!(
        hub.publish_durable(root, 4, &authority)?,
        PublishOutcome::AlreadyPublished { sequence: 1 }
    );
    assert_eq!(hub.latest(4, &authority)?, Some(metadata.clone()));
    assert_eq!(hub.status().published, 1);
    assert_eq!(hub.status().written_bytes, metadata.body_bytes() as u64);
    assert_eq!(hub.status().charged_bytes, metadata.body_bytes() as u64);
    assert_eq!(
        source_digest,
        ContentDigest::sha256(recording.objects().source)
    );
    Ok(())
}

#[test]
fn native_hevc_preserves_hev1_configuration_and_source_linked_bytes() -> TestResult {
    let hevc = hevc::fixture()?;
    let recording = hevc.publication_plan();
    let (mut hub, authority) = owner(
        scope(recording, PreviewCodec::Hevc),
        PreviewLimits::default(),
    )?;
    let metadata = publish(&mut hub, recording, 1, &authority)?;
    assert_eq!(metadata.codec, PreviewCodec::Hevc);
    // Retained fixture PTL is 01 60000000 900000000000 1e: compatibility bit order
    // reverses to 6; tier is L, level is decimal 30, and zero constraint suffixes trim.
    assert_eq!(metadata.mime, "video/mp4; codecs=\"hev1.1.6.L30.90\"");
    assert_eq!(metadata.decode_interval, 0..72_000);
    assert_eq!(metadata.samples, 4);
    let id = hub.subscribe_at(metadata.sequence, 100, 1, &authority)?;
    assert_eq!(
        read_body(&mut hub, id, &metadata, 1, &authority)?,
        expected_body(recording)
    );
    let (mut wrong, wrong_authority) = owner(
        scope(recording, PreviewCodec::Avc),
        PreviewLimits::default(),
    )?;
    assert_eq!(
        wrong.stage(recording, 1, &wrong_authority),
        Err(PreviewError::Scope)
    );
    assert_eq!(wrong.status().candidate_bytes, 0);
    Ok(())
}

#[test]
fn one_candidate_and_scope_clock_configuration_order_cannot_be_replaced() -> TestResult {
    let first = window(0)?;
    let second = window(1)?;
    let (mut hub, authority) = owner(scope(&first, PreviewCodec::Avc), PreviewLimits::default())?;
    hub.stage(&first, 1, &authority)?;
    assert_eq!(
        hub.stage(&second, 2, &authority),
        Err(PreviewError::Pending)
    );
    hub.publish_durable(first.manifest().root(), 2, &authority)?;
    assert_eq!(
        hub.stage(&first, 2, &authority),
        Err(PreviewError::Reordered)
    );
    assert_eq!(
        hub.stage(&second, 1, &authority),
        Err(PreviewError::ClockRegression)
    );
    let different_initialization = avc::repeated_from(
        555,
        1,
        100,
        3_600,
        include_bytes!("../../fss-packet/tests/fixtures/avc/high_cropped.264"),
    )?
    .prepare_at(3_600)?;
    assert_eq!(
        hub.stage(&different_initialization, 3, &authority),
        Err(PreviewError::Scope)
    );
    assert_eq!(hub.status().candidate_bytes, 0);
    assert!(matches!(
        hub.stage(&second, 3, &authority)?,
        StageOutcome::Staged { .. }
    ));

    let original_scope = scope(&first, PreviewCodec::Avc);
    let mut variants = Vec::new();
    let mut generation = original_scope.clone();
    generation.recording.generation += 1;
    variants.push(generation);
    let mut receive_clock = original_scope.clone();
    receive_clock.recording.receive_clock = ContentDigest::sha256(b"other-receive-epoch");
    variants.push(receive_clock);
    let mut anchor = original_scope.clone();
    anchor.recording.anchor = ContentDigest::sha256(b"other-source-anchor");
    variants.push(anchor);
    let mut time_scale = original_scope;
    time_scale.time_scale += 1;
    variants.push(time_scale);
    for changed in variants {
        let (mut other, other_authority) = owner(changed, PreviewLimits::default())?;
        assert_eq!(
            other.stage(&first, 1, &other_authority),
            Err(PreviewError::Scope)
        );
        assert_eq!(other.status().candidate_bytes, 0);
    }
    Ok(())
}

#[test]
fn slow_reader_whole_window_gaps_do_not_stop_fast_reader_or_recording() -> TestResult {
    let first = window(0)?;
    let second = window(1)?;
    let third = window(2)?;
    let limits = PreviewLimits {
        max_fragments: 1,
        ..PreviewLimits::default()
    };
    let (mut hub, authority) = owner(scope(&first, PreviewCodec::Avc), limits)?;
    let one = publish(&mut hub, &first, 1, &authority)?;
    let slow = hub.subscribe_at(one.sequence, 100, 1, &authority)?;
    let fast = hub.subscribe_at(one.sequence, 100, 1, &authority)?;
    assert_eq!(
        read_body(&mut hub, fast, &one, 1, &authority)?,
        expected_body(&first)
    );
    let two = publish(&mut hub, &second, 2, &authority)?;
    assert_eq!(
        hub.next(fast, 2, &authority)?,
        PreviewRead::Fragment(two.clone())
    );
    read_body(&mut hub, fast, &two, 2, &authority)?;
    let three = publish(&mut hub, &third, 3, &authority)?;
    assert_eq!(
        hub.next(slow, 3, &authority)?,
        PreviewRead::Gap {
            skipped: 2,
            next_sequence: 3
        }
    );
    assert_eq!(
        hub.next(slow, 3, &authority)?,
        PreviewRead::Fragment(three.clone())
    );
    assert_eq!(
        read_body(&mut hub, fast, &three, 3, &authority)?,
        expected_body(&third)
    );
    assert_eq!(
        read_body(&mut hub, slow, &three, 3, &authority)?,
        expected_body(&third)
    );
    assert_eq!(hub.status().queued_fragments, 1);
    assert_eq!(hub.status().queued_bytes, three.body_bytes());
    assert_eq!(hub.status().evicted, 2);
    assert_eq!(hub.status().published, 3);
    Ok(())
}

#[test]
fn byte_bound_eviction_never_splices_partial_or_unacknowledged_responses() -> TestResult {
    let first = window(0)?;
    let second = window(1)?;
    let bytes = expected_body(&first)
        .len()
        .max(expected_body(&second).len());
    let limits = PreviewLimits {
        max_fragments: 4,
        max_ring_bytes: bytes,
        max_fragment_bytes: bytes,
        max_initialization_bytes: first.objects().initialization.len(),
        ..PreviewLimits::default()
    };
    let (mut hub, authority) = owner(scope(&first, PreviewCodec::Avc), limits)?;
    let one = publish(&mut hub, &first, 1, &authority)?;
    let partial = hub.subscribe(100, 1, &authority)?;
    let uncertain = hub.subscribe(100, 1, &authority)?;
    assert_eq!(hub.chunk(partial, 1, 0, 20, 1, &authority)?.len(), 20);
    hub.advance(partial, 1, 7, 1, &authority)?;
    assert_eq!(hub.chunk(uncertain, 1, 0, 20, 1, &authority)?.len(), 20);
    let two = publish(&mut hub, &second, 2, &authority)?;
    assert_eq!(hub.status().queued_fragments, 1);
    assert!(hub.status().queued_bytes <= limits.max_ring_bytes);
    assert_eq!(hub.next(partial, 2, &authority), Err(PreviewError::Evicted));
    assert_eq!(
        hub.chunk(partial, one.sequence, 7, 20, 2, &authority),
        Err(PreviewError::Evicted)
    );
    assert_eq!(
        hub.chunk(partial, two.sequence, 0, 20, 2, &authority),
        Err(PreviewError::Evicted)
    );
    assert_eq!(
        hub.advance(uncertain, one.sequence, 11, 2, &authority),
        Err(PreviewError::Evicted)
    );
    assert_eq!(hub.status().charged_bytes, 18);
    assert_eq!(hub.status().written_bytes, 18);
    assert!(hub.disconnect(partial));
    assert!(hub.disconnect(uncertain));
    let recovered = hub.subscribe_at(two.sequence, 100, 2, &authority)?;
    assert_eq!(
        read_body(&mut hub, recovered, &two, 2, &authority)?,
        expected_body(&second)
    );
    Ok(())
}

#[test]
fn exact_manifest_selection_keeps_resident_old_window_and_rejects_missing_or_rewind() -> TestResult
{
    let first = window(0)?;
    let second = window(1)?;
    let (mut hub, authority) = owner(scope(&first, PreviewCodec::Avc), PreviewLimits::default())?;
    let one = publish(&mut hub, &first, 1, &authority)?;
    let two = publish(&mut hub, &second, 2, &authority)?;
    assert_eq!(hub.latest(2, &authority)?, Some(two));
    assert_eq!(hub.metadata(one.sequence, 2, &authority)?, one);
    assert_eq!(
        hub.subscribe_at(0, 100, 2, &authority),
        Err(PreviewError::Evicted)
    );
    assert_eq!(
        hub.subscribe_at(3, 100, 2, &authority),
        Err(PreviewError::Evicted)
    );
    let exact = hub.subscribe_at(one.sequence, 100, 2, &authority)?;
    assert_eq!(
        hub.chunk(exact, 2, 0, 4, 2, &authority),
        Err(PreviewError::Cursor)
    );
    assert_eq!(
        hub.chunk(exact, 1, 1, 4, 2, &authority),
        Err(PreviewError::Cursor)
    );
    assert_eq!(
        read_body(&mut hub, exact, &one, 2, &authority)?,
        expected_body(&first)
    );
    assert_eq!(
        hub.chunk(exact, one.sequence, 0, 4, 2, &authority),
        Err(PreviewError::Cursor)
    );
    Ok(())
}

#[test]
fn byte_offers_reserve_before_io_refund_only_known_unused_and_bound_every_client() -> TestResult {
    let recording = window(0)?;
    let limits = PreviewLimits {
        max_client_bytes: 10,
        max_total_bytes: 15,
        ..PreviewLimits::default()
    };
    let (mut hub, authority) = owner(scope(&recording, PreviewCodec::Avc), limits)?;
    publish(&mut hub, &recording, 1, &authority)?;
    let first = hub.subscribe(100, 1, &authority)?;
    let second = hub.subscribe(100, 1, &authority)?;
    assert_eq!(hub.chunk(first, 1, 0, usize::MAX, 1, &authority)?.len(), 10);
    assert_eq!(hub.status().charged_bytes, 10);
    assert_eq!(hub.status().written_bytes, 0);
    // WouldBlock retry exposes only the existing reservation, even with a larger request.
    assert_eq!(hub.chunk(first, 1, 0, usize::MAX, 1, &authority)?.len(), 10);
    assert_eq!(hub.status().charged_bytes, 10);
    assert_eq!(hub.chunk(second, 1, 0, usize::MAX, 1, &authority)?.len(), 5);
    assert_eq!(hub.status().charged_bytes, 15);
    hub.advance(first, 1, 3, 1, &authority)?;
    assert_eq!(hub.status().charged_bytes, 8);
    assert_eq!(hub.status().written_bytes, 3);
    assert_eq!(hub.chunk(first, 1, 3, usize::MAX, 1, &authority)?.len(), 7);
    hub.advance(first, 1, 7, 1, &authority)?;
    assert_eq!(
        hub.chunk(first, 1, 10, 1, 1, &authority),
        Err(PreviewError::Budget)
    );
    assert!(hub.disconnect(first));
    // Disconnect with an unresolved offer never pretends those five bytes were not exposed.
    assert!(hub.disconnect(second));
    assert_eq!(hub.status().charged_bytes, 15);
    assert_eq!(hub.status().written_bytes, 10);
    assert_eq!(hub.subscribe(100, 1, &authority), Err(PreviewError::Budget));
    assert_eq!(hub.status().subscriptions, 2);
    Ok(())
}

#[test]
fn authority_is_rechecked_on_metadata_and_actual_bytes_without_grant_by_possession() -> TestResult {
    let recording = window(0)?;
    let (mut hub, authority) = owner(
        scope(&recording, PreviewCodec::Avc),
        PreviewLimits::default(),
    )?;
    let metadata = publish(&mut hub, &recording, 1, &authority)?;
    let id = hub.subscribe(100, 1, &authority)?;
    let before = authority.checkpoints.get();
    hub.chunk(id, 1, 0, 8, 1, &authority)?;
    hub.advance(id, 1, 0, 1, &authority)?;
    assert!(authority.checkpoints.get() >= before + 2);
    authority.refusal.set(Some(PreviewError::Revoked));
    assert_eq!(
        hub.chunk(id, 1, 0, 8, 1, &authority),
        Err(PreviewError::Revoked)
    );
    assert_eq!(hub.latest(1, &authority), Err(PreviewError::Revoked));
    assert_eq!(
        hub.metadata(metadata.sequence, 1, &authority),
        Err(PreviewError::Revoked)
    );
    assert_eq!(
        hub.subscribe_at(metadata.sequence, 100, 1, &authority),
        Err(PreviewError::Revoked)
    );
    assert_eq!(hub.status().charged_bytes, 0);
    let mut alien = authority.scope.clone();
    alien.privacy_binding = ContentDigest::sha256(b"different-disclosure-approval");
    assert!(matches!(
        PreviewHub::new(alien, PreviewLimits::default(), 0, &authority),
        Err(PreviewError::Unauthorized)
    ));
    hub.close();
    assert!(hub.status().closed);
    assert_eq!(hub.status().queued_bytes, 0);
    assert_eq!(hub.status().clients, 0);
    assert_eq!(hub.next(id, 1, &authority)?, PreviewRead::Closed);
    Ok(())
}

#[test]
fn observed_writes_remain_accounted_when_authority_time_or_reader_expires_after_io() -> TestResult {
    let recording = window(0)?;
    for failure in [
        PreviewError::Revoked,
        PreviewError::Cancelled,
        PreviewError::Unauthorized,
    ] {
        let (mut hub, authority) = owner(
            scope(&recording, PreviewCodec::Avc),
            PreviewLimits::default(),
        )?;
        publish(&mut hub, &recording, 1, &authority)?;
        let id = hub.subscribe(100, 1, &authority)?;
        hub.chunk(id, 1, 0, 10, 2, &authority)?;
        authority.refusal.set(Some(failure));
        assert_eq!(hub.advance(id, 1, 4, 2, &authority), Err(failure));
        assert_eq!(hub.status().charged_bytes, 4);
        assert_eq!(hub.status().written_bytes, 4);
    }
    for (client_expiry, now_ns, failure) in [
        (100, 1, PreviewError::ClockRegression),
        (3, 3, PreviewError::Expired),
        (100, 10_000, PreviewError::Expired),
    ] {
        let (mut hub, authority) = owner(
            scope(&recording, PreviewCodec::Avc),
            PreviewLimits::default(),
        )?;
        publish(&mut hub, &recording, 1, &authority)?;
        let id = hub.subscribe(client_expiry, 1, &authority)?;
        hub.chunk(id, 1, 0, 10, 2, &authority)?;
        assert_eq!(hub.advance(id, 1, 4, now_ns, &authority), Err(failure));
        assert_eq!(hub.status().charged_bytes, 4);
        assert_eq!(hub.status().written_bytes, 4);
        if now_ns == 10_000 {
            assert!(hub.status().closed);
            assert_eq!(hub.status().queued_bytes, 0);
        }
    }
    Ok(())
}

#[test]
fn candidate_and_ring_age_use_original_admission_and_never_refresh_on_retries() -> TestResult {
    let first = window(0)?;
    let second = window(1)?;
    let third = window(2)?;
    let limits = PreviewLimits {
        max_fragment_age_ns: 10,
        ..PreviewLimits::default()
    };
    let (mut hub, authority) = owner(scope(&first, PreviewCodec::Avc), limits)?;
    hub.stage(&first, 1, &authority)?;
    hub.stage(&first, 10, &authority)?;
    assert_eq!(
        hub.publish_durable(first.manifest().root(), 11, &authority)?,
        PublishOutcome::Skipped {
            root: first.manifest().root(),
            reason: PreviewSkip::Expired
        }
    );
    assert_eq!(hub.status().candidate_bytes, 0);
    assert_eq!(hub.status().published, 0);
    let metadata = publish(&mut hub, &second, 12, &authority)?;
    assert_eq!(metadata.sequence, 1);
    let id = hub.subscribe(100, 12, &authority)?;
    hub.publish_durable(second.manifest().root(), 21, &authority)?;
    assert!(hub.latest(21, &authority)?.is_some());
    assert_eq!(hub.latest(22, &authority)?, None);
    assert_eq!(
        hub.next(id, 22, &authority)?,
        PreviewRead::Gap {
            skipped: 1,
            next_sequence: 2
        }
    );
    assert_eq!(hub.metadata(1, 22, &authority), Err(PreviewError::Evicted));
    assert_eq!(
        hub.subscribe_at(1, 100, 22, &authority),
        Err(PreviewError::Evicted)
    );
    let next = publish(&mut hub, &third, 23, &authority)?;
    hub.chunk(id, next.sequence, 0, 10, 32, &authority)?;
    assert_eq!(
        hub.advance(id, next.sequence, 4, 33, &authority),
        Err(PreviewError::Evicted)
    );
    assert_eq!(hub.status().charged_bytes, 4);
    assert_eq!(hub.status().written_bytes, 4);
    assert_eq!(hub.status().skipped, 1);
    Ok(())
}

#[test]
fn subscriptions_expire_and_reconnect_cannot_reset_lifetime_limits() -> TestResult {
    let recording = window(0)?;
    let limits = PreviewLimits {
        max_clients: 1,
        max_subscriptions: 2,
        ..PreviewLimits::default()
    };
    let (mut hub, authority) = owner(scope(&recording, PreviewCodec::Avc), limits)?;
    publish(&mut hub, &recording, 1, &authority)?;
    assert_eq!(hub.subscribe(1, 1, &authority), Err(PreviewError::Expired));
    assert_eq!(
        hub.subscribe(10_001, 1, &authority),
        Err(PreviewError::Expired)
    );
    let first = hub.subscribe(3, 1, &authority)?;
    assert_eq!(
        hub.subscribe(100, 1, &authority),
        Err(PreviewError::ClientLimit)
    );
    hub.chunk(first, 1, 0, 5, 1, &authority)?;
    assert_eq!(
        hub.chunk(first, 1, 0, 5, 3, &authority),
        Err(PreviewError::Expired)
    );
    assert_eq!(hub.status().clients, 0);
    assert_eq!(hub.status().charged_bytes, 5);
    let second = hub.subscribe(100, 3, &authority)?;
    assert!(second.get() > first.get());
    assert!(hub.disconnect(second));
    assert_eq!(
        hub.subscribe(100, 3, &authority),
        Err(PreviewError::SubscriptionLimit)
    );
    assert_eq!(hub.status().subscriptions, 2);
    hub.close();
    assert_eq!(hub.status().charged_bytes, 5);
    assert_eq!(hub.status().written_bytes, 0);
    assert_eq!(hub.status().candidate_bytes, 0);
    assert_eq!(hub.status().queued_fragments, 0);
    assert_eq!(hub.latest(3, &authority), Err(PreviewError::Closed));
    Ok(())
}

#[test]
fn oversize_optional_derivative_leaves_original_custody_unchanged_and_next_window_works()
-> TestResult {
    let large = avc::repeated(222, 4, 1, 0)?.prepare_at(0)?;
    let small = avc::repeated(223, 1, 100, 14_400)?.prepare_at(14_400)?;
    let max_bytes = expected_body(&small).len();
    assert!(expected_body(&large).len() > max_bytes);
    let limits = PreviewLimits {
        max_fragment_bytes: max_bytes,
        max_ring_bytes: max_bytes,
        max_initialization_bytes: small.objects().initialization.len(),
        ..PreviewLimits::default()
    };
    let source_digest = ContentDigest::sha256(large.objects().source);
    let original_root = large.manifest().root();
    let (mut hub, authority) = owner(scope(&large, PreviewCodec::Avc), limits)?;
    assert_eq!(
        hub.stage(&large, 1, &authority)?,
        StageOutcome::Skipped {
            root: original_root,
            reason: PreviewSkip::Oversize
        }
    );
    assert_eq!(
        hub.publish_durable(original_root, 1, &authority)?,
        PublishOutcome::Skipped {
            root: original_root,
            reason: PreviewSkip::NotStaged
        }
    );
    assert_eq!(hub.status().candidate_bytes, 0);
    assert_eq!(large.manifest().root(), original_root);
    assert_eq!(ContentDigest::sha256(large.objects().source), source_digest);
    let metadata = publish(&mut hub, &small, 2, &authority)?;
    assert_eq!(metadata.sequence, 1);
    assert_eq!(hub.status().skipped, 1);
    assert_eq!(hub.status().published, 1);
    assert!(hub.status().queued_bytes <= limits.max_ring_bytes);
    let id = hub.subscribe(100, 2, &authority)?;
    assert_eq!(
        read_body(&mut hub, id, &metadata, 2, &authority)?,
        expected_body(&small)
    );
    Ok(())
}
