#![forbid(unsafe_code)]
//! Source-bound replay stays verifiable after the private discovery file is gone.

use super::*;
use fss_reference::rtsp::recording_replay::OnvifReplaySource;

fn source() -> Result<OnvifReplaySource, Error> {
    Ok(OnvifReplaySource::new(
        ContentDigest::sha256(b"approved ONVIF recording selection"),
        ContentDigest::sha256(b"complete protected replay handoff"),
        ContentDigest::sha256(b"actual input inode permissions and times"),
        ContentDigest::sha256(b"canonical selected service advertisements"),
        ContentDigest::sha256(b"complete GetServices response"),
        ContentDigest::sha256(b"explicit selected recording token"),
        ContentDigest::sha256(b"complete canonical information with unknown bounds"),
        ContentDigest::sha256(b"exact scoped credential-free replay URI"),
        ContentDigest::sha256(b"complete GetReplayUri response"),
    )?)
}

fn selected_setup(
    name: &str,
    hevc: bool,
) -> Result<(PathBuf, LocalRootPublisher, ReplayReceipt), Error> {
    let root = path(name);
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let direct = if hevc { hevc_request()? } else { request()? };
    let selected = direct.clone().with_onvif_source(source()?)?;
    assert_ne!(selected.digest(), direct.digest());
    assert_ne!(selected.decode_clock(), direct.decode_clock());
    assert_eq!(selected.scope(), direct.scope());
    assert_eq!(selected.route(), direct.route());
    assert_eq!(selected.window(), direct.window());
    assert!(selected.clone().with_onvif_source(source()?).is_err());
    let proof = if hevc {
        let packets = hevc_recording_support::packets()?;
        let original = hevc_recording_support::prepare(
            &packets[..8],
            &hevc_recording_support::timings(2),
        )?;
        let slot = HevcArchiveNamespace::new(catalog_scope(&selected))?.window_slot(0)?;
        publish_window(&mut publisher, &slot, original.publication_plan())?;
        ReplayWindowProof::from_hevc(slot, &original)?
    } else {
        let original = fixture(73, true)?.prepare()?;
        let slot = ArchiveNamespace::new(catalog_scope(&selected))?.window_slot(0)?;
        publish_window(&mut publisher, &slot, &original)?;
        ReplayWindowProof::from_avc(slot, &original)?
    };
    let receipt = prepare(selected, vec![proof], ReplayTermination::RequestedStop, true)?;
    Ok((root, publisher, receipt))
}

fn load_selected(
    publisher: &LocalRootPublisher,
    root: ContentDigest,
    scope: &CatalogScope,
    request: ContentDigest,
    hevc: bool,
) -> Result<ReplayReceipt, fss_reference::rtsp::recording_replay::ReplayReceiptError> {
    if hevc {
        load_hevc_replay_receipt(publisher, root, scope, request, &NeverCancel)
    } else {
        load_replay_receipt(publisher, root, scope, request, &NeverCancel)
    }
}

#[test]
fn selected_replay_reopens_all_source_pins_and_native_originals_without_private_input() -> TestResult {
    for hevc in [false, true] {
        let (root, mut publisher, receipt) = selected_setup("onvif-reopen", hevc)?;
        publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
        drop(publisher);
        let reopened = LocalRootPublisher::open(&root, limits())?;
        let loaded = load_selected(
            &reopened, receipt.root(), receipt.scope(), receipt.request().digest(), hevc,
        )?;
        assert_eq!(loaded.metadata_bytes(), receipt.metadata_bytes());
        assert_eq!(loaded.request().onvif_source(), Some(&source()?));
        assert_eq!(loaded.approval(), receipt.approval());
        assert_eq!(loaded.windows(), receipt.windows());
        assert!(load_selected(
            &reopened, receipt.root(), receipt.scope(), receipt.request().digest(), !hevc,
        ).is_err());
        let direct = if hevc { hevc_request()? } else { request()? };
        assert!(load_selected(
            &reopened, receipt.root(), receipt.scope(), direct.digest(), hevc,
        ).is_err());
        let proof = &loaded.windows()[0];
        if hevc {
            let original = load_hevc_recording(&reopened, proof.slot(), proof.root(),
                loaded.request().scope(), &NeverCancel)?;
            assert_eq!(original.source_only_nals(), 3);
            assert_eq!(original.summary().samples, 2);
        } else {
            let original = load_recording(&reopened, proof.slot(), proof.root(),
                loaded.request().scope(), &NeverCancel)?;
            assert_eq!(original.summary().scope, *loaded.request().scope());
            assert_eq!(original.summary().samples, proof.samples());
        }
    }
    Ok(())
}

#[test]
fn rehashed_discovery_pin_substitution_cannot_keep_the_approved_request() -> TestResult {
    let source = source()?;
    let pins = [source.onboarding_plan(), source.handoff_digest(), source.file_identity(),
        source.services_digest(), source.services_observation_digest(),
        source.recording_token_digest(), source.information_digest(),
        source.uri_digest(), source.uri_observation_digest()];
    for hevc in [false, true] {
        for pin in pins {
            let (_, mut publisher, receipt) = selected_setup("onvif-substitution", hevc)?;
            let mut metadata = receipt.metadata_bytes().to_vec();
            let end = metadata.len().checked_sub(33).ok_or("checksum")?;
            replace_digest(&mut metadata[..end], pin,
                ContentDigest::sha256(b"different but valid observation"))?;
            rechecksum(&mut metadata)?;
            let forged = publish_metadata(&mut publisher, &receipt, receipt.scope(), &metadata)?;
            assert!(matches!(load_selected(&publisher, forged.root(), receipt.scope(),
                receipt.request().digest(), hevc), Err(E::Scope)));
        }
    }
    Ok(())
}

#[test]
fn selected_receipt_after_root_rename_recovers_with_source_and_approval_intact() -> TestResult {
    for hevc in [false, true] {
        let (root, mut publisher, receipt) = selected_setup("onvif-root-recovery", hevc)?;
        publisher.inject_crash_at(PublishCutPoint::AfterRootRename);
        assert!(publish_replay_receipt(&receipt, &mut publisher, &NeverCancel).is_err());
        drop(publisher);
        let mut reopened = LocalRootPublisher::open(&root, limits())?;
        let loaded = load_selected(&reopened, receipt.root(), receipt.scope(),
            receipt.request().digest(), hevc)?;
        assert_eq!(loaded.request().onvif_source(), Some(&source()?));
        assert_eq!(loaded.approval(), receipt.approval());
        assert_eq!(publish_replay_receipt(&receipt, &mut reopened, &NeverCancel)?.outcome,
            PublishOutcome::AlreadyPublished);
    }
    Ok(())
}
