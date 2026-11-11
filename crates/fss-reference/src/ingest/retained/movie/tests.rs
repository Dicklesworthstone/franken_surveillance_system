#![forbid(unsafe_code)]
//! Adversarial retained-index checks against the checked-in original MP4, without storage I/O.

use super::*;
use crate::ingest::{FileOmissionSpan, SegmentSpan};
use fss_container::demux::DemuxLimits;
use fss_core::CapsuleId;

type Test = Result<(), Box<dyn std::error::Error>>;
const SOURCE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-container/tests/fixtures/indexed_avc.mp4"
));

fn manifest(movie: &AvcMp4<'_>) -> Result<FileImportManifest, FileIngestError> {
    let mut segments = Vec::new();
    let mut omissions = Vec::new();
    let mut at = 0;
    for sample in movie.samples() {
        if at < sample.source.start {
            omissions.push(FileOmissionSpan {
                offset: at as u64,
                len: (sample.source.start - at) as u64,
                reason: "mp4_box:fixture".to_owned(),
            });
        }
        segments.push(SegmentSpan {
            segment_index: sample.index,
            offset: sample.source.start as u64,
            len: sample.source.len() as u64,
            segment_sha256: ContentDigest::sha256(&SOURCE[sample.source.clone()]),
            capsule_id: CapsuleId::parse(format!("capsule:movie-index:{}", sample.index))?,
            gap_before: false,
        });
        at = sample.source.end;
    }
    if at < SOURCE.len() {
        omissions.push(FileOmissionSpan {
            offset: at as u64,
            len: (SOURCE.len() - at) as u64,
            reason: "mp4_box:fixture".to_owned(),
        });
    }
    Ok(FileImportManifest {
        input_sha256: ContentDigest::sha256(SOURCE),
        input_bytes: SOURCE.len() as u64,
        format: "mp4avc".to_owned(),
        detector_evidence: "test:index-authentication".to_owned(),
        chunk_bytes: 1024,
        ordered_chunks: SOURCE.chunks(1024).map(ContentDigest::sha256).collect(),
        capsule_ids: segments.iter().map(|s| s.capsule_id.clone()).collect(),
        segment_spans: segments,
        omission_spans: omissions,
        limits_digest: ContentDigest::sha256(b"movie-index-test-limits"),
        adapter_id: ADP_FILE_ROW_ID.to_owned(),
        adapter_generation: ADP_FILE_GENERATION.to_owned(),
        part_roots: Vec::new(),
        capture_time_label: "unknown".to_owned(),
    })
}

#[test]
fn every_retained_index_must_match_the_original_sample_tables() -> Test {
    let movie = AvcMp4::parse(SOURCE, None, DemuxLimits::default())?;
    let original = manifest(&movie)?;
    assert_eq!(
        source_admission(&original, RetainedReadLimits::default())?,
        SOURCE.len()
    );
    verify_sample_index(&original, SOURCE, &movie, || Ok(()))?;
    for case in 0..7 {
        let mut changed = original.clone();
        match case {
            0 => changed.format = "mp4hevc".to_owned(),
            1 => {
                changed
                    .segment_spans
                    .truncate(changed.segment_spans.len() - 1);
            }
            2 => changed.segment_spans[0].segment_index += 1,
            3 => changed.segment_spans[0].offset += 1,
            4 => changed.segment_spans[0].len -= 1,
            5 => changed.segment_spans[0].gap_before = true,
            _ => changed.segment_spans[0].segment_sha256 = ContentDigest::sha256(b"wrong"),
        }
        assert!(
            verify_sample_index(&changed, SOURCE, &movie, || Ok(())).is_err(),
            "case {case}"
        );
    }
    Ok(())
}

#[test]
fn whole_original_admission_has_an_absolute_bound_and_explicit_origin_scope() -> Test {
    let movie = AvcMp4::parse(SOURCE, None, DemuxLimits::default())?;
    let original = manifest(&movie)?;
    assert!(
        source_admission(
            &original,
            RetainedReadLimits {
                max_source_bytes: original.input_bytes - 1,
                ..RetainedReadLimits::default()
            }
        )
        .is_err()
    );
    for length in [MAX_MP4_INPUT_BYTES as u64 + 1, u64::MAX] {
        let mut oversized = original.clone();
        oversized.input_bytes = length;
        assert!(matches!(
            source_admission(
                &oversized,
                RetainedReadLimits {
                    max_source_bytes: u64::MAX,
                    ..RetainedReadLimits::default()
                }
            ),
            Err(FileIngestError::Mp4Refused {
                refusal: DemuxError::Limit
            })
        ));
    }
    for case in 0..4 {
        let mut unsupported = original.clone();
        match case {
            0 => unsupported.adapter_id = "ADP-RTSP-UNKNOWN-001".to_owned(),
            1 => unsupported.adapter_generation.push_str(":other"),
            2 => unsupported.adapter_id = "ADP-FILE-002".to_owned(),
            _ => unsupported.format = "mkvavc".to_owned(),
        }
        assert!(matches!(
            source_admission(&unsupported, RetainedReadLimits::default()),
            Err(FileIngestError::Mp4Refused {
                refusal: DemuxError::Unsupported
            })
        ));
    }
    Ok(())
}

#[test]
fn every_native_origin_requires_its_exact_generation_profile() -> Test {
    let movie = AvcMp4::parse(SOURCE, None, DemuxLimits::default())?;
    let mut native = manifest(&movie)?;
    // Structural admission is deliberately weaker than selection: the real selector must also
    // authenticate completion membership and replay the retained origin identified by this hash.
    for (adapter, prefix) in [
        (rtsp_import::ADAPTER, rtsp_import::GENERATION),
        (
            rtsp_import::catalog::ADAPTER,
            rtsp_import::catalog::GENERATION,
        ),
        (rtsp_import::pages::ADAPTER, rtsp_import::pages::GENERATION),
        (rtsp_import::gaps::ADAPTER, rtsp_import::gaps::GENERATION),
        (
            rtsp_import::replay::ADAPTER,
            rtsp_import::replay::GENERATION,
        ),
    ] {
        native.adapter_id = adapter.to_owned();
        for generation in [
            ADP_FILE_GENERATION.to_owned(),
            format!("{prefix}{}", "a".repeat(63)),
            format!("{prefix}{}", "A".repeat(64)),
            format!("{prefix}{}:other", "a".repeat(64)),
        ] {
            native.adapter_generation = generation;
            assert!(source_admission(&native, RetainedReadLimits::default()).is_err());
        }
        native.adapter_generation = format!("{prefix}{}", "a".repeat(64));
        assert_eq!(
            source_admission(&native, RetainedReadLimits::default())?,
            SOURCE.len()
        );
    }
    Ok(())
}

#[test]
fn retained_tail_claims_cannot_replace_complete_source_metadata() -> Test {
    let movie = AvcMp4::parse(SOURCE, None, DemuxLimits::default())?;
    let mut retained = manifest(&movie)?;
    retained.omission_spans.push(FileOmissionSpan {
        offset: SOURCE.len() as u64 - 1,
        len: 1,
        reason: crate::ingest::CONTAINER_TRUNCATED_TAIL_REASON.to_owned(),
    });
    assert!(verify_sample_index(&retained, SOURCE, &movie, || Ok(())).is_err());
    Ok(())
}

#[test]
fn index_verification_is_cooperatively_cancellable_before_releasing_a_selection() -> Test {
    let movie = AvcMp4::parse(SOURCE, None, DemuxLimits::default())?;
    let retained = manifest(&movie)?;
    let mut visits = 0;
    let result = verify_sample_index(&retained, SOURCE, &movie, || {
        visits += 1;
        if visits == 3 {
            Err(FileIngestError::CancellationRequested { stage: STAGE_INDEX })
        } else {
            Ok(())
        }
    });
    assert!(matches!(
        result,
        Err(FileIngestError::CancellationRequested { stage: STAGE_INDEX })
    ));
    assert_eq!(visits, 3);
    Ok(())
}
