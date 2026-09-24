#![forbid(unsafe_code)]
//! Independent metadata-format fixture, NOT a playable recording or archive proof.
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::ObjectManifest;
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording_catalog::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const INDEX: &[u8] = include_bytes!("fixtures/recording_catalog/v1.index");
const ROOT: &[u8] = include_bytes!("fixtures/recording_catalog/v1.root");
fn scope() -> Result<CatalogScope, Box<dyn std::error::Error>> {
    Ok(CatalogScope {
        recording: RecordingScope {
            sensor: SensorId::parse("catalog-wire-fixture")?,
            stream: StreamId::parse("main")?,
            generation: 1,
            anchor: ContentDigest::try_sha256(b"owner")?,
            receive_clock: ContentDigest::try_sha256(b"receive")?,
        },
        decode_clock: ContentDigest::try_sha256(b"decode")?,
        time_scale: 90000,
    })
}
#[test]
fn independent_metadata_bytes_pin_format_and_interval_meaning() -> TestResult {
    assert_eq!(
        ContentDigest::try_sha256(INDEX)?.to_text(),
        "sha256:ea8bb342222032cc881bffcc83bbc6a8c9cc4690263dd86a16cc961e0dff9048"
    );
    assert_eq!(
        ContentDigest::try_sha256(ROOT)?.to_text(),
        "sha256:a848001ea49d905ba5d8e904ef2bbe74cfe42a2a6a401c25e4124cf90d4f2529"
    );
    let manifest = ObjectManifest::from_canonical_bytes(ROOT)?;
    let c = verify_catalog(&manifest, INDEX, &scope()?)?;
    assert_eq!(c.entries().len(), 2);
    assert_eq!(c.entries()[0].slot().as_str(), "first");
    assert_eq!(c.entries()[1].decode_interval(), 10800..14400);
    let selection = c.select(0..18000, CatalogQueryLimits::default())?;
    assert_eq!(selection.output_bytes(), 1024);
    assert_eq!(selection.unindexed(), &[0..3600, 7200..10800, 14400..18000]);
    Ok(())
}
#[test]
fn rechecksummed_unknown_version_is_still_refused() -> TestResult {
    let original = ObjectManifest::from_canonical_bytes(ROOT)?;
    let mut bytes = INDEX.to_vec();
    let version_at = 8 + "fss.recording_catalog.v1".len();
    bytes[version_at..version_at + 8].copy_from_slice(&2_u64.to_be_bytes());
    let end = bytes.len() - 33;
    let checksum = ContentDigest::try_sha256(&bytes[..end])?;
    bytes[end + 1..].copy_from_slice(&checksum.bytes());
    let meta = original.metadata_digest().ok_or("metadata")?;
    let children: Vec<_> = original
        .children()
        .iter()
        .copied()
        .filter(|d| *d != meta)
        .collect();
    let forged = ObjectManifest::new(
        CATALOG_KIND,
        children,
        Some(ContentDigest::try_sha256(&bytes)?),
    )?;
    assert!(matches!(
        verify_catalog(&forged, &bytes, &scope()?),
        Err(CatalogError::Malformed)
    ));
    Ok(())
}
