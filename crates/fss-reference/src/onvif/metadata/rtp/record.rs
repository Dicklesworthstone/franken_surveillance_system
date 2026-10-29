#![forbid(unsafe_code)]
//! Frozen hand-written source recipes and replay reports, independent of Rust Debug/Serde.

use std::ops::Range;

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm, SensorId,
    TimestampNs,
};
use fss_packet::{OnvifMetadataLimits, PacketLimits, ReorderLimits, StreamKey};

use super::{
    MetadataError, NATIVE_RECIPE_DOMAIN, RECIPE_DOMAIN, REPLAY_GENERATION, RtpMetadataConfig,
    RtpMetadataDocument, RtpMetadataImportLimits, RtpMetadataReport, SourceBinding,
};

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Recipe {
    pub(super) site: String,
    pub(super) binding: SourceBinding,
    pub(super) config: RtpMetadataConfig,
    pub(super) source: ContentDigest,
    pub(super) source_bytes: usize,
    pub(super) report: ContentDigest,
    pub(super) native_source: Option<(ContentDigest, usize)>,
}

pub(super) fn encode(recipe: &Recipe) -> Result<Vec<u8>, MetadataError> {
    recipe.binding.validate()?;
    recipe.config.validate()?;
    if !super::super::record::valid_label(&recipe.site)
        || recipe.source_bytes > recipe.config.limits.max_input_bytes
        || recipe.source.algorithm() != DigestAlgorithm::Sha256
        || recipe.report.algorithm() != DigestAlgorithm::Sha256
        || recipe.native_source.is_some_and(|(digest, length)| {
            digest.algorithm() != DigestAlgorithm::Sha256
                || !(1..=super::MAX_NATIVE_SOURCE_BYTES).contains(&length)
        })
    {
        return Err(MetadataError::InvalidBinding);
    }
    let mut e = CanonicalEncoder::new();
    e.text(if recipe.native_source.is_some() {
        NATIVE_RECIPE_DOMAIN
    } else {
        RECIPE_DOMAIN
    });
    e.text(REPLAY_GENERATION);
    e.text(super::super::PARSER_GENERATION);
    e.text(if recipe.native_source.is_some() {
        "native_rtsp_tcp"
    } else {
        "owner_supplied_rtpdump"
    });
    e.text("vnd.onvif.metadata/90000;uncompressed");
    e.text("recorded_offset_ms_untrusted_non_decreasing");
    e.text("after_first_observed_marker");
    e.text(&recipe.site);
    e.text(recipe.binding.sensor_id.as_str());
    e.digest(recipe.binding.device_generation);
    e.digest(recipe.binding.profile_generation);
    e.text(&recipe.binding.profile_token);
    e.i128(recipe.binding.receive_interval.earliest.0);
    e.i128(recipe.binding.receive_interval.latest.0);
    let c = recipe.config;
    e.u64((c.stream.ingress >> 64) as u64);
    e.u64(c.stream.ingress as u64);
    e.u64(c.stream.generation);
    e.u32(c.stream.ssrc);
    e.u8(c.payload_type);
    e.u64(c.limits.max_input_bytes as u64);
    e.u64(c.limits.max_records as u64);
    e.u64(c.limits.max_documents as u64);
    e.u64(c.reorder.packet.max_packet_bytes as u64);
    e.u64(c.reorder.packet.max_extension_bytes as u64);
    e.u64(c.reorder.packet.max_rtcp_packets as u64);
    e.u64(c.reorder.max_packets as u64);
    e.u64(c.reorder.max_bytes as u64);
    e.u64(c.reorder.max_delay_ns);
    e.u64(c.metadata.max_document_bytes as u64);
    e.u64(c.metadata.max_fragment_packets as u64);
    e.u64(c.metadata.max_pending_age_ns);
    e.digest(recipe.source);
    e.u64(recipe.source_bytes as u64);
    e.digest(recipe.report);
    // The original domain has no discriminator or trailing field: its bytes remain frozen.
    if let Some((digest, length)) = recipe.native_source {
        e.digest(digest);
        e.u64(length as u64);
    }
    let bytes = e.finish_checked()?;
    if bytes.len() > super::super::MAX_RECIPE_BYTES {
        return Err(MetadataError::Limit);
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Recipe, MetadataError> {
    if bytes.len() > super::super::MAX_RECIPE_BYTES {
        return Err(MetadataError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    let native = match d.text()? {
        RECIPE_DOMAIN => false,
        NATIVE_RECIPE_DOMAIN => true,
        _ => return Err(MetadataError::Custody),
    };
    for expected in [
        REPLAY_GENERATION,
        super::super::PARSER_GENERATION,
        if native {
            "native_rtsp_tcp"
        } else {
            "owner_supplied_rtpdump"
        },
        "vnd.onvif.metadata/90000;uncompressed",
        "recorded_offset_ms_untrusted_non_decreasing",
        "after_first_observed_marker",
    ] {
        if d.text()? != expected {
            return Err(MetadataError::Custody);
        }
    }
    let site = d.text()?.to_owned();
    let binding = SourceBinding {
        sensor_id: SensorId::parse(d.text()?)?,
        device_generation: d.digest()?,
        profile_generation: d.digest()?,
        profile_token: d.text()?.to_owned(),
        receive_interval: CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?,
    };
    let ingress = (u128::from(d.u64()?) << 64) | u128::from(d.u64()?);
    let stream = StreamKey {
        ingress,
        generation: d.u64()?,
        ssrc: d.u32()?,
    };
    let payload_type = d.u8()?;
    let limits = RtpMetadataImportLimits {
        max_input_bytes: size(&mut d)?,
        max_records: size(&mut d)?,
        max_documents: size(&mut d)?,
    };
    let packet = PacketLimits {
        max_packet_bytes: size(&mut d)?,
        max_extension_bytes: size(&mut d)?,
        max_rtcp_packets: size(&mut d)?,
    };
    let reorder = ReorderLimits {
        packet,
        max_packets: size(&mut d)?,
        max_bytes: size(&mut d)?,
        max_delay_ns: d.u64()?,
    };
    let metadata = OnvifMetadataLimits {
        max_document_bytes: size(&mut d)?,
        max_fragment_packets: size(&mut d)?,
        max_pending_age_ns: d.u64()?,
    };
    let recipe = Recipe {
        site,
        binding,
        config: RtpMetadataConfig {
            stream,
            payload_type,
            limits,
            reorder,
            metadata,
        },
        source: d.digest()?,
        source_bytes: size(&mut d)?,
        report: d.digest()?,
        native_source: if native {
            Some((d.digest()?, size(&mut d)?))
        } else {
            None
        },
    };
    d.ensure_finished()?;
    if encode(&recipe)? != bytes {
        return Err(MetadataError::Custody);
    }
    Ok(recipe)
}
fn size(d: &mut CanonicalDecoder<'_>) -> Result<usize, MetadataError> {
    usize::try_from(d.u64()?).map_err(|_| MetadataError::Limit)
}
fn span(e: &mut CanonicalEncoder, range: &Range<usize>) {
    e.u64(range.start as u64);
    e.u64(range.end as u64);
}
fn option_number(e: &mut CanonicalEncoder, value: Option<u64>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.u64(value);
    }
}
fn option_text(e: &mut CanonicalEncoder, value: Option<&str>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.text(value);
    }
}

#[cfg(test)]
mod native_compatibility {
    use super::*;

    fn recipe() -> Result<Recipe, MetadataError> {
        Ok(Recipe {
            site: "site:recipe-compat".into(),
            binding: SourceBinding {
                sensor_id: SensorId::parse("sensor:front")?,
                device_generation: ContentDigest::sha256(b"device-1"),
                profile_generation: ContentDigest::sha256(b"profile-1"),
                profile_token: "main".into(),
                receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
            },
            config: RtpMetadataConfig {
                stream: StreamKey {
                    ingress: 17,
                    generation: 3,
                    ssrc: 42,
                },
                payload_type: 107,
                limits: RtpMetadataImportLimits {
                    max_input_bytes: 8_388_608,
                    max_records: 16_384,
                    max_documents: 64,
                },
                reorder: ReorderLimits {
                    packet: PacketLimits {
                        max_packet_bytes: 65_535,
                        max_extension_bytes: 16_384,
                        max_rtcp_packets: 64,
                    },
                    max_packets: 128,
                    max_bytes: 8_388_608,
                    max_delay_ns: 100_000_000,
                },
                metadata: OnvifMetadataLimits {
                    max_document_bytes: 262_144,
                    max_fragment_packets: 4096,
                    max_pending_age_ns: 2_000_000_000,
                },
            },
            source: ContentDigest::sha256(b"original-packets"),
            source_bytes: 123,
            report: ContentDigest::sha256(b"replay-report"),
            native_source: None,
        })
    }

    #[test]
    fn existing_file_recipe_keeps_its_exact_pre_native_identity() -> Result<(), MetadataError> {
        let original = recipe()?;
        let bytes = encode(&original)?;
        // Frozen from the committed v1 field order, before introducing native acquisition.
        // An absent optional native source must not add even a one-byte discriminator.
        assert_eq!(bytes.len(), 644);
        assert_eq!(
            ContentDigest::sha256(&bytes).to_text(),
            "sha256:f3c7116f5c4dbebfaeee57c7c08652acce06d527cf67d38a484b331a8600d18f"
        );
        assert!(decode(&bytes)? == original);
        Ok(())
    }

    #[test]
    fn native_recipe_has_its_own_domain_and_mandatory_original_source_link()
    -> Result<(), MetadataError> {
        let mut native = recipe()?;
        let file = encode(&native)?;
        native.native_source = Some((ContentDigest::sha256(b"native-source"), 512));
        let bytes = encode(&native)?;
        assert_ne!(ContentDigest::sha256(&bytes), ContentDigest::sha256(&file));
        assert_eq!(CanonicalDecoder::new(&bytes).text()?, NATIVE_RECIPE_DOMAIN);
        assert!(decode(&bytes)? == native);
        assert!(decode(&bytes[..bytes.len() - 41]).is_err());
        let mut contaminated_file = file;
        contaminated_file.extend_from_slice(&bytes[bytes.len() - 41..]);
        assert!(decode(&contaminated_file).is_err());
        native.native_source = Some((ContentDigest::sha256(b"native-source"), 0));
        assert!(encode(&native).is_err());
        Ok(())
    }
}

/// Cold readers rederive this complete report from original source, never deserialize a claimed
/// projection as authority. Source framing, errors and every fragment mapping are compared bytes.
pub(super) fn report(
    report: &RtpMetadataReport,
    documents: &[RtpMetadataDocument],
) -> Result<Vec<u8>, MetadataError> {
    if report.records.len() > super::MAX_RECORDS
        || documents.len() > super::MAX_DOCUMENTS
        || report.complete_documents != documents.len()
        || report.usable_documents + report.rejected_documents != documents.len()
    {
        return Err(MetadataError::Custody);
    }
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_metadata_rtpdump_report.v1");
    e.text(REPLAY_GENERATION);
    e.text(super::super::PARSER_GENERATION);
    e.text("vendor_claimed");
    e.text("recorded_timestamps_unverified");
    e.u64(report.input_bytes as u64);
    e.text(report.end_reason);
    e.bool(report.unprocessed_span.is_some());
    if let Some(range) = &report.unprocessed_span {
        span(&mut e, range);
    }
    e.u64(report.complete_documents as u64);
    e.u64(report.usable_documents as u64);
    e.u64(report.rejected_documents as u64);
    e.u64(report.records.len() as u64);
    for record in &report.records {
        e.u64(record.index as u64);
        span(&mut e, &record.span);
        span(&mut e, &record.packet_span);
        e.u32(record.offset_ms);
        e.text(record.result);
        option_text(&mut e, record.sequence_class);
        option_number(&mut e, record.sequence);
        option_text(&mut e, record.reconstruction);
    }
    e.u64(report.issues.len() as u64);
    for issue in &report.issues {
        e.text(issue.reason);
        option_number(&mut e, issue.record.map(|record| record as u64));
        span(&mut e, &issue.source);
        option_number(&mut e, issue.first_sequence);
        option_number(&mut e, issue.last_sequence);
        e.u64(issue.discarded_bytes as u64);
        e.u64(issue.discarded_fragments as u64);
    }
    e.u64(documents.len() as u64);
    for document in documents {
        e.u64(document.index as u64);
        e.digest(document.source_digest());
        e.u64(document.bytes.len() as u64);
        e.bool(document.projection.is_some());
        if let Some(projection) = &document.projection {
            e.digest(ContentDigest::sha256(projection));
        }
        option_text(&mut e, document.parse_error);
        let provenance = &document.provenance;
        let boundary = &provenance.boundary;
        e.u64(boundary.record as u64);
        span(&mut e, &boundary.source);
        e.u64(boundary.sequence);
        e.u32(boundary.timestamp);
        e.u64(boundary.replay_received_ns);
        e.u64(provenance.replay_started_ns);
        e.u64(provenance.replay_completed_ns);
        e.u64(provenance.fragments.len() as u64);
        for fragment in &provenance.fragments {
            e.u64(fragment.record as u64);
            span(&mut e, &fragment.source);
            span(&mut e, &fragment.payload);
            span(&mut e, &fragment.document);
            e.u64(fragment.sequence);
            e.u32(fragment.timestamp);
            e.u64(fragment.replay_received_ns);
        }
    }
    let bytes = e.finish_checked()?;
    if bytes.len() > super::MAX_REPORT_BYTES {
        return Err(MetadataError::Limit);
    }
    Ok(bytes)
}
