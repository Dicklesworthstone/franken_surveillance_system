#![forbid(unsafe_code)]
//! Bounded canonical custody record and its non-authoritative JSON projection.

use fss_core::{CanonicalDecode, CanonicalDecoder, CanonicalEncoder};

use super::*;

mod reviewed;

impl OriginalMediaExportRecord {
    /// Exact request bound to this record.
    pub fn request(&self) -> &OriginalMediaExportRequest {
        &self.request
    }
    /// Explicit portable disclosure profile. Original revision-one records remain byte-identical.
    pub fn profile(&self) -> &'static str {
        if self.event_profile == "package_track" {
            PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE
        } else if self.review_lineage.is_some() {
            REVIEWED_ORIGINAL_MEDIA_EXPORT_PROFILE
        } else {
            ORIGINAL_MEDIA_EXPORT_PROFILE
        }
    }
    fn domain(&self) -> &'static str {
        if self.event_profile == "package_track" {
            PACKAGE_ORIGINAL_MEDIA_EXPORT_DOMAIN
        } else if self.review_lineage.is_some() {
            REVIEWED_ORIGINAL_MEDIA_EXPORT_DOMAIN
        } else {
            ORIGINAL_MEDIA_EXPORT_DOMAIN
        }
    }
    pub(super) fn policy(&self) -> &'static [u8] {
        if self.event_profile == "package_track" {
            PACKAGE_POLICY
        } else if self.review_lineage.is_some() {
            REVIEWED_POLICY
        } else {
            POLICY
        }
    }
    /// Exact metadata child digest.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }
    /// Fixed original-source filename.
    pub fn media_filename(&self) -> &'static str {
        self.source_format.filename()
    }
    /// Exact source hash, independently covered by the package root.
    pub const fn media_digest(&self) -> ContentDigest {
        self.source_digest
    }
    /// Complete selected original source length.
    pub const fn media_length(&self) -> u64 {
        self.source_bytes
    }
    /// Handwritten, versioned canonical custody bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSEXM01");
        e.u32(if self.event_profile == "package_track" {
            3
        } else if self.review_lineage.is_some() {
            2
        } else {
            1
        });
        e.text(self.domain());
        e.bytes(self.policy());
        e.bytes(&self.event_summary.to_bytes());
        e.digest(self.request.import_identity);
        e.digest(self.request.expected_import_root);
        e.bool(self.request.whole_source_authorized);
        e.digest(self.request.destination_binding);
        e.u64(self.request.max_source_bytes);
        self.request.attested_now.encode_canonical(&mut e);
        self.basis.encode_canonical(&mut e);
        e.digest(self.authority_binding);
        e.digest(self.event_provenance_root);
        e.u32(self.analysis_roots.len() as u32);
        for root in &self.analysis_roots {
            e.digest(*root);
        }
        e.text(&self.event_profile);
        e.u32(self.event_source_count);
        e.text(&self.source_adapter);
        e.digest(self.source_manifest);
        e.text(self.source_format.as_str());
        e.text(self.source_sensor.as_str());
        e.digest(self.source_digest);
        e.u64(self.source_bytes);
        e.u64(self.source_segments);
        self.source_interval.encode_canonical(&mut e);
        e.text(&self.source_capture_label);
        if let Some(lineage) = &self.review_lineage {
            lineage.encode(&mut e);
        }
        e.finish()
    }
    /// Decode explicit v1-native, v2-reviewed or v3-package profiles. Unknown/trailing fields refuse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ORIGINAL_MEDIA_RECORD_BYTES {
            return Err(OriginalMediaExportError::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSEXM01" {
            return Err(OriginalMediaExportError::UnsupportedProfile);
        }
        let version = d.u32()?;
        let (domain, policy) = match version {
            1 => (ORIGINAL_MEDIA_EXPORT_DOMAIN, POLICY),
            2 => (REVIEWED_ORIGINAL_MEDIA_EXPORT_DOMAIN, REVIEWED_POLICY),
            3 => (PACKAGE_ORIGINAL_MEDIA_EXPORT_DOMAIN, PACKAGE_POLICY),
            _ => return Err(OriginalMediaExportError::UnsupportedProfile),
        };
        if d.text()? != domain || d.bytes()? != policy {
            return Err(OriginalMediaExportError::UnsupportedProfile);
        }
        let summary_bytes = d.bytes()?;
        let event_summary =
            EventExportRecord::from_bytes(summary_bytes, ContentDigest::sha256(summary_bytes))?;
        let request = OriginalMediaExportRequest {
            event: event_summary.request().clone(),
            import_identity: d.digest()?,
            expected_import_root: d.digest()?,
            whole_source_authorized: d.bool()?,
            destination_binding: d.digest()?,
            max_source_bytes: d.u64()?,
            attested_now: CaptureInterval::decode_canonical(&mut d)?,
        };
        let basis = LedgerAnchor::decode_canonical(&mut d)?;
        let authority_binding = d.digest()?;
        let event_provenance_root = d.digest()?;
        let count = d.u32()? as usize;
        if !(1..=2).contains(&count) || count > d.remaining() / 33 {
            return Err(OriginalMediaExportError::Limit);
        }
        let mut analysis_roots = Vec::with_capacity(count);
        for _ in 0..count {
            analysis_roots.push(d.digest()?);
        }
        let event_profile = d.text()?.to_owned();
        let event_source_count = d.u32()?;
        let source_adapter = d.text()?.to_owned();
        let source_manifest = d.digest()?;
        let source_format = match d.text()? {
            "mjpeg" => MediaFormat::Mjpeg,
            "mp4avc" => MediaFormat::Mp4Avc,
            "mp4hevc" => MediaFormat::Mp4Hevc,
            _ => return Err(OriginalMediaExportError::UnsupportedProfile),
        };
        let source_sensor = SensorId::parse(d.text()?)?;
        let source_digest = d.digest()?;
        let source_bytes = d.u64()?;
        let source_segments = d.u64()?;
        let source_interval = CaptureInterval::decode_canonical(&mut d)?;
        let source_capture_label = d.text()?.to_owned();
        let review_lineage = if version == 2 {
            Some(ReviewedMediaLineage::decode(&mut d)?)
        } else {
            None
        };
        d.ensure_finished()?;
        let record = Self {
            request,
            event_summary,
            basis,
            authority_binding,
            event_provenance_root,
            analysis_roots,
            event_profile,
            event_source_count,
            source_adapter,
            source_manifest,
            source_format,
            source_sensor,
            source_digest,
            source_bytes,
            source_segments,
            source_interval,
            source_capture_label,
            review_lineage,
        };
        record.validate()?;
        if record.to_bytes() != bytes {
            return Err(OriginalMediaExportError::CustodyMismatch);
        }
        Ok(record)
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.request.validate()?;
        if self.event_profile == "package_track"
            && (self.review_lineage.is_some()
                || !self
                    .request
                    .event
                    .event_id
                    .as_str()
                    .starts_with("event:package:")
                || self.event_summary.event_state() != fss_core::EventState::Indeterminate)
        {
            return Err(OriginalMediaExportError::UnsupportedProfile);
        }
        if let Some(lineage) = &self.review_lineage {
            lineage.validate(self)?;
        } else if self.event_summary.event_revision() != 1 {
            // Native v1/v3 profiles never authorize a successor. Supported operator reviews
            // carry their distinct v2 proof pins, and package reviews remain unsupported.
            return Err(OriginalMediaExportError::CustodyMismatch);
        }
        if self.event_summary.request() != &self.request.event
            || self.source_bytes == 0
            || self.source_bytes > self.request.max_source_bytes
            || self.source_segments == 0
            || self.source_segments > MAX_ORIGINAL_MEDIA_SEGMENTS as u64
            || self.source_interval.earliest > self.source_interval.latest
            || self.request.event.expires_at <= self.source_interval.latest
            || self.source_capture_label != "operator_assumption"
            || self.source_adapter.len() > 256
            || self.basis.commit_sequence < self.event_summary.event_anchor().commit_sequence
            || ![
                self.authority_binding,
                self.event_provenance_root,
                self.source_manifest,
                self.source_digest,
            ]
            .into_iter()
            .all(valid_digest)
            || !self.analysis_roots.iter().copied().all(valid_digest)
        {
            return Err(OriginalMediaExportError::CustodyMismatch);
        }
        let expected_sources = match self.event_profile.as_str() {
            "long_watch" | "long_dwell" | "package_track" => 1,
            "long_corroboration" => 2,
            _ => return Err(OriginalMediaExportError::UnsupportedProfile),
        };
        if self.event_source_count != expected_sources
            || self.analysis_roots.len() != expected_sources as usize
            || (expected_sources == 2 && self.analysis_roots[0] == self.analysis_roots[1])
            || (self.source_format != MediaFormat::Mjpeg && !is_native_rtsp(&self.source_adapter))
            || self.to_bytes().len() > MAX_ORIGINAL_MEDIA_RECORD_BYTES
        {
            return Err(OriginalMediaExportError::CustodyMismatch);
        }
        Ok(())
    }
    /// Explicit whole-source/context disclosure, including uncertainty, model/policy identities,
    /// source/current-head custody and the operator-attested expiry check. JSON is not authority.
    pub fn to_json(&self) -> String {
        let roots = self
            .analysis_roots
            .iter()
            .map(|root| json(&root.to_text()))
            .collect::<Vec<_>>()
            .join(",");
        let mut result = format!(
            concat!(
                "{{\"schema\":{},\"profile\":{},\"record_digest\":{},\"event_summary\":{},",
                "\"authority_sequence\":{},\"authority_anchor_digest\":{},\"authority_binding\":{},",
                "\"event_provenance_root\":{},\"analysis_roots\":[{}],\"event_profile\":{},",
                "\"event_source_count\":{},\"included_source_count\":1,\"excluded_event_source_count\":{},",
                "\"source_import_identity\":{},\"source_import_root\":{},\"source_manifest\":{},",
                "\"source_adapter\":{},\"source_format\":{},\"source_sensor\":{},",
                "\"source_sha256\":{},\"source_bytes\":{},\"source_segments\":{},\"media_filename\":{},",
                "\"source_capture_earliest_ns\":{},\"source_capture_latest_ns\":{},\"capture_time_basis\":{},",
                "\"attested_now_earliest_ns\":{},\"attested_now_latest_ns\":{},\"expiry_basis\":\"operator_attestation\",",
                "\"destination_binding\":{},\"max_source_bytes\":{},\"privacy_mask_binding\":{},",
                "\"whole_source_authorized\":true,\"frame_precise_trim\":false,\"context_outside_event_may_be_included\":true,",
                "\"raw_media_included\":true,\"source_identity_included\":true,\"audio_included\":false,",
                "\"transformation\":\"identity_copy_of_retained_import\",\"redaction\":\"none_no_sensor_mask_policy\",",
                "\"native_perception_reexecuted\":false,\"other_camera_media_included\":false,",
                "\"live_archive_namespace_exposed\":false,\"external_copies_auto_erased\":false,",
                "\"delivery_status\":\"not_observed_by_preparation\",\"offline_verification\":\"exact_package_root_and_child_bytes_only\"}}"
            ),
            json(self.domain()),
            json(self.profile()),
            json(&self.digest().to_text()),
            self.event_summary.to_redacted_json(),
            self.basis.commit_sequence,
            json(
                &self
                    .basis
                    .canonical_digest("fss.original_media_export_basis.v1")
                    .to_text()
            ),
            json(&self.authority_binding.to_text()),
            json(&self.event_provenance_root.to_text()),
            roots,
            json(&self.event_profile),
            self.event_source_count,
            self.event_source_count - 1,
            json(&self.request.import_identity.to_text()),
            json(&self.request.expected_import_root.to_text()),
            json(&self.source_manifest.to_text()),
            json(&self.source_adapter),
            json(self.source_format.as_str()),
            json(self.source_sensor.as_str()),
            json(&self.source_digest.to_text()),
            self.source_bytes,
            self.source_segments,
            json(self.media_filename()),
            self.source_interval.earliest.0,
            self.source_interval.latest.0,
            json(&self.source_capture_label),
            self.request.attested_now.earliest.0,
            self.request.attested_now.latest.0,
            json(&self.request.destination_binding.to_text()),
            self.request.max_source_bytes,
            json(&binding_digest(None).to_text()),
        );
        if let Some(lineage) = &self.review_lineage {
            // Keep every v1 JSON byte unchanged: only the separately versioned reviewed profile
            // gains these fields, which disclose pins without review rationale or identity.
            result.pop();
            result.push_str(&lineage.json_fields());
            result.push('}');
        }
        result
    }
}

fn json(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
