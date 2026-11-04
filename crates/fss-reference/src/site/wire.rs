#![forbid(unsafe_code)]
//! Explicit canonical fingerprint inputs. JSON bytes and object-key ordering are not identity.

use fss_core::{CanonicalEncoder, ContentDigest};

use super::{
    ClockWitness, MAX_SITE_INPUT_BYTES, SiteError, SiteManifest, SiteProbeReceipt, SiteSource,
};

fn finish(encoder: CanonicalEncoder) -> Result<ContentDigest, SiteError> {
    let bytes = encoder.finish_checked().map_err(|_| SiteError::Limit)?;
    if bytes.len() > MAX_SITE_INPUT_BYTES {
        return Err(SiteError::Limit);
    }
    Ok(ContentDigest::sha256(&bytes))
}

fn optional_text(encoder: &mut CanonicalEncoder, value: Option<&str>) {
    match value {
        None => encoder.tag(0),
        Some(value) => {
            encoder.tag(1);
            encoder.text(value);
        }
    }
}

fn optional_clock_witness(encoder: &mut CanonicalEncoder, value: Option<&ClockWitness>) {
    match value {
        None => encoder.tag(0),
        Some(witness) => {
            encoder.tag(1);
            encoder.u64(witness.wall_clock_unix_ns);
            encoder.u64(witness.monotonic_ns);
            encoder.u64(witness.ntp_offset_ns);
            encoder.text(witness.ntp_offset_direction.as_str());
            encoder.u64(witness.ntp_uncertainty_ns);
        }
    }
}

fn source(encoder: &mut CanonicalEncoder, value: &SiteSource) {
    encoder.text(&value.source_id);
    encoder.u64(value.generation);
    encoder.text(value.kind.as_str());
    encoder.text(&value.peer.to_string());
    encoder.text(&value.authority);
    optional_text(encoder, value.presentation.as_deref());
    optional_text(encoder, value.control_root.as_deref());
    optional_text(encoder, value.onvif_service_path.as_deref());
    optional_text(encoder, value.unifi_camera_id.as_deref());
    encoder.text(value.stream_role.as_str());
    match &value.authentication {
        None => encoder.tag(0),
        Some(auth) => {
            encoder.tag(1);
            // validate() rejects non-UTF-8 paths before this private encoder is called.
            encoder.text(auth.credential_file.to_str().unwrap_or(""));
            encoder.text(&auth.realm);
            encoder.tag(u8::from(auth.legacy_md5));
            encoder.tag(u8::from(auth.legacy_no_qop));
        }
    }
    encoder.text(&value.retention_class);
    encoder.text(&value.rights_verdict_ref);
    encoder.u64(value.zones.len() as u64);
    for zone in &value.zones {
        encoder.text(&zone.zone_id);
        encoder.text(&zone.kind);
        encoder.u64(zone.vertices.len() as u64);
        for vertex in &zone.vertices {
            encoder.u32(vertex[0]);
            encoder.u32(vertex[1]);
        }
    }
    encoder.u64(value.payment_masks.len() as u64);
    for mask in &value.payment_masks {
        encoder.u32(mask.x);
        encoder.u32(mask.y);
        encoder.u32(mask.width);
        encoder.u32(mask.height);
    }
    encoder.u32(value.max_connections);
    encoder.tag(u8::from(value.owner_authorized));
    encoder.tag(u8::from(value.plaintext));
    encoder.tag(u8::from(value.retain_originals));
}

impl SiteSource {
    /// Canonical requested-source digest after full validation. Grants no acquisition authority.
    pub fn digest(&self) -> Result<ContentDigest, SiteError> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.site_source.v1");
        source(&mut encoder, self);
        finish(encoder)
    }
}

impl SiteManifest {
    /// Canonical digest binding every ordered source and all policy/credential references.
    /// Invalid public typed values return an error; no partial or empty encoding is hashed.
    pub fn digest(&self) -> Result<ContentDigest, SiteError> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.site_camera_manifest.v1");
        encoder.text(&self.site_id);
        encoder.u64(self.generation);
        encoder.text(self.network_route.as_str());
        encoder.u64(self.sources.len() as u64);
        for item in &self.sources {
            source(&mut encoder, item);
        }
        finish(encoder)
    }
}

impl SiteProbeReceipt {
    /// Canonical observation-claim digest. It identifies supplied claims, not authenticated truth.
    pub fn digest(&self) -> Result<ContentDigest, SiteError> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.site_probe_receipt.v1");
        encoder.text(&self.site_id);
        encoder.text(&self.source_id);
        encoder.digest(self.manifest_digest);
        encoder.u64(self.source_generation);
        encoder.text(&self.peer.to_string());
        encoder.text(&self.authority);
        encoder.text(&self.presentation);
        encoder.text(&self.control_root);
        encoder.u64(self.media_index as u64);
        encoder.u8(self.rtp_channel);
        encoder.u8(self.rtcp_channel);
        encoder.digest(self.sdp_digest);
        encoder.text(self.codec.as_str());
        encoder.u8(self.payload_type);
        encoder.u32(self.ssrc);
        encoder.u32(self.frame_duration_ticks);
        encoder.u32(self.clock_rate_hz);
        encoder.u32(self.observed_frames);
        encoder.u32(self.first_rtp_timestamp);
        encoder.u32(self.last_rtp_timestamp);
        encoder.u64(self.parameter_set_digests.len() as u64);
        for digest in &self.parameter_set_digests {
            encoder.digest(*digest);
        }
        encoder.text(&self.server_identity);
        optional_clock_witness(&mut encoder, self.clock_evidence.as_ref());
        finish(encoder)
    }
}
