#![forbid(unsafe_code)]
//! HEVC's explicit verifier, source-boundary policy and effective native ceilings.

use fss_packet::hevc::{HevcAssemblyLimits, HevcConfigurationLimits};
use fss_packet::{H265Limits, ReorderLimits};
use fss_reference::rtsp::live_hevc::LiveHevcConfig;
use fss_reference::rtsp::live_hevc_archive::{LiveHevcArchiveConfig, SelectedHevcRecordingConfig};
use fss_reference::rtsp::recording::hevc::MAX_HEVC_LOOKAHEAD_NALS;
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;

use super::Options;

#[derive(Debug)]
pub(super) struct HevcPlan {
    pub(super) namespace: HevcArchiveNamespace,
    pub(super) reorder: ReorderLimits,
    pub(super) reconstruction: H265Limits,
    pub(super) assembly: HevcAssemblyLimits,
    pub(super) configuration: HevcConfigurationLimits,
}
impl HevcPlan {
    pub(super) fn new(scope: CatalogScope) -> Result<Self, &'static str> {
        Ok(Self {
            namespace: HevcArchiveNamespace::new(scope)
                .map_err(|_| "native HEVC archive scope refused")?,
            reorder: ReorderLimits::default(),
            reconstruction: H265Limits::default(),
            assembly: HevcAssemblyLimits::default(),
            configuration: HevcConfigurationLimits::default(),
        })
    }

    /// Preserve AVC's approval bytes while binding only the selected codec's real limits.
    pub(super) fn replace_media_bounds(&self, numbers: &mut Vec<(&'static str, u64)>) {
        numbers.retain(|(key, _)| {
            !matches!(
                *key,
                "packet_bytes"
                    | "extension_bytes"
                    | "rtcp_packets"
                    | "reorder_packets"
                    | "reorder_bytes"
                    | "reorder_delay_ns"
                    | "nal_bytes"
                    | "packet_nals"
                    | "fragment_packets"
                    | "fragment_age_ns"
                    | "syntax_nal_bytes"
                    | "parameter_set_bytes"
                    | "coded_width"
                    | "coded_height"
                    | "luma_samples"
                    | "reference_frames"
                    | "slice_identity_bits"
                    | "assembly_nals"
                    | "assembly_bytes"
                    | "assembly_age_ns"
            )
        });
        let r = self.reorder;
        let n = self.reconstruction;
        let a = self.assembly;
        let c = self.configuration;
        numbers.extend([
            ("packet_bytes", r.packet.max_packet_bytes as u64),
            ("extension_bytes", r.packet.max_extension_bytes as u64),
            ("rtcp_packets", r.packet.max_rtcp_packets as u64),
            ("reorder_packets", r.max_packets as u64),
            ("reorder_bytes", r.max_bytes as u64),
            ("reorder_delay_ns", r.max_delay_ns),
            ("nal_bytes", n.max_nal_bytes as u64),
            ("packet_nals", n.max_packet_nals as u64),
            ("fragment_packets", n.max_fragment_packets as u64),
            ("fragment_age_ns", n.max_pending_age_ns),
            ("assembly_nals", a.max_nals as u64),
            ("assembly_bytes", a.max_bytes as u64),
            ("assembly_source_spans", a.max_source_spans as u64),
            ("assembly_age_ns", a.max_age_ns),
            ("parameter_set_bytes", c.max_parameter_bytes as u64),
            ("coded_width", u64::from(c.max_width)),
            ("coded_height", u64::from(c.max_height)),
            ("luma_samples", c.max_luma_samples),
            ("source_only_lookahead_nals", MAX_HEVC_LOOKAHEAD_NALS as u64),
        ]);
    }
}

impl Options {
    pub(crate) fn hevc_live_config(&self) -> Result<LiveHevcConfig, &'static str> {
        let selected = self.hevc.as_ref().ok_or("HEVC was not approved")?;
        let common = self.live_config();
        Ok(LiveHevcConfig {
            protocol: common.protocol,
            binding: common.binding,
            transport: common.transport,
            reorder: selected.reorder,
            reconstruction: selected.reconstruction,
            assembly: selected.assembly,
            realm: common.realm,
            digest_policy: common.digest_policy,
            deadline_ns: common.deadline_ns,
            max_steps: common.max_steps,
        })
    }
    pub(crate) fn hevc_recording_config(
        &self,
    ) -> Result<SelectedHevcRecordingConfig, &'static str> {
        let selected = self.hevc.as_ref().ok_or("HEVC was not approved")?;
        Ok(SelectedHevcRecordingConfig {
            scope: self.recording.scope.clone(),
            payload_type: self.recording.payload_type,
            time_scale: self.time_scale,
            limits: self.recording.limits,
            configuration_limits: selected.configuration,
        })
    }
    pub(crate) fn hevc_archive_config(&self) -> Result<LiveHevcArchiveConfig, &'static str> {
        let selected = self.hevc.as_ref().ok_or("HEVC was not approved")?;
        Ok(LiveHevcArchiveConfig {
            namespace: selected.namespace.clone(),
            limits: self.archive.limits,
            max_window_bytes: self.archive.max_window_bytes,
            max_steps: self.archive.max_steps,
            publication_deadline_ns: self.archive.publication_deadline_ns,
            max_storage_pause_ns: self.archive.max_storage_pause_ns,
        })
    }
}
