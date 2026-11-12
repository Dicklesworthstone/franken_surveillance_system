#![forbid(unsafe_code)]

use fss_core::{
    ContentDigest, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition, KnowledgeState,
};

use super::DeploymentRecordingReplayQuery;
use crate::rtsp::recording_replay::time::{ReplaySampleTime, ReplayTimeEvidence, ReplayTimeReport};

pub(super) struct ReplayProjection<'a> {
    pub report: &'a ReplayTimeReport,
    pub source_permit_digest: ContentDigest,
}

impl ReplayProjection<'_> {
    /// Project every native match, unknown and source-only observation without upgrading
    /// recorded assertions into trusted UTC, exposure time or physical coverage.
    #[must_use]
    pub fn epistemic(&self) -> EnvelopeEpistemic {
        let report = self.report;
        let query = &report.query;
        let source_observation = if report.scanned_windows == 0 {
            "This receipt declares no original windows; no original source bytes were read."
        } else {
            "Native source bytes were internally read and verified."
        };
        let mut propositions = vec![EnvelopeProposition {
            id: "claim:recordings-replay:source-verification".to_owned(),
            statement: format!(
                "Verified exact native {} replay receipt and every declared original under a separate current source-read grant: replay_root={}, replay_request={}, native_query={}, native_report={}, native_index={}, source_permit={}, ntp_era={}, requested_utc_ns=[{},{}), windows={}, samples={}, packets={}, source_bytes_reserved={}, source_bytes={}, matches={}, unknown_samples={}, source_only_groups={}, outside_samples={}. Source sensor={}, stream={}, generation={}, source_anchor={}, receive_clock={}, decode_clock={}, time_scale={}. {} This response contains no source media.",
                query.codec.as_str(), query.receipt_root, query.request, query.digest().map(|d| d.to_text()).unwrap_or_else(|_| "invalid".to_owned()),
                report.digest, report.index_digest, self.source_permit_digest, query.ntp_era,
                query.start_ns, query.end_ns, report.scanned_windows, report.scanned_samples,
                report.scanned_packets, report.source_bytes_reserved, report.source_bytes,
                report.matches.len(), report.unknown.len(), report.source_only.len(), report.outside_samples,
                query.scope.recording.sensor.as_str(), query.scope.recording.stream.as_str(),
                query.scope.recording.generation, query.scope.recording.anchor,
                query.scope.recording.receive_clock, query.scope.decode_clock, query.scope.time_scale, source_observation,
            ),
            state: KnowledgeState::Known,
            provenance: "derived".to_owned(),
            evidence: vec![query.receipt_root.to_text(), report.digest.to_text(), report.index_digest.to_text(), self.source_permit_digest.to_text()],
        }, EnvelopeProposition {
            id: "claim:recordings-replay:clock-conditions".to_owned(),
            statement: "UTC values are recorder-supplied ONVIF RTP assertions, verified against original datagrams and native sample provenance under the caller's explicit NTP era. They are unauthenticated clock assertions, not camera exposure times or host-clock mappings. Requested/accepted PLAY ranges, RTP timestamps and source arrival times do not supply missing UTC. Native decode order is preserved even when presentation or UTC order differs.".to_owned(),
            state: KnowledgeState::Known,
            provenance: "derived".to_owned(),
            evidence: vec![query.receipt_root.to_text(), report.index_digest.to_text()],
        }, EnvelopeProposition {
            id: "claim:recordings-replay:physical-observability".to_owned(),
            statement: "Trusted UTC, exposure time, uninterrupted recording, live coverage, physical activity and physical absence are unknown. An empty match set or known outside-sample count does not establish missing footage or why footage is missing. Source-only HEVC tails are not published pictures or recording-completion evidence.".to_owned(),
            state: KnowledgeState::Unknown,
            provenance: "derived".to_owned(),
            evidence: Vec::new(),
        }];
        for (partition, rows) in [("match", &report.matches), ("unknown", &report.unknown)] {
            for (ordinal, row) in rows.iter().enumerate() {
                propositions.push(sample_proposition(partition, ordinal, row));
            }
        }
        for (ordinal, row) in report.source_only.iter().enumerate() {
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-replay:source-only:{ordinal}"),
                statement: format!(
                    "Native trailing source-only group: window={}, slot={}, root={}, rtp_timestamp={}, {}. This group is retained regardless of UTC/query overlap, is not a media sample, and cannot establish recording completion.",
                    row.window, row.slot.as_str(), row.root, row.rtp_timestamp,
                    describe_evidence(&row.evidence),
                ),
                state: evidence_state(&row.evidence),
                provenance: "derived".to_owned(),
                evidence: vec![row.root.to_text(), row.evidence.packet_set_digest.to_text(), row.evidence.proof_digest.to_text()],
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                "The principal is an audit label. A separately supplied current CAP-READ-MEDIA-001 grant authorized this exact bounded source verification; neither the query admission nor a retained receipt grants media disclosure or effects.".to_owned(),
                "Archive source pins are explicit caller input, not deployment membership. Exact native custody and current deployment context were independently verified; there is no atomic cross-owner snapshot or future read lease.".to_owned(),
                "Recorder clocks and the caller-supplied NTP era are not authenticated by source custody. Source verification preserves unknown/malformed/conflicting assertions without borrowing another clock.".to_owned(),
                "The deployment spool doctor was not run; its metadata context retains the conservative attention verdict.".to_owned(),
            ],
            invalidators: vec!["Any authority/effect-prefix, source grant, publication, original source/index, deletion state, source/clock scope, NTP era, query interval or allowance change requires a new query.".to_owned()],
        }
    }

    /// Exhaustion describes one exact receipt; it makes no continuous coverage claim.
    #[must_use]
    pub fn coverage(&self) -> EnvelopeCoverage {
        EnvelopeCoverage {
            authorized_domain: vec!["one explicitly pinned AVC/HEVC replay receipt and its exact native originals under a separate current source-read grant".to_owned()],
            observed_domain: vec!["complete native original custody and sample/source-only associations; source-linked recorder UTC assertions, explicit unknowns and known outside-sample count".to_owned()],
            not_observable_domain: vec!["authenticated recorder clocks, camera exposure time, other receipts, live or continuous physical coverage, activity and absence".to_owned()],
            omitted_count: 0,
            omission_reasons: Vec::new(),
            stop_reason: "pinned_replay_receipt_exhausted".to_owned(),
        }
    }
}

impl DeploymentRecordingReplayQuery {
    /// Complete native assertions, preserving unknowns and unauthenticated clock semantics.
    #[must_use]
    pub fn epistemic(&self) -> EnvelopeEpistemic {
        ReplayProjection {
            report: &self.native.report,
            source_permit_digest: self.source_permit_digest,
        }
        .epistemic()
    }

    /// Exact receipt exhaustion without physical coverage or absence claims.
    #[must_use]
    pub fn coverage(&self) -> EnvelopeCoverage {
        ReplayProjection {
            report: &self.native.report,
            source_permit_digest: self.source_permit_digest,
        }
        .coverage()
    }
}

impl super::retained::DeploymentRetainedReplayQuery {
    /// The same native assertions plus their independently verified current destination import.
    #[must_use]
    pub fn epistemic(&self) -> EnvelopeEpistemic {
        let mut result = ReplayProjection {
            report: &self.report,
            source_permit_digest: self.source_permit_digest,
        }
        .epistemic();
        result.propositions.insert(0, EnvelopeProposition {
            id: "claim:recordings-replay:retained-import".to_owned(),
            statement: format!(
                "Verified current destination import={}, publication_root={}, manifest={}. The complete recorder receipt and original packets were reconstructed from this deployment's retained custody; the original archive directory was not opened. Original recorder scope remains historical provenance, distinct from current destination authority.",
                self.import_identity, self.import_root, self.manifest_digest,
            ),
            state: KnowledgeState::Known,
            provenance: "derived".to_owned(),
            evidence: vec![self.import_identity.to_text(), self.import_root.to_text(), self.manifest_digest.to_text()],
        });
        result.assumptions[1] = "The exact completed destination import, retained publication and original ancestry were verified under matching current authority observations. The original recorder pins are independently supplied historical source scope. Revalidation is not an atomic filesystem snapshot or future availability lease.".to_owned();
        result
    }

    /// Complete selected imported receipt, without extending its physical or temporal coverage.
    #[must_use]
    pub fn coverage(&self) -> EnvelopeCoverage {
        let mut result = ReplayProjection {
            report: &self.report,
            source_permit_digest: self.source_permit_digest,
        }
        .coverage();
        result.authorized_domain = vec!["one explicitly selected completed destination import and its independently pinned AVC/HEVC replay originals under a current source-read grant".to_owned()];
        result.stop_reason = "retained_replay_receipt_exhausted".to_owned();
        result
    }
}

fn sample_proposition(
    partition: &str,
    ordinal: usize,
    row: &ReplaySampleTime,
) -> EnvelopeProposition {
    EnvelopeProposition {
        id: format!("claim:recordings-replay:{partition}:{ordinal}"),
        statement: format!(
            "Native media sample: partition={}, window={}, slot={}, root={}, sample={}, decode_time={}, presentation_time={}, duration={}, rtp_timestamp={}, {}. Decode/presentation ticks remain in the explicitly pinned native time scale.",
            partition,
            row.window,
            row.slot.as_str(),
            row.root,
            row.sample,
            row.decode_time,
            row.presentation_time,
            row.duration,
            row.rtp_timestamp,
            describe_evidence(&row.evidence),
        ),
        state: evidence_state(&row.evidence),
        provenance: "derived".to_owned(),
        evidence: vec![
            row.root.to_text(),
            row.evidence.packet_set_digest.to_text(),
            row.evidence.proof_digest.to_text(),
        ],
    }
}

fn evidence_state(evidence: &ReplayTimeEvidence) -> KnowledgeState {
    if evidence.utc.is_some() {
        KnowledgeState::Known
    } else {
        KnowledgeState::NotObservable
    }
}

fn describe_evidence(evidence: &ReplayTimeEvidence) -> String {
    let utc = match evidence.utc {
        Some(interval) => format!(
            "recorded_utc_ns=[{},{}] (inclusive outward rounding enclosure)",
            interval.earliest_ns, interval.latest_ns
        ),
        None => "recorded_utc=unknown".to_owned(),
    };
    let unknown = evidence
        .unknown
        .map(|reason| {
            format!(
                "unknown_reason={}, parser_error={}",
                reason.as_str(),
                reason.error_code().unwrap_or("none")
            )
        })
        .unwrap_or_else(|| "unknown_reason=none, parser_error=none".to_owned());
    let header = evidence.header.map(|header| format!(
        "ntp_seconds={}, ntp_fraction={}, clean_point={}, end_of_contiguous_section={}, discontinuity={}, terminal={}, cseq_low={}",
        header.ntp.seconds, header.ntp.fraction, header.clean_point,
        header.end_of_contiguous_section, header.discontinuity, header.terminal, header.cseq_low,
    )).unwrap_or_else(|| "replay_header=absent".to_owned());
    format!(
        "{}, {}, {}, first_sequence={}, last_sequence={}, packet_count={}, packet_set={}, proof={}",
        utc,
        unknown,
        header,
        evidence.first_sequence,
        evidence.last_sequence,
        evidence.packet_count,
        evidence.packet_set_digest,
        evidence.proof_digest,
    )
}
