#![forbid(unsafe_code)]
//! Full source custody is an additional precondition, never a substitute for native media proof.

use std::collections::BTreeMap;

use super::*;
use fss_geometry::WorkBudget;
use fss_reference::rtsp::datagram_archive::{DatagramArchive, DatagramPin};
use fss_reference::rtsp::recording::PreparedRecording;
use minimum_source_pins::MinimumSourcePin;

const POLICY: &str = "source-first-recovery:complete-current-datagram-chain:exact-observed-head:\
all-source-stores-locked:original-rtp-bytes-and-receive-times-required:\
no-source-write-or-reconstruction:per-attempt-cumulative-work:v1";

/// No source bytes are retained by this owner. Metadata, exact pins and locks survive
/// the complete multi-attempt operation; repeated checks share the original work ceiling.
pub(super) struct SourceEntry {
    location: Location,
    publisher: Option<LocalRootPublisher>,
    head: Option<DatagramPin>,
    rtp: BTreeMap<(ContentDigest, u64, usize), usize>,
    work: WorkBudget<'static>,
}

impl SourceEntry {
    pub(super) fn load(
        config: &SourceConfig,
        attempt: &Options,
        location: Location,
        minimum: Option<MinimumSourcePin>,
        clock: &Clock<'_>,
    ) -> Result<Self> {
        if config.scope.binding != attempt.binding()
            || config.scope.receive_clock != attempt.recording_config().scope.receive_clock
            || config.scope.channels != attempt.live_config().protocol.channels
        {
            return Err(STATE);
        }
        clock.now()?;
        let mut result = Self {
            location,
            publisher: None,
            head: None,
            rtp: BTreeMap::new(),
            work: WorkBudget::new(config.work),
        };
        if result.location.directory.is_none() {
            if minimum.is_some() {
                return Err(STORAGE);
            }
            return Ok(result);
        }
        let publisher = LocalRootPublisher::open(&result.location.canonical, config.storage)
            .map_err(|_| STORAGE)?;
        clock.now()?;
        let archive = DatagramArchive::recover(
            &publisher,
            config.scope.clone(),
            config.limits,
            minimum.map(|pin| pin.pin(config)).transpose()?,
            clock,
            &mut result.work,
        )
        .map_err(|_| STORAGE)?;
        // Price the bounded lookup construction separately from native source verification.
        result
            .work
            .charge((archive.records().len() as u64).saturating_mul(32))
            .map_err(|_| STORAGE)?;
        for record in archive.records() {
            clock.now()?;
            if record.channel == config.scope.channels.0 {
                let count = result
                    .rtp
                    .entry((
                        record.payload_digest,
                        record.received_ns,
                        record.payload_bytes,
                    ))
                    .or_insert(0_usize);
                *count = count.checked_add(1).ok_or(STORAGE)?;
            }
        }
        result.head = Some(archive.pin());
        result.publisher = Some(publisher);
        Ok(result)
    }

    fn revalidate(&mut self, config: &SourceConfig, clock: &Clock<'_>) -> Result<()> {
        match (&self.publisher, self.head) {
            (None, None) => Ok(()),
            (Some(publisher), Some(head)) => {
                let current = DatagramArchive::recover(
                    publisher,
                    config.scope.clone(),
                    config.limits,
                    Some(head),
                    clock,
                    &mut self.work,
                )
                .map_err(|_| STORAGE)?;
                if current.pin() != head {
                    return Err(APPROVAL);
                }
                clock.now()?;
                Ok(())
            }
            _ => Err(STATE),
        }
    }

    pub(super) fn verify_recording(
        &mut self,
        recording: &PreparedRecording,
        clock: &Clock<'_>,
    ) -> Result<()> {
        let head = self.head.ok_or(STORAGE)?;
        if head.datagrams == 0 {
            return Err(STORAGE);
        }
        self.work
            .charge(
                recording.objects().source.len() as u64 * 2
                    + recording.summary().packets as u64 * 64,
            )
            .map_err(|_| STORAGE)?;
        let packets = recording.packets().map_err(|_| STORAGE)?;
        // One raw observation cannot justify repeated packets within one recording.
        // Reset consumption for each recording: adjacent windows may legitimately retain
        // the same boundary/lookahead datagram under their independent native witnesses.
        let mut consumed = BTreeMap::new();
        for packet in packets {
            clock.now()?;
            let key = (
                ContentDigest::sha256(packet.bytes),
                packet.received_ns,
                packet.bytes.len(),
            );
            let available = self.rtp.get(&key).copied().ok_or(STORAGE)?;
            let count = consumed.entry(key).or_insert(0_usize);
            *count = count.checked_add(1).ok_or(STORAGE)?;
            if *count > available {
                return Err(STORAGE);
            }
        }
        Ok(())
    }

    fn encode(&self, e: &mut CanonicalEncoder) -> Result<()> {
        encode_location(e, &self.location)?;
        e.bool(self.head.is_some());
        if let Some(head) = self.head {
            e.digest(head.scope);
            e.digest(head.head);
            e.u64(head.datagrams);
            e.u64(head.payload_bytes);
        }
        Ok(())
    }

    fn json(&self, attempt: usize) -> Result<String> {
        let head = self.head.map_or_else(
            || "null".into(),
            |pin| {
                object(&[
                    ("scope", string(&pin.scope.to_text())),
                    ("head", string(&pin.head.to_text())),
                    ("datagrams", pin.datagrams.to_string()),
                    ("payload_bytes", pin.payload_bytes.to_string()),
                ])
            },
        );
        Ok(object(&[
            ("attempt", (attempt + 1).to_string()),
            (
                "source_root",
                string(self.location.canonical.to_str().ok_or(ROOT)?),
            ),
            ("observed_source_head", head),
            (
                "source_custody",
                string(if self.head.is_some() {
                    "complete_current_datagram_chain_verified"
                } else {
                    "all_three_stores_unobserved"
                }),
            ),
            ("work_used", self.work.used().to_string()),
            ("work_remaining", self.work.remaining().to_string()),
            ("source_publication_requested", "false".into()),
            ("source_bytes_emitted", "false".into()),
            ("capture_complete", "false".into()),
        ]))
    }
}

pub(super) fn location_unchanged(
    plan: &impl RecoveryPlan,
    index: usize,
    entry: Option<&SourceEntry>,
    clock: &Clock<'_>,
) -> Result<()> {
    clock.now()?;
    match (plan.source(index)?, entry) {
        (None, None) => Ok(()),
        (Some(config), Some(source)) if locate(&config.root)? == source.location => Ok(()),
        (Some(_), Some(_)) => Err(ROOT),
        _ => Err(STATE),
    }
}

pub(super) fn revalidate(
    plan: &impl RecoveryPlan,
    index: usize,
    entry: Option<&mut SourceEntry>,
    clock: &Clock<'_>,
) -> Result<()> {
    match (plan.source(index)?, entry) {
        (None, None) => Ok(()),
        (Some(config), Some(source)) => source.revalidate(config, clock),
        _ => Err(STATE),
    }
}

pub(super) fn encode<C: ArchiveCodec>(
    plan: &impl RecoveryPlan,
    entries: &[Entry<C>],
    e: &mut CanonicalEncoder,
) -> Result<()> {
    if entries.iter().any(|entry| entry.source.is_some()) {
        e.text(POLICY);
        e.u64(entries.len() as u64);
        for entry in entries {
            entry.source.as_ref().ok_or(STATE)?.encode(e)?;
        }
    }
    if let Some(minimum) = plan.minimum_sources() {
        minimum.encode(e);
    }
    Ok(())
}

pub(super) fn annotate<C: ArchiveCodec>(
    plan: &impl RecoveryPlan,
    entries: &[Entry<C>],
    mut report: String,
) -> Result<String> {
    if !entries.iter().any(|entry| entry.source.is_some()) {
        return Ok(report);
    }
    let rows = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| entry.source.as_ref().ok_or(STATE)?.json(index))
        .collect::<Result<Vec<_>>>()?;
    let source = object(&[
        ("policy", string(POLICY)),
        ("attempts", format!("[{}]", rows.join(","))),
        (
            "minimum_source_pins",
            plan.minimum_sources()
                .map_or_else(|| "[]".into(), MinimumSourcePins::json),
        ),
        (
            "minimum_source_prefixes_verified",
            plan.minimum_sources().is_some().to_string(),
        ),
        (
            "minimum_scope",
            string("listed-attempts-only:caller-retained:not-a-camera-authentication-proof"),
        ),
        ("source_read_requested", "true".into()),
        (
            "original_rtp_membership_required_before_publication",
            "true".into(),
        ),
    ]);
    if report.pop() != Some('}') {
        return Err(STATE);
    }
    report.push_str(",\"datagram_source_custody\":");
    report.push_str(&source);
    report.push('}');
    if report.len() > REPORT_LIMIT {
        return Err(OUTPUT);
    }
    Ok(report)
}

pub(super) fn emit<C: ArchiveCodec>(
    plan: &impl RecoveryPlan,
    entries: &[Entry<C>],
    reports: &mut Reports<impl FnMut(&[u8]) -> Result<()>>,
    schema: &str,
) -> Result<()> {
    if entries.iter().any(|entry| entry.source.is_some()) {
        let detail = annotate(
            plan,
            entries,
            object(&[("publication_started", "false".into())]),
        )?;
        reports.row_with_schema(schema, "datagram_source_preflight_complete", detail)?;
    }
    Ok(())
}
