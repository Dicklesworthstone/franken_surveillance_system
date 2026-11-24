#![forbid(unsafe_code)]
//! Per-tick camera polling, ring fan-out, and live perception steps for [`crate::supervisor::DaemonSupervisor`].
//!
//! Semantic plane: `"authority"`.

use std::sync::Arc;

use fss_core::{DeltaPriority, MeaningfulDeltaClass, ResourcePressure, SensorId, TimestampNs};
use fss_ipc::BoundedControlOp;
use fss_projection_store::{CoverageStatus, SensorLivenessStatus};
use fss_reference::ingest::live_corroborate::{CorroborationOutcome, LiveCorroborationDecision};

use crate::error::DaemonError;
use crate::manifest::CameraAdapterKind;
use crate::sensor::{CameraFrame, SensorDisconnectReason, SensorDriverEvent, SensorState};
use crate::supervisor::DaemonSupervisor;

const MAX_POLLS_PER_CAMERA_PER_TICK: usize = 128;

pub(crate) struct CameraPollCounters {
    pub(crate) frames_received: u64,
    pub(crate) frames_shed: u64,
    pub(crate) coverage_gaps_emitted: u64,
    pub(crate) reconnects_completed: u64,
}

impl DaemonSupervisor {
    pub(crate) fn process_control_commands_step(
        &mut self,
        now_ns: i128,
        now: TimestampNs,
    ) -> Result<(bool, u64), DaemonError> {
        let mut force_scrub = false;
        let mut coverage_gaps = 0_u64;
        let pending = self
            .control_shared
            .as_ref()
            .map_or_else(Vec::new, |s| s.drain_control_commands());
        for cmd in pending {
            match cmd.op {
                BoundedControlOp::TriggerScrub => force_scrub = true,
                BoundedControlOp::StopCamera => {
                    if let Some(target) = cmd.target_camera_id.as_deref()
                        && let Ok(sid) = SensorId::parse(target)
                        && let Some(slot) = self.sensors.get_mut(&sid)
                    {
                        slot.driver.disconnect();
                        slot.state = SensorState::Stopped;
                        slot.active_gaps = slot.active_gaps.saturating_add(1);
                        let zone = slot.entry.primary_zone.clone();
                        let last = TimestampNs(slot.last_frame_ns);
                        let _ = self.regions.drain_failed_sensor_region(
                            &sid,
                            SensorDisconnectReason::OperatorStopped.as_str(),
                            now,
                        )?;
                        let receipt = self.storage.commit_coverage_and_liveness(
                            &sid,
                            &zone,
                            CoverageStatus::NotObservable,
                            SensorLivenessStatus::Offline,
                            slot.active_gaps,
                            last,
                            now,
                            self.regions.storage_ledger_cx(),
                            self.regions.region_tree(),
                        )?;
                        self.broadcast_delta(
                            receipt.commit_sequence,
                            receipt.batch_digest,
                            MeaningfulDeltaClass::CoverageLoss,
                            DeltaPriority::High,
                            format!("camera_stopped sensor={target}"),
                        );
                        coverage_gaps = coverage_gaps.saturating_add(1);
                    }
                }
                BoundedControlOp::StartCamera => {
                    if let Some(target) = cmd.target_camera_id.as_deref()
                        && let Ok(sid) = SensorId::parse(target)
                        && let Some(slot) = self.sensors.get_mut(&sid)
                        && slot.state == SensorState::Stopped
                    {
                        slot.state = SensorState::GapBackoff;
                        slot.next_reconnect_ns = now_ns;
                    }
                }
                BoundedControlOp::SnapshotCamera => {
                    self.handle_snapshot_camera(cmd.target_camera_id.as_deref())?;
                }
                BoundedControlOp::ReloadManifest => {
                    self.handle_reload_manifest()?;
                }
                BoundedControlOp::ProbeDetect => {
                    self.handle_probe_detect(cmd.target_camera_id.as_deref())?;
                }
            }
        }
        Ok((force_scrub, coverage_gaps))
    }

    fn handle_snapshot_camera(
        &mut self,
        target_camera_id: Option<&str>,
    ) -> Result<(), DaemonError> {
        let targets: Vec<SensorId> = match target_camera_id {
            Some(raw) => match SensorId::parse(raw) {
                Ok(sid) if self.sensors.contains_key(&sid) => vec![sid],
                _ => return Ok(()),
            },
            None => self.sensors.keys().cloned().collect(),
        };
        for sid in targets {
            let (latest_frame, adapter) = match self.sensors.get(&sid) {
                Some(slot) => (slot.ring.latest(), slot.entry.adapter),
                None => continue,
            };
            if let Some(frame) = latest_frame {
                let commit_seq = if !self.storage.is_quota_pinned() {
                    if let Some(receipt) = self.storage.flush_camera_gop(
                        &sid,
                        adapter,
                        self.regions.storage_ledger_cx(),
                        self.regions.region_tree(),
                    )? {
                        receipt.commit_sequence
                    } else {
                        self.storage.head_snapshot()?.commit_sequence
                    }
                } else {
                    self.storage.head_snapshot()?.commit_sequence
                };
                self.broadcast_delta(
                    commit_seq,
                    frame.source_digest,
                    MeaningfulDeltaClass::MaterialState,
                    DeltaPriority::Normal,
                    format!(
                        "camera_snapshot sensor={} gen={} seq={} dims={}x{} digest={}",
                        sid.as_str(),
                        frame.stream_generation,
                        frame.sequence,
                        frame.dimensions[0],
                        frame.dimensions[1],
                        frame.source_digest.to_text(),
                    ),
                );
            } else {
                let head = self.storage.head_snapshot()?;
                self.broadcast_delta(
                    head.commit_sequence,
                    head.history_root,
                    MeaningfulDeltaClass::SensorHealth,
                    DeltaPriority::Normal,
                    format!(
                        "camera_snapshot_unavailable sensor={} reason=no_buffered_frame",
                        sid.as_str()
                    ),
                );
            }
        }
        Ok(())
    }

    fn handle_reload_manifest(&mut self) -> Result<(), DaemonError> {
        let head = self.storage.head_snapshot()?;
        let Some(path) = self.manifest_path.clone() else {
            self.broadcast_delta(
                head.commit_sequence,
                self.manifest.digest(),
                MeaningfulDeltaClass::SensorHealth,
                DeltaPriority::High,
                "manifest_reload_refused reason=no_manifest_path_configured".to_owned(),
            );
            return Ok(());
        };
        let reloaded = match crate::manifest::SiteManifest::from_file(&path) {
            Ok(m) => m,
            Err(err) => {
                self.broadcast_delta(
                    head.commit_sequence,
                    self.manifest.digest(),
                    MeaningfulDeltaClass::SensorHealth,
                    DeltaPriority::High,
                    format!("manifest_reload_refused error_id={}", err.error_id()),
                );
                return Ok(());
            }
        };
        if reloaded.site_id != self.manifest.site_id {
            self.broadcast_delta(
                head.commit_sequence,
                self.manifest.digest(),
                MeaningfulDeltaClass::SensorHealth,
                DeltaPriority::High,
                "manifest_reload_refused reason=site_id_mismatch".to_owned(),
            );
            return Ok(());
        }
        if let Err(err) = self.perception.reload_manifest(&reloaded) {
            self.broadcast_delta(
                head.commit_sequence,
                self.manifest.digest(),
                MeaningfulDeltaClass::SensorHealth,
                DeltaPriority::High,
                format!(
                    "manifest_reload_refused reason=perception_reload_failed error_id={}",
                    err.error_id()
                ),
            );
            return Ok(());
        }
        let mut updated_cameras = 0_usize;
        for new_entry in &reloaded.cameras {
            if let Some(slot) = self.sensors.get_mut(&new_entry.sensor_id) {
                slot.entry.osd_ignore_rects = new_entry.osd_ignore_rects.clone();
                slot.entry.priority_tier = new_entry.priority_tier;
                slot.entry.primary_zone = new_entry.primary_zone.clone();
                slot.entry.zones = new_entry.zones.clone();
                slot.entry.failure_domains = new_entry.failure_domains.clone();
                slot.entry.reconnect_min_ms = new_entry.reconnect_min_ms;
                slot.entry.reconnect_max_ms = new_entry.reconnect_max_ms;
                slot.entry.stall_timeout_ms = new_entry.stall_timeout_ms;
                slot.entry.gop_frames = new_entry.gop_frames;
                slot.entry.auth_realm = new_entry.auth_realm.clone();
                slot.entry.allow_inband_sps_pps = new_entry.allow_inband_sps_pps;
                slot.entry.setup_companion_tracks = new_entry.setup_companion_tracks;
                slot.driver.update_manifest_entry(new_entry);
                slot.backoff = crate::sensor::BackoffSchedule::new(
                    new_entry.sensor_id.as_str(),
                    new_entry.reconnect_min_ms,
                    new_entry.reconnect_max_ms,
                );
                updated_cameras = updated_cameras.saturating_add(1);
            }
        }
        let digest = reloaded.digest();
        let site = reloaded.site_id.clone();
        self.manifest = reloaded;
        self.broadcast_delta(
            head.commit_sequence,
            digest,
            MeaningfulDeltaClass::MaterialState,
            DeltaPriority::Normal,
            format!(
                "manifest_reloaded site={site} digest={} updated_cameras={updated_cameras}",
                digest.to_text()
            ),
        );
        Ok(())
    }

    fn handle_probe_detect(&mut self, target_camera_id: Option<&str>) -> Result<(), DaemonError> {
        let mut probe_batch = Vec::new();
        let targets: Vec<SensorId> = match target_camera_id {
            Some(raw) => match SensorId::parse(raw) {
                Ok(sid) if self.sensors.contains_key(&sid) => vec![sid],
                _ => return Ok(()),
            },
            None => self.sensors.keys().cloned().collect(),
        };
        for sid in &targets {
            if let Some(slot) = self.sensors.get(sid)
                && let Some(frame) = slot.ring.latest()
            {
                probe_batch.push(frame);
            }
        }
        let label = target_camera_id.unwrap_or("all");
        if probe_batch.is_empty() {
            let head = self.storage.head_snapshot()?;
            self.broadcast_delta(
                head.commit_sequence,
                head.history_root,
                MeaningfulDeltaClass::SensorHealth,
                DeltaPriority::Normal,
                format!("probe_detect_unavailable target={label} reason=no_buffered_frames"),
            );
            return Ok(());
        }
        let Some(outcome) = self.perception.probe_frames(&probe_batch)? else {
            return Ok(());
        };
        let total_detections: usize = outcome
            .batch_receipt
            .frames
            .iter()
            .map(|r| r.detections.len())
            .sum();
        let ran_ml_count = outcome
            .batch_receipt
            .frames
            .iter()
            .filter(|r| r.stage_decision.ran_ml_inference())
            .count();
        self.commit_perception_decisions(&outcome.decisions)?;
        self.corroborated_events = self
            .corroborated_events
            .saturating_add(outcome.corroborated_count);
        self.shared_domain_held_events = self
            .shared_domain_held_events
            .saturating_add(outcome.shared_domain_held_count);
        let head = self.storage.head_snapshot()?;
        self.broadcast_delta(
            head.commit_sequence,
            outcome.batch_receipt.batch_digest,
            MeaningfulDeltaClass::Hypothesis,
            DeltaPriority::Normal,
            format!(
                "probe_detect_completed target={label} frames={} ran_ml={} detections={} decisions={}",
                probe_batch.len(),
                ran_ml_count,
                total_detections,
                outcome.decisions.len()
            ),
        );
        Ok(())
    }

    pub(crate) fn poll_all_cameras_step(
        &mut self,
        sensor_ids: &[SensorId],
        now_ns: i128,
        now: TimestampNs,
    ) -> Result<CameraPollCounters, DaemonError> {
        let mut out = CameraPollCounters {
            frames_received: 0,
            frames_shed: 0,
            coverage_gaps_emitted: 0,
            reconnects_completed: 0,
        };

        for sid in sensor_ids {
            let mut disconnect_ev: Option<(SensorDisconnectReason, String, TimestampNs, u32)> =
                None;
            let mut reconnect_ev: Option<(u64, String)> = None;
            let mut shed_ev: Option<(u64, String, TimestampNs, u32, ResourcePressure)> = None;

            if let Some(slot) = self.sensors.get_mut(sid) {
                if slot.state == SensorState::GapBackoff && now_ns >= slot.next_reconnect_ns {
                    let next_gen = slot.stream_generation.saturating_add(1);
                    match slot.driver.connect(next_gen) {
                        Ok(()) => {
                            slot.stream_generation = next_gen;
                            slot.backoff.reset();
                            slot.state = SensorState::Streaming;
                            slot.last_frame_ns = now_ns;
                            slot.active_gaps = 0;
                            slot.peak_concurrent_sessions = slot
                                .peak_concurrent_sessions
                                .max(slot.driver.active_session_count());
                            slot.ring.start_generation(next_gen);
                            slot.ingest_cursor.reset_for_generation(next_gen);
                            slot.perception_cursor.reset_for_generation(next_gen);
                            slot.preview_cursor.reset_for_generation(next_gen);
                            reconnect_ev = Some((next_gen, slot.entry.primary_zone.clone()));
                        }
                        Err(_) => {
                            let delay_ms = slot.backoff.next_delay_ms();
                            slot.next_reconnect_ns =
                                now_ns.saturating_add(i128::from(delay_ms) * 1_000_000);
                            slot.reconnects = slot.reconnects.saturating_add(1);
                        }
                    }
                }

                if slot.state == SensorState::Streaming {
                    for _ in 0..MAX_POLLS_PER_CAMERA_PER_TICK {
                        match slot.driver.poll_frame(now_ns) {
                            SensorDriverEvent::Frame(frame) => {
                                slot.peak_concurrent_sessions = slot
                                    .peak_concurrent_sessions
                                    .max(slot.driver.active_session_count());
                                slot.last_frame_ns = now_ns;
                                let lag_ns = now_ns.saturating_sub(frame.host_receive_ns).max(0);
                                slot.last_ingest_lag_ms =
                                    u64::try_from(lag_ns / 1_000_000).unwrap_or(u64::MAX);
                                out.frames_received = out.frames_received.saturating_add(1);
                                let push = slot.ring.push(frame);
                                if push.shed_frames > 0 {
                                    out.frames_shed =
                                        out.frames_shed.saturating_add(push.shed_frames);
                                    slot.active_gaps = slot.active_gaps.saturating_add(1);
                                    shed_ev = Some((
                                        push.shed_frames,
                                        slot.entry.primary_zone.clone(),
                                        TimestampNs(slot.last_frame_ns),
                                        slot.active_gaps,
                                        push.pressure,
                                    ));
                                }
                            }
                            SensorDriverEvent::Idle => {
                                let stall_ns = i128::from(slot.entry.stall_timeout_ms)
                                    .saturating_mul(1_000_000);
                                if now_ns.saturating_sub(slot.last_frame_ns) > stall_ns {
                                    slot.driver.disconnect();
                                    slot.state = SensorState::GapBackoff;
                                    slot.active_gaps = slot.active_gaps.saturating_add(1);
                                    slot.reconnects = slot.reconnects.saturating_add(1);
                                    let delay_ms = slot.backoff.next_delay_ms();
                                    slot.next_reconnect_ns =
                                        now_ns.saturating_add(i128::from(delay_ms) * 1_000_000);
                                    disconnect_ev = Some((
                                        SensorDisconnectReason::StalledPackets,
                                        slot.entry.primary_zone.clone(),
                                        TimestampNs(slot.last_frame_ns),
                                        slot.active_gaps,
                                    ));
                                }
                                break;
                            }
                            SensorDriverEvent::Disconnected(reason) => {
                                slot.driver.disconnect();
                                slot.state = SensorState::GapBackoff;
                                slot.active_gaps = slot.active_gaps.saturating_add(1);
                                slot.reconnects = slot.reconnects.saturating_add(1);
                                let delay_ms = slot.backoff.next_delay_ms();
                                slot.next_reconnect_ns =
                                    now_ns.saturating_add(i128::from(delay_ms) * 1_000_000);
                                disconnect_ev = Some((
                                    reason,
                                    slot.entry.primary_zone.clone(),
                                    TimestampNs(slot.last_frame_ns),
                                    slot.active_gaps,
                                ));
                                break;
                            }
                        }
                    }
                }
            }

            if let Some((generation, zone)) = reconnect_ev {
                let _ = self.regions.spawn_sensor_region(sid, generation, now)?;
                let receipt = self.storage.commit_coverage_and_liveness(
                    sid,
                    &zone,
                    CoverageStatus::Covered,
                    SensorLivenessStatus::Online,
                    0,
                    now,
                    now,
                    self.regions.storage_ledger_cx(),
                    self.regions.region_tree(),
                )?;
                self.broadcast_delta(
                    receipt.commit_sequence,
                    receipt.batch_digest,
                    MeaningfulDeltaClass::CoverageRecovery,
                    DeltaPriority::Normal,
                    format!("sensor_recovered sensor={} gen={generation}", sid.as_str()),
                );
                out.reconnects_completed = out.reconnects_completed.saturating_add(1);
            }

            if let Some((shed_count, zone, last_seen, gaps, pressure)) = shed_ev {
                let receipt = self.storage.commit_coverage_and_liveness(
                    sid,
                    &zone,
                    CoverageStatus::Stale,
                    SensorLivenessStatus::Degraded,
                    gaps,
                    last_seen,
                    now,
                    self.regions.storage_ledger_cx(),
                    self.regions.region_tree(),
                )?;
                self.broadcast_delta(
                    receipt.commit_sequence,
                    receipt.batch_digest,
                    MeaningfulDeltaClass::BudgetPressure,
                    DeltaPriority::High,
                    format!(
                        "ring_backpressure_shed sensor={} dropped={shed_count} pressure={pressure:?}",
                        sid.as_str()
                    ),
                );
                out.coverage_gaps_emitted = out.coverage_gaps_emitted.saturating_add(1);
            }

            if let Some((reason, zone, last_seen, gaps)) = disconnect_ev {
                let adapter = self
                    .sensors
                    .get(sid)
                    .map_or(CameraAdapterKind::Synthetic, |s| s.entry.adapter);
                if !self.storage.is_quota_pinned() {
                    let _ = self.storage.flush_camera_gop(
                        sid,
                        adapter,
                        self.regions.storage_ledger_cx(),
                        self.regions.region_tree(),
                    )?;
                }
                let _ = self
                    .regions
                    .drain_failed_sensor_region(sid, reason.as_str(), now)?;
                let receipt = self.storage.commit_coverage_and_liveness(
                    sid,
                    &zone,
                    CoverageStatus::NotObservable,
                    SensorLivenessStatus::Offline,
                    gaps,
                    last_seen,
                    now,
                    self.regions.storage_ledger_cx(),
                    self.regions.region_tree(),
                )?;
                self.broadcast_delta(
                    receipt.commit_sequence,
                    receipt.batch_digest,
                    MeaningfulDeltaClass::CoverageLoss,
                    DeltaPriority::High,
                    format!(
                        "coverage_gap sensor={} reason={}",
                        sid.as_str(),
                        reason.as_str()
                    ),
                );
                out.coverage_gaps_emitted = out.coverage_gaps_emitted.saturating_add(1);
            }
        }
        Ok(out)
    }

    pub(crate) fn fanout_rings_step(
        &mut self,
        sensor_ids: &[SensorId],
    ) -> Result<(Vec<Arc<CameraFrame>>, u64), DaemonError> {
        let mut perception_batch: Vec<Arc<CameraFrame>> = Vec::new();
        let mut frames_committed = 0_u64;
        for sid in sensor_ids {
            let (ingest_frames, adapter, gop_frames) = {
                let Some(slot) = self.sensors.get_mut(sid) else {
                    continue;
                };
                let (perc_frames, _) = slot.ring.read_for_cursor(&mut slot.perception_cursor, 8);
                slot.frames_decoded = slot.frames_decoded.saturating_add(perc_frames.len() as u64);
                perception_batch.extend(perc_frames);

                let _ = slot.ring.read_for_cursor(&mut slot.preview_cursor, 16);

                let ingest_frames = if !slot.ingest_paused && !self.storage.is_quota_pinned() {
                    let (frames, _) = slot
                        .ring
                        .read_for_cursor(&mut slot.ingest_cursor, slot.entry.gop_frames.max(8));
                    frames
                } else {
                    Vec::new()
                };

                let min_seq = slot
                    .ingest_cursor
                    .next_sequence
                    .min(slot.perception_cursor.next_sequence)
                    .min(slot.preview_cursor.next_sequence);
                slot.ring.reclaim_consumed_before(min_seq);
                (ingest_frames, slot.entry.adapter, slot.entry.gop_frames)
            };

            for frame in ingest_frames {
                match self.storage.ingest_frame(
                    frame,
                    adapter,
                    gop_frames,
                    self.regions.storage_ledger_cx(),
                    self.regions.region_tree(),
                ) {
                    Ok(_) => {
                        frames_committed = frames_committed.saturating_add(1);
                        if let Some(slot) = self.sensors.get_mut(sid) {
                            slot.frames_ingested = slot.frames_ingested.saturating_add(1);
                        }
                    }
                    Err(DaemonError::StorageQuotaPinned { .. }) => break,
                    Err(err) => return Err(err),
                }
            }
        }
        Ok((perception_batch, frames_committed))
    }

    pub(crate) fn run_perception_step(
        &mut self,
        perception_batch: &[Arc<CameraFrame>],
    ) -> Result<(u64, u64, Vec<LiveCorroborationDecision>), DaemonError> {
        let Some(outcome) = self.perception.process_frames(perception_batch)? else {
            return Ok((0, 0, Vec::new()));
        };
        self.commit_perception_decisions(&outcome.decisions)?;
        Ok((
            outcome.corroborated_count,
            outcome.shared_domain_held_count,
            outcome.decisions,
        ))
    }

    fn commit_perception_decisions(
        &mut self,
        decisions: &[LiveCorroborationDecision],
    ) -> Result<(), DaemonError> {
        for decision in decisions {
            if let Some(event) = decision.outcome.event() {
                let contributing: Vec<SensorId> = decision
                    .clock_receipts
                    .iter()
                    .filter_map(|r| SensorId::parse(&r.sensor_id).ok())
                    .collect();
                let receipt = self.storage.commit_event_hypothesis(
                    event,
                    contributing,
                    self.regions.storage_ledger_cx(),
                    self.regions.region_tree(),
                )?;
                let (priority, summary) = match &decision.outcome {
                    CorroborationOutcome::Corroborated {
                        supporting_clusters,
                        ..
                    } => (
                        DeltaPriority::High,
                        format!(
                            "corroborated event={} clusters={supporting_clusters} rev={}",
                            event.event_id.as_str(),
                            event.revision
                        ),
                    ),
                    CorroborationOutcome::SharedFailureDomainHeld { shared_domains, .. } => {
                        let joined: Vec<&str> = shared_domains.iter().map(String::as_str).collect();
                        (
                            DeltaPriority::Normal,
                            format!(
                                "shared_failure_domain_held event={} domains={}",
                                event.event_id.as_str(),
                                joined.join(",")
                            ),
                        )
                    }
                    CorroborationOutcome::InsufficientEvidenceHeld { .. } => (
                        DeltaPriority::Normal,
                        format!(
                            "insufficient_evidence_held event={}",
                            event.event_id.as_str()
                        ),
                    ),
                    CorroborationOutcome::ClockUncertaintyAbstained { .. } => (
                        DeltaPriority::Normal,
                        "clock_uncertainty_abstained".to_owned(),
                    ),
                };
                self.broadcast_delta(
                    receipt.commit_sequence,
                    decision.decision_digest,
                    MeaningfulDeltaClass::Hypothesis,
                    priority,
                    summary,
                );
            } else if let CorroborationOutcome::ClockUncertaintyAbstained {
                uncertainty_ns, ..
            } = &decision.outcome
            {
                let head_seq = self.storage.head_snapshot()?.commit_sequence;
                self.broadcast_delta(
                    head_seq,
                    decision.decision_digest,
                    MeaningfulDeltaClass::SensorHealth,
                    DeltaPriority::Normal,
                    format!("clock_uncertainty_abstained uncertainty_ns={uncertainty_ns}"),
                );
            }
        }
        Ok(())
    }
}
