#![forbid(unsafe_code)]
//! Always-on `DaemonSupervisor` coordinating `ProcessRegion -> PropertyRegion -> {StorageRegion,
//! PerceptionRegion, SensorRegion x N, ControlPlaneRegion}` end-to-end.
//!
//! Semantic plane: `"authority"`.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DeltaPriority, MeaningfulDeltaClass,
    OperationId, RootAuthoritySpec, SensorId, TimestampNs,
};
use fss_pack::ERR_STORAGE_QUOTA_PINNED_001;
use fss_projection_store::{CoverageStatus, SensorLivenessStatus};
use fss_vault::{
    CAP_SECRET_READ_001, LocalEncryptedVault, MAX_SECRET_BYTES, SecretAccessCx, SecretBytes,
    SecretError, SecretScope, SecretStore,
};

use crate::control::{ControlPlaneServer, ControlPlaneShared};
use crate::error::DaemonError;
use crate::manifest::{CameraAdapterKind, CameraManifestEntry, SiteManifest};
use crate::perception::PerceptionEngine;
use crate::regions::DaemonRegionTree;
use crate::ring::{BoundedFrameRing, RingConsumerCursor};
use crate::sensor::{
    BackoffSchedule, NetworkAdapterDriver, SensorDriver, SensorState, default_driver_for_camera,
};
use crate::storage::{StorageEngine, StorageHeadSnapshot};
pub use crate::supervisor_types::{
    CameraRuntimeView, DAEMON_SHUTDOWN_RECEIPT_DOMAIN, DaemonShutdownReport, DaemonStartConfig,
    TickReport,
};
use crate::supervisor_types::{
    CameraSlot, build_control_status, combined_pressure_label, compute_shutdown_digest,
    monotonic_wall_ns,
};
use crate::telemetry::{DaemonTelemetrySnapshot, SensorTelemetryRecord};

const MAX_TELEMETRY_LINES: usize = 512;

/// Always-on multi-camera supervisor owning regions, storage, perception, sensors, and IPC.
pub struct DaemonSupervisor {
    pub(crate) manifest: SiteManifest,
    pub(crate) manifest_path: Option<PathBuf>,
    pub(crate) daemon_instance_id: String,
    pub(crate) started_instant: Instant,
    pub(crate) last_now_ns: i128,
    pub(crate) tick_count: u64,
    pub(crate) regions: DaemonRegionTree,
    pub(crate) storage: StorageEngine,
    pub(crate) perception: PerceptionEngine,
    pub(crate) sensors: BTreeMap<SensorId, CameraSlot>,
    pub(crate) control: Option<ControlPlaneServer>,
    pub(crate) control_shared: Option<Arc<ControlPlaneShared>>,
    pub(crate) corroborated_events: u64,
    pub(crate) shared_domain_held_events: u64,
    pub(crate) coverage_gaps: u64,
    pub(crate) telemetry_jsonl: VecDeque<String>,
}

impl DaemonSupervisor {
    /// Starts an always-on [`DaemonSupervisor`] owning the full Asupersync/canonical region tree.
    pub fn start(mut config: DaemonStartConfig) -> Result<Self, DaemonError> {
        let now_ns = config.started_at_ns;
        let now = TimestampNs(now_ns);
        let root_dir = config
            .root_override
            .clone()
            .unwrap_or_else(|| config.manifest.deployment_root.clone());
        let daemon_instance_id = config.daemon_instance_id.unwrap_or_else(|| {
            format!("daemon:{}:{}", config.manifest.site_id, std::process::id())
        });

        let mut storage = StorageEngine::open(&config.manifest, Some(&root_dir))?;
        let mut regions = DaemonRegionTree::initialize(&config.manifest, &config.principal, now)?;
        let perception = PerceptionEngine::new(&config.manifest, config.perception_config)?;

        let mut resolved_vault_creds = resolve_camera_credentials_from_vault(
            &config.manifest,
            &config.custom_drivers,
            &config.principal,
            config.vault_dir.as_deref(),
            config.vault_passphrase_file.as_deref(),
            now,
        )?;

        let mut sensors = BTreeMap::new();
        let mut coverage_gaps = 0_u64;
        for entry in &config.manifest.cameras {
            let mut driver = if let Some(custom) = config.custom_drivers.remove(&entry.sensor_id) {
                custom
            } else if let Some((username, password)) = resolved_vault_creds.remove(&entry.sensor_id)
            {
                Box::new(
                    NetworkAdapterDriver::new(entry).with_vault_credentials(username, password),
                )
            } else {
                default_driver_for_camera(entry)
            };
            let ring = BoundedFrameRing::new(entry.ring_max_frames, entry.ring_max_bytes)?;
            let mut backoff = BackoffSchedule::new(
                entry.sensor_id.as_str(),
                entry.reconnect_min_ms,
                entry.reconnect_max_ms,
            );
            let (state, next_reconnect_ns, peak_sessions, active_gaps) = match driver.connect(1) {
                Ok(()) => {
                    let _ = storage.commit_coverage_and_liveness(
                        &entry.sensor_id,
                        &entry.primary_zone,
                        CoverageStatus::NotObservable,
                        SensorLivenessStatus::Unknown,
                        1,
                        now,
                        now,
                        regions.storage_ledger_cx(),
                        regions.region_tree(),
                    )?;
                    // Transport acceptance is not evidence of a usable frame or continuity.
                    (SensorState::Connecting, 0, driver.active_session_count(), 1)
                }
                Err(reason) => {
                    let _ = regions.drain_failed_sensor_region(
                        &entry.sensor_id,
                        reason.as_str(),
                        now,
                    )?;
                    let delay_ms = backoff.next_delay_ms();
                    let _ = storage.commit_coverage_and_liveness(
                        &entry.sensor_id,
                        &entry.primary_zone,
                        CoverageStatus::NotObservable,
                        SensorLivenessStatus::Offline,
                        1,
                        now,
                        now,
                        regions.storage_ledger_cx(),
                        regions.region_tree(),
                    )?;
                    coverage_gaps = coverage_gaps.saturating_add(1);
                    (
                        SensorState::GapBackoff,
                        now_ns.saturating_add(i128::from(delay_ms) * 1_000_000),
                        0,
                        1,
                    )
                }
            };

            sensors.insert(
                entry.sensor_id.clone(),
                CameraSlot {
                    entry: entry.clone(),
                    driver,
                    ring,
                    ingest_cursor: RingConsumerCursor::new(1),
                    perception_cursor: RingConsumerCursor::new(1),
                    preview_cursor: RingConsumerCursor::new(1),
                    backoff,
                    state,
                    stream_generation: 1,
                    previous_frame: None,
                    continuity_frames: 0,
                    last_frame_ns: now_ns,
                    next_reconnect_ns,
                    reconnects: u64::from(state == SensorState::GapBackoff),
                    frames_ingested: 0,
                    frames_decoded: 0,
                    last_ingest_lag_ms: 0,
                    active_gaps,
                    ingest_paused: false,
                    peak_concurrent_sessions: peak_sessions,
                },
            );
        }

        let head = storage.head_snapshot()?;
        let initial_status = build_control_status(&head, &sensors);
        let ipc_root = config
            .manifest
            .ipc_socket_override
            .clone()
            .unwrap_or_else(|| root_dir.clone());
        let known_cameras: Vec<String> = config
            .manifest
            .cameras
            .iter()
            .map(|c| c.sensor_id.as_str().to_owned())
            .collect();
        let shared = ControlPlaneShared::new(
            config.manifest.site_id.clone(),
            fss_ipc::deployment_root_digest(&ipc_root),
            known_cameras,
            initial_status,
            storage.forward_writer(),
        );
        let control = if config.enable_ipc {
            Some(ControlPlaneServer::start(
                ipc_root,
                config.manifest.site_id.clone(),
                daemon_instance_id.clone(),
                config.manifest.digest(),
                now_ns,
                Arc::clone(&shared),
            )?)
        } else {
            None
        };

        Ok(Self {
            manifest: config.manifest,
            manifest_path: config.manifest_path,
            daemon_instance_id,
            started_instant: Instant::now(),
            last_now_ns: now_ns,
            tick_count: 0,
            regions,
            storage,
            perception,
            sensors,
            control,
            control_shared: Some(shared),
            corroborated_events: 0,
            shared_domain_held_events: 0,
            coverage_gaps,
            telemetry_jsonl: VecDeque::with_capacity(64),
        })
    }

    /// Executes one deterministic supervision tick across control commands, all cameras,
    /// storage group-commit, perception cascade + live corroboration, retention compaction,
    /// incremental scrubbing, and telemetry publication.
    pub fn step_tick(&mut self, now_ns: i128) -> Result<TickReport, DaemonError> {
        self.tick_count = self.tick_count.saturating_add(1);
        self.last_now_ns = now_ns;
        let now = TimestampNs(now_ns);
        let sensor_ids: Vec<SensorId> = self.sensors.keys().cloned().collect();

        let (force_scrub, cmd_gaps) = self.process_control_commands_step(now_ns, now)?;
        let poll = self.poll_all_cameras_step(&sensor_ids, now_ns, now)?;
        let (perception_batch, fanout_frames_committed) = self.fanout_rings_step(&sensor_ids)?;
        let frames_committed = poll.frames_handed_off.saturating_add(fanout_frames_committed);
        let (tick_corroborated, tick_shared_held, decisions) =
            self.run_perception_step(&perception_batch)?;

        let coverage_gaps_emitted = cmd_gaps.saturating_add(poll.coverage_gaps_emitted);
        self.corroborated_events = self.corroborated_events.saturating_add(tick_corroborated);
        self.shared_domain_held_events = self
            .shared_domain_held_events
            .saturating_add(tick_shared_held);
        self.coverage_gaps = self.coverage_gaps.saturating_add(coverage_gaps_emitted);

        let maint = self.storage.run_maintenance_tick(
            self.regions.storage_pack_cx(),
            self.regions.region_tree(),
            now,
            force_scrub,
        )?;
        if maint.quota_pinned {
            let head_seq = self.storage.head_snapshot()?.commit_sequence;
            self.broadcast_delta(
                head_seq,
                ContentDigest::sha256(ERR_STORAGE_QUOTA_PINNED_001.as_bytes()),
                MeaningfulDeltaClass::BudgetPressure,
                DeltaPriority::Critical,
                format!(
                    "{ERR_STORAGE_QUOTA_PINNED_001} pinned={}/{}",
                    maint.pinned_bytes, maint.cap_bytes
                ),
            );
        }

        let head = self.storage.head_snapshot()?;
        if let Some(shared) = &self.control_shared {
            shared.publish_status(build_control_status(&head, &self.sensors));
        }
        let telemetry = self.build_telemetry_snapshot(&head);
        self.record_telemetry_lines(&telemetry);

        Ok(TickReport {
            tick: self.tick_count,
            frames_received: poll.frames_received,
            frames_shed: poll.frames_shed,
            frames_committed,
            coverage_gaps_emitted,
            reconnects_completed: poll.reconnects_completed,
            corroborated_events: tick_corroborated,
            shared_domain_held_events: tick_shared_held,
            quota_pinned: maint.quota_pinned,
            pressure: maint.pressure,
            decisions,
            telemetry,
        })
    }

    /// Runs the supervision loop until shutdown is requested (via IPC `Stop`, caller signal, or
    /// `max_ticks` completion), then executes strict `request -> drain -> finalize` shutdown.
    pub fn run_until_stopped(
        mut self,
        max_ticks: Option<u64>,
        tick_interval: Duration,
    ) -> Result<DaemonShutdownReport, DaemonError> {
        loop {
            if self.is_shutdown_requested() || max_ticks.is_some_and(|lim| self.tick_count >= lim) {
                break;
            }
            let now_ns = monotonic_wall_ns().max(self.last_now_ns.saturating_add(1_000_000));
            let _ = self.step_tick(now_ns)?;
            if self.is_shutdown_requested() || max_ticks.is_some_and(|lim| self.tick_count >= lim) {
                break;
            }
            if !tick_interval.is_zero() {
                let slice = Duration::from_millis(10);
                if let Some(shared) = &self.control_shared {
                    let _ = fss_runtime::asupersync_ops::CxTimerBoundary::sleep_cooperative_flag(
                        shared.shutdown_flag(),
                        tick_interval,
                        slice,
                    );
                } else {
                    let never = std::sync::atomic::AtomicBool::new(false);
                    let _ = fss_runtime::asupersync_ops::CxTimerBoundary::sleep_cooperative_flag(
                        &never,
                        tick_interval,
                        slice,
                    );
                }
            }
        }
        self.shutdown_graceful()
    }

    /// Executes strict `request -> drain -> finalize` quiescence across all regions and stores.
    pub fn shutdown_graceful(mut self) -> Result<DaemonShutdownReport, DaemonError> {
        let drain_start = Instant::now();
        let now = TimestampNs(self.last_now_ns.saturating_add(1_000));

        let mut first_error = None;
        let cameras: Vec<(SensorId, CameraAdapterKind, usize)> = self
            .sensors
            .iter()
            .map(|(id, slot)| (id.clone(), slot.entry.adapter, slot.entry.ring_max_frames))
            .collect();
        // Drain only already admitted frames, including a manually paused ingest cursor.
        // Storage authority must remain live until the bounded drain and GOP flush finish.
        for (sid, adapter, max_frames) in cameras {
            let (_, drain_error) = self.ingest_camera_ring_step(&sid, max_frames);
            if first_error.is_none() {
                first_error = drain_error;
            }
            if let Err(err) = self.storage.flush_camera_gop(
                &sid,
                adapter,
                self.regions.storage_ledger_cx(),
                self.regions.region_tree(),
            ) {
                first_error.get_or_insert(err);
            }
        }

        if let Err(err) = self.regions.request_shutdown(now) {
            first_error.get_or_insert(err);
        }
        for slot in self.sensors.values_mut() {
            slot.driver.disconnect();
            slot.state = SensorState::Draining;
        }
        self.perception.request_cancellation();

        if let Some(server) = self.control.take()
            && let Err(err) = server.shutdown()
        {
            first_error.get_or_insert(err);
        }
        if let Some(shared) = self.control_shared.take() {
            shared.request_shutdown();
            drop(shared);
        }

        // Attempt every cleanup phase before returning the earliest failure. Neither an
        // ingest error nor a storage shutdown error may bypass region finalization.
        let storage_result = self.storage.shutdown_and_flush();
        let region_result = self.regions.drain_and_finalize(now);
        if let Some(err) = first_error {
            return Err(err);
        }
        let storage_summary = storage_result?;
        let region_proof = region_result?;
        let drain_duration_ms =
            u64::try_from(drain_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let receipt_digest = compute_shutdown_digest(
            &self.manifest.site_id,
            &self.daemon_instance_id,
            self.tick_count,
            &storage_summary,
            &region_proof,
        );

        Ok(DaemonShutdownReport {
            site_id: self.manifest.site_id,
            daemon_instance_id: self.daemon_instance_id,
            ticks_executed: self.tick_count,
            drain_duration_ms,
            active_tasks: region_proof.active_tasks,
            leaked_obligations: region_proof.leaked_obligations,
            closed_regions: region_proof.closed_regions,
            head_commit_sequence: storage_summary.head_commit_sequence,
            history_root: storage_summary.history_root,
            state_root: storage_summary.state_root,
            verified_epochs: storage_summary.verified_epochs,
            verified_batches: storage_summary.verified_batches,
            corroborated_events: self.corroborated_events,
            shared_domain_held_events: self.shared_domain_held_events,
            coverage_gaps: self.coverage_gaps,
            region_proof,
            storage_summary,
            receipt_digest,
        })
    }

    /// Requests graceful shutdown programmatically (equivalent to `SIGINT`/`SIGTERM` or IPC stop).
    pub fn request_shutdown(&self) {
        if let Some(shared) = &self.control_shared {
            shared.request_shutdown();
        }
    }

    /// Returns `true` if graceful shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.control_shared
            .as_ref()
            .is_some_and(|s| s.is_shutdown_requested())
    }

    /// Returns the bound UDS socket path if IPC is enabled.
    #[must_use]
    pub fn ipc_socket_path(&self) -> Option<&Path> {
        self.control.as_ref().map(ControlPlaneServer::socket_path)
    }

    /// Returns the active region-owned task count across `ProcessRegion`.
    #[must_use]
    pub fn active_tasks(&self) -> usize {
        self.regions.active_tasks()
    }

    /// Returns the non-terminal leaked obligation count across `ProcessRegion`.
    #[must_use]
    pub fn leaked_obligations(&self) -> usize {
        self.regions.leaked_obligations()
    }

    /// Pauses or resumes the storage ingest consumer cursor for `sensor_id`.
    pub fn set_ingest_consumer_paused(&mut self, sensor_id: &SensorId, paused: bool) -> bool {
        if let Some(slot) = self.sensors.get_mut(sensor_id) {
            slot.ingest_paused = paused;
            true
        } else {
            false
        }
    }

    /// Returns a read-only view of every supervised camera's session, generation, and ring metrics.
    #[must_use]
    pub fn camera_views(&self) -> BTreeMap<SensorId, CameraRuntimeView> {
        self.sensors
            .iter()
            .map(|(id, slot)| {
                (
                    id.clone(),
                    CameraRuntimeView {
                        sensor_id: id.clone(),
                        state: slot.state,
                        stream_generation: slot.stream_generation,
                        active_sessions: slot.driver.active_session_count(),
                        peak_concurrent_sessions: slot.peak_concurrent_sessions,
                        total_connections: slot.driver.total_connections(),
                        reconnects: slot.reconnects,
                        frames_ingested: slot.frames_ingested,
                        frames_decoded: slot.frames_decoded,
                        ring: slot.ring.stats(),
                    },
                )
            })
            .collect()
    }

    /// Borrows the storage engine for hold pinning and projection verification.
    #[must_use]
    pub fn storage_mut(&mut self) -> &mut StorageEngine {
        &mut self.storage
    }

    /// Borrows the storage engine read-only.
    #[must_use]
    pub const fn storage(&self) -> &StorageEngine {
        &self.storage
    }

    /// Borrows the perception engine read-only.
    #[must_use]
    pub const fn perception(&self) -> &PerceptionEngine {
        &self.perception
    }

    /// Returns recent structured JSONL telemetry lines (strictly non-secret).
    #[must_use]
    pub fn telemetry_jsonl(&self) -> &VecDeque<String> {
        &self.telemetry_jsonl
    }

    pub(crate) fn broadcast_delta(
        &self,
        commit_sequence: u64,
        delta_digest: ContentDigest,
        delta_class: MeaningfulDeltaClass,
        priority: DeltaPriority,
        summary: String,
    ) {
        if let Some(shared) = &self.control_shared {
            shared.publish_delta_summary(
                commit_sequence,
                delta_digest,
                delta_class,
                priority,
                summary,
            );
        }
    }

    fn build_telemetry_snapshot(&self, head: &StorageHeadSnapshot) -> DaemonTelemetrySnapshot {
        let elapsed_secs = self.started_instant.elapsed().as_secs_f64().max(0.001);
        let uptime_ms =
            u64::try_from(self.started_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
        let pack_mb = (head.on_disk_pack_bytes as f64) / (1024.0 * 1024.0);
        let active_tasks = self.regions.active_tasks();
        let leaked_obligations = self.regions.leaked_obligations();

        let sensors = self
            .sensors
            .values()
            .map(|slot| {
                let stats = slot.ring.stats();
                SensorTelemetryRecord {
                    sensor_id: slot.entry.sensor_id.as_str().to_owned(),
                    state: slot.state.as_str().to_owned(),
                    stream_generation: slot.stream_generation,
                    fps_in: (stats.total_enqueued as f64) / elapsed_secs,
                    fps_decode: (slot.frames_decoded as f64) / elapsed_secs,
                    ingest_lag_ms: slot.last_ingest_lag_ms,
                    queue_depth: stats.current_frames,
                    dropped_frames: stats.dropped_frames,
                    reconnects: slot.reconnects,
                    pack_mb,
                    pressure: combined_pressure_label(head.pressure, stats.pressure).to_owned(),
                    corroborated_events: self.corroborated_events,
                    active_tasks,
                }
            })
            .collect();

        DaemonTelemetrySnapshot {
            site_id: self.manifest.site_id.clone(),
            daemon_instance_id: self.daemon_instance_id.clone(),
            tick: self.tick_count,
            uptime_ms,
            head_commit_sequence: head.commit_sequence,
            pack_mb,
            ring_used_bytes: head.ring_used_bytes,
            ring_cap_bytes: head.ring_cap_bytes,
            pressure: head.pressure.as_str().to_owned(),
            quota_pinned: head.quota_pinned,
            corroborated_events: self.corroborated_events,
            shared_domain_held_events: self.shared_domain_held_events,
            coverage_gaps: self.coverage_gaps,
            active_tasks,
            leaked_obligations,
            sensors,
        }
    }

    fn record_telemetry_lines(&mut self, snapshot: &DaemonTelemetrySnapshot) {
        self.push_jsonl(snapshot.to_jsonl());
        for sensor in &snapshot.sensors {
            self.push_jsonl(sensor.to_jsonl());
        }
    }

    fn push_jsonl(&mut self, line: String) {
        if self.telemetry_jsonl.len() >= MAX_TELEMETRY_LINES {
            self.telemetry_jsonl.pop_front();
        }
        self.telemetry_jsonl.push_back(line);
    }
}

fn resolve_camera_credentials_from_vault(
    manifest: &SiteManifest,
    custom_drivers: &BTreeMap<SensorId, Box<dyn SensorDriver>>,
    principal: &str,
    vault_dir: Option<&Path>,
    passphrase_file: Option<&Path>,
    now: TimestampNs,
) -> Result<BTreeMap<SensorId, (String, SecretBytes)>, DaemonError> {
    let (vault_dir, passphrase_file) = match (vault_dir, passphrase_file) {
        (None, None) => return Ok(BTreeMap::new()),
        (Some(_), None) => {
            return Err(DaemonError::InvalidConfig {
                detail: "`--vault-dir` requires `--passphrase-file <0600-file>`".to_owned(),
            });
        }
        (None, Some(_)) => {
            return Err(DaemonError::InvalidConfig {
                detail: "`--passphrase-file` requires `--vault-dir <dir>`".to_owned(),
            });
        }
        (Some(v), Some(p)) => (v, p),
    };

    let passphrase = read_vault_passphrase_file_0600(passphrase_file)?;
    let mut vault = LocalEncryptedVault::open(vault_dir);
    vault.unlock(&passphrase)?;

    let mut resolved = BTreeMap::new();
    for entry in &manifest.cameras {
        if custom_drivers.contains_key(&entry.sensor_id)
            || entry.adapter == CameraAdapterKind::Synthetic
        {
            continue;
        }
        let Some(secret_id) = &entry.secret_id else {
            continue;
        };
        let creds = resolve_one_camera_secret(&vault, entry, secret_id, principal, now);
        match creds {
            Ok(pair) => {
                resolved.insert(entry.sensor_id.clone(), pair);
            }
            Err(err) => {
                vault.lock();
                return Err(err);
            }
        }
    }
    vault.lock();
    Ok(resolved)
}

fn resolve_one_camera_secret(
    vault: &LocalEncryptedVault,
    entry: &CameraManifestEntry,
    secret_id: &fss_vault::SecretId,
    principal: &str,
    now: TimestampNs,
) -> Result<(String, SecretBytes), DaemonError> {
    let scope = SecretScope::new(
        entry.adapter.vault_adapter_family(),
        entry.sensor_id.as_str(),
        &entry.endpoint,
    )?;
    let op_id = OperationId::parse(format!(
        "op:daemon:vault:{}",
        entry.sensor_id.as_str().replace(':', "-")
    ))
    .or_else(|_| OperationId::parse("op:daemon:vault:read"))?;
    let budgets = BudgetVector::builder()
        .bytes(65_536)
        .build()
        .map_err(|err| DaemonError::InvalidConfig {
            detail: format!("failed constructing vault read budget: {err}"),
        })?;
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:daemon:vault:{}", entry.sensor_id.as_str()),
        operation_id: op_id,
        principal: principal.to_owned(),
        capabilities: vec![CAP_SECRET_READ_001.to_owned()],
        deadline: None,
        priority: 1,
        budgets,
        privacy_scope: "privacy:daemon-camera-credentials".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: scope.scope_digest(),
        generation: 1,
    })?;
    let cx = SecretAccessCx::new(auth, scope, now)?;
    let (_, secret) = vault.fetch(&cx, secret_id)?.into_parts();
    split_vault_camera_secret(secret)
}

fn split_vault_camera_secret(secret: SecretBytes) -> Result<(String, SecretBytes), DaemonError> {
    if let Some(colon) = secret.as_slice().iter().position(|&b| b == b':')
        && colon > 0
        && colon + 1 < secret.as_slice().len()
        && let Ok(user) = std::str::from_utf8(&secret.as_slice()[..colon])
    {
        let username = user.to_owned();
        let password = SecretBytes::new(secret.as_slice()[colon + 1..].to_vec())?;
        return Ok((username, password));
    }
    Ok(("admin".to_owned(), secret))
}

fn read_vault_passphrase_file_0600(path: &Path) -> Result<SecretBytes, DaemonError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|err| DaemonError::io("stat_vault_passphrase_file", err))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(DaemonError::Vault(SecretError::InsecurePermissions {
            detail: "vault passphrase file must be a regular non-symlink file".to_owned(),
        }));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o077) != 0 {
            return Err(DaemonError::Vault(SecretError::InsecurePermissions {
                detail: "vault passphrase file must have owner-only 0600 permissions".to_owned(),
            }));
        }
    }
    if meta.len() > MAX_SECRET_BYTES as u64 {
        return Err(DaemonError::Vault(SecretError::InvalidInput {
            detail: "vault passphrase file exceeds maximum allowed secret size".to_owned(),
        }));
    }
    let file =
        File::open(path).map_err(|err| DaemonError::io("open_vault_passphrase_file", err))?;
    let mut buf = Vec::new();
    file.take((MAX_SECRET_BYTES as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|err| DaemonError::io("read_vault_passphrase_file", err))?;
    if buf.ends_with(b"\r\n") {
        buf.truncate(buf.len().saturating_sub(2));
    } else if buf.ends_with(b"\n") {
        buf.truncate(buf.len().saturating_sub(1));
    }
    if buf.is_empty() || buf.len() > MAX_SECRET_BYTES {
        buf.fill(0);
    }
    Ok(SecretBytes::new(buf)?)
}
