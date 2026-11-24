#![forbid(unsafe_code)]
//! Strict Asupersync-backed canonical region ownership tree (`COMPREHENSIVE_PLAN §7`).
//!
//! Semantic plane: `"authority"`.
//!
//! Enforces the normative hierarchy:
//! `ProcessRegion -> PropertyRegion(site_id) -> {StorageRegion (Ledger + ObjectStore + Projection),
//! PerceptionRegion (Event -> ModelCall + Association), SensorRegion(sensor_id) x N,
//! ControlPlaneRegion (Operations)}`.
//!
//! Every child scope narrows its parent's [`AuthorityCx`] grants and [`BudgetVector`] allowance,
//! tracks active tasks and durable obligations in [`RegionTree`], and closes strictly bottom-up
//! via `request -> drain -> finalize`, producing a verified root [`QuiescenceProof`] with
//! `active_tasks == 0` and zero leaked obligations.

use std::collections::BTreeMap;

use fss_core::{
    BudgetVector, ContentDigest, MAX_SENSOR_REGIONS, ObligationId, OperationId, QuiescenceProof,
    RegionId, RegionKind, RegionTree, RootAuthoritySpec, RuntimeGrant, SensorId, TaskId,
    TaskOutcome, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::obligation::{ObligationTerminal, new_obligation, tree_report};

use crate::error::DaemonError;
use crate::manifest::SiteManifest;

/// Canonical summary emitted after closing a single [`SensorRegion`] generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorRegionDrainReceipt {
    /// Camera sensor identifier.
    pub sensor_id: SensorId,
    /// Closed stream generation ordinal.
    pub generation: u64,
    /// Closed region identifier (when a dedicated `SensorRegion` was finalized).
    pub region_id: RegionId,
    /// Verified quiescence proof if the region was finalized on this transition.
    pub quiescence_proof: Option<QuiescenceProof>,
}

/// Complete quiescence receipt emitted after full daemon `request -> drain -> finalize`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionShutdownProof {
    /// Root `ProcessRegion` verified [`QuiescenceProof`].
    pub root_proof: QuiescenceProof,
    /// Remaining active tasks across the entire region tree (must be `0`).
    pub active_tasks: usize,
    /// Remaining pending/leaked obligations across the entire region tree (must be `0`).
    pub leaked_obligations: usize,
    /// Total closed regions in the tree.
    pub closed_regions: usize,
}

struct SensorRegionSlot {
    region_id: RegionId,
    cx: AuthorityCx,
    generation: u64,
    active_task_id: Option<TaskId>,
    active_obligation_id: Option<ObligationId>,
}

/// Owned canonical region hierarchy backing a running `fss-daemon` instance.
pub struct DaemonRegionTree {
    site_id: String,
    trace_id: String,
    principal: String,
    anchor_universe: ContentDigest,
    tree: RegionTree,
    process_cx: AuthorityCx,
    property_cx: AuthorityCx,
    storage_ledger_cx: AuthorityCx,
    storage_pack_cx: AuthorityCx,
    storage_projection_cx: AuthorityCx,
    storage_task_id: Option<TaskId>,
    storage_obligation_id: Option<ObligationId>,
    perception_event_cx: AuthorityCx,
    perception_model_cx: AuthorityCx,
    perception_assoc_cx: AuthorityCx,
    perception_task_id: Option<TaskId>,
    perception_obligation_id: Option<ObligationId>,
    control_plane_cx: AuthorityCx,
    control_task_id: Option<TaskId>,
    control_obligation_id: Option<ObligationId>,
    sensors: BTreeMap<SensorId, SensorRegionSlot>,
    total_sensor_regions_created: usize,
    drain_requested: bool,
}

impl DaemonRegionTree {
    /// Initializes the complete daemon region ownership tree for `manifest`.
    pub fn initialize(
        manifest: &SiteManifest,
        principal: &str,
        now: TimestampNs,
    ) -> Result<Self, DaemonError> {
        let trace_id = format!("trace:daemon:{}", sanitize_id_part(&manifest.site_id));
        let anchor_universe = manifest.digest();
        let all_caps = daemon_root_capabilities();

        let root_budget = make_budget(1_u64 << 48, 2_000_000, 1_u64 << 40, 2_000_000)?;
        let root_spec = make_authority_spec(
            &trace_id,
            "op:daemon:process",
            principal,
            all_caps.clone(),
            0,
            root_budget,
            anchor_universe,
        )?;
        let process_id = RegionId::new(format!(
            "region:process:{}",
            sanitize_id_part(&manifest.site_id)
        ))?;
        let (mut process_cx, mut tree) =
            AuthorityCx::root(root_spec, process_id, RegionKind::Process, root_budget, now)?;

        let prop_budget = make_budget(1_u64 << 47, 1_500_000, 1_u64 << 39, 1_500_000)?;
        let prop_spec = make_authority_spec(
            &trace_id,
            "op:daemon:property",
            principal,
            all_caps,
            1,
            prop_budget,
            anchor_universe,
        )?;
        let prop_id = RegionId::new(format!(
            "region:property:{}",
            sanitize_id_part(&manifest.site_id)
        ))?;
        let mut property_cx = process_cx.scope_down(
            &mut tree,
            prop_id,
            RegionKind::Property,
            prop_budget,
            prop_spec,
            now,
        )?;

        // StorageRegion = LedgerRegion + ObjectStoreRegion + ProjectionRegion.
        let storage_caps = storage_capabilities();
        let slice_budget = make_budget(1_u64 << 40, 20_000, 1_u64 << 32, 20_000)?;
        let ctx = ScopeContext {
            trace_id: &trace_id,
            principal,
            anchor_universe,
            now,
        };
        let storage_ledger_cx = scope_child(
            &mut property_cx,
            &mut tree,
            "region:storage:ledger",
            RegionKind::Ledger,
            "op:daemon:storage:ledger",
            storage_caps.clone(),
            slice_budget,
            &ctx,
        )?;
        let storage_pack_cx = scope_child(
            &mut property_cx,
            &mut tree,
            "region:storage:pack",
            RegionKind::ObjectStore,
            "op:daemon:storage:pack",
            storage_caps.clone(),
            slice_budget,
            &ctx,
        )?;
        let storage_projection_cx = scope_child(
            &mut property_cx,
            &mut tree,
            "region:storage:projection",
            RegionKind::Projection,
            "op:daemon:storage:projection",
            storage_caps,
            slice_budget,
            &ctx,
        )?;
        let (storage_task_id, storage_obligation_id) = register_task_and_obligation(
            &storage_ledger_cx,
            &storage_ledger_cx,
            &mut tree,
            "task:storage:writer",
            "ob:storage:durable-flush",
            "op:daemon:storage:ledger",
            "flush active packs, emit ledger checkpoint, and compact MVCC projection before close",
            now,
        )?;

        // PerceptionRegion = EventRegion -> ModelCallRegion + AssociationRegion (strictly NO alert grants).
        let perc_caps = perception_capabilities();
        let perc_parent_budget = make_budget(1_u64 << 42, 400_000, 1_u64 << 34, 40_000)?;
        let mut perception_event_cx = scope_child(
            &mut property_cx,
            &mut tree,
            "region:perception:cascade",
            RegionKind::Event,
            "op:daemon:perception:cascade",
            perc_caps.clone(),
            perc_parent_budget,
            &ctx,
        )?;
        let perc_child_budget = make_budget(1_u64 << 40, 150_000, 1_u64 << 32, 10_000)?;
        let perception_model_cx = scope_child(
            &mut perception_event_cx,
            &mut tree,
            "region:perception:model_pool",
            RegionKind::ModelCall,
            "op:daemon:perception:model_pool",
            perc_caps.clone(),
            perc_child_budget,
            &ctx,
        )?;
        let perception_assoc_cx = scope_child(
            &mut perception_event_cx,
            &mut tree,
            "region:perception:corroboration",
            RegionKind::Association,
            "op:daemon:perception:corroboration",
            perc_caps,
            perc_child_budget,
            &ctx,
        )?;
        let (perception_task_id, perception_obligation_id) = register_task_and_obligation(
            &perception_model_cx,
            &perception_event_cx,
            &mut tree,
            "task:perception:worker",
            "ob:perception:drain",
            "op:daemon:perception:cascade",
            "complete in-flight cascade batch and close corroboration window cleanly",
            now,
        )?;

        // ControlPlaneRegion = OperationsRegion (owning fss-ipc UDS server).
        let control_plane_cx = scope_child(
            &mut property_cx,
            &mut tree,
            "region:control_plane:ipc",
            RegionKind::Operations,
            "op:daemon:control_plane",
            control_plane_capabilities(),
            slice_budget,
            &ctx,
        )?;
        let (control_task_id, control_obligation_id) = register_task_and_obligation(
            &control_plane_cx,
            &control_plane_cx,
            &mut tree,
            "task:control_plane:ipc",
            "ob:control_plane:ipc-drain",
            "op:daemon:control_plane",
            "notify subscribers, join all IPC workers, and unlink owned socket",
            now,
        )?;

        let mut daemon_tree = Self {
            site_id: manifest.site_id.clone(),
            trace_id,
            principal: principal.to_owned(),
            anchor_universe,
            tree,
            process_cx,
            property_cx,
            storage_ledger_cx,
            storage_pack_cx,
            storage_projection_cx,
            storage_task_id: Some(storage_task_id),
            storage_obligation_id: Some(storage_obligation_id),
            perception_event_cx,
            perception_model_cx,
            perception_assoc_cx,
            perception_task_id: Some(perception_task_id),
            perception_obligation_id: Some(perception_obligation_id),
            control_plane_cx,
            control_task_id: Some(control_task_id),
            control_obligation_id: Some(control_obligation_id),
            sensors: BTreeMap::new(),
            total_sensor_regions_created: 0,
            drain_requested: false,
        };

        for cam in &manifest.cameras {
            daemon_tree.spawn_sensor_region(&cam.sensor_id, 1, now)?;
        }

        Ok(daemon_tree)
    }

    /// Spawns a fresh isolated `SensorRegion` for `sensor_id` at `generation` (or rotates task
    /// generation if the canonical `MAX_SENSOR_REGIONS` historical ceiling is reached).
    pub fn spawn_sensor_region(
        &mut self,
        sensor_id: &SensorId,
        generation: u64,
        now: TimestampNs,
    ) -> Result<RegionId, DaemonError> {
        let sanitized = sanitize_id_part(sensor_id.as_str());
        if let Some(existing) = self.sensors.get_mut(sensor_id) {
            // Reusing active sensor region after hitting historical MAX_SENSOR_REGIONS ceiling.
            if existing.active_task_id.is_none() {
                let task_id = TaskId::new(format!("task:sensor:{sanitized}:g{generation}"))?;
                self.tree
                    .register_task(&existing.region_id, task_id.clone(), now)?;
                existing.active_task_id = Some(task_id);
            }
            if existing.active_obligation_id.is_none() {
                let ob = new_obligation(
                    format!("ob:sensor:{sanitized}:g{generation}"),
                    OperationId::parse(format!("op:sensor:{sanitized}:g{generation}"))?,
                    "observe stream continuity or emit explicit CoverageGap before close",
                )?;
                let ob_id = ob.obligation_id.clone();
                existing.cx.register_obligation(&mut self.tree, ob)?;
                existing.active_obligation_id = Some(ob_id);
            }
            existing.generation = generation;
            return Ok(existing.region_id.clone());
        }

        let region_id_str = format!("region:sensor:{sanitized}:g{generation}");
        let op_id_str = format!("op:sensor:{sanitized}:g{generation}");
        let sensor_budget = make_budget(1_u64 << 38, 1_000, 1_u64 << 30, 10_000)?;
        let ctx = ScopeContext {
            trace_id: &self.trace_id,
            principal: &self.principal,
            anchor_universe: self.anchor_universe,
            now,
        };
        let cx = scope_child(
            &mut self.property_cx,
            &mut self.tree,
            &region_id_str,
            RegionKind::Sensor,
            &op_id_str,
            sensor_capabilities(),
            sensor_budget,
            &ctx,
        )?;
        let region_id = cx.region().clone();
        let (task_id, ob_id) = register_task_and_obligation(
            &cx,
            &cx,
            &mut self.tree,
            &format!("task:sensor:{sanitized}:g{generation}"),
            &format!("ob:sensor:{sanitized}:g{generation}"),
            &op_id_str,
            "observe stream continuity or emit explicit CoverageGap before close",
            now,
        )?;

        self.total_sensor_regions_created = self.total_sensor_regions_created.saturating_add(1);
        self.sensors.insert(
            sensor_id.clone(),
            SensorRegionSlot {
                region_id: region_id.clone(),
                cx,
                generation,
                active_task_id: Some(task_id),
                active_obligation_id: Some(ob_id),
            },
        );
        Ok(region_id)
    }

    /// Drains and finalizes a failed `SensorRegion` on camera disconnect without affecting
    /// sibling cameras.
    ///
    /// When `PropertyRegion` still has historical `SensorRegion` slots under `MAX_SENSOR_REGIONS`,
    /// the failed `SensorRegion` transitions completely through `request -> drain -> finalize`,
    /// emits its [`QuiescenceProof`], and settles its reservation back to `PropertyRegion`.
    pub fn drain_failed_sensor_region(
        &mut self,
        sensor_id: &SensorId,
        reason: &str,
        now: TimestampNs,
    ) -> Result<Option<SensorRegionDrainReceipt>, DaemonError> {
        let can_rotate_region = self.total_sensor_regions_created < MAX_SENSOR_REGIONS;
        if can_rotate_region {
            let Some(mut slot) = self.sensors.remove(sensor_id) else {
                return Ok(None);
            };
            slot.cx.request_cancellation(&mut self.tree, now)?;
            slot.cx.begin_drain(&mut self.tree, now)?;
            if let Some(task_id) = slot.active_task_id.take() {
                let _ = self.tree.complete_task(
                    &slot.region_id,
                    &task_id,
                    TaskOutcome::Failed(reason.to_owned()),
                    now,
                )?;
            }
            if let Some(ob_id) = slot.active_obligation_id.take() {
                let proof = ContentDigest::sha256(reason.as_bytes());
                slot.cx.resolve_obligation(
                    &mut self.tree,
                    &ob_id,
                    ObligationTerminal::Drained,
                    Some(proof),
                    None,
                )?;
            }
            let quiescence_proof = slot.cx.finalize(&mut self.tree, now)?;
            let _ = self
                .property_cx
                .release_scope_reservation(&self.tree, &mut slot.cx)?;
            Ok(Some(SensorRegionDrainReceipt {
                sensor_id: sensor_id.clone(),
                generation: slot.generation,
                region_id: slot.region_id,
                quiescence_proof: Some(quiescence_proof),
            }))
        } else if let Some(slot) = self.sensors.get_mut(sensor_id) {
            if let Some(task_id) = slot.active_task_id.take() {
                let _ = self.tree.complete_task(
                    &slot.region_id,
                    &task_id,
                    TaskOutcome::Failed(reason.to_owned()),
                    now,
                )?;
            }
            if let Some(ob_id) = slot.active_obligation_id.take() {
                let proof = ContentDigest::sha256(reason.as_bytes());
                slot.cx.resolve_obligation(
                    &mut self.tree,
                    &ob_id,
                    ObligationTerminal::Drained,
                    Some(proof),
                    None,
                )?;
            }
            Ok(Some(SensorRegionDrainReceipt {
                sensor_id: sensor_id.clone(),
                generation: slot.generation,
                region_id: slot.region_id.clone(),
                quiescence_proof: None,
            }))
        } else {
            Ok(None)
        }
    }

    /// Returns the total active tasks currently registered across every node in [`RegionTree`].
    #[must_use]
    pub fn active_tasks(&self) -> usize {
        self.tree.iter().map(|node| node.active_tasks.len()).sum()
    }

    /// Returns the total non-terminal leaked obligations across the entire region tree.
    #[must_use]
    pub fn leaked_obligations(&self) -> usize {
        tree_report(&self.tree)
            .iter()
            .map(|report| report.leaked.len())
            .sum()
    }

    /// Borrows the canonical [`RegionTree`].
    #[must_use]
    pub const fn region_tree(&self) -> &RegionTree {
        &self.tree
    }

    /// Borrows the storage packfile [`AuthorityCx`] for `PackStore`/`BackgroundScrubber` calls.
    #[must_use]
    pub const fn storage_pack_cx(&self) -> &AuthorityCx {
        &self.storage_pack_cx
    }

    /// Borrows the storage ledger [`AuthorityCx`] for `CommitCombiner` calls.
    #[must_use]
    pub const fn storage_ledger_cx(&self) -> &AuthorityCx {
        &self.storage_ledger_cx
    }

    /// Returns the active region ID for `sensor_id`, if currently active.
    #[must_use]
    pub fn sensor_region_id(&self, sensor_id: &SensorId) -> Option<&RegionId> {
        self.sensors.get(sensor_id).map(|slot| &slot.region_id)
    }

    /// Returns the site identifier bound to this tree.
    #[must_use]
    pub fn site_id(&self) -> &str {
        &self.site_id
    }

    /// Phase 1 (`request`): propagates cancellation from `ProcessRegion` to all live descendants.
    pub fn request_shutdown(&mut self, now: TimestampNs) -> Result<(), DaemonError> {
        if !self.drain_requested {
            self.process_cx.request_cancellation(&mut self.tree, now)?;
            self.drain_requested = true;
        }
        Ok(())
    }

    /// Phase 2 & 3 (`drain -> finalize`): closes all active sensors, perception, control plane,
    /// storage, `PropertyRegion`, and `ProcessRegion` bottom-up, returning the verified root
    /// [`RegionShutdownProof`].
    pub fn drain_and_finalize(
        mut self,
        now: TimestampNs,
    ) -> Result<RegionShutdownProof, DaemonError> {
        if !self.drain_requested {
            self.request_shutdown(now)?;
        }

        // 1. Drain and finalize every active SensorRegion.
        let sensor_ids: Vec<SensorId> = self.sensors.keys().cloned().collect();
        for sensor_id in sensor_ids {
            if let Some(mut slot) = self.sensors.remove(&sensor_id) {
                close_scoped_child(
                    &mut self.property_cx,
                    &mut slot.cx,
                    &mut self.tree,
                    slot.active_task_id.take(),
                    TaskOutcome::Cancelled,
                    slot.active_obligation_id.take(),
                    ObligationTerminal::Drained,
                    now,
                )?;
            }
        }
        // 2. Drain and finalize PerceptionRegion (ModelCall + Association -> Event).
        close_scoped_child(
            &mut self.perception_event_cx,
            &mut self.perception_model_cx,
            &mut self.tree,
            self.perception_task_id.take(),
            TaskOutcome::Cancelled,
            None,
            ObligationTerminal::Completed,
            now,
        )?;
        close_scoped_child(
            &mut self.perception_event_cx,
            &mut self.perception_assoc_cx,
            &mut self.tree,
            None,
            TaskOutcome::Success,
            None,
            ObligationTerminal::Completed,
            now,
        )?;
        close_scoped_child(
            &mut self.property_cx,
            &mut self.perception_event_cx,
            &mut self.tree,
            None,
            TaskOutcome::Success,
            self.perception_obligation_id.take(),
            ObligationTerminal::Completed,
            now,
        )?;
        // 3. Drain and finalize ControlPlaneRegion (Operations).
        close_scoped_child(
            &mut self.property_cx,
            &mut self.control_plane_cx,
            &mut self.tree,
            self.control_task_id.take(),
            TaskOutcome::Cancelled,
            self.control_obligation_id.take(),
            ObligationTerminal::Completed,
            now,
        )?;
        // 4. Drain and finalize StorageRegion (Projection + ObjectStore + Ledger).
        close_scoped_child(
            &mut self.property_cx,
            &mut self.storage_projection_cx,
            &mut self.tree,
            None,
            TaskOutcome::Success,
            None,
            ObligationTerminal::Completed,
            now,
        )?;
        close_scoped_child(
            &mut self.property_cx,
            &mut self.storage_pack_cx,
            &mut self.tree,
            None,
            TaskOutcome::Success,
            None,
            ObligationTerminal::Completed,
            now,
        )?;
        close_scoped_child(
            &mut self.property_cx,
            &mut self.storage_ledger_cx,
            &mut self.tree,
            self.storage_task_id.take(),
            TaskOutcome::Success,
            self.storage_obligation_id.take(),
            ObligationTerminal::Completed,
            now,
        )?;
        // 5. Finalize PropertyRegion and ProcessRegion.
        close_scoped_child(
            &mut self.process_cx,
            &mut self.property_cx,
            &mut self.tree,
            None,
            TaskOutcome::Success,
            None,
            ObligationTerminal::Completed,
            now,
        )?;
        self.process_cx.begin_drain(&mut self.tree, now)?;
        let root_proof = self.process_cx.finalize(&mut self.tree, now)?;

        let active_tasks = self.active_tasks();
        let leaked_obligations = self.leaked_obligations();
        let closed_regions = self.tree.iter().filter(|n| n.state.is_closed()).count();
        if active_tasks != 0 || leaked_obligations != 0 {
            return Err(DaemonError::ShutdownViolation {
                detail: format!(
                    "non-zero active_tasks ({active_tasks}) or leaked_obligations ({leaked_obligations}) after finalize"
                ),
            });
        }

        Ok(RegionShutdownProof {
            root_proof,
            active_tasks,
            leaked_obligations,
            closed_regions,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn close_scoped_child(
    parent: &mut AuthorityCx,
    child: &mut AuthorityCx,
    tree: &mut RegionTree,
    task_id: Option<TaskId>,
    task_outcome: TaskOutcome,
    ob_id: Option<ObligationId>,
    ob_terminal: ObligationTerminal,
    now: TimestampNs,
) -> Result<(), DaemonError> {
    child.begin_drain(tree, now)?;
    if let Some(tid) = task_id {
        let _ = tree.complete_task(child.region(), &tid, task_outcome, now)?;
    }
    if let Some(oid) = ob_id {
        child.resolve_obligation(tree, &oid, ob_terminal, None, None)?;
    }
    let _ = child.finalize(tree, now)?;
    let _ = parent.release_scope_reservation(tree, child)?;
    Ok(())
}

struct ScopeContext<'a> {
    trace_id: &'a str,
    principal: &'a str,
    anchor_universe: ContentDigest,
    now: TimestampNs,
}

#[allow(clippy::too_many_arguments)]
fn register_task_and_obligation(
    task_cx: &AuthorityCx,
    ob_cx: &AuthorityCx,
    tree: &mut RegionTree,
    task_name: &str,
    ob_name: &str,
    op_name: &str,
    predicate: &str,
    now: TimestampNs,
) -> Result<(TaskId, ObligationId), DaemonError> {
    let task_id = TaskId::new(task_name)?;
    tree.register_task(task_cx.region(), task_id.clone(), now)?;
    let ob = new_obligation(ob_name, OperationId::parse(op_name)?, predicate)?;
    let ob_id = ob.obligation_id.clone();
    ob_cx.register_obligation(tree, ob)?;
    Ok((task_id, ob_id))
}

#[allow(clippy::too_many_arguments)]
fn scope_child(
    parent: &mut AuthorityCx,
    tree: &mut RegionTree,
    region_id: &str,
    kind: RegionKind,
    op_id: &str,
    capabilities: Vec<String>,
    budget: BudgetVector,
    ctx: &ScopeContext<'_>,
) -> Result<AuthorityCx, DaemonError> {
    let spec = make_authority_spec(
        ctx.trace_id,
        op_id,
        ctx.principal,
        capabilities,
        2,
        budget,
        ctx.anchor_universe,
    )?;
    Ok(parent.scope_down(tree, RegionId::new(region_id)?, kind, budget, spec, ctx.now)?)
}

fn make_budget(
    bytes: u64,
    model_calls: u32,
    cpu_millis: u64,
    storage_ops: u32,
) -> Result<BudgetVector, DaemonError> {
    BudgetVector::builder()
        .bytes(bytes)
        .model_calls(model_calls)
        .cpu_millis(cpu_millis)
        .storage_operations(u64::from(storage_ops))
        .build()
        .map_err(|err| DaemonError::InvalidConfig {
            detail: format!("failed to construct region budget: {err}"),
        })
}

fn make_authority_spec(
    trace_id: &str,
    operation_id: &str,
    principal: &str,
    capabilities: Vec<String>,
    priority: u8,
    budgets: BudgetVector,
    anchor_universe: ContentDigest,
) -> Result<RootAuthoritySpec, DaemonError> {
    Ok(RootAuthoritySpec {
        trace_id: trace_id.to_owned(),
        operation_id: OperationId::parse(operation_id)?,
        principal: principal.to_owned(),
        capabilities,
        deadline: None,
        priority,
        budgets,
        privacy_scope: "privacy:site-local".to_owned(),
        retention_scope: "retention:site-ring".to_owned(),
        anchor_universe,
        generation: 1,
    })
}

fn grants(list: &[RuntimeGrant]) -> Vec<String> {
    list.iter().map(|g| g.as_str().to_owned()).collect()
}

fn daemon_root_capabilities() -> Vec<String> {
    grants(&[
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::LedgerAppend,
        RuntimeGrant::MediaDecode,
        RuntimeGrant::ModelInfer,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObserveEvent,
        RuntimeGrant::ObserveStatus,
        RuntimeGrant::ReadMedia,
        RuntimeGrant::RetentionCommit,
        RuntimeGrant::RetentionPrepare,
    ])
}

fn storage_capabilities() -> Vec<String> {
    grants(&[
        RuntimeGrant::LedgerAppend,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObserveStatus,
        RuntimeGrant::ReadMedia,
        RuntimeGrant::RetentionCommit,
        RuntimeGrant::RetentionPrepare,
    ])
}

fn perception_capabilities() -> Vec<String> {
    grants(&[
        RuntimeGrant::MediaDecode,
        RuntimeGrant::ModelInfer,
        RuntimeGrant::ObserveEvent,
        RuntimeGrant::ReadMedia,
    ])
}

fn sensor_capabilities() -> Vec<String> {
    grants(&[
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::MediaDecode,
        RuntimeGrant::ObserveStatus,
    ])
}

fn control_plane_capabilities() -> Vec<String> {
    grants(&[
        RuntimeGrant::LedgerAppend,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObserveEvent,
        RuntimeGrant::ObserveStatus,
    ])
}

fn sanitize_id_part(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(48));
    for ch in raw.chars().take(48) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "site".to_owned()
    } else {
        out
    }
}
