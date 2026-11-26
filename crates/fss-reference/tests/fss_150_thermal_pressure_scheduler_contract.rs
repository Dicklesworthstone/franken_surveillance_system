#![forbid(unsafe_code)]
//! Contract, differential oracle, thermal hysteresis, critical hard-floor preemption,
//! idempotency, fault/quarantine/cancellation, live detector integration, and hostile-wire tests
//! for `FSS-150` (`fss-x4a.14.21`: CPU thermal/pressure-aware model scheduler with hard floors).

use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation, ResourcePressure, TimestampNs};
use fss_model_ir::{
    OnnxExportLimits, OnnxLimits, decode_canonical_model_ir, export_onnx_artifacts, import_onnx,
};
use fss_reference::kernel_dispatch::{KernelDispatchPolicy, StaticKernelDispatcher};
use fss_reference::model_scheduler::{
    HardFloorPolicy, MODEL_SCHEDULER_RECEIPT_DOMAIN, MODEL_SCHEDULER_WIRE_MAGIC,
    MODEL_SCHEDULER_WIRE_VERSION, ModelSchedulerError, ModelSchedulerReceipt, ModelWorkRequest,
    ModelWorkloadClass, SchedulerDecisionState, SchedulerDegradationReason,
    SchedulerPressureSample, ThermalHysteresisConfig, ThermalPressureModelScheduler, ThermalState,
    oracle_evaluate_admission,
};
use fss_reference::optimized_executor::{ExecThreads, KernelBackend};
use fss_reference::{ChannelTransform, ExecBudget, PreprocessProgram, ScalarExecCx};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DETECTOR_ONNX: &[u8] =
    include_bytes!("../../fss-model-ir/tests/fixtures/onnx/detector_split_pool.onnx");
const DETECTOR_GEN: Generation = Generation(41);

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn test_policy() -> TestResult<HardFloorPolicy> {
    Ok(HardFloorPolicy {
        max_total_threads: ExecThreads::new(8)?,
        critical_min_threads: ExecThreads::new(2)?,
        critical_min_invocations_per_window: 2,
        max_window_invocations_total: 6,
        window_ns: 10_000_000_000,
        critical_reserved_memory_bytes: 64 * 1024 * 1024,
        standard_max_memory_bytes: 128 * 1024 * 1024,
        background_max_memory_bytes: 64 * 1024 * 1024,
        max_active_invocations: 4,
        thermal_hysteresis: ThermalHysteresisConfig::default(),
        contract_basis_digest: ContentDigest::sha256(b"fss.contract_basis.fss150.test.v1"),
        policy_generation: 7,
    })
}

fn make_request(
    id: &str,
    class: ModelWorkloadClass,
    threads: usize,
    mem_mb: u64,
    auth_gen: u64,
) -> TestResult<ModelWorkRequest> {
    Ok(ModelWorkRequest {
        request_id: id.to_owned(),
        workload_class: class,
        model_generation_digest: ContentDigest::sha256(b"model-gen:detector-v1"),
        kernel_generation_digest: KernelBackend::OptimizedCpuV1.generation(),
        requested_threads: ExecThreads::new(threads)?,
        estimated_memory_bytes: mem_mb * 1024 * 1024,
        estimated_macs: 2_500_000,
        required_authority_generation: auth_gen,
        cancelled_before_admit: false,
        quarantined_model: false,
    })
}

fn sample(
    ts_secs: i128,
    cpu_temp_mc: i32,
    pressure: ResourcePressure,
    mem_used_mb: u64,
    mem_limit_mb: u64,
    power: Option<(u32, u32)>,
) -> SchedulerPressureSample {
    SchedulerPressureSample {
        timestamp: TimestampNs(ts_secs * 1_000_000_000),
        cpu_temp_mc,
        resource_pressure: pressure,
        cpu_util_ppm: 500_000,
        memory_used_bytes: mem_used_mb * 1024 * 1024,
        memory_limit_bytes: mem_limit_mb * 1024 * 1024,
        power_budget_mw: power.map(|(cap, _)| cap),
        power_draw_mw: power.map(|(_, draw)| draw),
    }
}

#[test]
fn exhaustive_thermal_pressure_class_matrix_matches_independent_oracle() -> TestResult {
    assert_eq!(
        MODEL_SCHEDULER_RECEIPT_DOMAIN,
        "fss.reference.model_scheduler_receipt.v1"
    );
    let policy = test_policy()?;
    let cx = ScalarExecCx::new();

    let temps = [45_000_i32, 68_000, 84_000, 96_000];
    let pressures = [
        ResourcePressure::Nominal,
        ResourcePressure::Elevated,
        ResourcePressure::Constrained,
        ResourcePressure::Critical,
    ];
    let classes = [
        ModelWorkloadClass::CriticalSafetyDetector,
        ModelWorkloadClass::StandardAnalytics,
        ModelWorkloadClass::BackgroundEnrichment,
    ];

    let mut checked = 0_usize;
    for &temp in &temps {
        for &pressure in &pressures {
            for &class in &classes {
                for power_cap in [None, Some((25_000_u32, 32_000_u32))] {
                    let mut sched =
                        ThermalPressureModelScheduler::new(policy.clone(), 1, TimestampNs(0))?;
                    let req = make_request("req-matrix", class, 4, 32, 1)?;
                    let s = sample(1, temp, pressure, 32, 256, power_cap);

                    let oracle =
                        oracle_evaluate_admission(&policy, &sched.snapshot(), &s, &req, false);
                    let receipt = sched.admit(&s, &req, &cx)?;

                    assert!(!receipt.grants_effect_authority());
                    assert_eq!(
                        receipt.effective_thermal_state,
                        oracle.effective_thermal_state
                    );
                    assert_eq!(receipt.decision_state, oracle.decision_state);
                    assert_eq!(receipt.degradation_reason, oracle.degradation_reason);
                    assert_eq!(receipt.granted_threads, oracle.granted_threads);
                    assert_eq!(receipt.hard_floor_protected, oracle.hard_floor_protected);

                    // CriticalSafetyDetector is NEVER starved under any thermal/pressure combo!
                    if class == ModelWorkloadClass::CriticalSafetyDetector {
                        assert!(
                            receipt.decision_state.is_admitted(),
                            "critical detector must be admitted at temp={temp} pressure={pressure:?}"
                        );
                        assert!(
                            receipt.granted_threads >= policy.critical_min_threads.get(),
                            "critical floor violated: granted={}",
                            receipt.granted_threads
                        );
                    }

                    // Under Critical thermal or Critical pressure, non-critical MUST be deferred.
                    if (temp >= 92_000 || pressure == ResourcePressure::Critical)
                        && !class.is_critical()
                    {
                        assert_eq!(
                            receipt.decision_state,
                            SchedulerDecisionState::DeferredByPressure
                        );
                        assert_eq!(receipt.granted_threads, 0);
                    }

                    // Every receipt round-trips through FSSMMS01 bit-identically.
                    let wire = receipt.encode_wire()?;
                    let decoded = ModelSchedulerReceipt::decode_wire(&wire)?;
                    assert_eq!(decoded, receipt);
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 96);
    emit_caplog(
        "fss_150_oracle_matrix",
        "all_96_thermal_pressure_class_power_states_match_oracle_and_wire_roundtrip",
        "all_96_thermal_pressure_class_power_states_match_oracle_and_wire_roundtrip",
        "pass",
    );
    Ok(())
}

#[test]
fn critical_hard_floor_preempts_lower_classes_and_thermal_hysteresis_prevents_flapping()
-> TestResult {
    let policy = test_policy()?;
    let cx = ScalarExecCx::new();
    let mut sched = ThermalPressureModelScheduler::new(policy.clone(), 5, TimestampNs(0))?;

    // Fill all 8 threads under Nominal conditions with Standard (4t) + Background (4t).
    let r_std = sched.admit(
        &sample(1, 45_000, ResourcePressure::Nominal, 0, 256, None),
        &make_request("std-1", ModelWorkloadClass::StandardAnalytics, 4, 64, 5)?,
        &cx,
    )?;
    assert_eq!(r_std.decision_state, SchedulerDecisionState::AdmittedFull);
    let r_bg = sched.admit(
        &sample(2, 46_000, ResourcePressure::Nominal, 64, 256, None),
        &make_request("bg-1", ModelWorkloadClass::BackgroundEnrichment, 4, 64, 5)?,
        &cx,
    )?;
    assert_eq!(r_bg.decision_state, SchedulerDecisionState::AdmittedFull);
    assert_eq!(sched.active_threads(), 8);

    // Thermal spikes immediately to Critical (95 C) + Critical resource pressure while 8/8 threads
    // are busy. CriticalSafetyDetector MUST preempt BackgroundEnrichment first and obtain its
    // hard floor (2 threads) without ever failing!
    let r_crit = sched.admit(
        &sample(3, 95_000, ResourcePressure::Critical, 128, 256, None),
        &make_request(
            "crit-1",
            ModelWorkloadClass::CriticalSafetyDetector,
            4,
            64,
            5,
        )?,
        &cx,
    )?;
    assert_eq!(r_crit.effective_thermal_state, ThermalState::Critical);
    assert_eq!(
        r_crit.decision_state,
        SchedulerDecisionState::AdmittedViaHardFloor
    );
    assert!(r_crit.hard_floor_protected);
    assert_eq!(r_crit.granted_threads, 2);
    assert_eq!(r_crit.preempted_work.len(), 1);
    assert_eq!(r_crit.preempted_work[0].request_id, "bg-1");
    assert_eq!(
        r_crit.preempted_work[0].workload_class,
        ModelWorkloadClass::BackgroundEnrichment
    );
    assert_eq!(sched.active_threads(), 6); // 4 (std-1) + 2 (crit-1)

    // Complete crit-1 and std-1 -> active resources cleanly drop to zero.
    sched.complete("crit-1")?;
    sched.complete("std-1")?;
    assert_eq!(sched.active_threads(), 0);
    assert_eq!(sched.active_memory_bytes(), 0);

    // Hysteresis anti-flapping proof:
    // At t=5s (only 2s after entering Critical at t=3s, dwell requires 5s), even if temp drops to
    // 55 C, thermal state MUST remain Critical until dwell expires!
    let r_dwell = sched.admit(
        &sample(5, 55_000, ResourcePressure::Nominal, 0, 256, None),
        &make_request("std-dwell", ModelWorkloadClass::StandardAnalytics, 2, 32, 5)?,
        &cx,
    )?;
    assert_eq!(r_dwell.effective_thermal_state, ThermalState::Critical);
    assert_eq!(
        r_dwell.decision_state,
        SchedulerDecisionState::DeferredByPressure
    );

    // At t=9s (6s elapsed >= 5s dwell) and temp 84 C (<= 85 C critical_exit, > 74 C hot_exit),
    // thermal state steps down cleanly from Critical -> Hot (not Nominal).
    let r_hot = sched.admit(
        &sample(9, 84_000, ResourcePressure::Nominal, 0, 256, None),
        &make_request("std-hot", ModelWorkloadClass::StandardAnalytics, 2, 32, 5)?,
        &cx,
    )?;
    assert_eq!(r_hot.effective_thermal_state, ThermalState::Hot);
    assert_eq!(
        r_hot.decision_state,
        SchedulerDecisionState::DeferredByPressure
    );

    // At t=15s (6s after entering Hot) and temp 50 C (<= warm_exit), thermal state recovers to Nominal.
    // Reusing the SAME request_id ("std-dwell") that was previously DeferredByPressure MUST succeed
    // cleanly after cool-down (non-admitted deferrals never poison the idempotency cache!).
    let r_nom = sched.admit(
        &sample(15, 50_000, ResourcePressure::Nominal, 0, 256, None),
        &make_request("std-dwell", ModelWorkloadClass::StandardAnalytics, 4, 32, 5)?,
        &cx,
    )?;
    assert_eq!(r_nom.effective_thermal_state, ThermalState::Nominal);
    assert_eq!(r_nom.decision_state, SchedulerDecisionState::AdmittedFull);
    assert_eq!(r_nom.granted_threads, 4);

    emit_caplog(
        "fss_150_preemption_and_hysteresis",
        "critical_hard_floor_preempts_bg_and_hysteresis_blocks_flapping",
        "critical_hard_floor_preempts_bg_and_hysteresis_blocks_flapping",
        "pass",
    );
    Ok(())
}

#[test]
fn idempotency_quarantine_stale_auth_cancel_live_detector_and_hostile_wire_fail_closed()
-> TestResult {
    let policy = test_policy()?;
    let cx = ScalarExecCx::new();
    let mut sched = ThermalPressureModelScheduler::new(policy.clone(), 10, TimestampNs(0))?;

    // 1. Live integration: schedule CriticalSafetyDetector under Nominal (4t) vs Critical (2t),
    // feed `receipt.admitted_exec_threads()` into StaticKernelDispatcher on real ONNX detector,
    // and prove bit-identical outputs AND identical static decision-path digests!
    let imported = import_onnx(
        DETECTOR_ONNX,
        ContentDigest::sha256(DETECTOR_ONNX),
        DETECTOR_GEN,
        OnnxLimits::default(),
        &|| false,
    )?;
    let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    let mut constants: BTreeMap<String, Vec<f32>> = BTreeMap::new();
    for (name, tensor) in imported.parameters() {
        constants.insert(name.clone(), tensor.to_vec::<f32>()?);
    }
    let raw_rgb: Vec<u8> = (0..48_u8).map(|i| i.wrapping_mul(17)).collect();
    let image = PreprocessProgram::new(4, 4, ChannelTransform::Rgb, true).execute_bytes(
        &raw_rgb,
        4,
        4,
        3,
        DETECTOR_GEN,
    )?;

    let r_nom = sched.admit(
        &sample(1, 48_000, ResourcePressure::Nominal, 16, 256, None),
        &make_request(
            "det-nom",
            ModelWorkloadClass::CriticalSafetyDetector,
            4,
            16,
            10,
        )?,
        &cx,
    )?;
    let t_nom = r_nom.admitted_exec_threads().ok_or("expected threads")?;
    assert_eq!(t_nom.get(), 4);
    sched.complete("det-nom")?;

    let r_crit = sched.admit(
        &sample(2, 96_000, ResourcePressure::Critical, 16, 256, None),
        &make_request(
            "det-crit",
            ModelWorkloadClass::CriticalSafetyDetector,
            4,
            16,
            10,
        )?,
        &cx,
    )?;
    let t_crit = r_crit.admitted_exec_threads().ok_or("expected threads")?;
    assert_eq!(t_crit.get(), 2);
    sched.complete("det-crit")?;

    let plan_nom = StaticKernelDispatcher::compile(
        &graph,
        &constants,
        KernelDispatchPolicy {
            backend: KernelBackend::OptimizedCpuV1,
            threads: t_nom,
            allow_scalar_fallback: false,
            verify_against_scalar_oracle: true,
            ..KernelDispatchPolicy::default()
        },
        &cx,
    )?;
    let plan_crit = StaticKernelDispatcher::compile(
        &graph,
        &constants,
        KernelDispatchPolicy {
            backend: KernelBackend::OptimizedCpuV1,
            threads: t_crit,
            allow_scalar_fallback: false,
            verify_against_scalar_oracle: true,
            ..KernelDispatchPolicy::default()
        },
        &cx,
    )?;
    assert_eq!(
        plan_nom.receipt().decision_path_digest,
        plan_crit.receipt().decision_path_digest
    );
    let out_nom = plan_nom.execute(&[("image", image.clone())], ExecBudget::unlimited(), &cx)?;
    let out_crit = plan_crit.execute(&[("image", image)], ExecBudget::unlimited(), &cx)?;
    let bits_nom: Vec<u32> = out_nom
        .outcome
        .get_output("head")
        .ok_or("missing head")?
        .to_vec::<f32>()?
        .iter()
        .map(|v| v.to_bits())
        .collect();
    let bits_crit: Vec<u32> = out_crit
        .outcome
        .get_output("head")
        .ok_or("missing head")?
        .to_vec::<f32>()?
        .iter()
        .map(|v| v.to_bits())
        .collect();
    assert_eq!(bits_nom, bits_crit);

    // 2. Idempotent exact replay vs conflicting request_id refusal.
    let replay = sched.admit(
        &sample(3, 48_000, ResourcePressure::Nominal, 16, 256, None),
        &make_request(
            "det-nom",
            ModelWorkloadClass::CriticalSafetyDetector,
            4,
            16,
            10,
        )?,
        &cx,
    )?;
    assert_eq!(replay, r_nom);

    let conflict_err = sched
        .admit(
            &sample(3, 48_000, ResourcePressure::Nominal, 16, 256, None),
            &make_request("det-nom", ModelWorkloadClass::StandardAnalytics, 2, 16, 10)?,
            &cx,
        )
        .expect_err("conflicting duplicate request_id must fail closed");
    assert_eq!(
        conflict_err.stable_id(),
        "ERR-MODEL-SCHED-IDEMPOTENCY-CONFLICT-001"
    );

    // 3. Stale authority generation, quarantine, cooperative cancellation, and time regression.
    sched.update_authority_generation(11)?;
    assert!(matches!(
        sched.update_authority_generation(10),
        Err(ModelSchedulerError::AuthorityGenerationRegression { .. })
    ));

    let stale = sched.admit(
        &sample(4, 48_000, ResourcePressure::Nominal, 16, 256, None),
        &make_request(
            "stale-req",
            ModelWorkloadClass::CriticalSafetyDetector,
            2,
            16,
            10,
        )?,
        &cx,
    )?;
    assert_eq!(
        stale.decision_state,
        SchedulerDecisionState::RefusedQuarantinedOrStale
    );
    assert_eq!(
        stale.degradation_reason,
        SchedulerDegradationReason::AuthorityGenerationStale
    );

    sched.quarantine_model(ContentDigest::sha256(b"model-gen:detector-v1"));
    let quar = sched.admit(
        &sample(5, 48_000, ResourcePressure::Nominal, 16, 256, None),
        &make_request(
            "quar-req",
            ModelWorkloadClass::CriticalSafetyDetector,
            2,
            16,
            11,
        )?,
        &cx,
    )?;
    assert_eq!(
        quar.decision_state,
        SchedulerDecisionState::RefusedQuarantinedOrStale
    );
    assert_eq!(
        quar.degradation_reason,
        SchedulerDegradationReason::ModelGenerationQuarantined
    );

    let cancelled_cx = ScalarExecCx::new();
    cancelled_cx.request_cancellation();
    let cancelled = sched.admit(
        &sample(6, 48_000, ResourcePressure::Nominal, 16, 256, None),
        &make_request(
            "cancel-req",
            ModelWorkloadClass::CriticalSafetyDetector,
            2,
            16,
            11,
        )?,
        &cancelled_cx,
    )?;
    assert_eq!(cancelled.decision_state, SchedulerDecisionState::Cancelled);
    assert_eq!(cancelled.granted_threads, 0);

    let regress_err = sched
        .admit(
            &sample(5, 48_000, ResourcePressure::Nominal, 16, 256, None),
            &make_request(
                "regress-req",
                ModelWorkloadClass::StandardAnalytics,
                2,
                16,
                11,
            )?,
            &cx,
        )
        .expect_err("timestamp regression must fail closed");
    assert_eq!(regress_err.stable_id(), "ERR-MODEL-SCHED-TIME-REGRESS-001");

    // 4. Hostile FSSMMS01 wire corruption tests.
    let wire = r_crit.encode_wire()?;
    assert_eq!(&wire[..8], &MODEL_SCHEDULER_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        MODEL_SCHEDULER_WIRE_VERSION
    );

    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert!(ModelSchedulerReceipt::decode_wire(&bad_magic).is_err());

    let mut bad_checksum = wire.clone();
    let last = bad_checksum.len() - 1;
    bad_checksum[last] ^= 0x01;
    assert!(ModelSchedulerReceipt::decode_wire(&bad_checksum).is_err());

    let mut trailing = wire.clone();
    trailing.push(0xAA);
    assert!(ModelSchedulerReceipt::decode_wire(&trailing).is_err());

    assert!(ModelSchedulerReceipt::decode_wire(&wire[..wire.len() - 1]).is_err());

    emit_caplog(
        "fss_150_detector_integration_and_faults",
        "bit_exact_throttled_detector_idempotency_quarantine_cancel_and_wire_verified",
        "bit_exact_throttled_detector_idempotency_quarantine_cancel_and_wire_verified",
        "pass",
    );
    Ok(())
}
