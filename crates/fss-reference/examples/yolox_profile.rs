#![forbid(unsafe_code)]
//! OFFLINE PROFILING helper for the YOLOX-Nano executor lane (fss-bd99t).
//!
//! Loads the verified package, preprocesses the pinned conformance cases exactly like the
//! conformance test, and reports, for the scalar reference and the optimized executor:
//!
//! * `whole`: wall time of complete-graph executions (median of N) per case, plus the digest of
//!   the exact output bits (the optimized digests must equal the scalar ones);
//! * `ops`: per-op-type wall-time totals for one inference, measured by executing each node as
//!   a one-node program in liveness order (every node's time includes that program's own
//!   validation/copy overhead, and the optimized breakdown is unfused);
//! * `memory`: the scalar liveness plan's peak and the optimized run's measured peak payload.
//!
//! * `sweep` (fss-zczw0): with `--threads 1,2,4,8`, whole-graph optimized timings and the
//!   optimized `ops` breakdown per thread count (after one scalar run per case for the
//!   bit-identity check), plus `/proc/loadavg` before and after each count, so shared-host
//!   contention is visible next to the numbers.
//!
//! Run in release mode only; debug timings are meaningless. Not a runtime path.
//! Usage: `yolox_profile [RUNS] [--threads N[,N...]]` (default 5 runs, full profile).

use std::collections::BTreeMap;
use std::error::Error;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, Generation, OperationId};
use fss_model_ir::{
    MemoryPlan, MemoryPlanLimits, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::preprocess::{ImageBytes, ResizeAspect, ResizeFilter, ResizeOptions};
use fss_reference::{
    ChannelTransform, ExecBudget, ExecOutcome, ExecThreads, KernelBackend, OptimizedGraph,
    PreprocessProgram, ReplayCx, ScalarExecCx, ScalarExecutor,
};
use fss_tensor::Tensor;

#[path = "../tests/yolox_support/cases.rs"]
mod cases;
#[path = "../tests/yolox_support/person.rs"]
mod person;

type Res<T = ()> = Result<T, Box<dyn Error>>;

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn load() -> Res<RgbDetectorPackage> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:yolox-profile".into(),
        operation_id: OperationId::parse("operation:yolox-profile")?,
        principal: "principal:yolox-profile".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:lab".into(),
        retention_scope: "retention:lab".into(),
        anchor_universe: ContentDigest::sha256(b"site:yolox-profile"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, std::env::temp_dir())?;
    // The scalar selection keeps the model free of a prepared plan; this helper prepares its
    // own optimized graph from the same frozen graph and parameters.
    Ok(RgbDetectorPackage::load_with_backend(
        PACKAGE,
        ContentDigest::parse(PACKAGE_SHA256)?,
        1 << 40,
        KernelBackend::ScalarReference,
        &cx,
        &ScalarExecCx::new(),
    )?)
}

/// Exact model input of one conformance case (same program as the conformance test).
fn model_input(name: &str) -> Res<Tensor> {
    let image = cases::source(name)?;
    let [w, h] = image.dimensions;
    let resized = PreprocessProgram::new(416, 416, ChannelTransform::Rgb, false)
        .execute_resized_bytes(
            ImageBytes {
                bytes: &image.pixels,
                height: h as usize,
                width: w as usize,
                channels: 3,
                generation: Generation(1),
            },
            ResizeOptions {
                filter: ResizeFilter::Bilinear,
                aspect: ResizeAspect::Letterbox(114),
                budget: ExecBudget::new(1 << 40, 1 << 30),
            },
            &ScalarExecCx::new(),
        )?;
    Ok(resized.tensor)
}

fn bindings(package: &RgbDetectorPackage, image: Tensor) -> Res<Vec<(String, Tensor)>> {
    let model = package.model();
    let graph = model.graph();
    let mut inputs = vec![(model.spec().image_input.clone(), image)];
    for (name, values) in model.parameters() {
        let port = graph.find_input(name).ok_or("parameter port")?;
        inputs.push((
            name.clone(),
            Tensor::from_values(port.shape().clone(), values, graph.generation())?,
        ));
    }
    Ok(inputs)
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

#[derive(Clone, Copy, PartialEq)]
enum Backend {
    Scalar,
    Optimized,
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Optimized => "optimized",
        }
    }
}

fn output_bits(out: &ExecOutcome) -> Res<ContentDigest> {
    let mut bits = Vec::new();
    for tensor in out.outputs().values() {
        for v in tensor.to_vec::<f32>()? {
            bits.extend_from_slice(&v.to_bits().to_le_bytes());
        }
    }
    Ok(ContentDigest::sha256(&bits))
}

fn whole(
    package: &RgbDetectorPackage,
    backend: Backend,
    runs: usize,
    threads: ExecThreads,
) -> Res<Vec<ContentDigest>> {
    let model = package.model();
    let graph = model.graph();
    let started = Instant::now();
    let prepared = OptimizedGraph::prepare(graph, model.parameters(), &ScalarExecCx::new())?;
    if backend == Backend::Optimized {
        println!(
            "prepared prepare_ms={:.1} kernel_generation={} plan={} kernels={:?}",
            ms(started.elapsed()),
            prepared.kernel_generation(),
            prepared.digest(),
            prepared.kernel_counts()
        );
    }
    let mut digests = Vec::new();
    let mut every = Vec::new();
    for name in cases::CASES {
        let native_jpeg = cases::source(name)?.jpeg.is_some();
        let image = model_input(name)?;
        let inputs = bindings(package, image.clone())?;
        let mut times = Vec::with_capacity(runs);
        let mut digest = None;
        let mut report = None;
        for _ in 0..runs {
            let cx = ScalarExecCx::new();
            let t = Instant::now();
            let out = match backend {
                Backend::Scalar => {
                    ScalarExecutor::run(graph, &inputs, ExecBudget::unlimited(), &cx)?
                }
                Backend::Optimized => {
                    let (out, r) = prepared.run_threaded(
                        &[(model.spec().image_input.as_str(), image.clone())],
                        ExecBudget::unlimited(),
                        threads,
                        &cx,
                    )?;
                    report = Some(r);
                    out
                }
            };
            times.push(t.elapsed());
            let d = output_bits(&out)?;
            if digest.is_some_and(|p| p != d) {
                return Err("nondeterministic output".into());
            }
            digest = Some(d);
        }
        let all: Vec<String> = times.iter().map(|t| format!("{:.1}", ms(*t))).collect();
        let digest = digest.ok_or("no run")?;
        every.extend(times.iter().copied());
        println!(
            "whole backend={} threads={} case={name} native_jpeg={native_jpeg} runs={runs} median_ms={:.1} min_ms={:.1} all_ms=[{}] output_bits={digest}",
            backend.name(),
            threads.get(),
            ms(median(times.clone())),
            ms(times.iter().copied().min().unwrap_or_default()),
            all.join(","),
        );
        if let Some(r) = report {
            println!(
                "memory backend=optimized threads={} case={name} peak_live_bytes={} scratch_bytes={} resident_bytes={} threads_used={}",
                threads.get(),
                r.peak_live_bytes,
                r.scratch_bytes,
                r.resident_bytes,
                r.threads_used
            );
        }
        digests.push(digest);
    }
    if !every.is_empty() {
        println!(
            "whole_summary backend={} threads={} samples={} median_ms={:.1} min_ms={:.1}",
            backend.name(),
            threads.get(),
            every.len(),
            ms(median(every.clone())),
            ms(every.iter().copied().min().unwrap_or_default())
        );
    }
    Ok(digests)
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unavailable".to_owned())
}

/// Parse `--threads 1,2,4,8` (every entry admitted by `ExecThreads::new`).
fn thread_list(args: &[String]) -> Res<Option<Vec<ExecThreads>>> {
    let Some(at) = args.iter().position(|a| a == "--threads") else {
        return Ok(None);
    };
    let list = args.get(at + 1).ok_or("--threads requires a list")?;
    let mut out = Vec::new();
    for entry in list.split(',') {
        out.push(ExecThreads::new(entry.parse()?)?);
    }
    Ok(Some(out))
}

/// Thread sweep: one scalar run per case as the bit-identity oracle, then `runs` optimized runs
/// per case for every requested thread count, all in this process on this host.
fn sweep(package: &RgbDetectorPackage, runs: usize, counts: &[ExecThreads]) -> Res {
    let scalar = whole(package, Backend::Scalar, 1, ExecThreads::SINGLE)?;
    for &threads in counts {
        println!("loadavg before threads={} {}", threads.get(), loadavg());
        let optimized = whole(package, Backend::Optimized, runs, threads)?;
        println!("loadavg after threads={} {}", threads.get(), loadavg());
        ops(package, Backend::Optimized, threads)?;
        let identical = scalar == optimized;
        println!(
            "bit_identical_outputs threads={} {identical}",
            threads.get()
        );
        if !identical {
            return Err("threaded outputs differ from the scalar reference".into());
        }
    }
    Ok(())
}

/// Repetitions per node program; the minimum is reported (the least-disturbed sample).
const NODE_REPEATS: usize = 3;

fn ops(package: &RgbDetectorPackage, backend: Backend, threads: ExecThreads) -> Res {
    let model = package.model();
    let graph = model.graph();
    let parameters = model.parameters();
    let plan = MemoryPlan::compile(graph, MemoryPlanLimits::default())?;
    let nodes: BTreeMap<_, _> = graph.nodes().iter().map(|n| (n.id(), n)).collect();
    let port = |name: &String| -> Res<TensorPort> {
        Ok(plan.values().get(name).ok_or("value")?.port().clone())
    };
    // Mirror the executor's fusion: a Conv2d whose only consumer is one SiLU node runs as one
    // two-node program on the optimized backend (reported as `Conv2d+Silu`).
    let mut uses: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in graph.nodes() {
        for name in node.inputs() {
            uses.entry(name.as_str()).or_default().push(node.id());
        }
    }
    let graph_outputs: Vec<&str> = graph.outputs().iter().map(TensorPort::name).collect();
    let mut fused_into: BTreeMap<&str, &str> = BTreeMap::new();
    if backend == Backend::Optimized {
        for node in graph.nodes() {
            if node.op() != OpCode::Conv2d {
                continue;
            }
            let Some(out) = node.outputs().first() else {
                continue;
            };
            if let Some([only]) = uses.get(out.as_str()).map(Vec::as_slice)
                && nodes.get(only).is_some_and(|n| n.op() == OpCode::Silu)
                && !graph_outputs.contains(&out.as_str())
            {
                fused_into.insert(only, node.id());
            }
        }
    }
    let silu_of: BTreeMap<&str, &str> = fused_into.iter().map(|(s, c)| (*c, *s)).collect();
    let mut env: BTreeMap<String, Tensor> = bindings(package, model_input("silhouette")?)?
        .into_iter()
        .collect();
    let mut totals: BTreeMap<String, (usize, Duration, u64)> = BTreeMap::new();
    let mut per_node: Vec<(Duration, String)> = Vec::new();
    let mut sum = Duration::ZERO;
    for step in plan.steps() {
        if !fused_into.contains_key(step.node_id()) {
            let node = nodes.get(step.node_id()).ok_or("node")?;
            let mut program_nodes = vec![(**node).clone()];
            let mut label = format!("{:?}", node.op());
            let mut out_names = node.outputs().to_vec();
            if let Some(silu) = silu_of.get(node.id()) {
                let silu = nodes.get(silu).ok_or("silu")?;
                program_nodes.push((**silu).clone());
                label.push_str("+Silu");
                out_names = silu.outputs().to_vec();
            }
            let mut unique = BTreeMap::new();
            for name in node.inputs() {
                unique.insert(name.clone(), port(name)?);
            }
            let outputs: Vec<TensorPort> = out_names.iter().map(port).collect::<Res<_>>()?;
            let program = ModelIrGraph::new_validated(
                "profile",
                ModelIrVersion::V1,
                graph.generation(),
                unique.values().cloned().collect(),
                outputs,
                program_nodes,
            )?;
            let args: Vec<(String, Tensor)> = unique
                .keys()
                .map(|n| Ok((n.clone(), env.get(n).ok_or("env")?.clone())))
                .collect::<Res<_>>()?;
            let constants: BTreeMap<String, Vec<f32>> = unique
                .keys()
                .filter_map(|n| parameters.get(n).map(|v| (n.clone(), v.clone())))
                .collect();
            // Weights are bound at preparation (outside the timed region), as in the model.
            let prepared = OptimizedGraph::prepare(&program, &constants, &ScalarExecCx::new())?;
            let runtime: Vec<(String, Tensor)> = args
                .iter()
                .filter(|(n, _)| !constants.contains_key(n))
                .cloned()
                .collect();
            let mut best = Duration::MAX;
            let mut result = None;
            for _ in 0..NODE_REPEATS {
                let cx = ScalarExecCx::new();
                let t = Instant::now();
                let out = match backend {
                    Backend::Scalar => {
                        ScalarExecutor::run(&program, &args, ExecBudget::unlimited(), &cx)?
                    }
                    Backend::Optimized => {
                        prepared
                            .run_threaded(&runtime, ExecBudget::unlimited(), threads, &cx)?
                            .0
                    }
                };
                best = best.min(t.elapsed());
                result = Some(out);
            }
            let out = result.ok_or("no run")?;
            sum += best;
            let entry = totals
                .entry(label.clone())
                .or_insert((0, Duration::ZERO, 0));
            entry.0 += 1;
            entry.1 += best;
            entry.2 += out.executed_macs();
            let shapes: Vec<String> = unique
                .values()
                .map(|p| format!("{}{:?}", p.name(), p.shape().dims()))
                .collect();
            per_node.push((
                best,
                format!(
                    "{} {label} in={} attrs={:?}",
                    node.id(),
                    shapes.join(","),
                    node.attributes()
                ),
            ));
            drop(args);
            for (name, tensor) in out.into_outputs() {
                env.insert(name, tensor);
            }
        }
        for name in step.release_after() {
            env.remove(name);
        }
    }
    let mut rows: Vec<_> = totals.into_iter().collect();
    rows.sort_by_key(|a| std::cmp::Reverse(a.1.1));
    println!(
        "ops backend={} threads={} case=silhouette nodes={} sum_ms={:.1} (per-node programs, min of {NODE_REPEATS})",
        backend.name(),
        threads.get(),
        plan.steps().len(),
        ms(sum)
    );
    for (op, (count, time, work)) in rows {
        println!(
            "op backend={} threads={} op={op} programs={count} ms={:.1} share={:.1}% work_units={work}",
            backend.name(),
            threads.get(),
            ms(time),
            100.0 * time.as_secs_f64() / sum.as_secs_f64()
        );
    }
    per_node.sort_by_key(|a| std::cmp::Reverse(a.0));
    for (dt, label) in per_node.iter().take(8) {
        println!(
            "top_node backend={} threads={} ms={:.2} {label}",
            backend.name(),
            threads.get(),
            ms(*dt)
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runs = args
        .first()
        .and_then(|a| a.parse().ok())
        .unwrap_or(5_usize)
        .max(1);
    let counts = match thread_list(&args) {
        Ok(counts) => counts,
        Err(e) => {
            eprintln!("yolox_profile: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Worker class: CPU model and logical CPU count (Linux only; informational).
    let cpu = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    println!(
        "host cpu={:?} logical_cpus={}",
        cpu.lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
            .map(str::trim)
            .unwrap_or("unknown"),
        cpu.lines().filter(|l| l.starts_with("processor")).count()
    );
    println!(
        "host available_parallelism={} loadavg {}",
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        loadavg()
    );
    let result = load().and_then(|package| {
        if let Some(counts) = &counts {
            return sweep(&package, runs, counts);
        }
        let plan = MemoryPlan::compile(package.model().graph(), MemoryPlanLimits::default())?;
        println!(
            "memory backend=scalar-plan peak_live_tensor_bytes={} cumulative_tensor_bytes={}",
            plan.peak_live_bytes(),
            plan.cumulative_bytes()
        );
        ops(&package, Backend::Scalar, ExecThreads::SINGLE)?;
        ops(&package, Backend::Optimized, ExecThreads::SINGLE)?;
        let scalar = whole(&package, Backend::Scalar, runs, ExecThreads::SINGLE)?;
        let optimized = whole(&package, Backend::Optimized, runs, ExecThreads::SINGLE)?;
        println!("bit_identical_outputs={}", scalar == optimized);
        if scalar != optimized {
            return Err("optimized outputs differ from the scalar reference".into());
        }
        Ok(())
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("yolox_profile: {e}");
            ExitCode::FAILURE
        }
    }
}
