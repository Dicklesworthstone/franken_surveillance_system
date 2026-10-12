# FrankenTorch assimilation admission status (bead fss-x4a.27.53)

Companion to `FRANKENTORCH.md`: the mechanism-by-mechanism record of where
each admitted pure-Rust model plan / kernel / receipt concept landed.

| Deep-dive mechanism | FSS landing site | Evidence | Status |
|---|---|---|---|
| §2 narrow-waist model format | `fss-model-ir` (attribute/graph/node/op/port canonical IR) | `model_ir_contract.rs` (128 tests), `model_manifest_contract.rs` | admitted |
| §3 tensor + storage semantics | `fss-tensor` crate + `fss-model-ir` memory plans | `memory_plan_contract.rs` | admitted |
| §4 operator dispatch/specialization | IR op registry with typed ports + shape inference | shape_inference module, port typing | admitted |
| §5 CPU-first safe-Rust mechanical sympathy | forbid(unsafe) everywhere; scalar oracle lanes | unsafe-prohibition checker (lane step, green); DEP-AUD-021 sweep | admitted |
| §6 quantization as a model generation | immutable model/device/config generations (registry) | model generation registry rows (30.93 realized); MOD rows with eligibility states | admitted |
| §7 accelerator posture | no ambient accelerator dependency; explicit generations only | dependency constitution (no foreign runtime); FSS-138 lane open for kernels | partial (posture admitted; kernel specialization = FSS-138 open) |
| §8 in-process invocation protocol | model execution receipts (typed, generation-pinned) | `model_receipt_tests`, model package manifests | admitted |
| §9 progressive model cascade | detector cascade (watch→corroborate gates) | reference deployment capabilities (cascade listed); YOLOX oracle lanes | admitted |
| §10 deterministic packages + custody | canonical tensor import + content digests | `model_package_contract.rs`, deterministic importer lane (FSS-138 open for the importer itself) | partial (package format admitted; importer = open bead) |
| §11 differential conformance | scalar-oracle differential lanes | `scripts/yolox_nano_oracle.py` + HOG oracle; model conformance lanes | admitted |
| §12 numeric policy | exact numeric ordering + deterministic execution invariants | stable sort keys; replay determinism proofs | admitted |

## Verdict

9 of 11 admitted; 2 partial with named open lanes (kernel specialization and
the canonical importer = FSS-138 family). The rejected-import list (no
foreign ML runtime, no runtime weight downloads) is enforced by the
dependency constitution and the unsafe/offline lanes.
