# Risk registry

| ID | Risk | Mitigation and release consequence |
|---|---|---|
| `RISK-VENDOR-001` | proprietary firmware/app breaks adapter | exact tuple, simulator, shadow qualification, fail closed, maintenance owner |
| `RISK-SDK-001` | desired drone/camera absent from official SDK | import/display bridge only; no native/autonomy claim |
| `RISK-CODEC-001` | hostile media triggers a defect or resource attack in the pure-Rust decoder | checked arithmetic, bounded arenas, scalar oracle, malformed-media corpus, cancellation budgets, source quarantine, fail-closed capability promotion |
| `RISK-MODEL-001` | VLM hallucination/poor calibration misses threat | cascade, independent verifier, event metrics, abstention, never direct effects |
| `RISK-CORRELATION-001` | multiple cameras/vendor cloud share failure domain | failure-domain graph and independent local sensors |
| `RISK-TIME-001` | clock/buffering error corrupts association | interval time, marker calibration, degradation thresholds |
| `RISK-GEOMETRY-001` | attractive but inaccurate 3D twin | certificate residuals/covariance/held-out validation; renderings derived |
| `RISK-COVERAGE-001` | static coverage map hides live failure | effective coverage includes continuity/quality/calibration health |
| `RISK-PRIVACY-001` | system over-collects household/bystander data | local-first, early masks, minimization, deletion closure, identity off |
| `RISK-SECRET-001` | vendor/archive credentials leak through logs/prompts | secret handles, process domains, redaction tests, support-bundle policy |
| `RISK-ARCHIVE-001` | cheap archive costs explode via tiny objects/retrieval | operation-cost registry, chunking, dated price manifest, audit |
| `RISK-RECOVERY-001` | crash leaves ambiguous alert/control/archive effect | operation receipts, obligations, reconcile before retry |
| `RISK-DATASET-001` | test leakage/property bias creates false quality | property/session split, sealed holdout, subgroup slices, new generations |
| `RISK-BIOMETRIC-001` | identity feature becomes surveillance network | disabled default, property-local TTL, explicit enrollment, no cross-property |
| `RISK-AGENT-001` | agent overreach or prompt injection from sensor text | read-first capabilities, taint, no shell/vendor proxy, prepared effects |
| `RISK-DEPENDENCY-001` | broad or foreign runtime stack undermines the pure-Rust product | closed universe, exact import contracts, release-closure census, foreign tools restricted to sealed oracle lanes, ADR/audit |
| `RISK-COMPLEXITY-001` | architecture delays usable vertical slice | deterministic replay/UVC walking skeleton, gate-ordered work, no substitute seams |
| `RISK-GUARANTEE-001` | “never miss” language creates false assurance | defined distributions, confidence bounds, negative evidence, explicit observability |
