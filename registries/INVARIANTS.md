# Invariant registry

Stable invariant IDs are never renumbered. A superseded invariant remains as a tombstone with its
replacement. Current machine source: `architecture/invariants.json`.

| ID | Invariant | Status |
|---|---|---|
| `INV-001` | Authority, cognition, and effect records are type-distinct and stored separately. | `normative` |
| `INV-002` | No model output is authoritative evidence and no model directly authorizes an effect. | `normative` |
| `INV-003` | Every retained observation names exact source bytes or records why source retention was forbidden. | `normative` |
| `INV-004` | Capture time is an interval with a declared clock basis, never an unjustified point timestamp. | `normative` |
| `INV-005` | Stream acceptance, first frame, continuity verification, and semantic detection are distinct states. | `normative` |
| `INV-006` | Every asynchronous child is owned by an Asupersync region and shutdown drains to a terminal or indeterminate receipt. | `normative` |
| `INV-007` | Consequential effects use prepare, revalidate, commit, observe, and verify semantics with idempotency. | `normative` |
| `INV-008` | Credentials are scoped to an adapter instance, never included in traces, model prompts, or evidence bundles. | `normative` |
| `INV-009` | Proprietary adapters operate only against owner-authorized devices and accounts; credential bypass is out of scope. | `normative` |
| `INV-010` | Original encoded media is never silently replaced by a transcoded derivative. | `normative` |
| `INV-011` | Published object graphs are root-last; a visible root cannot reference uncommitted children. | `normative` |
| `INV-012` | Derived indexes, graphs, embeddings, tracks, and digital-twin renderings are rebuildable from canonical evidence. | `normative` |
| `INV-013` | A model generation is immutable; mixed-generation embeddings or logits cannot share one score space. | `normative` |
| `INV-014` | Alert thresholds are versioned policy, not mutable model-side constants. | `normative` |
| `INV-015` | An alert includes evidence, uncertainty, sensor-health context, and a deterministic decision fingerprint. | `normative` |
| `INV-016` | Absence of detection cannot become evidence of absence when coverage, continuity, or calibration is degraded. | `normative` |
| `INV-017` | Privacy masks and excluded zones are applied before remote publication and before any model not authorized for unredacted data. | `normative` |
| `INV-018` | Face identification, cross-property identity linkage, and biometric enrollment are disabled by default. | `normative` |
| `INV-019` | The drone is a manually piloted calibration and observation sensor until a separate flight-safety qualification exists. | `normative` |
| `INV-020` | No v1 effect can deploy a weapon, pursue a person, or physically confront a subject. | `normative` |
| `INV-021` | Every public readiness claim is derivable from a retained proof bundle and a registered claim class. | `normative` |
| `INV-022` | Negative evidence, failed experiments, and known blind spots are retained and release-visible. | `normative` |
| `INV-023` | Local qualification is release authority; hosted CI is supplementary evidence. | `normative` |
| `INV-024` | A vendor firmware or app generation not in the compatibility registry fails closed or enters an explicit degraded mode. | `normative` |
| `INV-025` | A redacted or deleted object cannot remain reachable through an undeclared alternate index or cache. | `normative` |
| `INV-026` | Every durable schema is versioned and old versions remain readable or have a deterministic migration. | `normative` |
| `INV-027` | Every adaptive policy is bounded by non-adaptive safety invariants and logs its decision basis. | `normative` |
| `INV-028` | Detection quality is measured at event level under realistic class imbalance, not inferred from frame accuracy. | `normative` |
| `INV-029` | A false-negative claim includes the defined threat distribution and a confidence bound; absolute never-miss claims are forbidden. | `normative` |
| `INV-030` | Any operation whose registered cost cannot satisfy its SLO fails design review before implementation. | `normative` |
