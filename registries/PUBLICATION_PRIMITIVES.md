# Publication primitive registry

Machine source: `architecture/publication_primitives.json`. Publication is a semantic effect, not a successful write call. Every primitive reserves identity, materializes unpublished children, verifies closure, exposes the root last, and retains a receipt.

| ID | Primitive | Owner | Root invariant | State |
|---|---|---|---|---|
| `PUB-AUTH-001` | `authority_generation` | `fss-publication` | No reader observes a root whose children are incomplete | `specified` |
| `PUB-OBJECT-001` | `archive_object_graph` | `fss-custody` | Remote object existence alone is not publication | `specified` |
| `PUB-SEARCH-001` | `search_generation` | `fss-search` | Provisional searchable state is explicitly marked non-durable | `specified` |
| `PUB-GRAPH-001` | `graph_projection` | `fss-graph-store` | Projection declares consumed authority high-water mark | `specified` |
| `PUB-MODEL-001` | `model_activation` | `fss-model-registry` | Downloaded or merely loadable model is not active | `specified` |
| `PUB-CAL-001` | `calibration_activation` | `fss-geometry` | Low residual without held-out/coverage checks is insufficient | `specified` |
| `PUB-ADAPTER-001` | `adapter_compatibility_profile` | `fss-adapter-registry` | Device-family success never generalizes across firmware/app tuples | `specified` |
| `PUB-EVIDENCE-001` | `evidence_bundle` | `fss-evidence` | Human report and machine manifest publish atomically | `specified` |
| `PUB-DELETE-001` | `deletion_closure` | `fss-privacy` | Deletion success requires alternate-index/cache reachability closure | `specified` |
| `PUB-RELEASE-001` | `release_root` | `fss-release` | Partial target success cannot bless an aggregate release | `specified` |
