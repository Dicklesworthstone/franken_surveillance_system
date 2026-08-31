# Operation cost registry

Machine source: `architecture/operation_cost_registry.toml`.

| Cost ID | Unit | Mandatory semantic work | Key variables |
|---|---|---|---|
| `COST-ACQUIRE-001` | encoded segment | receive, time-bound, hash, reserve, stage, publish | bytes, packets, barriers |
| `COST-PROXY-001` | source second | decode/remux, transform, encode, segment, publish | pixels, codec, hardware seconds |
| `COST-ANALYZE-001` | candidate window | quality, gate, detect, track, associate, reason, calibrate, adjudicate | frames, tracks, model calls, GPU seconds |
| `COST-ARCHIVE-001` | published GiB | chunk, encrypt, multipart, child verify, root, retrieval sample | bytes, objects, requests, retrieval |
| `COST-QUERY-001` | agent query | anchor, candidates, projections, fusion, evidence shaping | rows, candidates, tokens, model calls |
| `COST-CALIBRATE-001` | calibration session | ingest, sync, tracks, geometry, optimize, coverage, certificate | cameras, frames, tracks, iterations |

No SLO is accepted until its cost row can derive the denominator and identify all mandatory work.
Provider pricing belongs in dated manifests, not these semantic rows.
