# Operation cost registry

Machine source: `architecture/operation_cost_registry.toml`.

| Cost ID | Unit | Mandatory semantic work | Key variables |
|---|---|---|---|
| `COST-ACQUIRE-001` | segment | adapter receive, timestamp bound, packet index, content digest, ledger reserve, object stage, root publish | source bytes, packet count, loss reorder, durability barriers |
| `COST-RTSP-001` | stream second | session keepalive, packet receive, rtcp update, continuity accounting, bounded buffer | packets, jitter, loss, auth refresh |
| `COST-PARSE-001` | access unit | framing, parameter epoch, syntax parse, bounds validate, index publish | bytes, nal or obu count, syntax depth |
| `COST-DECODE-001` | megapixel frame | reference resolve, entropy decode, inverse transform, prediction, reconstruction, color output | codec profile, bit depth, pixels, reference count |
| `COST-PROXY-001` | source second | remux or decode, scale, encode, segment, publish | decoded pixels, encoded pixels, codec generation, cpu or accelerator seconds |
| `COST-QUALITY-001` | frame | health features, blur exposure occlusion, tamper state, receipt | pixels, history window |
| `COST-DETECT-001` | candidate batch | preprocess, model execute, postprocess, publish result | pixels, batch, model generation, kernel plan |
| `COST-TRACK-001` | frame track set | predict, gate, assign, update, retire, publish delta | active tracks, detections, assignment edges |
| `COST-ASSOC-001` | association window | transition candidates, feature compare, temporal gate, k best assign, publish hypotheses | tracklets, candidate edges, k, graph size |
| `COST-ANALYZE-001` | candidate window | quality gate, motion gate, detect, track, associate, temporal reason, independent verify, calibrate, adjudicate | frames, pixels, active tracks, model invocations, cpu or accelerator seconds |
| `COST-GRAPH-001` | algorithm run | pin projection, authorize projection, execute reference or optimized, emit witness, shape output | n, m, algorithm operations, output size |
| `COST-SEARCH-001` | query | pin generation, exact filter, lexical candidates, graph expand, semantic refine, score ledger, shape output | documents, candidate count, graph edges, model calls, tokens |
| `COST-EVENT-001` | event revision | collect witnesses, revalidate, policy evaluate, reserve, publish, notify | evidence edges, negative domains, policy rules |
| `COST-ALERT-001` | alert attempt | prepare, idempotency reserve, dispatch, observe receipt, retry or reconcile, verify | channels, payload bytes, retry count |
| `COST-ARCHIVE-001` | published gibibyte | chunk, encrypt, repair encode, remote stage, verify children, publish root, retrievability sample | bytes, objects, repair ratio, put head operations, egress, retrieval |
| `COST-ATP-001` | transferred gibibyte | plan, manifest verify, fetch, repair if needed, object verify, closure verify, root publish | bytes, objects, paths, loss, repair symbols |
| `COST-RETRIEVE-001` | challenge | select samples, remote range get, verify, record, schedule repair | sample bytes, objects, providers, latency |
| `COST-DELETE-001` | deletion plan | authorize, enumerate reachability, delete children, verify absence, publish tombstone | reachable objects, providers, indexes, replicas |
| `COST-CALIBRATE-001` | calibration session | ingest, synchronize, feature track, geometry infer, bundle adjust, covariance, coverage compute, certificate publish | frames, camera count, track count, optimizer iterations |
| `COST-TWIN-001` | mapping session | select frames, pose estimate, depth or gaussian reconstruct, fuse, quality check, publish | frames, pixels, points or gaussians, iterations |
| `COST-MODEL-IMPORT-001` | model generation | verify source, lower ir, canonicalize tensors, static analyze, oracle compare, quality eval, repair encode, publish | operators, tensor bytes, corpus examples, oracle runs |
| `COST-QUERY-001` | query | anchor, structured filter, search, graph projection, fusion, memory pack, evidence shape | rows, candidates, graph operations, tokens, model calls |
| `COST-CHECKPOINT-001` | checkpoint | freeze anchor, materialize state, seal replay tail, verify, publish root | state bytes, delta count, indexes |
| `COST-RELEASE-001` | release matrix | clean snapshot, resolve sibling closure, run lanes, build targets, package, sign, upload, download verify, publish root | targets, lanes, test time, artifact bytes |

No SLO is accepted until its cost row can derive the denominator and identify all mandatory work. Provider pricing belongs in dated manifests, not these semantic rows.
