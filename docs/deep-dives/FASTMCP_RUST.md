# Deep dive: `fastmcp_rust` as FSS's agent presentation plane

**Document class:** normative import analysis
**Status:** design input, not an implementation claim
**FSS semantic owner:** `fss-mcp`, `fss-api`, `fss-capability`, `fss-obligation`
**Primary source:** <https://github.com/Dicklesworthstone/fastmcp_rust>

## 1. Why this project matters

The easy mistake is to treat MCP as a convenient JSON-RPC wrapper around FSS functions. That would put an agent-shaped aperture directly over camera credentials, raw media, graph expansion, archive deletion, alert channels, and perhaps future PTZ or drone controls. The difficult problem is not exposing methods. It is preserving request ownership, authority narrowing, cancellation, budgets, schema evolution, and honest task completion across a remote agent boundary.

`fastmcp_rust` is useful because it already treats MCP as a cancel-aware, capability-oriented presentation layer built on Asupersync rather than as an ambient web framework. FSS imports that posture but narrows the surface further: MCP is a projection of registered semantic operations; it does not own domain semantics and cannot manufacture authority.

## 2. Mechanism inventory

### 2.1 Request-owned regions

Every MCP request enters a request-owned Asupersync region. That region owns:

- input decoding and limit accounting;
- authorization and capability compilation;
- anchor acquisition;
- query or plan construction;
- any spawned retrieval/model/graph children;
- output shaping and bounded serialization;
- progress notifications;
- cancellation drain and final receipt.

The request may not return while it owns unresolved children. A transport disconnect requests cancellation; it does not detach work.

**FSS invariant:** a vanished client cannot leave an unowned export, model run, graph expansion, archive transfer, alert attempt, or prepared effect behind.

### 2.2 Explicit `McpContext` to `Cx` authority

An MCP handler receives a narrowed context carrying:

- authenticated principal and session identity;
- declared capability set and object/zone scope;
- request deadline and CPU/I/O/model/token budgets;
- evidence anchor and maximum staleness;
- privacy projection and redaction policy;
- schema, adapter, model, calibration, and policy epochs;
- trace/replay identity;
- cancellation reason chain.

The handler cannot recover a process-global administrator context. Rust types remove unavailable operations, while runtime capability masks prevent an ambient service handle from regaining them.

### 2.3 Four-valued outcomes

MCP results preserve the distinction among:

```text
Ok(value)
Err(expected_domain_failure)
Cancelled(reason_and_drain_receipt)
Panicked(forensic_identity)
```

Flattening cancellation into an ordinary error destroys retry semantics. Flattening panic into an application error destroys incident classification. FSS maps each quadrant to a stable protocol error class without erasing the underlying outcome.

### 2.4 Budgets, not one timeout

A request has independent limits for:

- wall-clock deadline;
- ledger reads and bytes;
- graph nodes/edges and algorithm operations;
- search candidates and refinement stages;
- decoded frames/pixels/audio samples;
- model invocations and accelerator time;
- archive bytes and remote operations;
- response bytes, items, and tokens;
- child count and retry count.

A handler may return a useful progressive answer when a refinement budget expires, but it must name the stop reason and cannot claim completeness.

### 2.5 Schema-generated tools with semantic registries above them

Macros and schema generation remove boilerplate, but generated schema is not the semantic authority. Every FSS MCP method also names:

- a stable operation ID;
- required capability IDs;
- read/write/effect class;
- accepted anchor and freshness behavior;
- input/output schema IDs;
- cost-registry row;
- cancellation boundary;
- idempotency rule;
- audit/redaction rule;
- taskability and resume semantics.

The method registry is compared against the CLI and Rust-library registries so the three surfaces do not drift.

### 2.6 Durable tasks are application-owned

Long operations such as archive export, model backfill, calibration solve, twin reconstruction, deletion closure, or retrievability scrub must not be represented by an in-memory MCP task alone. FSS owns durable task identity and state in the authority ledger. MCP exposes task observation and cancellation as a presentation adapter.

A durable task records:

```text
task_id
operation_id
principal_and_capability_digest
basis_anchor
input_root
policy_epochs
state
owned_obligations
last_checkpoint
result_or_failure_root
resume_fence
```

A process restart can resume or reconcile it without relying on the client session.

### 2.7 Bidirectional calls are never assumed

Sampling, elicitation, roots, progress, and cancellation each require independently qualified transport behavior. FSS does not base a correctness-critical workflow on a bidirectional capability merely because the protocol type exists. Unsupported transport profiles fail closed or use a simpler polling/task model.

### 2.8 Secret and taint discipline

MCP output is shaped from explicitly public projections. It never serializes:

- camera passwords, tokens, pairing secrets, or cloud credentials;
- unredacted media outside the principal's scope;
- raw vendor traffic captures by default;
- internal model prompts containing private imagery;
- unrestricted filesystem paths;
- opaque exception strings from foreign devices.

Retrieved manuals, event text, OCR, audio transcripts, and model descriptions retain taint. Text cannot grant capability or alter method routing.

## 3. FSS method families

The initial surface is read-first.

### Observation and status

- `fss.status`
- `fss.device.list`
- `fss.device.inspect`
- `fss.stream.health`
- `fss.coverage.inspect`
- `fss.event.list`
- `fss.event.inspect`
- `fss.timeline.query`
- `fss.explain`

### Derived investigation

- `fss.search`
- `fss.graph.query`
- `fss.track.inspect`
- `fss.association.explain`
- `fss.counterfactual.branch`
- `fss.evidence.pack`

### Prepared effects

- `fss.alert.prepare`
- `fss.export.prepare`
- `fss.retention.prepare`
- `fss.deletion.prepare`
- `fss.model_activation.prepare`
- `fss.calibration_activation.prepare`

Commit methods require a plan digest, fresh witnesses, explicit capability, and idempotency key. Generic shell, SQL, object-store, codec, vendor RPC, PTZ byte command, and drone-control methods are forbidden.

## 4. Progressive, token-economical responses

An agent usually needs the smallest sufficient evidence, not a raw world dump. Responses therefore support:

1. deterministic summary and anchor;
2. high-priority candidate list;
3. compact evidence spans/thumbnails/track excerpts;
4. optional graph/model refinement;
5. explicit continuation cursor rooted in the same generation.

Every stage is independently useful and states whether it is exact, bounded, approximate, provisional, or uncertified.

## 5. Failure modes a superficial import would create

1. **Handler-spawned zombies.** A request returns while model or export children continue.
2. **Transport acceptance equals domain completion.** A JSON-RPC response says an alert/export is complete before observation verifies it.
3. **Cancellation flattening.** A client retries a cancelled effect and duplicates it.
4. **Ambient administrator service.** Any handler can reach every camera or archive object.
5. **Unbounded graph/search response.** A query becomes a memory/CPU/token denial of service.
6. **Schema presence equals conformance.** Generated methods exist without transport lifecycle evidence.
7. **Ephemeral long tasks.** A restart loses calibration/deletion/export state.
8. **Prompt-text authority.** OCR or retrieved documentation changes tool behavior.
9. **One giant escape hatch.** A method exposes arbitrary vendor calls, SQL, or shell execution.
10. **Protocol version optimism.** Advertising a version is mistaken for qualified support.

## 6. Admission evidence

`fastmcp_rust` enters an authoritative FSS path only after:

1. every request child drains under success, error, cancellation, and panic;
2. capability non-escalation is tested statically and dynamically;
3. all input/output limits have adversarial fixtures;
4. cancellation races at decode, dispatch, child spawn, output reserve, and output commit replay deterministically;
5. durable task resume/reconcile works across process death;
6. transport profiles publish exact qualification matrices rather than aggregate support;
7. CLI, library, and MCP semantic registries are mechanically cross-checked;
8. secret/taint redaction tests cover every machine-output path;
9. idempotency and stale-plan refusal are proven for each effect family;
10. malformed framing, duplicate IDs, reordered notifications, slow clients, and output backpressure remain bounded;
11. every error maps to a stable FSS error without leaking sensitive internals;
12. the same end-to-end scenarios pass under real time and Asupersync LabRuntime.

## 7. Final import rule

FSS imports `fastmcp_rust` as a **narrow, request-owned, capability-scoped presentation plane**. MCP remains replaceable because the semantic operation registry, durable task model, authority ledger, and effect protocols live below it. No protocol convenience may widen the physical or privacy authority of the system.
