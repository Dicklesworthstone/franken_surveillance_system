# Deep dive: `asupersync` as the execution, authority, evidence, and transfer substrate

**Document class:** normative source-to-design audit
**FSS integration gate:** `INT-AS-001`
**Status:** design import; no runtime readiness claim
**Audit basis:** repository architecture, v4 design bible, ATP architecture and DoD, adaptive RaptorQ design, deterministic-lab and evidence surfaces inspected 2026-08-31

## 1. Why this project is load-bearing

The superficial import would be “use Asupersync instead of Tokio.” That would miss almost all of the value. The load-bearing idea is that execution, cancellation, authority, partial effects, evidence, and transfer all share one explicit semantic model:

```text
owned work
+ context-carried authority and budgets
+ request -> drain -> finalize cancellation
+ reserve -> commit effects
+ tracked obligations
+ deterministic schedules and virtual time
+ proof-carrying transfer receipts
= concurrency that can be reasoned about after failure
```

For FSS, this is not an ergonomic preference. A property may have dozens of continuous streams, multiple decode and inference rates, remote archives, live viewers, agent queries, and alerts. The system must remain correct when any one of those is cancelled, delayed, duplicated, corrupted, restarted, or partitioned.

## 2. Mechanism inventory and exact FSS transplants

### 2.1 Region ownership is the lifecycle topology

Every unit of work has one owner. FSS adopts a region tree rather than a collection of services with detached loops:

```text
process-region
├── authority-region
│   ├── ledger-publication
│   ├── policy-registry
│   ├── identity-registry
│   └── evidence-sealer
├── property-region
│   ├── clock-authority
│   ├── coverage-authority
│   ├── archive-supervisor
│   ├── graph/search projectors
│   ├── agent-session regions
│   └── sensor-region*
│       ├── adapter-session
│       ├── packet-receive-pump
│       ├── continuity-monitor
│       ├── source-spool
│       ├── media-stage regions
│       ├── cognition-stage regions
│       └── publication obligations
└── effect-region
    ├── alert-coordinator
    ├── camera-control coordinator
    ├── export/deletion coordinator
    └── reconciliation workers
```

A region cannot report terminal closure while a child still owns a packet, file descriptor, credential lease, model job, archive multipart upload, notification attempt, or unsealed evidence record. Region closure emits a drain receipt naming all completed, cancelled, failed, panicked, and indeterminate children.

### 2.2 `Cx` is not a cancellation token; it is attenuated authority

Every operation that can block, allocate shared capacity, touch a device, publish state, call a model, move an object, or create child work accepts an explicit context. FSS extends the context with domain epochs and scopes:

```text
principal_id
property_id / privacy_domain
request_id / trace_id / replay_id
observation_anchor
sensor and object scopes
capability mask
policy / adapter / model / calibration / schema epochs
deadline and capture-time deadline
poll / CPU / memory / decoded-pixel / network / disk / model-token budgets
alert and external-effect budget
cancellation state and reason chain
pressure vector
```

Authority is narrowed twice. Rust types remove impossible operations from an interface; runtime capability masks and object scopes prevent a component from recovering broader authority through ambient service references. A detector cannot open the credential store. A query worker cannot create an alert coordinator. A model executor cannot choose its own network destination.

### 2.3 Budgets form a compositional resource contract

FSS imports the budget-combination doctrine rather than scattering timeouts and semaphore limits. Child budgets are monotone attenuations of parent budgets. The budget vector includes dimensions that conventional runtimes leave implicit:

- wall-clock and event-latency deadline;
- scheduler polls and cooperative checkpoints;
- CPU work units and SIMD tiles;
- decoded pixels and audio samples;
- resident, pinned, and staged bytes;
- network ingress, egress, and retransmission bytes;
- object-store operations and estimated dollar cost;
- model invocations, tokens, layers, or temporal windows;
- external effects and retries;
- privacy-sensitive materializations.

No subsystem may “recover” from exhaustion by silently switching to an unadmitted path. Degradation follows a registered ladder and emits a receipt.

### 2.4 Four-valued outcomes prevent epistemic flattening

FSS retains the `Ok / Err / Cancelled / Panicked` quadrant at every asynchronous boundary. Domain state adds `Indeterminate` where an external effect or device operation may have occurred but cannot yet be proven. `Indeterminate` belongs in the durable operation state machine, not as a fifth Rust exception accidentally caught by generic retry logic.

Examples:

- `Cancelled`: a model job observed cancellation before publishing output and drained cleanly.
- `Err`: an RTSP server rejected authentication before stream establishment.
- `Panicked`: an internal invariant failed; the worker is quarantined and the panic evidence retained.
- `Indeterminate`: a push notification request crossed the provider boundary, then the connection died before a receipt.

The severity lattice determines default aggregation, but domain policy may not convert a more severe state into a less severe one.

### 2.5 Cancellation is request, drain, and finalization

Dropping futures is forbidden as a shutdown protocol. Each long-running FSS subsystem declares:

1. admission-close behavior;
2. its safe cancellation checkpoints;
3. work that is temporarily masked;
4. obligations that must drain;
5. a nonnegative drain potential;
6. escalation and indeterminacy behavior;
7. finalization evidence.

Representative potential functions:

```text
camera drain potential = queued packets + owned frame buffers + staged capsules + in-flight model windows
archive drain potential = unsealed children + unverified remote parts + resumable journal entries
alert drain potential = undispatched intents + transmitted-unreconciled attempts + unsealed receipts
model drain potential = admitted jobs + active kernels + unpublished outputs + pinned input views
property drain potential = live child regions + active leases + unresolved effects + unsealed roots
```

Progress certificates sample the potential, active regime, expected descent, rebounds, and the reason safe quiescence can or cannot be guaranteed. A timeout is evidence about elapsed time; it is not proof that an effect did not occur.

### 2.6 Reserve/commit and linear obligations protect partial effects

FSS imports two-phase operations wherever cancellation between “started” and “visible” could lose or duplicate work:

- channel sends;
- packet and frame buffer admission;
- ledger sequence allocation;
- evidence-root publication;
- model output publication;
- alert dispatch;
- camera controls;
- archive multipart publication;
- retention and deletion;
- model, adapter, calibration, and policy activation.

The reserve step fixes identity, authority, budget, preconditions, generation, and destination. Commit is a short bounded section that makes the effect visible or dispatches it. Dropping a reservation has explicit abort semantics. Committed obligations remain tracked until terminal proof or durable indeterminacy.

### 2.7 Deterministic laboratory execution is inherited by every boundary

All time, sleeps, retry schedules, jitter, queue selection, leases, deadlines, fault decisions, and scheduler handoffs must be supplied through the runtime abstraction. The laboratory explores:

- cancellation at each registered yield point;
- packet loss, duplication, corruption, delay, and reorder;
- camera disconnect and reconnect at every acquisition transition;
- source-clock steps, drift, wraparound, and contradictory timestamps;
- process death at every reserve/materialize/publish barrier;
- alert lost-ACK and duplicate-callback schedules;
- simultaneous agents preparing overlapping effects;
- archive path failure during chunk, repair, verify, or root publication;
- model crash, OOM, malformed result, and generation rollover;
- restore while stale readers, prepared effects, and derived generations remain alive.

The same semantic scenario must run under production scheduling and LabRuntime. Production-only timers, threads, or hidden randomness are verification escape hatches.

### 2.8 Trace equivalence and canonical replay reduce schedule noise

Asupersync’s Mazurkiewicz-trace and Foata-normal-form work suggests a stronger FSS replay contract. The replay engine records observable dependency labels, not merely one brittle total ordering. Independent actions may commute; dependent actions may not. FSS canonicalizes equivalent schedules into stable parallel layers and records:

```text
trace_class_fingerprint
canonical_schedule_digest
switch_count
independence_policy_epoch
happens-before edges
resource/effect conflicts
```

This matters for multi-camera ingestion: packets from independent cameras may interleave arbitrarily without changing semantics, while two publications to the same event lineage or archive root are dependent. Canonicalization keeps regression diffs human-readable and lets schedule exploration focus on distinct races.

### 2.9 ATP is an immutable object-graph plane, not generic RPC

FSS imports ATP for movement of immutable graphs:

- source-media capsule graphs;
- archive manifests and chunks;
- replay/crashpack bundles;
- model and calibration generations;
- digital-twin geometry and coverage generations;
- graph/search generations;
- qualification corpora and proof bundles;
- read-replica deltas.

An ATP root names a manifest; manifests name typed children; children name chunks and optional repair symbols. The receiver stages bytes, verifies identities, verifies graph closure, records a resumable journal, and publishes the root last. Path candidates may race, but losing paths drain. Post-repair plaintext identity is authoritative; successful erasure decoding is not sufficient by itself.

ATP is explicitly not the transport for non-idempotent camera control, alerts, deletion, or drone effects. Those need request identity, fencing, lookup, reconciliation, and domain-specific terminal predicates.

### 2.10 Transfer receipts become economic and forensic evidence

Every transfer receipt records more than byte count:

- source/destination and capability identity;
- immutable root and graph closure result;
- path set, chosen path, and hedged paths;
- chunk/FEC parameters and repair usage;
- bytes read/sent/retransmitted/staged/discarded;
- resume point and journal identity;
- checksum and post-repair verification;
- queue, CPU, memory, disk, and network pressure;
- object-store request counts and estimated cost;
- cancellation and drain evidence;
- exact reproduction command and implementation identity.

This makes archive strategy auditable and lets FSS distinguish “provider accepted bytes” from “the evidence graph is remotely retrievable.”

### 2.11 Adaptive transfer and scheduling are bounded decisions

The Transfer Brain and adaptive-RaptorQ work contributes a general rule: adaptation selects among safe registered arms; it never defines safety. FSS may adapt:

- chunk size and transfer concurrency;
- path hedging;
- repair-symbol overhead;
- live-preview frame rate;
- model routing and candidate budgets;
- buffer-pool targets;
- archive object sizing;
- witness-refinement effort.

Each adaptive decision has a decision card, safe baseline, clamps, shadow panel, common-random-number evaluation, regime boundaries, minimum evidence, rollback, and negative-evidence record. “The learned policy chose it” is not an explanation.

### 2.12 Capability tokens are suitable for relay and worker isolation

FSS adopts narrow capability tokens for worker and relay operations. A token binds:

```text
actions
destination or object prefix
methods / operation families
byte and cost ceiling
expiry and nonce
required checksums / roots
privacy class
principal and issuing policy epoch
```

Tokens are verified before expensive state allocation. Anti-replay state is bounded and domain-scoped. A model-executor token cannot be repurposed as an archive-upload token; an archive token cannot read arbitrary objects.

### 2.13 Evidence and decision registries are first-class runtime products

The `franken_decision`, `franken_evidence`, and qualification ideas are imported as a cross-cutting substrate. Every optimization, adaptive policy, compatibility promotion, and readiness claim names:

- decision identity and allowed arms;
- invariant owner;
- reference model;
- evidence schema;
- validity and expiry;
- environment and generation tuple;
- positive and negative evidence;
- rollback and revival conditions.

Metrics are not allowed to mutate answers. Missing optional telemetry may reduce confidence in a performance claim; it cannot change the selected event, graph path, or effect outcome.

## 3. FSS semantic owners

| Imported mechanism | Owning FSS component | Replacement prohibition |
|---|---|---|
| Regions, `Cx`, budgets, outcomes | `fss-runtime` | No second async runtime or detached worker model |
| Two-phase channels/effects | `fss-runtime`, `fss-effect` | No “send then hope” mutation path |
| Obligations and leases | `fss-obligation`, `fss-effect` | No untracked committed external work |
| LabRuntime and trace canonicalization | `fss-lab` | No production-only time/randomness path |
| ATP object graphs | `fss-transfer` | No ad hoc multipart uploader as authoritative transfer |
| Adaptive decision cards | `fss-decision` | No opaque online threshold mutation |
| Evidence receipts | `fss-evidence` | No log-line-only readiness claims |

## 4. Superficial imitations that would fail

1. Passing `&Cx` through APIs while adapters recover global credentials or clocks.
2. Using regions for tasks but spawning codec or vendor subprocesses outside ownership.
3. Cancelling by dropping queues and losing which packets/effects were committed.
4. Treating ATP as an RPC bus and sending alert or PTZ commands over eventual delivery.
5. Recording transfer throughput without graph closure or retrievability.
6. Adding FEC without post-repair content verification.
7. Using a learned scheduler before a deterministic safe baseline exists.
8. Running deterministic unit tests while production uses separate timers, random jitter, or native threads.
9. Reporting timeout as cancellation even when a provider or device effect may have happened.
10. Treating telemetry failure as permission to skip safety checks.

## 5. Admission evidence for `INT-AS-001`

Asupersync becomes load-bearing only after all of the following pass:

1. One complete property lifecycle runs under real and laboratory time with identical semantic roots.
2. Region close proves no owned task, descriptor, subprocess, buffer lease, credential lease, or effect obligation survives.
3. Cancellation campaigns cover every registered yield/publication barrier and preserve reason chains.
4. Drain certificates are produced for stream, archive, model, and effect regions; forced termination yields explicit indeterminacy.
5. Authority attenuation is tested statically and dynamically against attempted scope recovery.
6. Two-phase channel and publication paths survive cancellation before reserve, after reserve, during materialization, and after commit.
7. ATP corruption, truncation, reordering, duplicate chunks, path loss, resume, FEC repair, and root-last publication preserve object identity.
8. Relay tokens reject wrong destination, method, root, expiry, nonce, privacy class, and byte ceiling.
9. Adaptive policies cannot select an unregistered arm or cross hard clamps; shadow/revert behavior is deterministic.
10. Schedule-class replay and canonicalization remain stable across repeated runs and expose real dependency changes.
11. Same-binary A/A experiments show the evidence instrumentation does not change semantic outputs.
12. A negative-evidence bundle documents unsupported/noncooperative host-boundary behavior.

## 6. Deliberately rejected imports

- Making pure geometry, parsing, score calibration, or media kernels async merely for consistency.
- Claiming bounded cancellation for noncooperative vendor or operating-system calls without an isolation boundary.
- Using distributed “exactly once” terminology. FSS uses identity, idempotency, leases, receipts, and reconciliation.
- Allowing adaptive pressure control to weaken freshness, coverage, privacy, or evidence requirements.
- Treating ATP repair success as source truth before post-repair digest and graph-closure verification.

## 7. Resulting architectural leap

The deepest import is not a runtime API. It is the ability to make every long-lived FSS operation answer four questions precisely:

1. **Who owns this work?**
2. **What authority and budget does it possess?**
3. **What partial effects or obligations can exist if it stops now?**
4. **What retained evidence proves its terminal state?**

Without those answers, a surveillance system is a pile of best-effort loops. With them, it becomes an inspectable, replayable control plane.
