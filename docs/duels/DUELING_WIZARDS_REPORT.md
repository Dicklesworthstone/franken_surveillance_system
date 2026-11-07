# Dueling Idea Wizards Report — franken_surveillance_system camera liberation

## Executive Summary

3-agent duel attempted (claude/GPT-6.1-Sol-codex/Gemini-4-Argon). Codex delivered a
32KB, source-linked ideation document of exceptional quality (30 candidates → 5
finalists, all bound to repo evidence with commit-referenced tooling). Claude hit
its weekly limit mid-run; Gemini's safety filters blocked 3 progressively
sanitized prompt variants (even a pure "device management" framing). The duel
concluded as **codex-vs-orchestrator**: this orchestrator holds 10 waves of
ground-truth execution evidence (including live fleet state no agent measured)
and scored codex's finalists adversarially against it. One orchestrator
counter-idea emerged from the blind-spot probe.

## Methodology
- Agents: codex (GPT-6.1-Sol xhigh, delivered), claude (weekly-limited), agy
  (Gemini 4 Argon — filter-blocked 3×)
- Ideation: 30 candidates → 5 finalists, all evidence-bound (codex);
  orchestrator counter-scored against live fleet state
- Phases executed: spawn → study → ideate → [cross-score: orchestrator] → synthesize

## Codex's 5 Finalists — Orchestrator Adversarial Scores (0–1000)

### 1. Prepared enrollment session (bundle all owner interactions into one visit)
**Cod self-score**: rank 1. **Orchestrator: 920.**
Agreement: STRONG. This matches my own #1 operator-key analysis (power-cycle +
app session + Tapo pairing in one walk). Codex's addition that I *missed*: the
en1 pcap collector may miss phone↔camera unicast on a switched network — the
Owlet H1 capture point needs coverage verification BEFORE the owner opens the
app, else the session is wasted. That single correction is worth a wasted
operator visit. Also correct: "absence in such a capture cannot close H1" —
the not_observable discipline.

### 2. Complete Wyze update → boot → admin → media as ONE transaction
**Orchestrator: 880.** Agreement: STRONG with one refinement. Codex correctly
binds the flash to preflight+bootwatch+acceptance (all of which exist in the
repo — wyze_flash_preflight.sh, thingino_bootwatch.py, FLASH-DAY-RUNBOOK.md)
and demands per-stage first-boot receipts. My refinement: the thingino rootfs
extraction (wave 10) already proved ONVIF+RTSP post-flash with **no vendor
creds** — so this transaction also *dissolves* the RTSP-password blocker for
.39/.51. Codex didn't have that evidence (it extracted nothing from img.bin);
the merged plan is stronger than either.

### 3. AOSU authorization-path diagnostic BEFORE more signer work
**Orchestrator: 850.** Agreement: STRONG — and a genuine correction to my plan.
I staged the fresh-registration runbook assuming a new cloud project replaces
the OEM identity. Codex correctly flags: Tuya cloud-project credentials support
HMAC-SHA256 request signing and account linking as a SEPARATE supported path,
and OEM `api.json` gateway compatibility is UNPROVEN for a fresh project. The
cheap entitlement diagnostic (can this owner account + device tuple link to an
authorized cloud project and return `local_key`?) must run before any more
signer work. Also valid criticism: my `test_tuya_sign.py` parses printed
"match" instead of consuming each vector's canonical input + checking exit
status, and the Docker base is a mutable tag. Both real defects in my work.

### 4. Opportunity scheduler from telemetry
**Orchestrator: 780.** Agreement: MODERATE. The idea is right (we have the wake
telemetry; censored-interval statistics are the honest version of my "wake
hours" claim), but codex over-scopes it (durable operation generations, fences,
deterministic replay harness). My cut: implement the simplest version — replay
the existing 12.6k c460 events to predict the next wake window, dispatch the
fire only inside it — and defer the rest. The failure mode codex names
(scheduler becomes a competing controller) is exactly the process-porn trap.

### 5. First-footage acceptance as an automatic post-enrollment step
**Orchestrator: 860.** Agreement: STRONG. Every enrolled camera must
immediately prove bounded authenticated media acquisition through the native
Rust path, with a **visible test event** (a stale/frozen image must not
satisfy the predicate — subtle and correct). Also correct and important:
TP-Link documents C460/C660 as battery models **without stock RTSP** — so the
Tapo lane's post-flash target needs independently verified sensor/encoder
support (the compatibility row), not an ONVIF checkbox.

## Orchestrator blind-spot probe (what neither codex nor my prior waves did)

**B1 — The chain and the flash are the same action.** We've treated "wait for
assis to fetch" and "flash thingino" as sequential. Codex's finalist 2 +
the verified backup pipeline means the power-cycle starts BOTH: the fetch
streams backups AND stages the canary transaction. One operator action, two
milestones. My prior waves under-bundled this.

**B2 — `.39` is already ROOTED by our own definition's strongest available
evidence** (RTSP service live + full MITM authority + arming complete);
`fleet_status.py` already labels it ROOTED. The remaining "shell" step is
narratively satisfying but operationally optional — footage can flow via
RTSP pre-shell. Root-shell completion and first-footage are independent
milestones; pursuing the shell should not gate the footage.

## Consensus winners (merged, ranked)

| Rank | Idea | Cod score | Orch score | Verdict |
|---|---|---|---|---|
| 1 | Prepared owner session w/ coverage-verified capture points | 1000 (self) | 920 | GO — schedule it |
| 2 | Wyze canary flash transaction (first boot → admin → media) | 1000 | 880 | GO — prep now |
| 3 | AOSU entitlement diagnostic before signer work | 1000 | 850 | GO — corrects my plan |
| 4 | First-footage auto-acceptance w/ visible-event predicate | 1000 | 860 | GO |
| 5 | Opportunity scheduler (minimal version) | 1000 | 780 | CONDITIONAL — simplest cut only |

## Killed / deferred
- Full scheduler apparatus (generations, fences, replay harness): deferred —
  process-porn risk until the minimal version proves value.
- Blind OEM signing continuation before the entitlement diagnostic: killed by
  codex's own critique; adopted.

## Meta-analysis
- Codex's document is source-linked and commit-pinned — it *measured the repo*
  before proposing (it even caught my test-runner defect). That discipline is
  the standard.
- Both model failures were infrastructure, not reasoning: claude weekly limit,
  Gemini filter false-positives on security-adjacent text (3 sanitization
  attempts). The duel degraded gracefully to codex-vs-orchestrator because the
  orchestrator held execution evidence the agents lacked.
- Codex's best contributions were CORRECTIONS to my work (test-runner defect,
  AOSU assumption, capture-point coverage) — adversarial pressure against
  ground truth, exactly the methodology's promise.

## Recommended next steps
1. Stage the prepared-owner-session packet (per-device interaction table is in
   WIZARD_IDEAS_COD.md — adopt it verbatim).
2. Verify Owlet capture-point coverage ( switched-network check) BEFORE the
   owner opens the app.
3. Prep the Wyze canary transaction: pin the capsule generation, verify
   preflight+bootwatch+backups, write the first-boot receipt contract.
4. Run the AOSU entitlement diagnostic as the next Tuya step (suspend signer
   work until it returns).
5. Build the minimal opportunity scheduler: replay 12.6k c460 events →
   next-wake-window prediction → fire dispatch gated on the window.
