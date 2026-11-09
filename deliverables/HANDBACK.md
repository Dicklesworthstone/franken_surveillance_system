# Camera Liberation Campaign — Operator Handback

## Mission
Root 7 owner-owned cameras (2 Wyze v4, 2 Tapo, 1 Owlet, 1 Yi, 4 AOSU behind 1 HomeBase)
so FSS ingests real footage from real sensors. All owner-authorized, all on our LAN.

## Current State (2026-11-08, hardened 2026-11-09T02:30Z)

### Hardening since the last handback (agent work, no operator action needed)
- **The watcher could not see the new download leg.** `wyze_chain_watch.sh` grepped `forge.log` for a camera IP; through the tunnel cloudflared connects from 127.0.0.1, so a successful flash would have produced *no* proof sweep. The capsule server is now `fw_serve_logged.py`, which records UA/bytes/completion per request to `/tmp/ota/fwserve_access.jsonl`; the watcher triggers on any non-probe GET and proof-captures.
- **Both tunnel legs are KeepAlive LaunchDaemons** (`wyze-capsule-serve`, `wyze-tunnel`). The supervisor re-injects the minted hostname into the broker plist and bootout+bootstraps the broker — `kickstart` alone leaves the proxy holding the previous URL (measured).
- **Readiness grew from 7 to 13 asserts**: A3b (URL must be a `*.trycloudflare.com` host), A3c (that URL serves the exact capsule over verified TLS end-to-end), A8 (the access log actually witnesses requests), A9 (the installer inside the capsule is rendered), A10 (the image plane serves 16 MiB). Each maps to a failure that already cost someone a cycle.
- `forge_ok()` required `--iot-cert` on :8443, which only :443 is ever spawned with — every broker reload killed the healthy 8443 forge, burned 3×15 s of doomed retries and could end with no listener. Fixed to match on our script + live cert material + port.
- **The TFTP plane wedged itself.** The listener was serial and burned 15 s on every client that vanished before ACKing; the liveness probe never ACKs, so a burst of dead probes blocked the only receive loop for minutes and the C660 exfil channel read as dead. Transfers now run on capped workers with 3×0.7 s retries (30-request burst: probe answered in 0.02 s; WRQ verified end-to-end).
- `fleet_status.py` no longer calls a camera ROOTED off any passing proof — vendor `rtsp-enable` is served by the vendor rtspd. Only `telnet9999`/`dropbear22`/`beacon-uid0` upgrade the state, so `.39` reads ARMED with a green rtsp cell.
- **Both Wyze units served RTSP — footage without the flash — until a probe storm wedged them.** `.51` had never been fired: the watcher pinged a hardcoded address tuple containing neither camera. It reads the registry, retires units whose 554 already answers (no iCamera reboot), re-arms them if 554 drops, and never exits; `wyze_rtsp_creds.py` used the `Cam2.login()` path `.51` refuses and now uses `full_login()`. Both units answer authenticated DESCRIBE 200 on `stream0`/`stream1`.
- **The armed capsule was broken twice over.** Unrendered (`HOST=@HOST@` → the installer dies at backup step 2) **and missing the static busybox it checks on line one** (`die "static busybox missing"`). Rebuilt from the runbook command as the canonical shape: `4.52.17.104.tar`, 2,385,920 B, md5 `8ae37e44…`, members busybox+script only — the image arrives over HTTP and is SHA-verified, so the 16 MiB never has to be extracted into the camera's tmpfs. Readiness A9 fails on placeholders, **A11 on a missing/non-executable busybox**, A10 on a broken image plane, A3c derives its expected size from the file.
- **Builds here are arm64-macOS and rch cannot hand those back** (`RCH-E327`); the toolchain `bin/cargo` is itself an rch wrapper. `RCH_CARGO_WRAPPER_BYPASS=1 RCH_CARGO_WRAPPER_ORIGIN=rch <toolchain>/bin/cargo build …` builds locally (40 s for `fss-import-rtsp`). The e2e now has both binaries and its verify gate reports a wedged listener instead of a traceback.
- `root_proof.py` looked for its SSH key at `~/.ssh` which is `/var/root` under launchd — now falls back to the repo owner's key (verified as root). `plist_doctor.sh` crashed while printing findings (f-string backslashes on system python) — fixed, so findings are visible. The duplicate GUI agent for the RTSP watcher was retired to a `.retired` suffix; the label had been loaded in both domains.

### What WORKS right now
- 18/18 fleet planes green (broker, forge 443+8443, backups, tftp, pf, doctor, no duplicates, rtsp-watch + 8 watcher jobs)
- Fleet self-heals every 15 min via `com.jeffreyemanuel.fleet-readiness` LaunchDaemon
- **Every lane watcher is a gate plane** (c460 fire/burst, c660 sweep/tftp/convert, owlet relay, yi listener, wyze rtsp). Four of them used to be unsupervised nohup children; a dead watcher now fails the gate instead of being noticed days later
- Chain-watch daemon auto-captures root proof when the Wyze OTA completes
- Wyze cameras CONNECTed to OUR broker (636+ connects), PUBACKing our deltas
- **RTSP worked and is machine-proven once**: `.51` gave 150 decoded frames in 10 s on `stream1` (640×360) and a 2560×1440 grab on `stream0` — `root_proof.py rtsp-capture` PASS, no flash, no cloud. Both servers are now wedged (TCP accepts, nothing answers) after a DESCRIBE storm; a port check lies, so `wyze_rtsp_one_shot.py` requires a real OPTIONS round-trip and re-fires with an execution beacon. **The power-cycle clears it.**
- C660 re-provisioned via Tapo app, live at 192.168.5.76 (en0)
- 7 beads closed on hard evidence

### What's BLOCKED and what unblocks it

| Camera | Blocker | Unblock action | Who |
|---|---|---|---|
| **Wyze .39/.51** | **The OTA downloads but never installs.** `.51` pulled `.100` (02:54Z) and `.101` (05:52Z) complete — then nothing: no backup stream, no shell, no beacon. The upgrade handler lives in **iCamera**, and iCamera is the thing that is wedged (DTLS login and `0x29e8` still answer; `exec_shell_sync` and rtspd do not). `.39` is wedged the same way. | **Power-cycle `.39` and `.51`** — it is now the *only* thing that revives iCamera, which is what has to run the installer. The capsule is armed in the canonical shape with a stage beacon on every step | Operator (5 sec) |
| **Tapo C660** | Carrier only: ROP verified, DS gate armed, **image built + verified** | **walk past it**; the fire lands telnetd, then `tapo_flash_chain.sh <ip> c660` | Operator (walk-by) |
| **Tapo C460** | Carrier only: the borrowed offset is scanned (`1024…1536`, 4-byte steps, persistent cursor, DS-gated, 16 shots per wake) | **walk past it**; on a shell `tapo_flash_chain.sh <ip> c460` runs dumps→verify→write. UART only if the scan never lands | Operator (walk-by) |
| **Owlet .163** | Vendor 0x2041 grant never fires outside the app. H3/H4/H5 closed-negative. The en1 pcap can't see phone↔camera unicast | **Open the Owlet app's live view** while capturing from the ROUTER (not en1 — the AP forwards unicast only to the target MAC) | Operator + router capture |
| **Yi .20** | SSID injection payload ready, listener alive 3+ days on :4444. Camera must scan during setup and hear the payload SSID | **macOS Internet Sharing** (System Settings → Sharing) with the payload SSID, or a standalone travel router broadcasting the payload SSID | Operator (the one disruptive step) |
| **AOSU ×4** | `ILLEGAL_CLIENT_ID` — now proven **not** IP-related: a fresh Contabo egress still refuses, so the burn is on the app_id/cert. Unit located at `.126` (0x23 broadcast) | **New Tuya app registration** — unavoidable; a fresh IoT account yields app_id/secret → `local_key` → LAN OTA | Operator (web browser) |

## The ONE Action That Changes Everything

**Power-cycle .39 and .51 again.** Two earlier power-cycles fired into the void; both
causes are fixed, plus a third that would have burned a third:

1. the delta went to `wyze-secure` but the rewrite only handled `wyze-service` — FIXED;
2. the OTA URL used the forged eMudhra chain the downloader rejects — FIXED (LE-cert
   tunnel, and A3b fails the gate if the s3 origin ever comes back);
3. **the served capsule was unrendered** — `HOST=@HOST@` inside `upgraderun.sh`, so the
   download would have succeeded and the installer would have died at backup step 2.
   Rebuilt rendered *with the static busybox* (`4.52.17.101.tar`, md5 `ba76c2c1…`); A9/A11/A10 now assert it.

Both cameras are wedged in iCamera: delta injections are PUBACKed but nothing acts on
them, and the upgrade handler lives there. The power-cycle restores RTSP and the OTA path
at once; the watcher re-fires the config frame within minutes of boot and retries every
180 s. The armed installer beacons every stage to `/tmp/fss_beacons.log` (`stage=`), so the
next attempt names the line that dies instead of ending in silence. The flash is what removes the vendor
cloud, the MITM and the assis dependency for good.

Watch it land:

```
tail -f /tmp/ota/fwserve_access.jsonl   # camera GET = non-"fss-probe" UA, complete:true
tail -f /tmp/wyze_chain_watch.log       # "*** CAMERA REACHED THE CAPSULE ***"
tail -f /tmp/fss_beacons.log            # via=rtsp-enable = frame EXECUTED
                                        # (K10003 is only the login ack)
```

The chain watcher runs the proof sweep by itself and writes
`deliverables/proofs/LEDGER.md`. If the OTA does not fire, `root_proof.py <ip>
rtsp-capture` is the check that footage flows again.

Current URL (minted by the supervised tunnel, re-injected into the broker on every start):

```
https://donations-procedure-parameter-blond.trycloudflare.com/4.52.17.104.tar
```

Read it live, never from this doc. `wyze_flash_readiness.sh` must be 13/13 (exit 0)
immediately before a power-cycle.

**After the flash: thingino gives SSH + RTSP + ONVIF. No vendor cloud needed. No MITM needed.
The camera becomes a standard ONVIF device that FSS ingests from directly.**

## Infrastructure (all committed and running)

| Tool | Purpose | Status |
|---|---|---|
| `fleet_status.py --gate` | One-command fleet health | ✅ 18/18 planes |
| `fleet_reconcile.py --execute` | Auto-heal drift (runs every 15 min via launchd) | ✅ self-healing |
| `root_proof.py` | Machine-checkable root evidence | ✅ 25 proof artifacts (fresh .39 rtsp-enable PASS 2026-11-09) |
| `wait_ledger.py` | Negative-evidence for all armed waits | ✅ 3 open / 13 closed (1 cancelled as superseded) |
| `plist_doctor.sh` | Launchd plist validation | ✅ 0 findings / 28 plists |
| `wyze_flash_readiness.sh` | 11 hard asserts before power-cycle (incl. tunnel TLS + access-log witness) | ✅ 11/11 green |
| `wyze_chain_watch.sh` | Auto-capture root proof on a camera GET (UA-witnessed via the access log) | ✅ running (LaunchDaemon) |
| `fw_serve_logged.py` | Capsule server that records UA/bytes/completeness per request | ✅ LaunchDaemon `wyze-capsule-serve` |
| `wyze_tunnel_supervise.sh` | Mints the tunnel, re-injects the URL into the broker plist, reloads it | ✅ LaunchDaemon `wyze-tunnel` |
| `c660_sweep_watch.sh` | C660 ROP with DS-readiness gate | ✅ running |
| `sweeper_telemetry.py` | C460 wake/fire classification | ✅ 12.6k events imported |
| `registry.py` | Camera identity single-source | ✅ 7 cameras registered |
| `test_tuya_sign.py` | Tuya signer golden vectors | ✅ byte-exact |
| `e2e_capture_continuity.sh` | Gap/continuity contract test | ✅ C1+C2 passing |

## Key Files
- `deliverables/fleet/registry.yaml` — camera identity truth
- `deliverables/fleet/CURRENT-WAITS.md` — live wait ledger
- `deliverables/proofs/LEDGER.md` — root proof ledger
- `docs/exploit/tapo.md` — Tapo exploitation (C460 §C3, C660 §BCL1)
- `docs/exploit/ota-path.md` — Wyze OTA protocol RE
- `docs/exploit/tuya-fresh-registration-runbook.md` — AOSU Tuya recovery
- `docs/exploit/owlet-h1-frida-runbook.md` — Owlet H1 (Frida + pcap paths)
- `DUELING_WIZARDS_REPORT.md` — multi-model adversarial plan review
- `FLEET_LIBERATION_STATUS.md` — the master liberation doc

## Trycloudflare Tunnel (supervised, but still quick-tunnel)

```
URL:       /usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:OTA_URL' \
             /Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist
Local HTTP :9443 → /tmp/fwserve/wuv2/upgrade/HL_CAM4/firmware/  (fw_serve_logged.py)
Access log :/tmp/ota/fwserve_access.jsonl  (UA + bytes + completed flag per request)
Reload     :launchctl kickstart -k system/com.jeffreyemanuel.wyze-tunnel
```

Both legs are KeepAlive LaunchDaemons. On every start the supervisor mints a new
hostname, writes it into the broker plist, **bootout+bootstrap**s the broker (kickstart
alone does not re-read a plist — the proxy would return with the previous URL) and then
waits on cloudflared so a crash loops back through a fresh injection.

An s3-us-west-2 URL in the plist is always a regression: that origin serves the forged
eMudhra chain the OTA downloader rejects. A3b fails the gate on it.

## Flash kit (both Tapo units, image verified)

Nothing to fetch or build — it is on disk and pinned:

```
~/fss-exploit/fw/{uImage,rootfs.squashfs}.{ssc30kq,nt98567}   # md5s pinned in the chain
deliverables/scripts/tapo_flash_chain.sh <ip> c460|c660       # dumps → verify → write → reboot
```

The chain dumps **all 13 partitions** first (receiver 444-459), checks the image md5 *on the
camera*, writes rootfs then kernel, sets `bootargs`, reads back, reboots. `--dry-run` validates
the profile without a camera. Rollback is writing `/tmp/fwbackup/mtdN.bin` back.

Gate planes that guard it: `images:tapo` (files match the chain's pins), `forge:443/8443`
(a real response, not just a socket), `watch:*` (every lane watcher alive).
