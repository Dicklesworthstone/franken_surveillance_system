# Camera Liberation Campaign — Operator Handback

## Mission
Root 7 owner-owned cameras (2 Wyze v4, 2 Tapo, 1 Owlet, 1 Yi, 4 AOSU behind 1 HomeBase)
so FSS ingests real footage from real sensors. All owner-authorized, all on our LAN.

## Current State (2026-11-08)

### What WORKS right now
- 8/8 fleet planes green (broker, forge 443+8443, backups, tftp, pf, doctor, no duplicates)
- Fleet self-heals every 15 min via `com.jeffreyemanuel.fleet-readiness` LaunchDaemon
- Chain-watch daemon auto-captures root proof when the Wyze OTA completes
- Wyze cameras CONNECTed to OUR broker (636+ connects), PUBACKing our deltas
- C660 re-provisioned via Tapo app, live at 192.168.5.76 (en0)
- 7 beads closed on hard evidence

### What's BLOCKED and what unblocks it

| Camera | Blocker | Unblock action | Who |
|---|---|---|---|
| **Wyze .39/.51** | assis hasn't pulled the capsule. Delta now carries the trycloudflare tunnel URL with a VALID Let's Encrypt cert (the forged eMudhra chain was rejected by the OTA downloader's strict TLS verification) | **Power-cycle .39 and .51 again** — the first power-cycle was BEFORE the wyze-secure delta fix and the tunnel. This time the delta carries a URL the camera's TLS can actually download from | Operator (5 sec) |
| **Tapo C660** | ROP fired 3× with verified gadgets but camera went back to sleep before telnetd could bind | **Walk past the C660** to trigger a PIR wake while the sweep is armed. The DS-readiness gate ensures the fire only happens when the camera can actually execute | Operator (walk by it) |
| **Tapo C460** | Offset 1060 borrowed from C660, DIFFERENT SoC. 121 instrumented fires with identical no-shell-port-closed signature | **USB-serial UART connection** (3.3V, 115200 8N1) → extract `/bin/main` from the SXZ partition → derive the correct offset | Operator + UART adapter |
| **Owlet .163** | Vendor 0x2041 grant never fires outside the app. H3/H4/H5 closed-negative. The en1 pcap can't see phone↔camera unicast | **Open the Owlet app's live view** while capturing from the ROUTER (not en1 — the AP forwards unicast only to the target MAC) | Operator + router capture |
| **Yi .20** | SSID injection payload ready, listener alive 3+ days on :4444. Camera must scan during setup and hear the payload SSID | **macOS Internet Sharing** (System Settings → Sharing) with the payload SSID, or a standalone travel router broadcasting the payload SSID | Operator (the one disruptive step) |
| **AOSU ×4** | Tuya registration burned (ILLEGAL_CLIENT_ID confirmed live). LAN OTA (0x1A/0x1B/0x1C) needs `local_key` from the Tuya gateway. H2E HomeBase is the real target (always-on, fronts all 4 cameras) but not yet located on the LAN | **New Tuya IoT Platform account** (iot.tuya.com, 10 min) → new app_id/secret → local_key → LAN OTA | Operator (web browser) |

## The ONE Action That Changes Everything

**Power-cycle .39 and .51 again.** The first power-cycle fired into the void because:
1. The delta went to wyze-secure but the rewrite only handled wyze-service (FIXED)
2. The OTA URL used the forged eMudhra cert which the camera's OTA downloader rejects (FIXED with tunnel)

Now the delta carries `https://cigarettes-dispatched-partnerships-assessments.trycloudflare.com/4.52.17.99.tar`
with a valid Let's Encrypt cert. The camera's OTA downloader (CURLOPT_SSL_VERIFYHOST=2,
CURLOPT_CAINFO=local/cacert.pem) will accept this cert. assis will download the 16.7MB
capsule, verify the md5, extract, and run `upgraderun.sh` as root.

**After the flash: thingino gives SSH + RTSP + ONVIF. No vendor cloud needed. No MITM needed.
The camera becomes a standard ONVIF device that FSS ingests from directly.**

## Infrastructure (all committed and running)

| Tool | Purpose | Status |
|---|---|---|
| `fleet_status.py --gate` | One-command fleet health | ✅ 8/8 planes |
| `fleet_reconcile.py --execute` | Auto-heal drift (runs every 15 min via launchd) | ✅ self-healing |
| `root_proof.py` | Machine-checkable root evidence | ✅ 25 proof artifacts |
| `wait_ledger.py` | Negative-evidence for all armed waits | ✅ 3 open / 12 closed |
| `plist_doctor.sh` | Launchd plist validation | ✅ 0 findings / 25 plists |
| `wyze_flash_readiness.sh` | 7 hard asserts before power-cycle | ✅ 7/7 green |
| `wyze_chain_watch.sh` | Auto-capture root proof on capsule GET | ✅ running (LaunchDaemon) |
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

## Trycloudflare Tunnel (EPHEMERAL — will die on reboot)
```
URL: https://cigarettes-dispatched-partnerships-assessments.trycloudflare.com/4.52.17.99.tar
Local HTTP: :9443 serving /tmp/fwserve/wuv2/upgrade/HL_CAM4/firmware/
Restart: cloudflared tunnel --url http://localhost:9443 > /tmp/cloudflared_tunnel.log 2>&1 &
```
If the tunnel dies, the OTA reverts to the s3-us-west-2 URL (forged cert, which the OTA
downloader rejects). Restart the tunnel and update the broker plist OTA_URL.
