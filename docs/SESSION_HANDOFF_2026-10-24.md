# Session handoff — 2026-10-24 02:15 (CloudyMill, six panes)

Start here. Status, not narrative. The scoreboard is `docs/FLEET_LIBERATION_STATUS.md`
("Session 2026-10-24" section); each bead has its own handoff comment.

## Verified tonight (with the check that proves it)

| Claim | Proof |
|---|---|
| Wyze command channel is decoded and executes | `powerOff` (1232) powered `.4.23` off; body re-encrypts byte-identically to the cloud's own ciphertext; handler map and the product-type model table in `docs/exploit/ota-path.md` §13 |
| Wyze AV command execution | `killall -9 iCamera` at payload 1360 with `ra=0x4747F0` killed and respawned `iCamera` twice on `.4.24`; gadget bytes `25280000 d8ff220c 1800a427` at file offset `0x747f0` (base `0x400000`) |
| Wyze OTA delivery | two device GETs of our served capsule from `192.168.4.23` in `/tmp/ota/forge.log`, both 200; the official installer ran as root |
| Tapo unauthenticated root | two-step empty-`cnonce` login → `user_group=root` + `stok`; marker crash at offset 1060 with ~40 s recovery |
| Tapo units are on en1 | ARP `50:3d:d1:e3:e2:07` / `50:3d:d1:2f:49:b9` at `.4.70`/`.4.71` |

## Blocked, with the exact next action

- `fss-wyze-av-shell-2c37b` — the 680-byte one-liner is silent because `/bin/base64` and `/bin/gunzip`
  live in the initramfs (`/tmp/rd/bin`), not `/bin`. Retry with those paths, then `id`/uid, then the
  escalation survey.
- `fss-wyze-our-bytes-dlbs2` — `begin_upgrade` returns `code 2 "Device is upgrading now"` for every
  record id and `get_upgrade_firmware` 500s. Nothing device-side; it is a cloud flag.
- `fss-tapo-460-root-zhhtf` — no local `/bin/main`, so addresses are guesses and the walk is ~17 h.
  Finish the sstarXZ ramdisk instead: the LZMA2 chunk length is `next + 3` and the block currently
  decodes to a verbatim copy, so the stored-vs-compressed question is the live one.
- `fss-aosu-local-key-ddr77` — signer reversed and validated on `/log.json`; login still
  `SING_VALIDATE_FALED`. Replay a captured iotbing `sid` for `thing.m.device.key.get` rather than
  logging in.
- `fss-yi-ssid-inject-ozmim` — Internet Sharing cannot be raised headlessly: `launchctl kickstart`
  is SIP-refused and the GUI toggle rewrites the SSID. Use a hotspot renamed to the payload and
  change the payload address to the hotspot gateway.

## Host state left behind

- OTA stack armed via launchd (`com.jeffreyemanuel.wyze-broker`), forge on 443, DNS redirect for
  s3 / aws-iot / a24rq with the resolver addresses aliased, ARP spoof running. The `fss` pf anchor
  is intentionally empty: an `rdr` to a local address is translated but never delivered on this
  host, so aliasing is used instead.
- `/tmp/binshim` (GNU tool links) and the patched `thingino/board.mk` + `dependencies.sh` are
  required for any firmware build; see `docs/exploit/firmware-build.md` §9.
- Disk is 93 % full, so `scripts/qualify.sh` refuses at the capacity preflight. Nothing was deleted.
