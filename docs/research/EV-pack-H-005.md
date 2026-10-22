# EV pack H-005 — TP-Link Tapo 192.168.4.70 (443 + 8800)

**Hypothesis H-005.** The Tapo local HTTPS JSON API (`/app`, `auth` / `securePassthrough`) has a
reachable pre-auth or owner-auth weakness yielding root — auth bypass, command injection,
weak/derivable handshake key, or an unsigned-firmware path — with a persistence path that
survives reboot.

**Status: PARTIAL.** The API is real, reachable, and *is* a pre-auth oracle — but it is an
**offline password verifier, not a bypass**. Root is gated behind one cracked secret. The
pre-auth RCE class that exists on this platform is unreachable on this exact build because the
device never reads a request body until auth succeeds. Persistence is signature-gated.

**Probe discipline.** All 67 probes below are read-only — nothing was written to the camera, no
`[WRITE]` step was executed. Every port was retried ≥3× (443: 3× on `/app`, >40 further
`login` posts; 8800: every request repeated). Interface `en1` = 192.168.4.170/22, unprivileged.

> **Scanner trap, record it.** `nmap -Pn` reports **443/tcp filtered** while `curl` succeeds on
> the same port in 60 ms. The camera silently drops SYNs, so a SYN-based verdict on this host is
> wrong. Port state here must be taken from repeated connect-based probes, not from scan output.

---

## Findings

Legend: **PA** = pre-auth (no owner secret). Reliability is over the probe runs actually made.

| # | transport | port | PA? | primitive class | exact function / binary | reliability | evidence |
|---|---|---|---|---|---|---|---|
| F-1 | HTTPS JSON `POST /` | 443 | **yes** | **INFO / AUTH — offline password verifier** | `login` handler, `encrypt_type:"3"`, reply field `device_confirm` | **certain** (12/12 replies) | EV-920, EV-921 |
| F-2 | HTTPS JSON `POST /` | 443 | **yes** | INFO — public key disclosure | 512-bit RSA SPKI served as `data.key` | **certain** | EV-928 |
| F-3 | HTTPS JSON `POST /` | 443 | no | AUTH — session establishment (`digest_passwd` → `stok`), unlockable offline | `_validateDeviceConfirm` / `digest_passwd` in the `main` binary `[INFERENCE on symbol; scheme verified from pytapo]` | certain the gate exists | EV-921, EV-929 |
| F-4 | HTTPS JSON `POST /` | 443 | **yes-but-gated** | INFO — `scanApList` reachable pre-dispatch, still returns auth error | `scanApList` | certain | EV-925 |
| F-5 | HTTPS JSON `POST /` | 443 | no | **RCE (stack overflow, CVE-2025-8065 class)** | ONVIF SOAP XML parser — oversized XML namespace prefix copied to a fixed stack buffer, length unchecked | **certain the CVE exists; not reachable here unauthenticated** | EV-924, EV-930, EV-934 |
| F-6 | HTTP/SOAP | 8800 | **no** | AUTH — Digest challenge | `Streamd`, `realm="TP-Link IP-Camera"`, `algorithm=MD5`, `qop=auth` | certain | EV-923 |
| F-7 | HTTP/SOAP | 8800 | no | DoS / possible RCE surface | same `Streamd` ONVIF handler; body only parsed post-auth | certain it does not parse pre-auth | EV-924 |
| F-8 | HTTPS | 443 | no | **CFG→RCE — firmware update** | OTA accepts `0000020055aa` magic + RSA-2048-PSS sig + AES-128-CBC body; AES key derived from the signature salt | literature only, unverified on-device | EV-933 |

### F-1 — the actual pre-auth weakness (detail)

One unauthenticated POST yields a server-computed verifier over the *real* password:

```
POST /  {"method":"login","params":{"encrypt_type":"3","username":"<sha256("admin") uppercase>","cnonce":"35B9283A8EF6DEF1"}}
→ {"result":{"data":{"code":-40401,"time":9,"max_time":10,"encrypt_type":["3"],
     "key":"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKi3oL5k...","nonce":"B3852CB41BA61E64",
     "device_confirm":"FFC5EFD9…20494B3852CB41BA61E6435B9283A8EF6DEF1"}},"error_code":-40413}
```

Structure, confirmed by both field lengths and the reference implementation
(`pytapo.py:486-510`):

```
device_confirm = SHA256( cnonce + hash(password) + nonce ).upper() + nonce + cnonce
   hash() = md5 hex upper   OR   sha256 hex upper      (device accepts either; the reply
                                                        distinguishes which via this same field)
```

`cnonce` is attacker-chosen, `nonce` is returned. So the **entire authentication secret is one
unsalted hash `hash(password)`**, and `device_confirm` is a complete, self-contained offline
verifier. Field boundaries are proven, not assumed: the reply is exactly 96 chars and
`[64:80] == nonce`, `[80:96] == cnonce`, leaving `[0:64]` as the 64-hex verifier (EV-936);
re-issuing with a fresh nonce changes the verifier and not the layout. Raw capture:
`evidence/excerpts/EV-920-oracle.txt`. There is no per-attempt server cost and therefore no lockout on the crack: the
`time/max_time` 9/10 countdown only meters negotiation posts, not guesses.

Measured cost, this Mac, single core, pure Python: **1,651,832 candidates in 6.1 s** (~270 k/s),
end-to-end including the oracle fetch — against ≈10¹⁰ for an 8-char lowercase+digit space, i.e.
minutes-to-hours, not weeks. Runnable as-is: `evidence/excerpts/crack-device-confirm.py`.

Grading: the hash is **unsalted and un-stretched**, so precomputation and table reuse work
across every Tapo on earth, not just this device. That is the weakness. It is a *password
difficulty* weakness, not an authentication-logic weakness — with an 8+ char random camera
password it is not free.

### F-2 — the 512-bit key

The served SPKI decodes to `Public-Key: (512 bit)`, `e=65537`. The keypair **rotates**: three
bursts returned three distinct moduli while the nonce rotated with it. `pytapo` 3.4.28 **never
consumes `data.key`** on this path — it only redacts it for logs — and the whole `device_confirm`
flow is symmetric-hash only, so the key is vestigial *for this client*. But
`{"method":"securePassthrough","params":{"request":"…"}}` **is** still recognised by the device
(EV-928), so the RSA-OAEP wrap path is live for older clients.

512-bit RSA is factorable in minutes-to-hours with CADO-NFS on one laptop. Because the AES
session key derives only from `cnonce`+`nonce`+`hash(pw)`, factoring alone does not hand over a
session — it is useful as an *alternative* oracle: capture one RSA-wrapped login (needs L2 MITM,
which the swarm already has), factor the modulus, decrypt → `hash(pw)` without the device's help.
`[INFERENCE — the wrapped-blob field order is not verified on this build.]`

### F-3 — taxonomy (corrected; the pytapo `const.py` table is authoritative)

| code | meaning | what produces it here |
|---|---|---|
| `-40413` | `INVALID_NONCE` | **normal** negotiation reply (carries `key`/`nonce`/`device_confirm`) |
| `-40209` | `INVALID_LOGIN_CREDENTIALS` | every method without a valid `stok` |
| `-40401` (`data.code -40407`) | `INVALID_STOK_VALUE` / `OTHER_ERROR` | HTTP 401 on `/app` and on gated methods |
| `-40210` | `METHOD_DO_NOT_EXIST` | `{}`, unparseable body, unknown method |
| `-40411` | *(wrong password at `digest_passwd`)* | only reachable **after** a correct password — it is why a wrong-password run never reaches it (EV-929) |
| `-40409`, `-40405`, `-40408`, `-52405/407/419` | `NONCE_EXPIRED`, `DEVICE_FACTORY`, `SYSTEM_BLOCKED`, `TOO_MANY_*` | not observed |

`-40209` on `getDeviceInfo` therefore does **not** mean "unsupported" — all 112 enumerated
methods are recognised; they simply have no session.

### F-4/F-7 — what is *not* there

- `multipleRequest`, `scanApList`, `login` are the only names that get past the pre-dispatch gate.
- The CVE-2026-105814 / CVE-2026-105672 shape ("append an onboarding-scoped object to a request
  to skip the session check") **fails on this build**: 20 injection variants
  (`proto`/`onboarding`/`scanApList`/`connect`/`public` × `proto`/sibling/top-level/target_method)
  all return `-40209` (EV-926). So this is *not* a C210 v3.60 or C325WB v2.
- UDP 20002 (TDP) is dead — 5 framings, all timeout (EV-927). The documented TDP surface on
  other revisions ("accepts any public key from anyone", qkaiser) is absent here.
- ONVIF pre-auth: `Expect: 100-continue` gets **no** `100 Continue` and an instant 401 with
  `Connection: close`. Prefixes of 0 / 64 / 1 K / 8 K / 16 K / 32 K / 65 K / 130 KB body produce
  an identical 401 and zero connection resets (EV-924). **The SOAP parser never runs
  unauthenticated on this build**, so CVE-2025-8065 — described by TP-Link as unauthenticated —
  needs credentials here. This is the single most load-bearing observation in the pack.

### F-8 — signing posture

Tapo camera images are `00 00 02 00 55 aa` + RSA-2048-PSS signature + AES-128-CBC body. The
updater calls `rsaVerifyPSSSignByBase64EncodePublicKeyBlob`, which *verifies and derives the AES
key/IV from the recovered salt in one operation* — so decryption needs only a public key, and 11
public keys cover the whole fleet. **Verification is still enforced**, and because the AES key
comes from the signature, a forged image fails twice: the pubkey check and the decrypt. So an
unsigned image is **not** accepted directly; you need either TP-Link's private key or write
access to the verification pubkey plus non-enforced secure boot (`[INFERENCE — "probably" per
tpbreak, confirmed only on EAP]`). Separately, rootfs confidentiality is decorative: AES-128-CFB1
with `TP_LINK88i667gnt` hardcoded in the kernel and a **fixed IV**
(`55AADEADC0DE 4C494E5558457854AA55`) — EV-935 — so modifying a flash dump is trivial. Network-only
that still buys nothing on its own.

### F-5 — exploitability, since it is the root half of the chain

TP-Link CVE-2025-8065 (C200 v3 < `V3_1.4.5 Build 251104`, C520WS v2.6 < `1.2.4 Build 260326`),
CVSS v4 8.7, `PR:N`. And the platform build makes a stack smash close to free: **no NX, no stack
canary, no PIE/ASLR, no RELRO, stack mapped executable** (EV-934), and every network service —
ONVIF, web management, cloud client — lives in one root `main` binary. A return-to-stack-shellcode
is the expected exploitation shape, not a ROP chain.

---

## Chain

Shortest end-to-end path, and the exact point where it stops being free:

```
1. [READ]  POST / {"method":"login","encrypt_type":"3","username":sha256("admin"),
                   "cnonce":<8 random bytes hex>}
           → device_confirm.  One packet. No credentials.
2. [READ]  Offline: for each candidate p, test
              SHA256(cnonce + (md5|sha256)(p) + nonce) == device_confirm[:64]
           → hash(password).  Unlimited, unrestricted, no lockout, no device traffic.
3. [READ]  POST / with the same cnonce and
           digest_passwd = SHA256(hash+cnonce+nonce).upper()+cnonce+nonce
           (params are exactly {cnonce, encrypt_type:"3", digest_passwd, username}; no nonce
           field — the pairing is carried by cnonce) → stok, start_seq, and
           lsk/ivb = SHA256("lsk"|"ivb" + cnonce + nonce + SHA256(cnonce+hash+nonce))[:16]
           → authenticated admin session on 443. All 112 methods open.
           Caveat: replayed by hand the verifier lands in time, because the device rotates
           nonce+keypair on every negotiation post and stamps the reply -40413 (EV-929).
4. [READ]  Same secret on 8800: the Digest challenge even advertises encrypt_type="3", i.e. the
           ONVIF account is the same hashed credential → ONVIF + media session.
           [INFERENCE: HA1 is md5(admin:"TP-Link IP-Camera":hash(pw)) — the hashed form is
           strongly indicated by encrypt_type="3" in WWW-Authenticate, not yet verified.]
5. Now the root half is reachable, and only now: the ONVIF SOAP parser is entered, so an
   oversized-namespace-prefix SOAP request (CVE-2025-8065) overflows a fixed stack buffer in the
   root `main` binary with no ASLR/canary/NX → shellcode on an executable stack → root.
6. Persistence — the honest options, best first:
   a. [WRITE] Downgrade to a *genuine, TP-Link-signed* build below the CVE-2025-8065 fix and keep
      the step-5 payload. Signature stays valid because the image is genuine; firmware survives
      reboot by definition; re-exploit only after the next OTA. This is the only path that needs
      no private key.
   b. [WRITE] Repack a modified image (rootfs key is public, EV-935) and rewrite the verification
      PUBKEY in writable flash first, then push. Convertible to fully persistent, at the cost of
      depending on non-enforced secure boot.
   c. Enable whatever boot-started daemon the model exposes (the CVE-2026-102369 pattern:
      "enable a privileged service that becomes accessible after a reboot") — cheapest in theory,
      model-specific and unconfirmed here.
```

**Where it breaks:** steps 1-2 are free and certain; **step 3 is where an unguessable password
stops the run inside the budget** (1.65 M candidates of `/usr/share/dict/words` + casing/digit
mutations did not hit). Everything from 5 down is literature, not measurement, because we have no
credential and therefore no session.

**No chain, and the falsifier that killed it** — the pure pre-auth path is dead on this build,
not merely unexplored: `Expect: 100-continue` with no `100 Continue` and identical 401s at every
body size prove the ONVIF parser is never entered without a session (EV-924). TP-Link's
"unauthenticated" for CVE-2025-8065 is therefore not true of this firmware. Similarly the
onboarding-parameter bypasses are dead here: 20/20 shapes → `-40209` (EV-926).

---

## Brick risk + recovery

Nothing in steps 1-4 is a write: no reboot, no config, no firmware. Brick risk of the completed
investigation as run is **nil**. Risk only begins at step 6.

- **Step 5 (RCE payload) — low.** Worst case the payload crashes `main`; the device restarts
  itself. CVE-2026-0918/0919 and CVE-2026-15316 in the same parser family are all self-recovering
  DoS. Recovery: power-cycle at the plug. No flash is touched.
- **Step 6a (downgrade) — low-moderate.** Real risks: (i) an interrupted transfer leaving a
  half-written image — mitigate by not power-cycling mid-upload, the updater writes to the spare
  partition; (ii) the downgrade is rejected or the bootloader refuses the older version — benign,
  device stays on current firmware. Recovery: retry, else re-flash the current version through the
  app (the vendor download page for the model stays reachable).
- **Step 6b (modified image + pubkey rewrite) — moderate, and the only real brick path.** If the
  pubkey is replaced and the image is then rejected, the device has no valid verification key and
  no reachable shell → stuck. Order matters: write and confirm the pubkey, verify its digest,
  *then* upload. Recovery without UART: **none** once verify fails — U-Boot + serial is the only
  way back. Since the brief forbids UART, 6b should only be attempted with the camera physically
  in hand anyway, and 6a is the recommended persistence path precisely because it needs no
  recovery story.
- **Safe practice for all of it:** `[WRITE]` label every step; do not start 6 while the camera is
  on a UPS-less plug or the SD card is mid-write; keep the exact current firmware build number
  recorded (authenticated `getDeviceInfo`) *before* the first write so a known-good re-flash
  target exists.

---

## What would falsify this

Decisive tests, in the order they should be run:

1. **Authenticate once with the real password, then read the model + build.**
   `getDeviceInfo` → `device_info.basic_info.device_type`, `fw_ver`, `hw_ver`. This single call
   decides the pack: if it is not C200 v3 / C520WS v2.6 below the fix, F-5 is not our bug and the
   whole root half is a different CVE. **Nothing below matters until this is done** — the model is
   currently unestablished and the cert CN (`TAPO-DEVICE`) carries no model.
2. **With a session, replay the 65 K-prefix SOAP request to 8800.** If the connection resets or
   `Streamd` dies → CVE-2025-8065 present, F-5 confirmed reachable. If it 401s cleanly and stays
   up → patched, and the chain collapses to "creds only, no root".
3. **Nonce-replay check on 8800.** Against a *valid* credential, resend one captured Digest header
   25× and then after 60 s. Acceptance proves the replay weakness of the CVE-2026-102369 class on
   this build; the 401 we get today with *wrong* creds is indistinguishable from replay rejection,
   which is why this cannot be settled pre-auth (the `opaque` value is a constant
   `64943214654649846565646421` across every challenge — a poor freshness sign, not proof).
4. **Downgrade test.** Push the current-minus-one genuine image; if the updater accepts a strictly
   older `fw_ver`, persistence path 6a is confirmed real.
5. **Cracking sanity check.** Run the EV-921 formula against a password known to the owner. If it
   does not match, the derivation order or hash casing is wrong and every crack result here is
   void (the formula is copied from a client that is known to work, so this is a real check, not
   theatre).

Full recovery from any of these: no write precedes test 1, and tests 1-3 are read-only.

---

## Verdict

**PARTIAL — moderate confidence (≈0.65).**

*Confirmed by measurement:* the Tapo 443 surface is real and pre-auth reachable, and carries a
genuine, un-metered **offline password verifier** (`device_confirm`, F-1) over an **unsalted**
credential hash, next to a **512-bit** rotating RSA key and a live `securePassthrough` path. The
error taxonomy and the full 112-method gate is mapped. The platform is maximally friendly to a
stack smash (no NX/canary/ASLR/RELRO, executable stack, single root `main` binary), and the
canonical bug for it (CVE-2025-8065, `PR:N`, CVSS 8.7) is documented by the vendor with a fixed
version.

*Refuted by measurement:* H-005's core claim that a **pre-auth weakness yields root**. It does
not yield root by itself. No auth bypass fires on this build: the ONVIF parser is never entered
without a session (proven by `100-continue` non-response), the onboarding-parameter injection
shapes all fail, and UDP 20002 is absent. The pre-auth oracle yields *the password*, and the
password yields root — two hops, one of which is strictly a guessing problem.

*Confidence is 0.65 rather than higher* for exactly one reason: **the model and firmware build are
still unknown**. `TAPO-DEVICE`, no `Server` header, no pre-auth `getDeviceInfo`, no mDNS/SSDP/UDP
discovery answer. Every CVE attribution here is matched on *platform* (Tapo camera, `Streamd`,
`encrypt_type 3`), never on a confirmed model/build, and the three most on-target CVEs
(CVE-2025-8065 C200 v3; CVE-2026-102369 and CVE-2026-15315 C120 v1/C200 v5) name revisions that
a single authenticated `getDeviceInfo` would either confirm or kill. Until then this pack is a
well-evidenced *class* answer, not a certified device-specific one.

*If the owner's password is weak or already known:* H-005 flips to **CONFIRMED** for the
credentials half immediately (steps 1-4 are complete and certain) and the remaining question is
only whether the specific build is pre-fix for CVE-2025-8065.
