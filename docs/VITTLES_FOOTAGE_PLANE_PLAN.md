# FSS as the footage plane for vittles.cloud and FLDT

Status: integration plan, 2026-11-03. It is not an ADR and it does not upgrade
any FSS claim. It covers standards-based camera access only. The
interoperability-lab work (TUTK, Tuya, firmware and app reverse engineering)
is out of scope by owner instruction and is not part of this plan.

The owner asked for three things. FSS should take video from whatever cameras a
restaurant customer already runs. It should bring that video in automatically
once the customer records the system in vittles.cloud. And it should be the
place where agents work with footage. This document states what FSS can do
today, what has to be built, and in what order.

## 1. What FSS is today

FSS is a pure-Rust, evidence-native toolkit for owner-authorized cameras. Every
capability below is an unqualified reference implementation. It is tested on
generated fixtures and loopback harnesses, and none of it has been measured on
real camera footage. The status comes from the code, `README.md` and
`IMPLEMENTATION_STATUS.md` as of commit `23cc5785`, and a separate read-only
pass checked each claim against that commit.

| Area | Works today (reference) | Not built |
| --- | --- | --- |
| RTSP | `fss-capture-rtsp`: OPTIONS/DESCRIBE/SETUP/PLAY over interleaved TCP; AVC, HEVC and RTP/JPEG; original RTP retained in root-last archives; reconnect and finite campaigns; Digest auth; `--ssrc auto` for single AVC/HEVC captures | RTP over UDP, RTSPS/TLS, Basic auth, DNS (literal IP only), credential and private-file workflows off Linux (Digest, ONVIF handoff files, `from-unifi`, PullPoint), always-on recording |
| ONVIF | `fss-onvif`: an allowlist of read operations (`GetCapabilities`, `GetServices`, `GetProfiles`, `GetStreamUri`, `GetSnapshotUri` on Media1, `GetSystemDateAndTime`); HTTP Digest or WS-UsernameToken; handoff to `fss-capture-rtsp from-onvif`; snapshot capture; `fss-onvif-metadata`: PullPoint events (HTTP Digest only; `--subscribe yes` creates a device-side subscription) and uncompressed ONVIF metadata over RTP | HTTPS, Profile T or Profile M qualification, any PTZ/imaging/relay/config operation (by design: the client has no control code path) |
| UniFi Protect | `fss-capture-rtsp from-unifi` (commit `5b1333f0`): records one exact `high`/`medium`/`low`/`package` view from a private Protect export (camera object plus `rtsps-stream` URLs); refuses RTSPS instead of downgrading it; plaintext only through `--stream-transport operator-rtsp` with an independently verified URL | Protect API client (needs TLS), RTSPS capture, automatic export production, hardware qualification |
| Discovery | `fss-discover`: mDNS, SSDP, WS-Discovery, UDP beacons on the local LAN | Discovery across a VPN (multicast does not cross it) |
| Decode | H.264 Baseline/Main/High 8-bit 4:2:0; H.265 Main 8-bit; baseline JPEG; bit-exact against FFmpeg on fixtures | 10-bit, interlaced, 4:2:2/4:4:4, progressive JPEG |
| Analysis | motion, background foreground, Kalman/Hungarian tracking, zone candidates, HOG people, YOLOX-Nano COCO-80 detector, two-camera corroboration through homographies, visual-degradation screening | any measured detection quality; QSR observations (queues, dwell, drive-thru stages) |
| Storage | local root-last archives, ledger, evidence holds, deletion closure, backup and restore, rectangular privacy masks | retention schedules, a retention ring, cloud archive, search |
| Agent surface | `fss` CLI and `fss-mcp` (stdio MCP) with all 14 `fss/1` operations: `session open/resume/orient/follow`, `query`, `investigate`, `plan`, `commit`, `wait`, `cancel`, `explain`, `handoff`, `feedback`, `doctor` | a footage-window query, QSR views, a remote MCP transport |

Three facts shape everything that follows.

1. **Every capture is a single bounded operation.** It needs an explicit
   approval digest and stops after a declared picture count or, in reconnect
   mode, an approved duration. Campaign mode chains a finite number of sessions
   with unfilled gaps between them. There is no recording daemon. The docs say
   so directly: "This is not an always-on daemon or a gap-free recording claim."
2. **Each capture needs about twenty owner-supplied values.** These include
   ingress number, cadence in 90 kHz ticks, and four SHA-256 identities
   (authority anchor, receive clock, timing evidence, journal epoch). FSS
   refuses to infer them from ONVIF metadata. Two recent additions help.
   `--ssrc auto` learns the RTP sender ID once per single AVC/HEVC session; it
   is refused in reconnect and retain-source modes, which still need a number.
   `from-unifi` supplies authority and presentation from the export. A person
   can type the rest for one camera. Nobody can type them for a 16-channel NVR
   at every store.
3. **There is no TLS.** `rustls` is an exception candidate in
   `architecture/dependency_allowlist.toml` and is not admitted without a DEP
   record, an ADR and release evidence. Without TLS, FSS cannot reach UniFi's RTSPS port (7441),
   HTTPS ONVIF, or any vendor cloud API. The standards path today is plaintext
   RTSP and HTTP on a trusted LAN or VPN.

The strengths are real and suit this use. Source custody is exact. Coverage
gaps are first-class: a missing camera is never evidence of absence. The ONVIF
client cannot move a camera or fire a relay, because no such code exists.
Privacy masks apply before decode. The agent protocol is typed, bounded and
already exposed over MCP.

## 2. Where FSS sits in the stack

FLDT's `AGENTS.md` already reserves this role. Camera and wearable media bytes
belong to "the separately deployed external video-vault process suite, never to
`fldtd`". FLDT keeps byte-free handles, receipts and admitted typed
observations. FSS is the obvious implementation of that vault: it already
treats source bytes as custody objects, separates source evidence from derived
cognition, and refuses to let a model score become a fact.

```text
customer cameras / NVR / UniFi console        (customer-owned; read-only)
        │  RTSP/TCP, ONVIF SOAP, vendor export JSON  (LAN or site VPN)
        ▼
FSS site node (Linux)                          (bytes live here only)
  site manifest → probe → one site approval → recorder
  archives · coverage witnesses · masks · holds · deletion
  analysis cascade → typed observations
        │  byte-free custody receipts, clip handles, observations
        ▼
FLDT (fldt / fldtd)                            (no media bytes)
  fldt-vms ClipHandle/VideoZone · fldt-footage-rights verdicts
  POS/labor/purchasing facts · DecisionCards · outcome ledger
        │  fldt binary and published envelopes only
        ▼
vittles.cloud                                  (onboarding, Briefs)
  cameras area records the system; credentials sealed in the browser
```

FLDT's `docs/MEDIA_PLANE_DESIGN.md` names five topology roles. FSS fills them
as follows:

- **RecorderOfRecord:** the customer's NVR or console wherever one exists (the
  Hanwha NVR at Rusty's, a UniFi Protect console). FSS becomes recorder of
  record only for cameras with no recorder. This follows FLDT's rule that the
  vault is "the archive custodian, not a second recorder" until parity is
  proven, and it avoids doubling camera connections.
- **ArchiveCustodian:** FSS, for windows it retains (event windows, POS-exception
  windows, held evidence), with root-last custody receipts.
- **InferenceSource:** FSS, normally on the substream, with motion gating and
  sampled detector bursts (`RISK-008`: full-resolution continuous inference is
  not economical).
- **ReviewSurface:** FSS exports of retained windows for a human reviewer, routed
  through FLDT DecisionCards. vittles shows the decision, never a video wall.
- **PreservationSource:** FSS evidence holds (`fss-hold`) mirrored as FLDT legal
  holds.

**Owner decision (D1).** FLDT's media-plane design names Frigate as the pilot
recorder and review surface. It also puts the vault in "an in-repo separate
workspace" and says the sibling-repo option is closed. Making FSS the vault
reverses both statements. The owner's request authorizes the direction, but
FLDT's ADR-B (`fldt-governed-video-archive-vv7qh.10`) has to record it. See
bead request F1 in section 10.

### Deployment

FSS runs on a small Linux host per site, or on one Linux host per customer that
reaches each store through the customer's site VPN. Linux is the right default
for three reasons. FSS's credential and private-file backends (RTSP Digest,
ONVIF inventory and handoff files, `from-unifi`, PullPoint) are Linux-only
today. The qualification lanes target it. And store edge boxes are cheap Linux mini PCs.
The site node needs no inbound internet exposure. It talks to cameras on the
LAN or VPN and to FLDT over authenticated local IPC, per FLDT's media-plane
design.

## 3. Getting video in from each camera family

The table uses only vendor-supported, standard routes. Typical URI shapes are
starting points: FSS should always take the real URI from ONVIF `GetStreamUri`
or the vendor inventory, then confirm it with one DESCRIBE. Model and firmware
details vary, so every row needs a probe receipt before it counts as working.

| Family | Standard route | What the customer provides | FSS today | Gap |
| --- | --- | --- | --- | --- |
| **Ubiquiti UniFi Protect** | Per-camera RTSP enabled in Protect; console serves RTSPS on 7441 and plaintext RTSP on 7447; official Integration API (`/proxy/protect/integration/v1/cameras`, per-camera `rtsps-stream`) with an `X-API-KEY` header. Cameras do not serve ONVIF themselves. | Console LAN IP; RTSP enabled per camera and quality; an Integration API key (created under Settings → Control Plane → Integrations; it is admin-scoped, so treat it as a password) | `from-unifi` records a selected view from a private export, over an operator-verified plaintext RTSP URL | Automatic export production (VIT-004); inventory fetch and RTSPS need TLS; hardware qualification |
| **TP-Link Tapo** (wired models) | "Camera Account" created in the Tapo app enables RTSP on 554 (`stream1` main, `stream2` sub) and ONVIF Profile S on 2020. Battery models generally have no RTSP. Tapo Care, SD recording and RTSP/ONVIF viewing cannot all run at once: two of the three at most. | Camera LAN IP; the camera-account username and password (separate from the Tapo cloud login) | ONVIF Media1 onboarding and RTSP capture cover this path | Digest auth on the site node (Linux is fine); real-device probe |
| **Wyze** | Official RTSP firmware has existed only for some models (Cam v3 and Pan v3, partly beta via the WyzeBeta app, and paused at times). No official RTSP for Cam v4 as of this writing. | Model; whether official RTSP firmware is installed; RTSP credentials set in the app | Generic RTSP path if the official firmware exposes it | Most Wyze cameras are cloud-only through official routes. Treat them as unsupported live sources, or as import-only (exported clips), and say so in onboarding. |
| **Hanwha Wisenet** (cameras and NVRs, including the ARN-1610S at Rusty's) | RTSP (`…/profileN/media.smp` family of URIs, channel-indexed on NVRs); ONVIF on most cameras and many NVRs; SUNAPI HTTP API (vendor-documented) | NVR or camera address on the LAN or VPN; a viewer-role account if the NVR supports roles | ONVIF onboarding if the NVR serves ONVIF; RTSP capture with Digest | Probe whether the ARN-1610S serves ONVIF; if not, a manifest entry with explicit per-channel URIs |
| **Hikvision** | RTSP `…/Streaming/Channels/101` (main) and `102` (sub); ONVIF (some firmware needs ONVIF enabled and a separate ONVIF user); ISAPI HTTP API | Device address; a user with live-view rights; ONVIF enabled if used | RTSP and ONVIF paths apply | Digest is mandatory on current firmware (Linux site node) |
| **Dahua** and **Lorex** (many Lorex recorders are Dahua-based) | RTSP `…/cam/realmonitor?channel=N&subtype=0|1`; ONVIF; HTTP CGI API. Some Lorex consumer lines are cloud-only. | Device or NVR address; user with live-view rights | RTSP and ONVIF paths apply | Lorex model check during onboarding |
| **Axis** | RTSP `…/axis-media/media.amp`; ONVIF Profiles S/T/M; VAPIX HTTP API | Device address; a viewer account | RTSP, ONVIF and uncompressed ONVIF metadata capture apply | Profile M is not qualified; HTTPS-only installations need TLS |
| **Reolink** (wired and NVR) | RTSP (`…/h264Preview_01_main` or `h265Preview_…` shapes); ONVIF; both may need enabling in the network settings on newer firmware. Battery models stream only through a Reolink hub or NVR. | Device or NVR address; user; RTSP/ONVIF switched on | RTSP and ONVIF paths apply | Real-device probe |
| **Verkada** and other cloud VMS | Cloud only. Verkada's documented route is its Streaming API: HLS (`.m3u8`) live and historical footage, authorized by a short-lived JWT minted from an API key. No local RTSP. Meraki MV, Rhombus and Eagle Eye have their own APIs. | An API key with footage-streaming scope; camera and org IDs | Nothing | Needs TLS plus an HLS client. Defer until TLS is admitted. Event and analytics metadata through the vendor API is the cheaper first step. |
| **Recorder or VMS software** (Milestone, Genetec, Exacq, Blue Iris, Frigate) | Most re-serve RTSP per camera or offer ONVIF bridging | Server address; a read-only user | RTSP path applies | Record in provenance that the stream is NVR-generated (`DOC-051`) |
| **Generic RTSP/ONVIF** | As above | Address, URI or ONVIF endpoint, credentials | Works for plaintext RTSP over TCP and plaintext ONVIF | TLS; UDP-only servers |

Two rules hold for every family. First, prefer the NVR over the cameras when an
NVR exists. One connection per channel through the NVR avoids loading
consumer-grade cameras that cap concurrent streams, and the NVR stays the
recorder of record. Second, use the substream for continuous analysis and
fetch main-stream windows only on demand.

## 4. From the vittles cameras area to an FSS source, automatically

vittles already records a camera system. The `cameras` category offers the
`devices`, `api`, `portal` and `vendor_contact` methods. The `devices` method
captures `protocols` (`rtsp`, `onvif`, `nvr`, `cloud`, `unknown`),
`deviceCount`, `controller` (recorder or gateway address), `username`,
`network` (`public`, `allowlist`, `vpn`, `onsite`, `unknown`), and a sealed
`password` secret. vittles is vendor-neutral by rule (V-L16). Product
particulars belong in `fldt`, and product guidance arrives as catalog data.

"Automatic" here means no hand-typed commands after the customer saves the
system and the operator approves the site once. It does not mean skipping
approval. FSS's per-route approval is a safety property worth keeping, and FLDT
already designs the same shape as a "standing sanctioned channel": one
confirm-ladder approval per exact route, then short-lived leases.

```text
1. vittles   customer saves the cameras system (devices/api method);
             the password or API key is sealed in the browser to the operator key
2. fldt      operator tooling unseals inside fldt only; fldt compiles a
             CameraSiteSpec from the record plus catalog data
             → emits fss.site_camera_manifest.v1 (no secrets inline; each
               credential becomes a 0600 file on the site node)
3. FSS       fss site probe   : per source, read-only probes
                                 ONVIF GetProfiles/GetStreamUri, or UniFi
                                 inventory JSON, or RTSP DESCRIBE + one short
                                 SETUP/PLAY to observe SSRC, payload and cadence
             fss site plan    : compiles manifest + probe receipts into the
                                 existing per-source capture plans and mints
                                 the anchor/clock/timing/journal identities
                                 deterministically from (site, source, epoch)
                                 → one site approval digest binding every
                                   per-source plan digest
4. owner     approves the site digest once (FLDT confirm ladder)
5. FSS       fss site run     : always-on recorder under that approval;
                                 any drift (new camera, changed URI, codec,
                                 cadence, credential) stops that source and
                                 asks for a new approval
6. FLDT      receives custody receipts, coverage witnesses and observations;
             fldt-vms ClipHandles point at FSS object identities
```

Two design points need care.

- **Probe receipts replace owner-typed pins.** FSS refuses to take SSRC or
  cadence from metadata, and that refusal is right. A probe session that
  actually observes SDP, SSRC and RTP timestamps is evidence, not metadata. The
  plan binds the probe receipt's digest, so an approval names exactly what was
  observed. A change in SSRC or cadence at capture time is drift, not something
  to absorb silently.
- **Credentials never pass through vittles in plaintext.** The browser seals
  them to the operator key. `fldt` unseals and writes the FSS credential file
  (exactly `username LF password LF`, owner-read only, one link). FSS reads it
  only after approval and revokes its lease if the file changes. The API-key
  secret follows the same path.

The vittles form can stay vendor-neutral and still collect what FSS needs. Bead
request V1 adds these questions to the `devices` method:

- Can this account move cameras, trigger alarms or change settings? This
  records the Rusty's case: a read-only agreement on an account that can
  control PTZ.
- Main stream and substream available? (yes / no / not sure)
- How many channels does the recorder have?

It also adds an API-key secret to the `api` method for consoles and cloud VMS.
Per-product setup steps ("create a Camera Account in the Tapo app", "enable RTSP
per camera in Protect", "create an Integration API key") belong in catalog data
(bead request V2).

## 5. Use cases

Each use case below names what FSS supplies, what FLDT supplies, the rights
gate, and the first output worth measuring. All identity-bearing analysis is
governed site by site by FLDT's `FootageRightsProfile` (Architecture Revision
02). Where a site's profile allows a use, the capability is first-class. Where
it is forbidden or unresolved, FSS fails closed. FSS's own default ("face
identification disabled", P4 opt-in in `PRIVACY.md`) is the no-verdict
default, not a ban. FSS consumes the FLDT verdict as its opt-in authority (FSS
bead VIT-010).

### 5.1 Security

- **FSS:** `perimeter_breach`, `unknown_presence` and `sensor_tamper` event
  candidates; after-hours zone entry; camera health. Video loss is a coverage
  gap with a witness, never "nothing happened".
- **FLDT:** store hours and labor punches. A person in the back of house at 2 a.m.
  with nobody clocked in is the interesting case.
- **First output:** a nightly coverage report per site, for example "CAM08 and
  CAM09 at Upper State have had no video since T" at Rusty's, plus after-hours
  presence candidates joined to the labor schedule.

### 5.2 Loss prevention and POS-to-video

- **FLDT:** POS exceptions from the POS ingest (the Toast export lane is being
  built): voids, refunds, no-sale drawer opens, comps, large discounts,
  post-close transactions.
- **FSS:** a footage-window query (VIT-008). Given a register camera and a time
  window, it returns a byte-free clip handle, the coverage witness for that
  window, and cheap analysis (person present at the register, drawer-region
  motion, a second person present). Payment terminals are masked before decode
  under the `PaymentZoneVideoFloor` (VIT-011). No raw PAN is ever stored.
- **Join:** FLDT asks; FSS answers with handles and observations; FLDT builds a
  DecisionCard for human review. Nothing is autonomous: no discipline and no
  accusation, only a review queue with receipts.
- **First output:** for one week of POS exceptions at one store, the share
  with usable footage, and the reviewed outcome of each.

### 5.3 Customer and employee tracking

- **Anonymous by default:** within-site tracks (Kalman/Hungarian), cross-camera
  association over calibrated ground planes, counts, dwell and paths. No
  identity is needed for queue length, table turn or the share of the dining
  room occupied.
- **Identity-bearing** analysis (employee re-identification, face matching,
  audio) runs only where the site's profile resolves `allowed` for that exact
  use context. FSS has no such model today; the plan adds the gate first
  (VIT-010) so that a model admitted later lands behind it.
- **Owner decision (D4).** FSS's `PRIVACY.md` forbids cross-property identity
  linkage. A multi-unit operator may want an employee recognized across its own
  stores. That is a policy question for the rights profile, not a code default.

### 5.4 Supply and inventory monitoring

- **FSS:** observations at the receiving door (vehicle arrival and departure,
  dwell), walk-in cooler and freezer door-open durations (zone dwell on a door
  region), and back-of-house presence during deliveries.
- **FLDT:** distributor invoices and delivery windows from purchasing, plus
  temperature sensors from building controls.
- **Join:** a delivery invoiced with no observed receiving event, or a door held
  open for many minutes while the cooler temperature rises.
- **Limit:** item-level counting (cases, shelf stock) needs models FSS does not
  have. COCO-80 covers person, car, truck, bottle and cup, not "case of
  fries". Admit such a model through the model registry later.

### 5.5 Speed of service

- **FSS:** drive-thru lane stage times from vehicle tracks through named zones
  (order point, pay window, present window), cars in line, counter queue
  length, and time from order to handoff where a camera covers both ends.
- **FLDT:** `fldt-drivethru` already models per-car sessions and the
  stopped-clock gap (`total_to_handoff − total_timer`) and bridges to POS
  probabilistically, never by plate. FSS becomes a manufactured source for it.
- **First output:** camera-derived stage times compared with the store's own
  drive-thru timer for one week. The disagreement is the product.

## 6. How an agent works with footage in FSS

Agents use the existing `fss/1` protocol through the `fss` CLI or `fss-mcp`.
FSS deliberately has no generic shell, SQL or vendor escape hatch. New
capability arrives as typed queries and views, not new privileged tools.

```text
fss session open   --json --root SITE --principal P \
                   --mission-text "Review last night's POS exceptions" \
                   --objective "Report covered and uncovered windows"
fss session orient --json --root SITE             # smallest sufficient SituationCapsule
fss query          --json --root SITE --kind unknown_presence --from-ns T0 --through-ns T1
fss explain        --json --root SITE --event-id E   # evidence, coverage, what would change it
fss investigate    --json --root SITE --session S ...   # durable competing-hypothesis case
fss investigate    ... --transition probe --subscription ID --authority-root sha256:...
                                                  # re-evaluate a retained scope once
fss-watch-rtsp-campaign / fss-sentinel-rtsp-campaign   # re-analysis of retained campaigns
fss-export event|media ... / fss-hold place ...  # review copy; evidence hold
fss feedback / fss handoff                        # outcome, typed continuation
```

`--mission-text` takes literal text; `--mission` is read as a file path when such
a file exists. `fss-capture-rtsp sentinel` is a live capture with detection, not
re-analysis of retained footage.

What exists: orient, query over event records, explain, investigate, retained
probes, handoff and feedback, all available through both the CLI and
`fss-mcp`. Exports (`fss-export`) and holds (`fss-hold`) are separate
binaries, not MCP tools. What this plan adds:

- `fss site status` (VIT-005): per-source recorder health and coverage over a
  window.
- A footage-window query (VIT-008): "what does camera X hold for [t0, t1]?" It
  returns handles, gaps and costs, never bytes by default.
- QSR observation views (VIT-012): queue length, dwell, lane stages and door-open
  time as typed observations with coverage witnesses.

Every answer keeps FSS's epistemics: `unknown`, `not_observable`, `stale` and
`redacted` stay distinct, and a missing detection during a gap is not absence.

## 7. Safety invariants for this integration

1. **Read-only toward customer devices.** No PTZ, preset, relay, alarm, trigger,
   reboot or configuration operation. FSS's ONVIF client has no code for any of
   them. Keep it that way: a control operation for customer devices would need
   its own ADR and is out of scope. This matters at Rusty's, where the account
   can move PTZ cameras and fire alarms.
2. **Subscriptions are effects too.** ONVIF PullPoint creates device-side state.
   It stays off at a site until the owner allows it for that site.
3. **Bounded load.** At most one connection per channel; respect per-device
   stream caps (Tapo's two-of-three rule); never compete with the operator's
   own viewing.
4. **Rights before use.** Every use context (collect, persist, infer, egress,
   identity, audio) checks a current FLDT verdict lease; absent or unresolved
   means refuse.
5. **Payment zones masked before decode;** no raw PAN anywhere.
6. **No media bytes or PII in FLDT stores or in `ee` memory.** Only byte-free
   handles, receipts and redacted observations cross.
7. **Secrets** stay in sealed records, `fldt`, and 0600 credential files. Never
   in manifests, logs, prompts, fixtures or URIs.
8. **Customer data location.** Rusty's data stays under `/data/fldt-pilot/rustys/`.

## 8. Owner decisions

| ID | Decision | Why it blocks |
| --- | --- | --- |
| D1 | Ratify FSS as FLDT's external video-vault product, superseding the in-repo workspace and Frigate-pilot statements in FLDT's media-plane docs | FLDT's ADR-B and its epic must name the product that holds the bytes |
| D2 | Admit TLS (`rustls` with a pure-Rust or audited crypto provider) through a DEP record and ADR, or accept plaintext-on-LAN/VPN only for now | Gates UniFi RTSPS and API access, HTTPS ONVIF, and every cloud VMS (Verkada, Meraki) |
| D3 | Site node hardware: one Linux host per store, or one per customer reaching stores through the VPN | Sets the recorder's concurrency and bandwidth budget |
| D4 | Cross-property identity for multi-unit operators: allowed by rights profile, or always forbidden | `PRIVACY.md` forbids it today |
| D5 | Rusty's: allow FSS to read the ARN-1610S (inventory plus bounded captures of working channels) from a Linux host on the OpenVPN, with PullPoint off | First real customer source; read-only agreement |

## 9. Build order

The order is chosen so that each step is usable on its own.

1. **Site manifest and compiler (VIT-001, VIT-002).** The ergonomic unlock.
   This is pure, no-I/O code: parse `fss.site_camera_manifest.v1`, mint the
   per-source identities, and compile to the exact capture plans FSS already
   approves. It is testable entirely on fixtures, and it turns "twenty flags per
   camera" into "one file per site".
2. **Read-only probe (VIT-002).** Observe SDP, SSRC and cadence; record a probe
   receipt; feed the compiler. For UniFi consoles, VIT-004 wires the existing
   `from-unifi` into the compiler and produces the private export automatically.
3. **First real camera (VIT-013).** One owner-lab standards camera (wired Tapo,
   Reolink, or UniFi through 7447) through manifest → probe → plan → capture →
   decode. This yields the first measured row in `DEVICE_ADAPTER_MATRIX.md`.
4. **Always-on recorder and retention ring (VIT-005, VIT-006).** It generalizes
   campaign mode under a standing approval, with gap accounting and health.
5. **FLDT contract (VIT-009, VIT-010, VIT-011)** with the matching FLDT beads:
   custody receipts, rights verdict leases, payment-zone masks.
6. **Footage-window query and QSR observations (VIT-008, VIT-012),** then the
   use cases in section 5.
7. **Rusty's pilot (VIT-014)** once D5 is decided. It can run as early as
   step 3 using manual plans, because it needs only inventory and bounded
   captures.
8. **TLS-gated sources (VIT-016)** after D2.

## 10. Work graph

FSS beads live in this repository's `.beads` under the epic `fss-vit-je36t`.

| Bead | Work | Blocked by |
| --- | --- | --- |
| `.1` VIT-001 | Site manifest and probe-receipt schemas, sans-IO parser | — |
| `.2` VIT-002 | `fss site plan` compiler, one site approval digest | .1 |
| `.3` VIT-003 | `fss site probe` (read-only ONVIF/RTSP/UniFi) | .1 |
| `.4` VIT-004 | UniFi source kind in the compiler and automatic export production | .2 |
| `.5` VIT-005 | Always-on site recorder (`fss site run`/`status`) | .2, .3 |
| `.6` VIT-006 | Retention ring | .5 |
| `.7` VIT-007 | Digest auth on macOS | — |
| `.8` VIT-008 | Footage-window query | .5 |
| `.9` VIT-009 | FLDT vault contract adapter | .8 |
| `.10` VIT-010 | Rights verdict leases as capability authority | .1 |
| `.11` VIT-011 | Payment-zone masks from the manifest | .1 |
| `.12` VIT-012 | QSR observation vocabulary | .1 |
| `.13` VIT-013 | First measured standards camera | .2, .3 |
| `.14` VIT-014 | Rusty's ARN-1610S read-only pilot | .3, .18 |
| `.15` VIT-015 | fss/1 site, footage-window and QSR views | .8, .12 |
| `.16` VIT-016 | TLS-gated sources | .17 |
| `.17` VIT-D2 | Owner decision: TLS | — |
| `.18` VIT-D5 | Owner decision: Rusty's read | — |

Related, non-blocking links: .5 to DOC-019 daemon lifecycle (`fss-x4a.5.19`) and
SLO-INGEST-001 (`fss-x4a.30.57`); .6 to DOC-060 (`fss-x4a.5.60`) and FSS-036
(`fss-x4a.9.6`); .13 to GATE-030 (`fss-x4a.2.4`) and TEST-RTSP-001
(`fss-x4a.28.6`). `br dep cycles` reports no cycles.

FLDT and vittles beads belong to FLDT's `.beads`, whose single writer is
BlueJaguar. They were sent as requests through Agent Mail (FLDT project, topic
`fss-footage-plane`) rather than written:

- **F1** amend ADR-B (`fldt-governed-video-archive-vv7qh.10`) and the stack
  qualification (`vv7qh.6`) for FSS as the vault (decision D1).
- **F2** an `fldt` camera site compiler that emits `fss.site_camera_manifest.v1`
  and writes credential files.
- **F3** re-scope Cameras C2 (`fldt-video-ingest-abstraction-1yqd0`) so FLDT
  consumes FSS handles instead of acquiring frames itself.
- **F4** export rights verdict leases and payment regions (`vv7qh.17`,
  `vv7qh.17.1`, `vv7qh.20`) to FSS.
- **F5** POS exception to footage-window review DecisionCards.
- **F6** admit FSS QSR observations into `fldt-drivethru`, `fldt-foot-traffic`,
  `fldt-shrinkage-sensors` and `fldt-order-accuracy`.
- **F7** the FLDT side of the Rusty's pilot.
- **V1** vendor-neutral questions for the vittles cameras form; **V2** camera
  product catalog data; **V3** Brief items for coverage and loss-prevention review.

Existing FLDT camera beads that this plan builds on rather than duplicates:
Cameras C1 Lorex site survey (`fldt-lorex-site-survey-uz9dl`), C4 rights
profiles for the California pilot stores (`fldt-footage-profile-pilot-drjo4`),
C7 wired camera qualification (`fldt-wired-camera-qualification-8d5if`), and
the governed video archive epic (`fldt-governed-video-archive-vv7qh`).

## 11. Evidence from this session

- `cargo test -p fss-reference --lib unifi` on rch worker ovh-a: 11 passed, 0
  failed (UniFi export parsing, quality and view separation, no implicit
  RTSPS rewrite, redaction, mutation safety).
- The RTSP capture, ONVIF native capture and orient CLI test suites were not
  run. rch kept selecting worker `trj`, which refused this repository
  ("source namespace: conflicting alias base"), and the policy refuses local
  fallback. Rerun them when the worker is repaired:
  `cargo test -p fss-cli --test capture_rtsp_cli --test onvif_native_capture_cli --test orient_cli_contract`.
- A whole-package `cargo test -p fss-reference` does not compile on rch workers,
  because `.rch/config.toml` excludes `**/*.onnx` and
  `tests/onnx_package_import.rs` includes ONNX fixtures with `include_bytes!`.
  This is the same class of problem the config already fixed for `.mp4` and
  `.safetensors`.

## 12. What this plan did not verify

- No FSS binary ran against a physical camera in this session. FSS builds go
  through `rch` to Linux workers, so no local macOS binary was produced. The
  focused test runs are reported in section 11.
- Vendor URI shapes and feature limits come from vendor FAQs, documentation
  and forum reports. Confirm each one per model and firmware with a probe.
- Whether the ARN-1610S serves ONVIF is unknown until it is probed (D5).
- The plan has had no external review rounds yet. The `planning-workflow`
  method calls for several before it is treated as settled.
