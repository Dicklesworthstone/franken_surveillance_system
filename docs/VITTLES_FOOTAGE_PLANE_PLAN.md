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
| ONVIF | `fss-onvif`: an allowlist of read operations on Media1 (`GetCapabilities`, `GetProfiles`, `GetStreamUri` for H.264, `GetSnapshotUri`) and Media2 (`GetServices`, `GetProfiles`, `GetStreamUri` for H.264/H.265, `GetSystemDateAndTime`); HTTP Digest or WS-UsernameToken; handoff to `fss-capture-rtsp from-onvif`; snapshot capture; `fss-onvif-metadata`: PullPoint events (HTTP Digest only; `--subscribe yes` creates a device-side subscription) and uncompressed ONVIF metadata over RTP | HTTPS, Profile T or Profile M qualification, any PTZ/imaging/relay/config operation (by design: the client has no control code path) |
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
   at every store. Digest auth defaults to SHA-256 and needs an explicit,
   approval-bound `--legacy-md5 yes` for MD5, which most camera families in
   section 3 still use; expect that opt-in to be the normal case, not the
   exception.
3. **There is no TLS.** `rustls` is an exception candidate in
   `architecture/dependency_allowlist.toml` and is not admitted without a DEP
   record, an ADR and release evidence. Without TLS, FSS cannot reach UniFi's RTSPS port (7441),
   HTTPS ONVIF, or any vendor cloud API. The standards path today is plaintext
   RTSP and HTTP on a trusted LAN or VPN.

The strengths are real and suit this use. Source custody is exact. Coverage
gaps are first-class: a missing camera is never evidence of absence. The ONVIF
client cannot move a camera or fire a relay, because no such code exists. The
agent protocol is typed, bounded and already exposed over MCP.

One limit matters as much as the strengths. FSS privacy masks are applied when
pixels are derived. Original RTSP custody stays unmasked, and RTSP capture and
archiving decode no pixels at all (`PRIVACY.md`, custody versus derivation).
Masks are not yet enforced on live RTSP capture paths. So FSS cannot, by
itself, keep a payment terminal out of retained footage. Section 7.5 states
what that means.

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
  ExternalMediaRef/EvidenceSlice handles · fldt-footage-rights verdicts
  POS and labor facts (no purchasing ingest yet) · DecisionCards · outcome ledger
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
  windows, held evidence), with root-last custody receipts. A window FSS records
  live beside a recording NVR is "independently recorded" in FLDT's
  `CustodyTransferReceipt` terms, and FLDT keeps a second RTSP recorder
  experimental until it proves there is no competing original and no doubled
  camera connection. VIT-005 has to prove that.
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
reverses both statements. FLDT's `AGENTS.md` also says both halves of
FranchiseOS are built in its own repository, with no sibling implementation
repo, so a third statement changes too. The owner's request authorizes the
direction, but three FLDT records have to change: an explicit repository
decision in `AGENTS.md`, ADR-B (`fldt-governed-video-archive-vv7qh.10`), and the
process split that ADR-B depends on. This plan runs credential reads, archives,
decoding and the detector on one host. FLDT's open beads for splitting vault
authority by OS process and credential envelope (`vv7qh.18`) and for
sandboxing model and decoder code (`vv7qh.23`) decide how that is partitioned.
See bead request F1 in section 10.

### Deployment

FSS runs on a small Linux host per site, or on one Linux host per customer that
reaches each store through the customer's site VPN. Linux is the right default
for three reasons. FSS's credential and private-file backends (RTSP Digest,
ONVIF inventory and handoff files, `from-unifi`, PullPoint) are Linux-only
today. The qualification lanes target it. And store edge boxes are cheap Linux mini PCs.
The site node needs no inbound internet exposure. FLDT's media-plane design
assumes authenticated local IPC between FLDT and the vault. Under vittles that
does not hold: `fldt` runs on a line host, line hosts dial out, and customer
reach exists only inside a permitted window (V-L5, V-L7). FSS has no TLS and no
remote MCP transport. Nothing yet carries signed leases out, custody receipts
in, or the owner's approval to the node. Owner decision D6 closes that gap, and
until it is made "automatic" covers manifest compilation only. Who controls the
node and the bytes on it is decision D3.

## 2b. Sizing (estimates; VIT-013 should measure them)

FSS keeps each window's original RTP alongside an MP4 media fragment of the
same samples, so disk is roughly twice the stream's bitrate: about 11 GB per
camera-day at a 512 kb/s substream, about 86 GB at a 4 Mb/s main stream. A
16-channel site recording substream only needs about 180 GB a day (1.2 TB for
7 days, 5.3 TB for 30); continuous main-stream recording (about 1.4 TB a day)
is out of scope. Pulling 16 substreams over a site VPN costs roughly 8 Mb/s of
the store's upstream; 16 main streams do not fit most store connections.
Substream decode and motion analysis need one to two CPU cores; the detector
runs in sampled bursts, not continuously, because full-resolution continuous
inference is not economical (`RISK-008`). What this plan can honestly promise
is substream retention of N days, sized to the disk actually provisioned,
never a gap-free or main-stream archive.

## 3. Getting video in from each camera family

The table uses only vendor-supported, standard routes. Typical URI shapes are
starting points: FSS should always take the real URI from ONVIF `GetStreamUri`
or the vendor inventory, then confirm it with one DESCRIBE. Model and firmware
details vary, so every row needs a probe receipt before it counts as working.

| Family | Standard route | What the customer provides | FSS today | Gap |
| --- | --- | --- | --- | --- |
| **Ubiquiti UniFi Protect** | Per-camera RTSP enabled in Protect; console serves RTSPS on 7441 and plaintext RTSP on 7447; official Integration API (`/proxy/protect/integration/v1/cameras`, per-camera `rtsps-stream`) with an `X-API-KEY` header. Cameras do not serve ONVIF themselves. | Console LAN IP; RTSP enabled per camera and quality; an Integration API key (created under Settings → Control Plane → Integrations; it is admin-scoped, so treat it as a password) | `from-unifi` records a selected view from a private export, over an operator-verified plaintext RTSP URL | Protect publishes only RTSPS links; FSS will not derive a plaintext URL by rewriting one, so every camera and quality needs an operator-verified plaintext 7447 URL until D2. The Integration API key has no read-only form: it can move PTZ, arm alarms, fire alarm webhooks, change camera settings and delete streams, so it stays in `fldt` and never reaches the site node or FSS argv/stdout/manifests. The inventory fetch itself is HTTPS with a self-signed console certificate (bead request F10). Hardware qualification |
| **TP-Link Tapo** (wired models) | "Camera Account" created in the Tapo app enables RTSP on 554 (`stream1` main, `stream2` sub) and ONVIF Profile S on 2020. Battery models generally have no RTSP. Tapo Care, SD recording and RTSP/ONVIF viewing cannot all run at once: two of the three at most. | Camera LAN IP; the camera-account username and password (separate from the Tapo cloud login) | ONVIF Media1 onboarding and RTSP capture cover this path | Digest auth on the site node (Linux is fine); real-device probe |
| **Wyze** | Production RTSP firmware shipped for Cam v3 and Pan v3 in early 2026; Cam v4 has had beta RTSP support since mid-2026, and a beta update has been reported to reset RTSP settings back off. | Model; which firmware version is installed; RTSP credentials set in the app | Generic RTSP path if the installed firmware exposes it | Most Wyze cameras are cloud-only through official routes. Treat them as unsupported live sources, or as import-only (exported clips), confirm firmware version at onboarding, and say so in onboarding. |
| **Hanwha Wisenet** (cameras and NVRs, including the ARN-1610S at Rusty's) | Cameras: RTSP `…/profileN/media.smp`. NVRs: reported as `…/LiveChannel/<0-based channel>/media.smp`, with the RTSP port sometimes the NVR's last device port, and sessions that don't share a session ID each counting as a separate NVR user (confirm both with a probe); ONVIF on most cameras and many NVRs; SUNAPI HTTP API (vendor-documented) | NVR or camera address on the LAN or VPN; a viewer-role account if the NVR supports roles | ONVIF onboarding if the NVR serves ONVIF; RTSP capture with Digest | Probe whether the ARN-1610S serves ONVIF and which URI and port shape it actually uses; a 16-channel NVR makes the one-user-per-session limit worth checking before relying on it |
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
recorder of record. Second, use the substream for continuous analysis. Main
stream windows can only be captured forward in time: FSS has no NVR playback or
export client, so a POS exception that arrives the next day is answered from
FSS's retained substream, or reported as "not in the vault". Recorder playback
and export would be its own piece of work.

## 4. From the vittles cameras area to an FSS source, automatically

vittles already records a camera system. The `cameras` category offers the
`devices`, `api`, `portal` and `vendor_contact` methods. The `devices` method
captures `protocols` (`rtsp`, `onvif`, `nvr`, `cloud`, `unknown`),
`deviceCount`, `controller` (recorder or gateway address), `username`,
`network` (`public`, `allowlist`, `vpn`, `onsite`, `unknown`), and a sealed
`password` secret. vittles is vendor-neutral by rule (V-L16). Product
particulars belong in `fldt`, and product guidance arrives as catalog data.

"Automatic" here means no hand-typed commands after the customer saves the
system, an installer has qualified each camera's payment-zone protection
(section 7.5), FLDT has resolved the site's rights profile, and the owner
approves the site once. It does not mean skipping any of those. FSS's per-route
approval is FSS's own safety requirement and worth keeping. FLDT gates capture
by rights verdict with no human approval, and uses a confirm-once "standing
sanctioned channel" for vault bucket writes, so these are separate gates that
both apply.

```text
1. vittles   customer saves the cameras system (devices/api method);
             the password or API key is sealed in the browser to the operator key
2. fldt      (proposed, F2) compiles a camera site spec from the record plus
             catalog data
             → emits fss.site_camera_manifest.v1 (no secrets inline; each
               credential becomes a 0600 file on the site node, placed as
               described below)
3. owner     approves the probe; FLDT's rights gate admits a framing-only
             probe for each source (nothing is kept except the receipt)
   FSS       fss site probe   : per source, read-only probes
                                 ONVIF GetProfiles/GetStreamUri, or UniFi
                                 inventory JSON, or RTSP DESCRIBE + one short
                                 SETUP/PLAY to observe SSRC, payload and cadence
4. FLDT      resolves the site FootageRightsProfile and issues a
             PaymentZonePermit per source and route; a source with any
             unresolved needed effect stays unadmitted
5. FSS       fss site plan    : compiles manifest + probe receipts into the
                                 existing per-source capture plans and mints
                                 the anchor/clock/timing/journal identities
                                 deterministically from (site, source, epoch)
                                 → one site approval digest binding every
                                   per-source plan digest
6. owner     approves the site digest once, through an authenticated vittles
             action and never an agent (V-L9)
7. FSS       fss site run     : always-on recorder under that approval;
                                 envelope drift (new camera, changed URI,
                                 codec, parameter-set family, cadence outside
                                 the declared bound, credential) stops that
                                 source and asks for a new approval; SSRC and
                                 in-bound frame-rate changes do not
8. FLDT      receives custody receipts, coverage witnesses and observations;
             ExternalMediaRef/EvidenceSlice handles point at FSS object identities
```

Two design points need care.

- **Probe receipts replace owner-typed pins.** FSS refuses to take SSRC or
  cadence from metadata, and that refusal is right. A probe session that
  actually observes SDP, SSRC and RTP timestamps is evidence, not metadata. The
  plan binds the probe receipt's digest, so an approval names exactly what was
  observed. Not every observed value is a stable property of the source,
  though. An RTSP server may choose a new SSRC per session, and real cameras
  lower or skip frames at night or on a static scene (slow-shutter modes, Axis
  Zipstream's dynamic frame rate). FSS's live timing today refuses variable
  cadence outright and refuses `--ssrc auto` in exactly the reconnect mode an
  always-on recorder needs, so pinning the probe's exact SSRC and cadence would
  stop a real camera on its second session or its first quiet night. The
  approval has to bind a source envelope instead: peer, URI, codec, payload
  type and parameter-set family, plus a declared cadence bound. SSRC and the
  timestamp base are learned once per session. Envelope drift (a new camera,
  changed URI, codec or parameter-set family, cadence outside the bound) stops
  the source; per-session SSRC and frame-rate variation within the bound do
  not. This needs its own ADR, because FSS's live timing and reconnect modes
  refuse exactly this today.
- **Credentials never pass through vittles in plaintext.** The browser seals
  them to the vittles operator key. Today an operator releases a sealed bundle
  (the release is audited) and opens it offline with
  `tooling/systems-sealing-key.ts open-bundle`, which prints the plaintext on
  the machine that holds the key. FLDT's credential rule is that it stores no
  vendor passwords. So the path to the site node is not built. Bead request V4
  proposes re-sealing to a per-node key, so that plaintext exists only on the
  node, as the FSS credential file (exactly `username LF password LF`,
  owner-read only, one link). An agent never runs `open-bundle`, because the
  plaintext would land in its transcript. FSS records every read of the file
  (file identity digest, never content) and revokes its lease if the file
  changes.
- **Threat model.** A node holds every credential it uses, so a compromised
  node can do whatever those accounts can do. FSS being read-only is a property
  of its code, not of the credential. Each recorder therefore needs a
  dedicated read-only (viewer-role) account, and an account that can control
  cameras (the Rusty's case) needs the customer's written acceptance and node
  egress limited to the exact device address and port pairs. Credentials are
  not reused across stores or nodes. The admin-scoped UniFi Integration API key
  stays off the node until TLS is admitted (D2): the customer supplies the
  export instead. A changed password means a new envelope, a re-release, and a
  typed source stop until it is redeployed.

The vittles form can stay vendor-neutral and still collect what FSS needs. Bead
request V1 adds these questions to the `devices` method, gated so that they
appear only when the protocols include rtsp, onvif or nvr (the method is shared
with building controls):

- Can this account move cameras, trigger alarms or change settings? This
  records the Rusty's case: a read-only agreement on an account that can
  control PTZ.
- Main stream and substream available? (yes / no / not sure)
- How many channels does the recorder have?
- Does any camera see a card terminal, register screen or receipt printer? Is
  audio recorded? Are camera notices posted? Which state or country? These
  feed the rights profile and the payment-zone check, not FSS.

The `api` method already has an `api_key` secret, so it needs nothing new for
consoles and cloud VMS. One cameras system record holds one controller and one
password, so a customer with several stores or recorders records one system per
recorder. Per-product setup steps ("create a Camera Account in the Tapo app",
"enable RTSP per camera in Protect", "create an Integration API key") are
engine-supplied catalog data (FLDT provider manifests; bead request V2), not
form text. V3 adds Brief exits, which belong in the vittles plan's list of
exits.

## 4b. Time

FSS records no wall-clock capture time today: RTP timestamps are relative,
camera clocks are an unauthenticated claim, and RTCP sender reports are kept
without an NTP mapping. The POS-to-footage join in section 5.2 and FLDT's own
clock evidence both need a wall-clock interval with a stated uncertainty, not
just a relative offset. This plan does not yet have a bead for it, but needs
one: a site clock witness that pairs the node's own real and monotonic clocks
with an NTP offset and uncertainty at every session start, end and heartbeat;
keeps the camera's and the NVR's own clock claims as separately labeled,
unverified evidence; and maps each retained window to a UTC interval widened
by that uncertainty before it is compared with a POS timestamp. The node's
clock should slew rather than step after boot, because a clock step is itself
a discontinuity that has to be reported, not hidden.

## 5. Use cases

Each use case below names what FSS supplies, what FLDT supplies, the rights
gate, and the first output worth measuring. A rights gate is an exact FLDT use
context (modality, purpose, subject class, zone, audience, retention) plus the
media effects the use needs. A restaurant's raw footage mixes customers,
employees, contractors and minors, and the most restrictive verdict governs.
The acceptance numbers below are starting proposals, to be fixed before the
first run. All identity-bearing analysis is
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
- **Rights gate:** premises security. Check whether an existing FLDT purpose
  covers it, and request one if none does. Person counts are scalar. A join to
  the labor schedule stays at count level ("someone was present with no open
  punch"), never a claim about a person.
- **First output:** a nightly coverage report per site, for example "CAM08 and
  CAM09 at Upper State have had no video since T" at Rusty's. Proposed
  acceptance over seven nights: every channel-hour is classed covered,
  gap-with-cause or not_observable; two manual recorder spot checks a night
  agree with the report on every channel checked; a channel that shows a
  recorder's video-loss placeholder is never "covered". After-hours presence
  candidates come later and need a measured detector first (proposed: at least
  50 labeled windows with presence and 200 without, precision and recall
  published with confidence intervals, shipped only at precision 0.9 or
  better).

### 5.2 Loss prevention and POS-to-video

- **FLDT:** POS exceptions from the POS ingest (the Toast export lane is being
  built): voids, refunds, no-sale drawer opens, comps, large discounts,
  post-close transactions.
- **FSS:** a footage-window query (VIT-008). Given a register camera and a time
  window, it returns a byte-free clip handle, the coverage witness for that
  window, and cheap analysis (person present at the register, drawer-region
  motion, a second person present). A source is admitted only with a current
  FLDT `PaymentZonePermit` (section 7.5). FSS decode masks (VIT-011) are
  defense in depth, because retained RTSP custody is unmasked.
- **Join:** FLDT asks; FSS answers with handles and observations; FLDT builds a
  DecisionCard for human review. Nothing is autonomous: no discipline and no
  accusation, only a review queue with receipts.
- **Rights gate:** a clip linked to a POS exception can be traced to a cashier,
  so the review packet is treated as identity-bearing: purpose loss prevention,
  employee subjects, internal-operator audience, effects persist and disclose.
  It runs only where the site profile resolves `allowed` for that exact
  context.
- **First output:** for one week at one store, the share of POS exceptions with
  usable footage (proposed: at least 30 exceptions, otherwise report
  "insufficient"). Usable means the source was admitted, the coverage witness
  spans the window with no gap (60 seconds either side of the exception), the
  register zone was in view, and the POS-to-camera clock offset is bounded
  (proposed: 2 seconds or less). Only exception types the store's POS lane
  actually emits count; the Toast export lane's format notes list what it
  reads. A customer reviewer sees the clip through an FLDT media access grant
  and records explained, unexplained or footage insufficient.

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
  linkage outright, while FLDT's Revision 02 rejects any categorical
  prohibition or permission and treats permissions as non-transitive: person
  tracking does not authorize cross-visit linkage. A multi-unit operator may
  want an employee recognized across its own stores. FLDT's use context holds
  a single site today, so the allowed case cannot be expressed on either side.
- **First output:** dining-room occupancy every 15 minutes against a human
  count on at least 200 sampled frames (proposed: mean absolute error of at
  most 1 person). Identity-bearing analysis has no first output until a model
  is admitted and a site verdict allows it.

### 5.4 Supply and inventory monitoring

- **FSS:** observations at the receiving door (vehicle arrival and departure,
  dwell), walk-in cooler and freezer door-open durations (zone dwell on a door
  region), and back-of-house presence during deliveries.
- **FLDT:** distributor invoices and delivery windows from purchasing (FLDT has
  no purchasing or receiving ingest yet), plus temperature sensors from
  building controls.
- **Join:** a delivery invoiced with no observed receiving event, or a door held
  open for many minutes while the cooler temperature rises.
- **Limit:** item-level counting (cases, shelf stock) needs models FSS does not
  have. COCO-80 covers person, car, truck, bottle and cup, not "case of
  fries". Admit such a model through the model registry later.
- **First output:** walk-in door-open durations against at least 50 labeled
  openings (proposed: error of 5 seconds or less on 90 percent of them). The
  invoice join waits for a receiving ingest lane.

### 5.5 Speed of service

- **FSS:** drive-thru lane stage times from vehicle tracks through named zones
  (order point, pay window, present window), cars in line, counter queue
  length, and time from order to handoff where a camera covers both ends.
- **FLDT:** `fldt-drivethru` already models per-car sessions and the
  stopped-clock gap (`total_to_handoff − total_timer`) and bridges to POS
  probabilistically, never by plate. FSS becomes a manufactured source for it.
- **First output:** first a measured FSS error against at least 200 hand-timed
  cars across at least three dayparts (proposed: median stage-time error of 2
  seconds or less, 90th percentile of 5 seconds or less, car recall of 97
  percent or better). Then camera-derived stage times against the store's own
  drive-thru timer for one week, reported with that error band. Without the
  measured error a disagreement cannot be attributed to the timer.

### 5.6 Incident preservation and disclosure

The most common real security request is not detection. It is "keep the
footage of this window" after a fall, a dispute, or a request from police or
an insurer, before a recorder overwrites it on its own schedule. It needs no
detector.

- **FSS:** `fss-hold place` on retained windows. For a window only the NVR
  holds, FSS answers "not in the vault; upstream retention unknown".
- **FLDT:** a preservation case and legal hold. `Disclose` binds the recipient
  (counsel, insurer, law enforcement) and needs a human authority.
- **First output:** request-to-hold time, and the share of requests whose window
  was still retained when the request arrived.

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

### Agents outside the site node

`fss-mcp` is a stdio server on the node, and every `--root` above is a path on
the node. Agents in FLDT and vittles therefore never call FSS directly: a
vittles agent reaches the engine only through the host-side broker (V-L7) and
cannot approve anything (V-L9). They use the pending `fldt vault` verbs
(`coverage`, `clips`, `site-manifest`; FLDT bead request F3, and the
`franken-surveillance-system` skill in FLDT's skills directory), which answer
from custody receipts and observations already received over the D6 control
plane. Cameras are addressed by zone through the CameraViewPolicyMap, so an
agent can ask about "register 2" without knowing a camera ID. The site manifest
maps each FLDT or vittles principal to an FSS `--principal`. Agents read,
explain and propose. Approvals, holds, exports and deletions stay with humans.

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
4. **Rights before use.** Every FLDT media effect FSS performs (device
   collection, vault receipt, persist, local inference, disclose, hold apply
   and release, lifecycle and manual delete) checks a current signed FLDT
   rights execution lease for its exact context; absent or unresolved means
   refuse. FSS never selects an audio track on its own. A zone the profile
   excludes is never admitted, and a zone whose required notice is not attested
   is refused.
5. **Payment-zone floor at the source.** FSS performs no capture, vault receipt
   or persistence for a source without a current FLDT `PaymentZonePermit` for
   that source and route. The permit requires every fixed-camera surface (main
   stream, substream, snapshot, recorder export, local recording, failover) to
   be protected by physical placement or a permanent camera-side or
   recorder-side mask, with an optical check recorded, and FLDT refuses an
   overlay that exists only in a user interface. The customer or installer sets
   the mask, because FSS never configures a device. FSS decode masks are
   defense in depth and never satisfy the floor, because original RTSP custody
   stays unmasked. So every camera needs one on-site qualification before it is
   admitted, and "automatic" begins after it. No raw PAN is stored anywhere.
6. **No media bytes or PII in FLDT stores or in `ee` memory.** Only byte-free
   handles, receipts and redacted observations cross.
7. **Secrets** stay in sealed records and in 0600 credential files on the node.
   Never in manifests, logs, prompts, fixtures or URIs, and never in an agent's
   transcript.
8. **Customer data location.** Rusty's data stays under `/data/fldt-pilot/rustys/`.
9. **Controller and legal gate.** The restaurant customer decides what is
   recorded, kept and disclosed. vittles and FSS act on its instructions. The
   gate is the site `FootageRightsProfile` that FLDT resolves. The customer and
   its counsel own whether a statute applies, and the vittles owner owns the
   processor terms. FSS refuses without a verdict. This plan gives no legal
   advice.
10. **Retention and requests.** Retention comes from the site profile per zone,
    never from an FSS default. Access and deletion requests are answered by
    sensor and window scope, and a search for a person is itself a gated,
    identity-bearing use.
11. **Kill switch and audit.** Freezing a customer or revoking a source in
    vittles stops lease issuance, and FSS fences within the lease lifetime (a
    bound to be stated; proposed 60 seconds). A local stop fences at once.
    Probe, capture start and stop, credential read, export, hold and delete are
    ledger records that the customer can read.
12. **Encrypted at rest.** Footage, journals and credential files on a site
    node sit on an encrypted volume (for example LUKS2 with a TPM-sealed key)
    until FSS has admitted encryption of its own, so a stolen or discarded
    mini PC exposes nothing.
13. **Offboarding closes completely.** FSS deletion today is local unlinking,
    not cryptographic erasure, and does not reach `fss-backup` copies,
    replicas or already-exported clips. Ending a customer means: release or
    transfer holds, revoke every camera credential and vendor key in `fldt`,
    end any PullPoint subscription, delete archives, journals and backups,
    then destroy the volume key so the deletion is actually cryptographic.
    FLDT gets a signed deletion receipt naming anything that could not be
    reached (an exported copy, an upstream recorder). One site node serves one
    customer.

## 7b. Operations

None of this is beaded yet; it is what "always-on" actually requires day to
day, and it needs beads of its own once the plan settles.

- **Provisioning and updates.** A site-node image with its encrypted volume,
  built and updated through whatever carries the D6 control plane, with
  rollback on a bad update. FSS builds and releases through `rch` to pinned
  Linux workers today; a field update path is separate work.
- **Health.** Per-source heartbeat, disk headroom, clock offset and lease
  expiry travel as metadata only, over the same D6 link. "FSS cannot reach
  CAM08" is a different fact from "CAM08 is down" — the latter needs evidence
  from somewhere other than FSS (an NVR health signal, a manual check), never
  an inference from FSS's own silence.
- **Disk pressure.** Until the retention ring (VIT-006) exists, a full disk
  stops capture outright with a typed gap; there is no eviction to fall back
  on.
- **Credential rotation.** A changed password revokes the current lease and
  resumes under the new credential file without widening what the source can
  do; it should not need a fresh owner approval unless scope actually widens.
- **Upstream drift.** Vendor firmware and settings changes can silently turn
  a stream off (a camera's own storage-mode limit, a firmware update that
  resets RTSP). Treat that as a typed per-source gap and a customer-facing
  question, not a silent hole in coverage.

## 8. Owner decisions

| ID | Decision | Why it blocks | Status |
| --- | --- | --- | --- |
| D1 | Ratify FSS as FLDT's external video-vault product, superseding the in-repo workspace and Frigate-pilot statements in FLDT's media-plane docs, with a crosswalk: FSS meets root-last custody, holds and coverage witnesses; FLDT re-scopes bucket upload, per-object data keys and key retirement, and process-authority manifests; FSS still has to add encryption at rest, signed receipts and clock evidence | FLDT's ADR-B and its epic must name the product that holds the bytes, and today FSS custody is unencrypted local files whose deletion unlinks rather than cryptographically erases | **Decided 2026-11-04: yes.** Matches FLDT `AGENTS.md`'s existing rule that media bytes and custody live outside `fldtd`; FLDT holds only byte-free references and observations. FLDT's ADR-B still has to be filed (bead request F1); this only settles the owner's direction. |
| D2 | Crypto admission, in three parts that need not move together: (a) Ed25519 signing and verification for the leases and receipts in D6; (b) footage and credential encryption at rest; (c) TLS (`rustls`) for camera-facing sources. For (c), `rustls`'s built-in providers carry C or assembly, which FSS's own policy forbids, and its pure-Rust provider is marked experimental, so the choice is a policy exception or an unaudited provider, not a clean yes/no | (a) blocks VIT-009 and VIT-010. (b) blocks footage sitting unencrypted on a restaurant box. (c) gates UniFi RTSPS and API access, HTTPS ONVIF, and every cloud VMS (Verkada, Meraki) | **Decided 2026-11-04: admit TLS via (c), `rustls`.** RTSPS and HTTPS ONVIF are allowed where a camera offers them, with certificate pinning per site manifest; plain RTSP stays allowed on the site LAN or VPN only. This settles the policy yes; the formal DEP record, ADR, and the C/assembly-vs-experimental-pure-Rust provider choice are separate engineering work, not yet done. |
| D3 | Site node custody: a customer-owned host on the store LAN, or a vittles-operated host (per store, or per customer over the VPN). A vittles-operated host puts raw footage in vittles' custody, which contradicts the vittles plan's statement that camera media never enters vittles, and would need processor terms, a trust-page and subprocessor update, and a data-location rule | Sets controller and processor roles, custody, bandwidth and concurrency | **Decided 2026-11-04: one Linux host per customer, reached over that customer's VPN**, to start. Keep the host layout in the site manifest so a second host or a cloud relay can be added later without a schema change. |
| D4 | Cross-site identity within one tenant: change FSS `PRIVACY.md` from "forbidden" to "refused unless an FLDT verdict allows it", and have FLDT add a multi-site use context (bead request F9). Cross-tenant linkage stays forbidden | Neither system can express the allowed case, and FLDT's Revision 02 rejects a categorical prohibition | **Decided 2026-11-04: allow cross-property identity only where the site's `FootageRightsProfile` allows it.** This follows FLDT's Architecture Revision 02 (dated 2026-07-09, consolidated 2026-08-04, verified against `ARCHITECTURE_REVISION_02_FOOTAGE_RIGHTS_PROFILE.md`), whose own trigger is that a blanket ban "can encode constraints that do not exist" for a given site and jurisdiction; per-site profiles replace it, never a new blanket ban in either direction. Default stays off per site until a profile resolves it. PRIVACY.md still needs the wording change (this plan's own finding 7 already called for it); not yet made. |
| D5 | Rusty's: allow FSS to read the ARN-1610S from a Linux host on the OpenVPN, with PullPoint off. Inventory and framing-only probes first; bounded captures wait for a resolved Rusty's rights profile (bead request F8) and a payment-zone permit per channel | First real customer source; read-only agreement. The account can control PTZ and alarms | **Not decided.** A relayed "use your judgment" delegation reached this plan proposing a yes for inventory-only read, but this is the one decision in this table that means an FSS process opening a real network connection to a real customer's live camera NVR. That needs the owner's own direct word, here, not an inference passed through another session. Held open; `VIT-D5` (`.18`) stays open pending it. |
| D6 | FLDT-to-site-node control plane: which side dials out; framing and authentication of signed leases outbound and custody receipts inbound with no TLS in FSS; how the owner's approval reaches the node; the maximum age of an `OfflineRightsLease` before a WAN outage fences new recording (too short loses coverage on a routine outage, too long lets a cut line keep recording with no live rights check) | Under V-L5 and V-L7 nothing yet carries a lease, receipt or approval across, and the offline bound decides what happens during exactly the outage that matters most (someone cutting the line before a break-in) | Not decided. |
| D7 | Allow a supervised always-on site recorder (VIT-005) under a standing site approval. This reverses FSS's stated "not an always-on daemon" posture and its one-bounded-capture-per-approval model, and puts independently recorded archives beside a recording NVR, which FLDT keeps experimental | Every FSS capture today is a single bounded operation; the recorder changes that | Not decided. |

## 9. Build order

The order is chosen so that each step is usable on its own.

1. **Site manifest and compiler (VIT-001, VIT-002).** The ergonomic unlock.
   This is pure, no-I/O code: parse `fss.site_camera_manifest.v1`, mint the
   per-source identities, and compile to the exact capture plans FSS already
   approves. It is testable entirely on fixtures, and it turns "twenty flags per
   camera" into "one file per site".
2. **Read-only probe (VIT-003).** Observe SDP, SSRC and cadence; record a probe
   receipt; feed the compiler. For UniFi consoles, VIT-004 wires the existing
   `from-unifi` into the compiler and produces the private export automatically.
3. **First real camera (VIT-013).** One owner-lab standards camera (wired Tapo,
   Reolink, or UniFi through 7447) through manifest → probe → plan → capture →
   decode. This yields the first measured row in `DEVICE_ADAPTER_MATRIX.md`.
4. **Always-on recorder and retention ring (VIT-005, VIT-006).** This is a new
   standing-approval model, not campaign mode generalized: campaign mode lists
   every possible attempt in advance and forbids automatic recovery, neither of
   which an unattended box can do. It needs its own ADR (D7) before it reverses
   FSS's stated "not an always-on daemon" posture. On a customer source it
   starts only after step 5's rights and payment gates; the owner-lab camera in
   step 3 needs neither.
5. **FLDT contract (VIT-009, VIT-010, VIT-011)** with the matching FLDT beads:
   custody receipts, rights verdict leases, payment-zone masks.
6. **Footage-window query and QSR observations (VIT-008, VIT-012),** then the
   use cases in section 5.
7. **Rusty's pilot (VIT-014)** once D5 is decided. Until a Rusty's rights
   profile resolves (F8) and each channel has a payment-zone permit, it is
   inventory and framing-only probes with no retained media. A payment-zone
   qualification needs a person on site, and the pilot rule is that Rusty's
   staff are not contacted, so retained media there waits for a qualification
   the owner arranges.
8. **TLS-gated sources (VIT-016)** after D2.

## 10. Work graph

FSS beads live in this repository's `.beads` under the epic `fss-vit-je36t`.

| Bead | Work | Blocked by |
| --- | --- | --- |
| `.1` VIT-001 | Site manifest and probe-receipt schemas, sans-IO parser | — |
| `.2` VIT-002 | `fss site plan` compiler, one site approval digest | .1 |
| `.3` VIT-003 | `fss site probe` (read-only ONVIF/RTSP/UniFi) | .1 |
| `.4` VIT-004 | UniFi source kind in the compiler and automatic export production | .2 |
| `.5` VIT-005 | Always-on site recorder (`fss site run`/`status`); a new standing-approval model, not campaign mode generalized (D7) | .2, .3, .10, VIT-020, VIT-021, VIT-024, VIT-D7, DOC-019 (`fss-x4a.5.19`) |
| `.6` VIT-006 | Retention ring | .5 |
| `.7` VIT-007 | Digest auth on macOS | — |
| `.8` VIT-008 | Footage-window query | .5, VIT-019, VIT-022 |
| `.9` VIT-009 | FLDT vault contract adapter | .8, VIT-020 |
| `.10` VIT-010 | Rights verdict leases as capability authority | .1 |
| `.11` VIT-011 | Verify and attest source-side payment-zone masks; decode masks as defense in depth | .1 |
| `.12` VIT-012 | QSR observation vocabulary | .1 |
| `.13` VIT-013 | First measured standards camera | .2, .3 |
| `.14` VIT-014 | Rusty's ARN-1610S read-only pilot (probe-only until a Rusty's rights profile and per-channel payment attestation exist; see bead request F8) | .3, .18 |
| `.15` VIT-015 | fss/1 site, footage-window and QSR views | .8, .12 |
| `.16` VIT-016 | TLS-gated sources | .17 |
| `.17` VIT-D2 | Owner decision: TLS | — |
| `.18` VIT-D5 | Owner decision: Rusty's read | — |
| `VIT-019` | Site clock witness and UTC interval mapping (`ClockEvidence`) | .1 |
| `VIT-020` | FLDT-to-site-node uplink: local spool and wire contract (D6) | .1, VIT-D6 |
| `VIT-021` | SSRC-per-session and VFR-tolerant source-envelope approval (ADR) | .1, .2, VIT-D7 |
| `VIT-022` | Recorder-of-record window retrieval (ONVIF Profile G / vendor playback) | .1, .3 |
| `VIT-023` | Trimmed, masked review export of one retained window | .8, .11 |
| `VIT-024` | Site-node image, provisioning, encrypted volume, update/rollback, health | .1, VIT-020, VIT-D3 |
| `VIT-025` | Customer offboarding and deletion closure | .6, VIT-020 |
| `VIT-D1` | Owner decision: ratify FSS as FLDT's vault (crosswalk) | — |
| `VIT-D3` | Owner decision: site-node custody | — |
| `VIT-D4` | Owner decision: cross-site identity within one tenant | — |
| `VIT-D6` | Owner decision: FLDT-to-site-node control plane and offline lease age | — |
| `VIT-D7` | Owner decision: admit an always-on site recorder | — |

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
- **F8** a Rusty's `FootageRightsProfile` (the California-pilot profile,
  `fldt-footage-profile-pilot-drjo4`, covers only those two stores); gates
  VIT-014's bounded captures.
- **F9** a multi-site use context in FLDT's footage-rights model, so a
  verdict can express "allowed" for cross-site identity within one tenant
  (decision D4); `FootageUseContext` holds a single site today.
- **F10** TLS (a pinned self-signed certificate) for the UniFi Protect
  Integration API inventory fetch, which `fldt` performs; gates VIT-004's
  automatic export production.
- **V1** vendor-neutral questions for the vittles cameras form; **V2** camera
  product catalog data; **V3** Brief items for coverage and loss-prevention review.

Existing FLDT camera beads that this plan builds on rather than duplicates:
Cameras C1 Lorex site survey (`fldt-lorex-site-survey-uz9dl`), C4 rights
profiles for the California pilot stores (`fldt-footage-profile-pilot-drjo4`),
C7 wired camera qualification (`fldt-wired-camera-qualification-8d5if`), and
the governed video archive epic (`fldt-governed-video-archive-vv7qh`).

**New FSS work from this review, now beaded.** Two independent review rounds
found work this plan depends on that had no bead. VIT-019 through VIT-025
above exist to cover it, with real dependency edges onto the existing beads
they feed (`br dep cycles` reports none across all 26 VIT-family beads).
VIT-005 and VIT-011 were also rescoped in place: VIT-005 is now described as
a new standing-approval model rather than campaign mode generalized, and
VIT-011 as verifying a source-side attestation rather than only applying a
decode mask. Two gaps remain FLDT-side, requested alongside F1-F7: a Rusty's
rights profile (bead request F8, needed before VIT-014's bounded captures)
and TLS on the UniFi inventory fetch (bead request F10).

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
- The plan has had one fact-check pass (section 1, against commit `23cc5785`)
  and two independent adversarial review rounds: one on architecture, FSS code
  claims and vendor claims; one on the FLDT/vittles contract, rights, privacy
  and safety, and on whether the use cases are measurable. Both rounds' BLOCKER
  and MAJOR findings are integrated above. Neither round covered the beads
  themselves (that is section 10's new work-graph note), and no further round
  has checked this integration from a fresh, independent read.
