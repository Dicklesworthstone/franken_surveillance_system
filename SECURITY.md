# Security policy and threat model

## 1. Security objective

FSS should make an inexpensive heterogeneous sensor mesh safer than the collection of vendor apps
it replaces, without turning a home-security deployment into a privileged remote-code-execution
platform. Its core security strategy is **authority minimization plus evidence**:

- each component receives only the device, bytes, secret handle, filesystem object, model, or
  effect capability required for one operation;
- unsafe/native/proprietary runtimes are process-isolated;
- every consequential operation has an immutable request, idempotency identity, receipt, and
  verification predicate;
- secrets and private media are excluded from diagnostics by construction;
- degraded security state is visible and can remove capability.

## 2. Authorized-use boundary

Interoperability work is limited to devices, accounts, networks, footage, and cloud buckets owned
by the operator or explicitly authorized for testing. FSS does not accept contributions for:

- credential theft, session hijacking, authentication bypass, or token forgery;
- access to third-party devices/accounts/footage;
- broad internet or local-network camera scanning;
- persistence on vendor devices or modification of firmware protections;
- evasion of account/device-owner notifications;
- covert monitoring or disabling visible/required recording indicators;
- offensive physical response, weapons, or pursuit.

A vendor protocol may be studied to interoperate with an owner’s legitimate authenticated session.
The production adapter must continue to use normal authorization and support revocation.

## 3. Assets

High-value assets include:

- camera/drone/account credentials and device certificates;
- live and archived media;
- property geometry, zones, blind spots, schedules, and household routines;
- identity/appearance embeddings and operator feedback;
- alert destinations and acknowledgement channels;
- archive encryption keys;
- canonical event/effect ledger;
- model/policy/calibration generations;
- software supply-chain identities;
- negative evidence that reveals system weaknesses.

## 4. Adversaries and failures

FSS considers:

1. unauthenticated network attacker on camera/Wi-Fi/vendor paths;
2. malicious or compromised camera, vendor cloud, or mobile app;
3. malformed media designed to exploit codec/model runtimes;
4. compromised model weights or runtime dependencies;
5. stolen archive credentials or bucket exposure;
6. malicious/over-authorized agent or plugin;
7. local user/process with partial access;
8. replay/spoof/tamper of sensor feeds;
9. physical intruder exploiting blind spots or camera failure;
10. accidental operator misconfiguration;
11. firmware/app drift that changes semantics;
12. process, disk, power, network, clock, and GPU failure.

## 5. Network architecture

Recommended default:

- cameras on an isolated VLAN/SSID with no lateral access to trusted hosts;
- edge node has narrowly scoped routes to registered camera endpoints;
- no inbound internet exposure;
- vendor-cloud adapters use explicit destination allowlists and independent credentials;
- model hosts listen only on local authenticated IPC or an encrypted capability transport;
- remote archive credentials are write/read/delete separated where provider permits;
- operator UI uses local binding or authenticated reverse proxy with CSRF/session protections;
- discovery is bounded to configured interfaces/subnets and never an unrestricted scanner.

## 6. Secret custody

Secrets are referenced by opaque handles. The secret provider may be the OS keychain, hardware
module, encrypted local vault, or deployment-specific service. Requirements:

- no plaintext secrets in tracked config, environment dumps, command lines, process titles,
  evidence bundles, model prompts, crash reports, or logs;
- adapter receives the minimum secret for one device/account;
- token refresh remains inside the adapter’s secret domain;
- credentials are zeroized where feasible and descriptors close on cancellation;
- rotation/removal tests prove revocation;
- a support bundle reports secret *references and scopes*, never values;
- vendor account credentials are not reused for FSS administration.

## 7. Process isolation

### Codec host

FFmpeg/equivalent receives designated input/output descriptors, no credentials, no arbitrary path,
no outbound network, bounded CPU/RAM/time/output, sanitized environment, owned process group, and a
typed transformation plan. A crash is a media outcome, not a core process compromise.

### Model host

A model host receives immutable model files and authorized redacted input objects. It has no effect
capability, vendor credentials, archive keys, canonical DB write access, or arbitrary internet.
Output is schema-validated and bounded. Prompt text from untrusted metadata cannot invoke tools.

### Vendor adapter host

A vendor host receives one device/account capability and output channel. It cannot read unrelated
secrets, media, models, ledger, or filesystem. Mobile-app automation or display capture, when used
experimentally, runs in a dedicated profile/device and is not conflated with a stable API.

## 8. Supply chain

- pinned Rust toolchain and locked dependencies;
- closed dependency universe with ADR for additions;
- no build/test runtime downloads without a verified acquisition manifest;
- model weights and vendor helper binaries checksum/signature pinned;
- OCI/container images pinned by digest;
- release archives carry checksums and provenance where available;
- dependency/license/security scans are evidence inputs, not proof by themselves;
- a compromised or revoked model/device generation can be deactivated atomically.

## 9. Input bounds

Every boundary declares maximum:

- packet/frame/object size;
- dimensions, duration, frame rate, sample rate, channels;
- metadata nesting/string/array sizes;
- concurrent streams and reconnect rate;
- model prompt/tokens/frames;
- output objects and bytes;
- archive multipart count;
- agent result rows/tokens;
- retry attempts and backoff duration.

Malformed or oversized inputs return stable errors and cannot create unbounded buffering.

## 10. Effect security

Effects are classified:

| Class | Examples | Default authority |
|---|---|---|
| `E0 read` | status, health, bounded observation, evidence explanation | read principal |
| `E1 acknowledgement` | acknowledge/annotate event | operator/agent scoped to event |
| `E2 reversible device` | PTZ, spotlight/siren enable where permitted, temporary quality change | explicit capability + lease + restore plan |
| `E3 durable data` | retention change, export, archive delete, privacy-mask change | prepare/commit + strong approval |
| `E4 flight/physical` | future drone mission | disabled in v1; separate safety system required |
| `E5 offensive` | pursuit, weapon, confrontation | forbidden |

A model host receives none of E1–E4. An agent cannot invent a missing capability. Timeouts after
dispatch create indeterminate receipts and reconciliation obligations.

## 11. Feed authenticity and tamper

FSS records evidence for:

- packet continuity and sequence;
- TLS/device/channel identity where available;
- codec bitstream anomalies;
- frozen/repeated frames;
- display/replay indicators;
- expected scene landmarks and camera pose;
- image-quality/obstruction/glare;
- cross-sensor consistency;
- clock discontinuity;
- physical/network health.

These provide probabilistic tamper evidence, not absolute authenticity. A compromised camera and
its vendor cloud may share a failure domain; corroboration must account for that.

## 12. Audit and support bundles

Audit records are append-only revisions with content identities, principal, capability,
precondition, request, receipt, result, and decision path. Default support bundles include:

- exact build/config/device/model/policy/calibration identities;
- bounded timeline and event ring;
- stable errors and degraded state;
- object/evidence hashes and sizes;
- sanitized process/resource telemetry;
- replay command using synthetic or operator-approved evidence.

They exclude credentials, raw household media, exact home address, unredacted geometry, and
bystander identity unless an explicit forensic export capability includes them.

## 13. Vulnerability reporting

Do not open a public issue containing credentials, private footage, exploitable vendor details,
active account tokens, device certificates, or a zero-day. Use GitHub’s private vulnerability
reporting for the eventual public repository. Include affected revision, deployment profile,
reproduction using synthetic/sanitized material, impact, and any known workaround.

Security claims remain unqualified until a dedicated contact and private-reporting workflow are
configured on the public repository.
