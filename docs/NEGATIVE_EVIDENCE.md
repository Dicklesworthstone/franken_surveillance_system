# Negative evidence ledger

This ledger records hypotheses that failed, did not improve the system, or produced a narrower
result than expected. A failed experiment is not deleted when a new candidate appears.

## Required fields

| Field | Meaning |
|---|---|
| ID | Stable `NEG-###` identifier |
| Date / commit | Exact experiment context |
| Hypothesis | What was expected and why |
| Setup | Corpus, device/model/firmware/platform, policy, command, and artifact digests |
| Result | Measurements, failures, divergences, and confidence |
| Decision | Reject, retain as oracle, narrow scope, or revisit |
| Revival condition | New evidence that would justify repeating the work |

## Entries

No implementation experiments have been run. The architecture research already records these
negative constraints:

### NEG-001 — Do not make DJI Flip SDK support an architectural dependency

- **Hypothesis:** the drone can be treated as a normal officially supported DJI Mobile SDK source.
- **Finding:** current public supported-product documentation does not establish DJI Flip support.
- **Decision:** recorded-file import and authorized capture-bridge experiments only; manual flight;
  an unsupported result is acceptable.
- **Revival:** an official compatible SDK/product listing or a repeatable, owner-authorized,
  supportable capture surface.

### NEG-002 — Do not treat proprietary app access as a stable camera standard

- **Hypothesis:** a consumer camera advertised with Wi-Fi/cloud viewing has a stable local stream.
- **Finding:** public owner-facing documentation for target proprietary products does not establish
  a durable ONVIF/RTSP contract.
- **Decision:** standards-first adapters; vendor paths remain exact-tuple interoperability-lab work.
- **Revival:** official local API/profile support or a qualified owner-authorized adapter matrix.

### NEG-003 — Do not select one frontier VLM as the complete security stack

- **Hypothesis:** the newest large multimodal model can replace detection, tracking, geometry, and
  calibrated event policy.
- **Finding:** latency, licensing, temporal grounding, reproducibility, and failure isolation differ
  by task; no single current candidate establishes the complete contract.
- **Decision:** progressive model cascade with immutable generations and held-out event gauntlets.
- **Revival:** a candidate passes every task, license, cost, privacy, and deterministic boundary
  against the decomposed incumbent under the same workload.

### NEG-004 — TUTK OLD-protocol LAN search does not discover Wyze NEW-protocol firmware

- **Hypothesis:** the credential-less TUTK/IOTC OLD-protocol `0x0601` LAN-search probe
  (TransCodePartial cipher, byte-exact vs the CuboAI-verified oracle) discovers the owner's Wyze
  cameras on the authorized LAN, giving a pre-credential discovery path.
- **Date / commit:** 2026-10-07 first negative (python oracle); 2026-10-08 Rust re-run at
  `0dfff448` (`fss-tutk::oldproto` + `examples/oldproto_probe.rs`).
- **Setup:** owner LAN 192.168.4.0/22; 88-byte `0x0601` probe, empty UID (all devices), 3 rounds;
  targets: 255.255.255.255:32761, 192.168.7.255:32761 (directed broadcast), and unicast to all
  three known Wyze addresses (192.168.4.23/.24, 192.168.5.242). Cipher differential vs oracle:
  2,700 cases, 0 failures.
- **Result:** 0 answers in every round — Wyze NEW-protocol (0xCC51) firmware absorbs OLD-protocol
  probes without responding (does not answer empty-UID search). One camera (192.168.4.23) was
  verifiably awake and answering NEW-protocol discovery on port 32761 during the same window, so
  the absence is protocol behavior, not an offline camera.
- **Decision:** narrow scope — the probe is retained for older-firmware Wyze tuples and other TUTK
  brands (CuboAI, Shenzhen IPCs); it is NOT a discovery path for the qualified
  HL_CAM4/4.52.17.26 tuple. NEW-protocol `0x1002` discovery is the only supported path there.
- **Revival:** a Wyze firmware generation that answers `0x0601`, or an owner-added device of
  another TUTK brand on the LAN.
