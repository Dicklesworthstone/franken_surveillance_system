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
