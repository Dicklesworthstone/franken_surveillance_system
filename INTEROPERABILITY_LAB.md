# Authorized interoperability lab

## 1. Purpose

The lab exists to integrate consumer devices whose owner-facing functionality is available only
through proprietary apps or undocumented transports. Its goal is a narrow, maintainable,
authenticated interoperability adapter—not exploitation, account bypass, universal tooling, or
access to anyone else’s system.

## 2. Lab topology

```text
owned test camera/drone/base
        │ isolated Wi-Fi/VLAN
        ▼
dedicated phone/emulator/controller profile
        │
lab capture bridge / proxy / instrumentation
        │
sanitation boundary
        ▼
protocol simulator + deterministic fixtures
        │
FSS adapter implementation and gauntlet
```

Production credentials and private household footage do not enter the repository fixture path.

## 3. Experiment record

Each experiment records:

- `LAB-` stable ID;
- owner authorization and device provenance;
- exact hardware, firmware, app, OS, region, account/device settings;
- question and falsifiable hypothesis;
- normal vendor workflow used;
- network/process/display instrumentation;
- collection start/end and data classes;
- immediate sanitization steps;
- observations, uncertainty, and alternate explanations;
- negative result or failure;
- artifacts and hashes;
- whether publication is safe;
- next experiment and stop condition.

Failed approaches are retained so future agents do not rediscover or overstate them.

## 4. Preferred investigation order

1. official open standard or local endpoint;
2. official SDK/API and exact product support list;
3. documented file export or local storage;
4. user-authorized app intent/deep link/share/display capture;
5. local traffic shape and protocol simulation;
6. minimal owner-authenticated protocol client;
7. stop when the remaining path would require bypassing authentication, weakening device security,
   accessing third-party data, or publishing broadly dangerous secrets.

## 5. Simulator-first implementation

The live device is not the development test harness. Sanitized observations become a deterministic
simulator capable of:

- auth success/expiry/revocation without real secrets;
- stream negotiation and first-frame delay;
- packet shapes and errors;
- reconnect and firmware drift;
- vendor rate limit/cloud outage;
- control ACK/timeout/indeterminate outcomes;
- malformed and adversarial input.

The adapter is implemented against this simulator, then differentially compared to the owned
device. CI never requires vendor credentials or live hardware.

## 6. Publication red lines

Never publish:

- live tokens, refresh tokens, passwords, device certificates, signing keys;
- a generic bypass or universal account/device key;
- third-party endpoints or identifiers collected incidentally;
- private packet captures, audio, video, addresses, Wi-Fi names, or phone data;
- code to defeat certificate validation, secure boot, pairing, or owner notification;
- instructions to enumerate or access devices outside the configured owner scope;
- a method whose principal value is unauthorized access rather than interoperability.

Publish sanitized message schemas, deterministic fixtures, stable errors, and the minimum normal-
auth protocol behavior required for the adapter.

## 7. Firmware compatibility

A proprietary adapter is certified to a tuple, not a brand:

```text
manufacturer
model and hardware revision
firmware version
base-station version
mobile app version
OS/platform
account region and feature flags
adapter revision
```

Unknown tuples fail closed or enter a read/import-only degraded mode. Silent optimistic operation
is forbidden. Upgrade qualification runs in shadow before production activation.

## 8. Mobile/app capture boundary

Some products may permit no stable stream beyond the official app. A bounded display-capture
bridge can still have value, but it is labeled accurately:

- it captures an owner-authorized displayed live view;
- it may lose original codec/timestamps/metadata;
- it depends on app layout, focus, OS capture permissions, and device performance;
- it cannot claim packet continuity or camera-source fidelity;
- it may be useful for calibration or temporary observation, not authoritative continuous archive;
- every captured frame’s provenance includes the display bridge generation.

## 9. DJI-specific boundary

DJI Flip is initially manual-only. A lab may investigate owner-side live-view capture or file
transfer exposed by DJI Fly. FSS will not represent unsupported Mobile SDK access, reverse-
engineered flight control, or autonomous missions as part of the adapter. Flight effects remain a
separate disabled capability even if video capture becomes qualified.

## 10. Exit criteria

A lab adapter can leave `lab` only when:

- normal authorization and revocation work;
- exact compatibility tuple is known;
- secret and process isolation pass;
- acquisition state/continuity semantics are honest;
- long soak and reconnect pass;
- malformed input and cancellation pass;
- privacy/log/support-bundle review passes;
- simulator and live device differential pass;
- firmware drift fails safely;
- negative evidence and unsupported features are public;
- maintenance owner accepts the expected vendor breakage burden.
