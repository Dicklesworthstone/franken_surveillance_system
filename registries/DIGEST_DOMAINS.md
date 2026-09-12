# Canonical Digest Domain Registry

Registry of canonical-digest domain tags used for domain separation in deterministic encoding and content addressing. These identifiers operate as typed digest domain boundaries rather than standalone interchange schemas.

| ID | Domain | Scope | Authority | Invariant rule |
|---|---|---|---|---|
| `SCHEMA-DOMAIN-CANONICAL-001` | `fss.canonical.v1` | Core canonical codec | authority/encoding | root canonical encoder domain tag; immutable across versions |
| `SCHEMA-DOMAIN-AGENT-CONTROL-ENVELOPE-001` | `fss.agent_control_envelope.v1` | Agent control plane | control intent | categorized control envelope digest domain; branches and world bindings immutable |
| `SCHEMA-DOMAIN-AGENT-RESOURCE-STATE-001` | `fss.agent_resource_state.v1` | Agent resource model | resource authority | resource-state canonical digest domain; budgets, pressure, and degraded dimensions preserved |
| `SCHEMA-DOMAIN-AGENT-SILENCE-CERT-001` | `fss.agent_silence_certificate.v1` | Meaningful delta | epistemic continuity | silence certificate digest domain; window bounds and non-reporting witness verifiable |
| `SCHEMA-DOMAIN-CONTINUATION-PAGE-001` | `fss.continuation_page.v1` | Continuation pagination | context/hydration | continuation page boundary digest domain; page range and item digest immutable |
| `SCHEMA-DOMAIN-CONTINUATION-STREAM-001` | `fss.continuation_stream.v1` | Continuation streaming | context/hydration | continuation stream boundary digest domain; stream sequence and items monotonic |
| `SCHEMA-DOMAIN-EFFECT-JOURNAL-001` | `fss.effect_journal.v1` | Effect execution | effect truth | effect journal entry digest domain; idempotency and state monotonicity preserved |
| `SCHEMA-DOMAIN-EFFECT-PROOF-001` | `fss.effect_proof.v1` | Effect execution | effect truth | effect terminal proof canonical digest domain; binds full intent and terminal predicate |
| `SCHEMA-DOMAIN-EFFECT-TRANSITION-001` | `fss.effect_transition.v1` | Effect execution | effect truth | effect transition canonical digest domain; lifecycle state and proof preserved |
| `SCHEMA-DOMAIN-REFERENCE-STATE-001` | `fss.reference_state.v1` | Sensor evidence | authority/evidence | reference state witness domain tag; calibration and baseline immutable |
| `SCHEMA-DOMAIN-HANDLE-DESCRIPTOR-001` | `fss.semantic_handle_descriptor.v1` | Semantic hydration | context/hydration | handle descriptor revision digest domain; level, budget, and ladder policy immutable |
| `SCHEMA-DOMAIN-HANDLE-IDENTITY-001` | `fss.semantic_handle_identity.v1` | Semantic hydration | context/hydration | semantic handle identity domain tag; immutable across descriptor revisions |
| `SCHEMA-DOMAIN-HANDLE-LADDER-POLICY-001` | `fss.semantic_handle_ladder_policy.v1` | Semantic hydration | context/hydration | hydration ladder policy domain tag; step sequence and level requirements invariant |
| `SCHEMA-DOMAIN-SENSOR-METADATA-001` | `fss.sensor_capsule.metadata.v1` | Sensor evidence | authority/sensor | sensor capsule metadata domain tag; frame timing and sensor parameters preserved |
| `SCHEMA-DOMAIN-TOMBSTONE-001` | `fss.tombstone.v1` | Stable identities | authority/identity | tombstone record canonical digest domain; stable ID, prior generation, and witness preserved |
