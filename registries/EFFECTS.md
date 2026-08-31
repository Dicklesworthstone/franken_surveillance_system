# Effect registry

Every effect has prepare, revalidate, commit, observe, verify, cancel, and reconcile semantics.

| ID | Effect | Reversibility | Required verification | v1 disposition |
|---|---|---|---|---|
| `EFFECT-ALERT-001` | send event alert | compensable by correction, not retractable | durable provider receipt or explicit indeterminate | target |
| `EFFECT-ACK-001` | acknowledge/annotate event | supersedable | canonical event annotation revision | target |
| `EFFECT-PTZ-001` | move camera PTZ | normally reversible | observed pose/scene and restore obligation | future after standards baseline |
| `EFFECT-CAMERA-SETTING-001` | change imaging/bitrate/audio/event settings | reversible where old value known | readback + stream-generation rollover | future |
| `EFFECT-SPOTLIGHT-001` | temporary light/siren control | reversible, physically observable | device state and timeout restore | disabled by default |
| `EFFECT-RETENTION-001` | change retention policy | prospective; deletion may be irreversible | policy revision and affected-object plan | target admin path |
| `EFFECT-ARCHIVE-PUBLISH-001` | publish encrypted archive root | additive | root/child/retrievability proof | target |
| `EFFECT-ARCHIVE-DELETE-001` | delete/cryptographically erase archive | irreversible | closure proof or blocked reason | target admin path |
| `EFFECT-EXPORT-001` | create/share evidence package | disclosure irreversible | root, recipient, access/expiry receipt | target admin path |
| `EFFECT-PRIVACY-MASK-001` | change capture/redaction mask | reversible prospectively | rendered preview + policy revision + coverage impact | target admin path |
| `EFFECT-MODEL-ACTIVATE-001` | activate model/index generation | reversible by rollback | atomic generation readback + shadow proof | target |
| `EFFECT-CALIBRATION-ACTIVATE-001` | activate calibration certificate | reversible | exact certificate generation and residual gate | target |
| `EFFECT-ADAPTER-UPGRADE-001` | activate adapter/firmware compatibility tuple | reversible by rollback | shadow/soak receipt | target |
| `EFFECT-REPAIR-001` | mutate ledger/object state per sealed plan | potentially irreversible | revalidation, mutation receipts, post-doctor | target |
| `EFFECT-DRONE-FLIGHT-001` | command drone mission | physically consequential | separate flight-safety system | forbidden in v1 |
| `EFFECT-OFFENSIVE-001` | pursue, restrain, harm, or deploy weapon | dangerous | none acceptable | forbidden |
