# Device adapter registry

See `DEVICE_ADAPTER_MATRIX.md` for research details.

| ID | Surface | Tier | Current state | Promotion gate |
|---|---|---:|---|---|
| `ADP-REPLAY-001` | deterministic replay | T0 | specified | `GATE-010` |
| `ADP-FILE-001` | bounded media import | T0/T4 | specified | `GATE-010` |
| `ADP-UVC-001` | UVC/UAC | T1 | specified | `GATE-020` |
| `ADP-INSTA-LINK-001` | Insta360 Link via UVC/UAC | T1 | researched, unimplemented | `GATE-020` |
| `ADP-RTSP-001` | RTSP/RTP | T1 | specified | `GATE-030` |
| `ADP-RTSP-JPEG-ARCHIVE-001` | exact retained RTP/JPEG prefix to source-closed MJPEG import | T4 | finite native reference profile; independent physical mapping and unknown capture time | `GATE-040` |
| `ADP-RTSP-REPLAY-ARCHIVE-001` | whole-receipt AVC/HEVC replay to source-closed MP4 import | T4 | finite native reference profile; recorder provenance retained and capture time unknown unless separately declared | `GATE-040` |
| `ADP-ONVIF-T-001` | ONVIF Profile T | T1 | specified | `GATE-030` |
| `ADP-ONVIF-M-001` | ONVIF Profile M metadata | T1 | specified | `GATE-030` |
| `ADP-WYZE-V4-LAB-001` | Wyze Cam v4 owner-auth lab | T3 | research target | `GATE-090` |
| `ADP-AOSU-P1MAX-LAB-001` | AOSU P1 Max owner-auth lab | T3 | research target | `GATE-090` |
| `ADP-DJI-FLIP-LAB-001` | DJI Flip manual capture/import lab (NEG-001 non-SDK) | T3/T4 | research target | `GATE-100` |
| `ADP-YI-IPC-LAB-001` | Yi IPC owner-auth lab (ONVIF gated pre-provisioning) | T3 | research target | `GATE-090` |
| `ADP-S3-IMPORT-001` | S3-compatible import | T4 | specified | `GATE-040` |
