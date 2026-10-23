# EV pack — H-012: vendor APK reverse engineering (Owlet, Canary)

Method: `apkeep -d apk-pure -o 'acknowledge_dangers=true,arch=arm64-v8a;armeabi-v7a'`, then
`unzip` and a `strings` pass over the dex before any decompilation (`jadx` for the hot packages).
Only the two families with no usable protocol knowledge were pulled.

## Owlet — `com.owletcare.sleep` 3.40.1

The camera is **ThroughTek Kalay (TUTK/IOTC) plus Ayla Networks**, i.e. two independent stacks:

- TUTK: `com.tutk.IOTC.IOTCAPIs`, `AVAPIs`, `P2PTunnelAPIs`, `st_SearchDeviceInfo`, and — new —
  **`IOTC_Lan_Search` / `IOTC_Search_Device_Start` / `IOTC_Set_LanSearchPort` /
  `IOTC_Set_Device_Lan_Detectable` / `IOTC_WakeUp_WakeDevice`**. The app can put the camera in
  "LAN mode" and wake it; strings `Device must be in LAN mode`, `Device is not in LAN mode`,
  `Enable Lan Mode`, `CamSDK.IOTCLanSearch` come from the UI.
- Ayla local control (`com.aylanetworks.aylasdk.localcontrol.lan.*`: `AylaHttpServer`,
  `AylaEncryption`, `AylaLanMessage`, `AylaCommand`) exposing an HTTP API:

```
/local_lan/key_exchange.json          /local_lan/commands.json
/local_lan/status.json                /local_lan/property/datapoint.json
/local_lan/wifi_scan.json             /local_lan/wifi_scan_results.json
/local_lan/wifi_status.json           /local_lan/wifi_stop_ap.json
/local_lan/regtoken.json              /local_lan/oats_get.json
/local_lan/connect_status             /local_lan/node/conn_status.json
```

The endpoint list is a ready-made attack surface (parsers behind a key exchange) once the device is
reachable, and `wifi_scan` / `wifi_stop_ap` are effect paths.

**The UID is the gate.** TUTK discovery needs it. The app gets it from the cloud as a device
property (`tutkId`, threaded through `CameraV2SetupAction`), and it is also shown in the app's own
**debug drawer** under "camera auth data" (`debug_drawer_camera_auth_data_tutk_id`). So one
screenshot of that drawer yields UID (and any AuthKey shown), after which
`IOTC_WakeUp_WakeDevice` + `IOTC_Lan_Search` work without the cloud.

## Canary — `is.yranac.canary`

Confirms the REST host `https://api.canaryis.com` — the same domain family as the SNIs already
observed on the wire (`i.` ingress, `o.`, `v.`). OkHttp `CertificatePinner` is present; whether a pin
set is actually configured was not settled from strings alone (library class names dominate).
No local streaming protocol strings surfaced (no RTSP/ONVIF/server socket in the app), consistent
with the observed outbound-only device behaviour.

## Why this matters

- Owlet: turns "we cannot even find it" into "get one string from the UI, then wake and search".
- Canary: the remaining blocker is a trust anchor; if the app pins a leaf key, a forged CA is
  pointless and the app-side path (owner account) is the only one. Worth confirming from
  `javap`/jadx of the network module before more MITM effort.
