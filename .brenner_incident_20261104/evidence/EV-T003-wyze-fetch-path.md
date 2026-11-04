# EV-T-003: Wyze fetch path — real presigned URL captured, all layers verified
- **type:** experiment
- **captured real camera request body** (forge log, .4.39): mac 80482C525905, enr Lt6RL78/0V0Pe1y2,
  processname wyzeedgeai_cam_v4_test_protocol, filename launch.sh, version 14.9.50040.r
  — the camera EXPLICITLY ASKS for filename=launch.sh. The process channel is not a no-op path.
- **replayed through forge with Host: api.wyzecam.com** → real presigned URL returned:
  https://sinker-t-usw2.s3.us-west-2.amazonaws.com/wyzeedgeai_cam_v4_test_protocol/14.9.50040.r/launch.sh
  ?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=3b69821f... (valid SigV4, 300s expiry)
- **DNS spoof coverage:** caplet lists s3-us-west-2.amazonaws.com — bettercap suffix-matches
  sinker-t-usw2.s3.us-west-2.amazonaws.com. Covered.
- **TLS:** forge cert SAN explicitly includes sinker-t-usw2.s3.us-west-2.amazonaws.com + all Wyze
  hosts. Camera pulled our CA/privkey/rootCA 59 times (it is provisioning against our PKI).
- **Payload serving:** forge GET on the exact URL path returns 200, 661B launch.sh. VERIFIED.
- **Conclusion (H-003/H-004):** the historical fetch gap is explained by the forged 0-signature
  URLs (H-003 mechanism) + possibly checksum-manifest gating (H-004b). With passthrough now
  default, the next camera poll cycle gets a valid URL whose fetch lands on our payload.
  Expected observable: camera-sourced GET of the launch.sh path in forge log within one poll
  cycle, followed by /fss-ran beacon on :8080 if execution follows.
