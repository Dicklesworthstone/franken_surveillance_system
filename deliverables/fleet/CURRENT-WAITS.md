## CURRENT WAITS (auto-generated from the wait ledger — do not edit by hand)

Generated: 2026-11-07T00:24:52-05:00  ·  source: /var/lib/fss-telemetry/waits.jsonl  ·  re-run: `wait_ledger.py show`

### OPEN waits (alive — do not re-arm, do not double-run)

| camera | waiting for | since | notes |
|---|---|---|---|
| wyze-.39/.51 | assis GET for 4.52.17.99.tar capsule (the chain completing) | 2026-11-06T18:00 | broker restored 2026-11-06 11:46, session live, accepted-rewrite firing; waiting on power- |
| wyze-.39/.51 | assis GET for 4.52.17.99.tar from camera IP | 2026-11-06T18:26 | 13:26: 6 GETs all from 160 (smoke tests); no camera-sourced fetch yet; injector cycling wi |
| wyze-192.168.4.39 | RTSP :554 answering OPTIONS 200 continuously | 2026-11-06T22:10 | 17:09: RECOVERED — OPTIONS 200 + DESCRIBE 401-with-nonce (fresh nonce each time). The 13:3 |

### CLOSED waits (evidence bank — a negative here means DO NOT re-run blind)

| camera | waited for | outcome | observations | note |
|---|---|---|---|---|
| tapo-c460-192.168.4.243 | DS-open window during wake for in-band login bypass | timeout | 62880 | incremental sweeper login waits ~62.9k tries as of 2026-11-06 00:19 |
| owlet-192.168.4.163 | 0x2041 grant after DTLS chain (probe/nO/ACK/0x06E3/AV-CONNECT) | timeout | 1139 | 1139 consecutive no-grant rounds logged in /tmp/owlet_root_attempt.log through 2026-11-06  |
| owlet-192.168.4.163 | 0x2041 grant after byte-verbatim LAN-direct replay of the captured app session (50 frames, 0x2043 registrations included) | timeout | 50 | H3 CLOSED-NEGATIVE: full 50-frame replay at original pacing (registrations 0x2043, channel |
| owlet-192.168.4.163 | 0x2041 grant observed at 10x slower cadence | timeout | 15 | H5 CLOSED-NEGATIVE: 5 slow rounds x 3 sub-attempts (30s gaps), full DTLS chain each, zero  |
| wyze-192.168.4.39 | RTSP DESCRIBE 200 with known credentials (Digest realm Wyze_Cam) | timeout | 6 | 554 OPEN + OPTIONS 200 proven (RootProof PASS). DESCRIBE requires Digest auth; 6 candidate |
| owlet-192.168.4.163 | 0x2041 grant observed when probing within seconds of wake | timeout | 3 | H4 CLOSED-NEGATIVE: 3 boot-window rounds fired at t+0s on PRESENT, full DTLS chain each ti |
| wyze-192.168.4.39 | RTSP :554 OPTIONS 200 after cooldown | timeout | 2 | 14:15: TCP resets continue 30+ min after the auth-probe burst. Cameras ARE alive (MQTT PUB |
| tapo-c460-192.168.4.243 | PIR-wake fire landing a shell (port 4444 or 23) | timeout | 1 | fire daemon hit PRESENT 2026-11-05 23:31:42, one shot, no hang; sweeper continues (62.9k l |
| test-local | loopback echo | observed | 1 | selftest |
| aosu-192.168.4.86 | Tuya discovery beacons on UDP 6667 (SETUP MODE) | timeout | 0 | ARP ghost at .86, no ping, no beacons since 2026-11-06 00:30 probe |
| tapo-c460-192.168.4.243 | camera returns to LAN (PIR wake visible) | timeout | 0 | 13:26 probe: .243 down; fire daemon correctly refused re-fire (FORCE gate works); sweeper  |
| yi-192.168.4.20 | camera joining our AP post re-provision (yi_u1.py catch) | timeout | 0 | listener armed 20h+ (pid 38257 since Nov 4); camera low-power ARP-present; needs Yi app pr |

