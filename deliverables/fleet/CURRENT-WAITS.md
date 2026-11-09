## CURRENT WAITS (auto-generated from the wait ledger — do not edit by hand)

Generated: 2026-11-08T21:15:56-0500  ·  source: /var/lib/fss-telemetry/waits.jsonl  ·  re-run: `wait_ledger.py show`

### OPEN waits (alive — do not re-arm, do not double-run)

| cam | expectation | state | observations | since | note/tag |
|---|---|---|---|---|---|
| wyze-.39/.51 | assis GET for 4.52.17.99.tar capsule (the chain completing) | open | 0 | 2026-11-06T18:00:19 | broker restored 2026-11-06 11:46, sessio |
| wyze-192.168.4.39 | RTSP :554 answering OPTIONS 200 continuously | open | 2 | 2026-11-09T01:53:29 | 2026-11-09T01:52Z DOWN: 0x29e8 with fssu |
| wyze-192.168.4.51 | RTSP :554 serving (OPTIONS round-trip) after the DESCRIBE st | open | 1 | 2026-11-09T02:15:52 | 2026-11-09T02:12Z: wedged after ~40 min  |

### CLOSED waits (evidence bank — a negative here means DO NOT re-run blind)

| cam | expectation | state | observations | since | note/tag |
|---|---|---|---|---|---|
| aosu-192.168.4.86 | Tuya discovery beacons on UDP 6667 (SETUP MODE) | timeout | 0 | 2026-11-06T18:00:19 | ARP ghost at .86, no ping, no beacons si |
| owlet-192.168.4.163 | 0x2041 grant after DTLS chain (probe/nO/ACK/0x06E3/AV-CONNEC | timeout | 1139 | 2026-11-06T18:00:19 | 1139 consecutive no-grant rounds logged  |
| owlet-192.168.4.163 | 0x2041 grant after byte-verbatim LAN-direct replay of the ca | timeout | 50 | 2026-11-06T22:40:00 | H3 CLOSED-NEGATIVE: full 50-frame replay |
| owlet-192.168.4.163 | 0x2041 grant observed at 10x slower cadence | timeout | 15 | 2026-11-06T18:50:26 | H5 CLOSED-NEGATIVE: 5 slow rounds x 3 su |
| owlet-192.168.4.163 | 0x2041 grant observed when probing within seconds of wake | timeout | 3 | 2026-11-06T18:37:39 | H4 CLOSED-NEGATIVE: 3 boot-window rounds |
| tapo-c460-192.168.4.243 | DS-open window during wake for in-band login bypass | timeout | 62880 | 2026-11-06T18:00:19 | incremental sweeper login waits ~62.9k t |
| tapo-c460-192.168.4.243 | PIR-wake fire landing a shell (port 4444 or 23) | timeout | 1 | 2026-11-06T18:00:19 | fire daemon hit PRESENT 2026-11-05 23:31 |
| tapo-c460-192.168.4.243 | camera returns to LAN (PIR wake visible) | timeout | 0 | 2026-11-06T18:26:21 | 13:26 probe: .243 down; fire daemon corr |
| test-local | loopback echo | observed | 1 | 2026-11-06T18:00:26 | selftest |
| wyze-.39/.51 | assis GET for 4.52.17.99.tar from camera IP | cancelled | 0 | 2026-11-09T01:18:39 | superseded 2026-11-09: through the tunne |
| wyze-.39/.51 | camera GET for 4.52.17.99.tar over the supervised trycloudfl | observed | 1 | 2026-11-09T01:20:10 | 2026-11-09T01:19Z synthetic witness: bro |
| wyze-.39/.51 | camera GET for 4.52.17.99.tar over the trycloudflare tunnel | observed | 2 | 2026-11-09T01:19:05 | chain completed; capture started 2026-11 |
| wyze-192.168.4.39 | RTSP :554 OPTIONS 200 after cooldown | timeout | 2 | 2026-11-06T19:10:02 | 14:15: TCP resets continue 30+ min after |
| wyze-192.168.4.39 | RTSP DESCRIBE 200 with known credentials (Digest realm Wyze_ | timeout | 6 | 2026-11-06T18:48:01 | 554 OPEN + OPTIONS 200 proven (RootProof |
| wyze-192.168.4.39 | TUTK DTLS login for a no-reboot helper command (config exfil | timeout | 3 | 2026-11-09T02:06:33 | 2026-11-09T02:05Z: 3/3 attempts fail in  |
| yi-192.168.4.20 | camera joining our AP post re-provision (yi_u1.py catch) | timeout | 0 | 2026-11-06T18:00:19 | listener armed 20h+ (pid 38257 since Nov |
