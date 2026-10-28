import sys, importlib.util, json
spec = importlib.util.spec_from_file_location("t", "deliverables/scripts/tapo_connectap_sc.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
HOST = "192.168.4.70"
s = t.login(HOST, tries=60)

def probe(method, params):
    r = t.req(HOST, s, {"method": method, "params": params})
    inner = None
    if isinstance(r, dict):
        resps = (r.get("result") or {}).get("responses") or [r]
        inner = resps[0]
    code = (inner or {}).get("error_code", "?")
    return code, json.dumps(inner or r)[:130]

# component namespaces (device_info style) — the known-working getDeviceInfo shape
COMPONENTS = ["firmware", "cloud_config", "ota", "log", "file", "media",
              "record", "sd_card", "system", "debug", "export", "time",
              "storage", "snapshot", "video", "clip"]
print("== component getDeviceInfo probes:")
for c in COMPONENTS:
    code, d = probe("getDeviceInfo", {"device_info": {"name": [c]}})
    if code != -40101:
        print("  %-14s %s %s" % (c, code, d[:110]))

print("== component-style method probes (get.<component>):")
for c in COMPONENTS:
    code, d = probe("get" + c.replace("_", " ").title().replace(" ", ""), {"get": None})
    print("  %-14s %s %s" % (c, code, d[:110]))
