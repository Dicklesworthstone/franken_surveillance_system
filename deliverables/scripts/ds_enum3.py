import sys, importlib.util, json
spec = importlib.util.spec_from_file_location("t", "deliverables/scripts/tapo_connectap_sc.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
HOST = "192.168.4.70"
s = t.login(HOST, tries=60)
def probe(method, params, label=""):
    r = t.req(HOST, s, {"method": method, "params": params})
    inner = None
    if isinstance(r, dict):
        resps = (r.get("result") or {}).get("responses") or [r]
        inner = resps[0]
    code = (inner or {}).get("error_code", "?")
    print("%-28s %s %s" % (label or method, code, json.dumps(inner or r)[:150]))
    return inner

# full getCloudConfig result:
probe("getCloudConfig", {"get": None}, "getCloudConfig full")
# firmware upgrade namespace (C460 is newer gen — 'upgrade' component):
for m, p in [
    ("getFirmwareUpgradeState", {"get": None}),
    ("getFirmwareDownloadProgress", {"get": None}),
    ("getLatestFirmware", {"get": None}),
    ("checkFirmware", {"get": None}),
    ("getUpgradeInfo", {"get": None}),
    ("getDeviceInformation", {"get": None}),
    ("getSystemInfo", {"get": None}),
    ("getHWInfo", {"get": None}),
    ("getDiagnoseInfo", {"get": None}),
    ("getComponentList", {"get": None}),
    ("getModuleInfo", {"get": None}),
    ("getLogSetting", {"get": None}),
    ("getLogFileList", {"get": None}),
]:
    probe(m, p)
