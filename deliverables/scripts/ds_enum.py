import sys, importlib.util, json
spec = importlib.util.spec_from_file_location("t", "deliverables/scripts/tapo_connectap_sc.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)

HOST = "192.168.4.70"
CANDIDATES = [
    # media/clip/log/file family (camera-generation methods)
    "getMediaClipList", "searchClipList", "getVideoClip", "exportClip",
    "getRecordList", "getRecordPlan", "getMediaFileList",
    "getLogList", "getDeviceLog", "exportLog", "logExport", "getLogs",
    "getSnapUrl", "getSnapshotUrl", "getSnapshotConfig", "getScreenshot",
    "getFileList", "readFile", "downloadFile", "exportFile", "getExportFile",
    "getUpgradeInfo", "getFwInfo", "getFirmwareInfo", "getUpgradeProgress",
    "getCloudConfig", "getSystemLog", "exportSystemLog", "getDebugInfo",
    "getDeviceRecording", "getLocalRecordConfig", "getSdCardStatus",
    "getMediaManageConfig", "getTimeZone", "getDeviceTime", "getTimezone",
    "getCachedMediaList", "getLastClipInfo", "getVideoQuality",
]
s = t.login(HOST, tries=60)
results = {}
for m in CANDIDATES:
    # batch in one multipleRequest, params minimal "get"
    body = {"method": "multipleRequest", "params": {"requests": [
        {"method": m, "params": {"get": None}}]}}
    r = t.req(HOST, s, {"method": m, "params": {"get": None}})
    inner = None
    if isinstance(r, dict):
        resps = (r.get("result") or {}).get("responses") or [r]
        inner = resps[0]
    code = (inner or {}).get("error_code", "?")
    results[m] = (code, json.dumps(inner or r)[:110])
    print("%-24s %s" % (m, results[m][1][:100]))
# unknown = -40210; anything else = REAL method
print("\n=== real methods (error_code != -40210):")
for m, (c, d) in results.items():
    if c != -40210:
        print(m, c, d)
