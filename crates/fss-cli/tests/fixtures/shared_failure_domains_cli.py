"""Test-only JSON/filesystem oracle driven by shared_failure_domains_cli_contract.rs."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

scratch, file_bin, event_bin = sys.argv[1:]
scratch = Path(scratch)
root = scratch / "deployment"
site = "site:shared-failure-cli"


def command(binary, *args, success=True):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, timeout=60)
    if success:
        assert result.returncode == 0, (result.stdout, result.stderr)
    else:
        assert result.returncode != 0, (result.stdout, result.stderr)
        assert result.stdout == b"", "a refused scenario leaked a partial report"
    return result


def graph(*args, success=True):
    return command(event_bin, "graph", "single-points", "--root", root, "--site", site,
                   *args, success=success)


def inventory():
    return {
        str(path.relative_to(root)): (
            path.stat().st_mode, path.stat().st_size, path.stat().st_mtime_ns,
            path.stat().st_ino,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        )
        for path in [root, *root.rglob("*")]
    }


for name, zones in [
    ("north", ["door:64,0,32,32", "gate:0,0,32,32"]),
    ("south", ["door:64,0,32,32", "attic:80,32,32,32"]),
    ("east", ["shed:16,8,32,32"]),
]:
    source = scratch / f"{name}.mjpeg"
    imported = command(file_bin, "import", "--root", root, "--site", site,
                       "--input", source, "--sensor", f"sensor:{name}", "--stream", f"stream:{name}",
                       "--media-format", "mjpeg", "--receive-time-ns", "10000000000000",
                       "--capture-start-ns", "1000000000", "--capture-uncertainty-ns", "1000000",
                       "--assumed-fps", "10")
    identity = next(line.removeprefix("import_identity=") for line in imported.stdout.decode().splitlines()
                    if line.startswith("import_identity="))
    source.unlink()
    watch = ["watch", "--root", root, "--site", site, "--import-id", identity, "--interpretation", "gray"]
    for zone in zones:
        watch += ["--zone", zone]
    preview = json.loads(command(event_bin, *watch).stdout)
    approval = preview["coverage"]["approval_digest"]
    retained = json.loads(command(event_bin, *watch, "--retain-coverage", approval).stdout)
    assert retained["coverage"]["coverage_status"] == "retained"

before = inventory()
plain = graph().stdout
baseline = json.loads(plain)
assert "shared_failure_scenarios" not in baseline
network = "network:lan=sensor:north,sensor:south"
power = "power:ups=sensor:south,sensor:east"
args = ["--failure-domain", network, "--failure-domain", power]
first = graph(*args).stdout
assert first == graph(*args).stdout
assert first == graph("--failure-domain", "power:ups=sensor:east,sensor:south",
                      "--failure-domain", "network:lan=sensor:south,sensor:north").stdout
report = json.loads(first)
shared = report.pop("shared_failure_scenarios")
assert report == baseline, "shared scenarios changed the underlying coverage report"
assert shared["independence"] == "unknown"
assert shared["undeclared_dependencies"] == "unknown_not_absent"
assert shared["joint_domain_failures_evaluated"] is False
assert shared["parent_witness_digest"] == baseline["witness_digest"]
rows = {(row["kind"], row["id"]): row for row in shared["scenarios"]}
assert rows[("network", "lan")]["lost_zones"] == ["zone:door", "zone:gate"]
assert rows[("power", "ups")]["lost_zones"] == ["zone:shed"]
for row in rows.values():
    assert "zone:attic" not in row["lost_zones"], "already-unobserved zone classified as newly lost"
    witness = row["witness"]
    assert witness["algorithmId"] == "ALG-BRIDGE-001"
    assert witness["anchor"] == baseline["anchor"]
    assert baseline["witness_digest"] in witness["projectionId"]
    assert witness["dominantOperationCounts"]["dfs_node_visits"] == witness["nodeCount"]
    assert witness["dominantOperationCounts"]["adjacency_scans"] == 2 * witness["edgeCount"]

# Outside every retained capture interval: no sensor is a qualifying observer, even though
# all sensors and declared domain memberships remain present. No historical edge may leak in.
a = json.loads(graph(*args, "--during", "900000000000:900000000001").stdout)
b = json.loads(graph(*args, "--during", "900000000002:900000000003").stdout)
for result in [a, b]:
    assert all(zone["state"] == "not_observable" for zone in result["zones"])
    assert all(row["lost_zones"] == [] for row in result["shared_failure_scenarios"]["scenarios"])
assert a["shared_failure_scenarios"]["scenarios"][0]["witness"]["inputDigest"] == \
       b["shared_failure_scenarios"]["scenarios"][0]["witness"]["inputDigest"]
assert a["shared_failure_scenarios"]["scenarios"][0]["witness_digest"] != \
       b["shared_failure_scenarios"]["scenarios"][0]["witness_digest"]

for malformed in ["network:lan=", "power:ups=sensor:north,sensor:north", "bogus:x=sensor:north"]:
    command(event_bin, "graph", "single-points", "--root", scratch / "nonexistent",
            "--site", site, "--failure-domain", malformed, success=False)
unknown = graph(*args, "--failure-domain", "host:nvr=sensor:missing", success=False)
assert b"ERR-GRAPH-INPUT-INVALID-001" in unknown.stderr
graph(*args, "--failure-domain", network, success=False)
assert graph().stdout == plain
assert inventory() == before, "read-only common-failure analysis mutated custody"
assert b"--failure-domain" in command(event_bin, "graph", "single-points", "--help").stdout
print("PASS: common failures, overlapping domains, time-window binding, deterministic bytes, unknowns and read-only custody")
