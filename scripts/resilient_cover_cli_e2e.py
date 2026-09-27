#!/usr/bin/env python3
"""Native retained-source regression harness for fss-cover select-resilient.

Requires already-built fss-file, fss-event and fss-cover from the same checkout.
Uses only synthetic static JPEGs and exact coverage approvals. Python is a test
peer, not an alternative production solver or evidence authority. No build/network.
"""
from __future__ import annotations

import argparse
import itertools
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from set_cover_cli_e2e import SITE, WINDOW, command, import_sensor, retain, selection, state

KIND_ORDER = {kind: index for index, kind in enumerate(("network", "power", "clock", "host"))}
DOMAINS = ["power:ups=sensor:a,sensor:b", "network:switch=sensor:b,sensor:c"]


def direct_oracle(support: dict[str, set[str]], zones: list[str], failures: list[set[str]],
                  mandatory: set[str], excluded: set[str], maximum: int) -> list[str] | None:
    """Direct observer-set oracle; no expanded obligations, masks or production search code."""
    sensors = sorted(support)
    for size in range(min(maximum, len(sensors)) + 1):
        for picked in itertools.combinations(sensors, size):
            selected = set(picked)
            if not mandatory <= selected or excluded & selected:
                continue
            if all(any(zone in support[sensor] for sensor in selected - failed)
                   for failed in [set(), *failures] for zone in zones):
                return list(picked)
    return None


def check_report(report: dict[str, Any], support: dict[str, set[str]]) -> None:
    """Relational checks against known synthetic facts, beyond JSON Schema shape checks."""
    assert report["format"] == "fss.coverage_resilient_selection.v1"
    assert report["authority"] == "derived_cognition_no_effect_authority"
    assert report["scenario_semantics"] == "baseline_and_each_declared_domain_separately"
    assert report["anchor"] == report["witness"]["anchor"] == report["source_coverage_witness"]["anchor"]
    assert report["witness"]["inputDigest"] == report["expanded_input_digest"]
    assert report["source_coverage_witness_digest"] in report["witness"]["projectionId"]
    assert report["witness"]["algorithmId"] == "ALG-SETCOVER-001"
    assert report["source_coverage_witness"]["algorithmId"] == "ALG-BRIDGE-001"
    assert report["capture_window"]["selection"] == "whole-witness-v1"
    assert report["capture_window"]["clock_alignment"] == "operator_hints_not_calibration"
    objective = report["objective"]
    zones = objective["required_zones"]
    assert zones == sorted(set(zones))
    selected = report["selected_sensors"]
    assert selected == sorted(set(selected)) and set(selected) <= support.keys()
    assert len(selected) == report["selection_cost_units"] <= objective["maximum_sensors"]
    mandatory = set(objective["mandatory_sensors"])
    excluded = set(objective["excluded_sensors"])
    assert mandatory <= set(selected) and not excluded & set(selected)
    domains = report["failure_domains"]
    keys = [(KIND_ORDER[domain["kind"]], domain["id"]) for domain in domains]
    assert keys == sorted(set(keys)) and domains
    for domain in domains:
        assert domain["members"] == sorted(set(domain["members"]))
        assert domain["members"] and set(domain["members"]) <= support.keys()
        assert domain["node_id"] == f"failure/{domain['kind']}/{domain['id']}"
    failures = [set(domain["members"]) for domain in domains]
    rows = report["obligations"]
    assert len(rows) == (len(domains) + 1) * len(zones) <= 64
    uncovered = uncoverable = 0
    for scenario, (domain, failed) in enumerate([(None, set()), *zip(domains, failures)]):
        for index, zone in enumerate(zones):
            row = rows[scenario * len(zones) + index]
            assert row["zone_scope"] == zone
            assert row["failed_domain"] == (None if domain is None else domain["node_id"])
            assert row["obligation_id"] == f"obligation:{report['reduction_input_digest']}:{scenario}:{index}"
            providers = sorted(sensor for sensor in set(selected) - failed if zone in support[sensor])
            eligible = [sensor for sensor in support.keys() - excluded - failed if zone in support[sensor]]
            expected = "supported" if providers else ("uncovered" if eligible else "uncoverable")
            assert row["status"] == expected, (row, expected)
            assert row["sensor_id"] == (providers[0] if providers else None)
            uncovered += not providers
            uncoverable += not eligible
    assert report["objective_covered"] == (uncovered == 0) == (report["status"] == "covered")
    assert (report["status"] == "uncoverable") == (uncoverable > 0)
    optimum = direct_oracle(support, zones, failures, mandatory, excluded, objective["maximum_sensors"])
    if report["method"] == "exact_small":
        assert report["witness"]["exactness"] == "exact"
        assert report["status"] != "heuristic_incomplete"
        if optimum is None:
            assert report["status"] in ("uncoverable", "infeasible_within_limit")
        else:
            assert report["status"] == "covered" and selected == optimum
    else:
        assert report["method"] == "greedy" and report["witness"]["exactness"] == "approximate"
        assert report["status"] != "infeasible_within_limit"
        if report["status"] == "covered":
            assert optimum is not None


def query(bins: dict[str, Path], root: Path, zones: list[str], domains: list[str],
          support: dict[str, set[str]], extra: list[str] | None = None, *,
          during: str = WINDOW, succeeds: bool = True) -> tuple[bytes, dict[str, Any] | None]:
    args: list[str | Path] = ["select-resilient", "--root", root, "--site", SITE, "--during", during]
    for zone in zones:
        args += ["--zone", "zone:" + zone]
    for domain in domains:
        args += ["--failure-domain", domain]
    args += extra or []
    before = state(root)
    output = command(bins["fss-cover"], args, succeeds=succeeds)
    assert state(root) == before, "resilient selection changed deployment bytes or metadata"
    if not succeeds:
        return output.stdout, None
    report = json.loads(output.stdout)
    check_report(report, support)
    checkout = Path(__file__).resolve().parents[1]
    report_file = root.parent / "last-resilient-report.json"  # outside the deployment
    report_file.write_bytes(output.stdout)
    validated = subprocess.run([
        sys.executable, "-B", str(checkout / "scripts/json_instance_validate.py"),
        str(checkout / "schemas/coverage_resilient_selection.v1.json"), str(report_file),
    ], capture_output=True, timeout=30, check=False)
    assert validated.returncode == 0, validated.stderr.decode(errors="replace")
    return output.stdout, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error("assertions must be enabled; do not use python -O")
    bins = {name: args.bin_dir.resolve() / name for name in ("fss-file", "fss-event", "fss-cover")}
    missing = [name for name, path in bins.items() if not path.is_file()]
    if missing:
        parser.error("native tests NOT RUN; missing binaries: " + ", ".join(missing))
    with tempfile.TemporaryDirectory(prefix="fss-resilient-cover-e2e-") as directory:
        work = Path(directory)
        root = work / "deployment"
        zones = ["gate", "yard"]
        support = {f"sensor:{name}": {"zone:gate", "zone:yard"} for name in "abc"}
        for name in "abc":
            retained_id = import_sensor(bins, work, root, name)
            retain(bins, root, retained_id, zones)
        # The ordinary minimum is A; the resilient minimum for these overlapping domains is A,C.
        nominal_raw, nominal = selection(bins, root, zones, ["--max-sensors", "2"])
        assert nominal is not None and nominal["selected_sensors"] == ["sensor:a"]
        raw, exact = query(bins, root, zones, DOMAINS, support, ["--max-sensors", "2"])
        assert exact is not None and exact["selected_sensors"] == ["sensor:a", "sensor:c"]
        assert exact["source_coverage_witness_digest"] == nominal["source_coverage_witness_digest"]
        assert exact["anchor"] == nominal["anchor"]
        reordered = ["network:switch=sensor:c,sensor:b", "power:ups=sensor:b,sensor:a"]
        again, _ = query(bins, root, list(reversed(zones)), reordered, support, ["--max-sensors", "2"])
        assert raw == again
        pin = exact["source_coverage_witness_digest"]
        pinned, _ = query(bins, root, zones, DOMAINS, support, ["--max-sensors", "2", "--expected-coverage", pin])
        assert pinned == raw
        # Re-running nominal selection after resilient queries must not change its bytes.
        nominal_again, _ = selection(bins, root, zones, ["--max-sensors", "2"])
        assert nominal_again == nominal_raw
        for method in ["exact-small", "greedy"]:
            _, full = query(bins, root, zones, DOMAINS, support, ["--method", method, "--max-sensors", "2"])
            assert full is not None and full["status"] == "covered"
            _, limited = query(bins, root, zones, DOMAINS, support, ["--method", method, "--max-sensors", "1"])
            assert limited is not None and limited["status"] == ("infeasible_within_limit" if method == "exact-small" else "heuristic_incomplete")
            _, impossible = query(bins, root, zones, DOMAINS, support, ["--method", method, "--exclude-sensor", "sensor:c"])
            assert impossible is not None and impossible["status"] == "uncoverable"
        _, mandatory = query(bins, root, zones, DOMAINS, support, ["--require-sensor", "sensor:b", "--max-sensors", "3"])
        assert mandatory is not None and mandatory["selected_sensors"] == ["sensor:a", "sensor:b", "sensor:c"]
        assert all(row["sensor_id"] != "sensor:b" for row in mandatory["obligations"] if row["failed_domain"] is not None)
        query(bins, root, zones, DOMAINS, support, ["--require-sensor", "sensor:b", "--max-sensors", "2"])
        _, all_lost = query(bins, root, zones, ["host:all=sensor:a,sensor:b,sensor:c"], support)
        assert all_lost is not None and all_lost["status"] == "uncoverable"
        # Missing zones remain obligations in every scenario. A different time has no providers.
        query(bins, root, ["unseen"], DOMAINS, support)
        query(bins, root, zones, DOMAINS, {sensor: set() for sensor in support}, during="5000000000:6000000000")
        renamed = ["power:renamed=sensor:a,sensor:b", DOMAINS[1]]
        _, rebound = query(bins, root, zones, renamed, support, ["--max-sensors", "2", "--expected-coverage", pin])
        assert rebound is not None and rebound["source_coverage_witness_digest"] == pin
        assert rebound["selected_sensors"] == exact["selected_sensors"]
        assert rebound["reduction_input_digest"] != exact["reduction_input_digest"]
        assert rebound["witness_digest"] != exact["witness_digest"]
        for extra in (["--work-units", "1"], ["--max-report-bytes", "1024"],
                      ["--require-sensor", "sensor:unknown"], ["--max-domain-losses", "2"],
                      ["--require-sensor", "sensor:a", "--exclude-sensor", "sensor:a"]):
            query(bins, root, zones, DOMAINS, support, list(extra), succeeds=False)
        for domains in ([], ["power:ups=sensor:unknown"], [DOMAINS[0], DOMAINS[0]],
                        ["power:ups=sensor:a,sensor:a"]):
            query(bins, root, zones, list(domains), support, succeeds=False)
        # D is a real retained sensor, but only in a disjoint later interval. It must not rescue
        # this window, even when explicitly mandatory, and the previous source pin is now stale.
        later = import_sensor(bins, work, root, "d", start=20_000_000_000)
        retain(bins, root, later, zones)
        support["sensor:d"] = set()
        query(bins, root, zones, DOMAINS, support, ["--expected-coverage", pin], succeeds=False)
        _, latest = query(bins, root, zones, DOMAINS, support, ["--max-sensors", "2"])
        assert latest is not None and latest["selected_sensors"] == ["sensor:a", "sensor:c"]
        assert latest["source_coverage_witness_digest"] != pin
        _, idle_mandatory = query(bins, root, zones, DOMAINS, support, ["--require-sensor", "sensor:d", "--max-sensors", "3"])
        assert idle_mandatory is not None and "sensor:d" in idle_mandatory["selected_sensors"]
        assert all(row["sensor_id"] != "sensor:d" for row in idle_mandatory["obligations"])
        query(bins, root, zones, ["clock:later=sensor:d"], support, ["--max-sensors", "1"])
        # The 65+ obligation request is malformed independently of an absent source root.
        absent = work / "must-not-be-created"
        oversized: list[str | Path] = ["select-resilient", "--root", absent, "--site", SITE,
                                       "--during", WINDOW, "--failure-domain", DOMAINS[0]]
        for index in range(33):
            oversized += ["--zone", f"zone:z{index}"]
        refused = command(bins["fss-cover"], oversized, succeeds=False)
        assert b"64 baseline/scenario-zone obligations" in refused.stderr and not absent.exists()
    print("PASS: native resilient retained-evidence selection, decoded scenario support, source pins, disjoint windows and read-only state")


if __name__ == "__main__":
    main()
