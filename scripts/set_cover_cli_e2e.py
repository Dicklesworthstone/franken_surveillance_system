#!/usr/bin/env python3
"""Native-binary laboratory test for fss-cover; no build, network or production Python.

Requires fss-file, fss-event and fss-cover already built from this exact tree.
Only synthetic, static, owner-fixture JPEGs are used. This does not evaluate real
camera detection quality or qualify the graph family. No dependency beyond Python
standard library is required to run the harness.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

SITE = "site:set-cover-e2e"
WINDOW = "1500000000:2100000000"
# Generated grayscale, baseline, 96x48 JPEGs; fourteen repetitions make one quiet source.
JPEG_FIXTURES = {
    "a": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/wAALCAAwAGABAREA/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oACAEBAAA/APhSiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiv/9k=",
    "b": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/wAALCAAwAGABAREA/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oACAEBAAA/APn+iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiv/9k=",
    "c": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/wAALCAAwAGABAREA/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oACAEBAAA/AMqiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiv/2Q==",
    "d": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/wAALCAAwAGABAREA/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oACAEBAAA/APVaKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK//9k="
}


def state(root: Path) -> dict[str, tuple[int, int, int, str]]:
    """Detect file-content, membership and metadata writes; access-time reads are irrelevant."""
    result = {}
    for path in sorted([root, *root.rglob("*")]):
        metadata = path.lstat()
        value = "directory" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
        result[str(path.relative_to(root))] = (metadata.st_mode, metadata.st_size, metadata.st_mtime_ns, value)
    return result


def command(binary: Path, args: list[str | Path], *, succeeds: bool = True) -> subprocess.CompletedProcess[bytes]:
    output = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=60, check=False)
    if succeeds and output.returncode:
        raise AssertionError(f"{binary.name} failed ({output.returncode}): {output.stderr.decode(errors='replace')}")
    if not succeeds:
        assert output.returncode != 0, (binary.name, output.stdout)
        assert not output.stdout, ("failure emitted partial report", output.stdout)
    return output


def import_sensor(bins: dict[str, Path], work: Path, root: Path, name: str, start: int = 1_000_000_000) -> str:
    source = work / f"{name}.mjpeg"
    source.write_bytes(base64.b64decode(JPEG_FIXTURES[name]) * 14)
    output = command(bins["fss-file"], [
        "import", "--root", root, "--site", SITE, "--input", source,
        "--sensor", f"sensor:{name}", "--stream", f"stream:{name}", "--media-format", "mjpeg",
        "--receive-time-ns", "10000000000000", "--capture-start-ns", str(start),
        "--capture-uncertainty-ns", "1000000", "--assumed-fps", "10",
    ])
    source.unlink()
    values = [line.removeprefix("import_identity=") for line in output.stdout.decode().splitlines()
              if line.startswith("import_identity=")]
    assert len(values) == 1
    return values[0]


def retain(bins: dict[str, Path], root: Path, import_id: str, zones: list[str]) -> None:
    args: list[str | Path] = ["watch", "--root", root, "--site", SITE, "--import-id", import_id,
                            "--interpretation", "gray", "--confirmation-hits", "1"]
    for zone in zones:
        args += ["--zone", f"{zone}:0,0,40,40"]
    proposal = json.loads(command(bins["fss-event"], args).stdout)
    approval = proposal["coverage"]["approval_digest"]
    retained = json.loads(command(bins["fss-event"], args + ["--retain-coverage", approval]).stdout)
    assert retained["coverage"]["coverage_status"] == "retained"


def selection(bins: dict[str, Path], root: Path, zones: list[str], extra: list[str] | None = None,
              *, during: str = WINDOW, succeeds: bool = True) -> tuple[bytes, dict | None]:
    args: list[str | Path] = ["select", "--root", root, "--site", SITE, "--during", during]
    for zone in zones:
        args += ["--zone", "zone:" + zone]
    args += extra or []
    before = state(root)
    output = command(bins["fss-cover"], args, succeeds=succeeds)
    assert state(root) == before, "read-only selection changed deployment state"
    if not succeeds:
        return output.stdout, None
    report = json.loads(output.stdout)
    assert report["format"] == "fss.coverage_set_selection.v1"
    assert report["authority"] == "derived_cognition_no_effect_authority"
    assert report["objective_covered"] == (report["status"] == "covered")
    assert report["selection_cost_units"] == len(report["selected_sensors"])
    assert report["anchor"] == report["witness"]["anchor"] == report["source_coverage_witness"]["anchor"]
    assert report["witness"]["algorithmId"] == "ALG-SETCOVER-001"
    assert report["source_coverage_witness_digest"] in report["witness"]["projectionId"]
    assert report["capture_window"]["selection"] == "whole-witness-v1"
    assert report["capture_window"]["clock_alignment"] == "operator_hints_not_calibration"
    required = set(report["objective"]["required_zones"])
    support = {row["zone_scope"] for row in report["support_certificate"]}
    assert support | set(report["uncovered_zones"]) == required
    assert not support & set(report["uncovered_zones"])
    assert all(row["sensor_id"] in report["selected_sensors"] for row in report["support_certificate"])
    assert set(report["objective"]["mandatory_sensors"]).issubset(report["selected_sensors"])
    assert not set(report["selected_sensors"]) & set(report["objective"]["excluded_sensors"])
    return output.stdout, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True, help="Directory containing the three already-built native binaries")
    args = parser.parse_args()
    bins = {name: args.bin_dir.resolve() / name for name in ("fss-file", "fss-event", "fss-cover")}
    missing = [name for name, path in bins.items() if not path.is_file()]
    if missing:
        parser.error("native tests NOT RUN; missing binaries: " + ", ".join(missing))
    with tempfile.TemporaryDirectory(prefix="fss-set-cover-e2e-") as directory:
        work = Path(directory)
        root = work / "deployment"
        for name, zones in [("a", ["1", "2", "3", "4"]), ("b", ["1", "2", "5"]), ("c", ["3", "4", "6"])]:
            retained_id = import_sensor(bins, work, root, name)
            retain(bins, root, retained_id, zones)
        zones = [str(i) for i in range(1, 7)]
        raw, exact = selection(bins, root, zones, ["--max-sensors", "2"])
        assert exact is not None and exact["status"] == "covered"
        assert exact["selected_sensors"] == ["sensor:b", "sensor:c"]
        assert exact["witness"]["exactness"] == "exact"
        again, _ = selection(bins, root, list(reversed(zones)), ["--max-sensors", "2"])
        assert raw == again, "canonical reordered objective changed result bytes"
        pinned, _ = selection(bins, root, zones, ["--max-sensors", "2", "--expected-coverage", exact["source_coverage_witness_digest"]])
        assert pinned == raw
        _, greedy = selection(bins, root, zones, ["--max-sensors", "2", "--method", "greedy"])
        assert greedy is not None and greedy["status"] == "heuristic_incomplete"
        assert greedy["selected_sensors"] == ["sensor:a", "sensor:b"]
        assert greedy["uncovered_zones"] == ["zone:6"]
        _, impossible = selection(bins, root, zones, ["--max-sensors", "1"])
        assert impossible is not None and impossible["status"] == "infeasible_within_limit"
        _, mandatory = selection(bins, root, zones, ["--max-sensors", "3", "--require-sensor", "sensor:a"])
        assert mandatory is not None and mandatory["selected_sensors"] == ["sensor:a", "sensor:b", "sensor:c"]
        _, excluded = selection(bins, root, zones, ["--max-sensors", "2", "--exclude-sensor", "sensor:a"])
        assert excluded is not None and excluded["selected_sensors"] == ["sensor:b", "sensor:c"]
        _, no_provider = selection(bins, root, zones, ["--exclude-sensor", "sensor:b"])
        assert no_provider is not None and no_provider["status"] == "uncoverable"
        assert no_provider["uncoverable_zones"] == ["zone:5"]
        _, unknown = selection(bins, root, ["unseen"])
        assert unknown is not None and unknown["uncoverable_zones"] == ["zone:unseen"]
        _, wrong_time = selection(bins, root, zones, during="5000000000:6000000000")
        assert wrong_time is not None and wrong_time["status"] == "uncoverable"
        assert wrong_time["uncoverable_zones"] == ["zone:" + z for z in zones]
        for extra in (["--work-units", "1"], ["--max-report-bytes", "1024"],
                      ["--require-sensor", "sensor:unknown"], ["--zone", "zone:1"],
                      ["--require-sensor", "sensor:a", "--exclude-sensor", "sensor:a"]):
            selection(bins, root, zones, list(extra), succeeds=False)
        # A new sensor sees missing elements only in a disjoint future interval. It cannot
        # become a cheaper common-window provider; the old source witness pin becomes stale.
        later = import_sensor(bins, work, root, "d", start=20_000_000_000)
        retain(bins, root, later, ["5", "6"])
        selection(bins, root, zones, ["--expected-coverage", exact["source_coverage_witness_digest"]], succeeds=False)
        _, latest = selection(bins, root, zones, ["--max-sensors", "2"])
        assert latest is not None and latest["selected_sensors"] == ["sensor:b", "sensor:c"]
        assert latest["source_coverage_witness_digest"] != exact["source_coverage_witness_digest"]
        # Missing required window is rejected before a nonexistent root could be touched.
        absent = work / "must-not-be-created"
        command(bins["fss-cover"], ["select", "--root", absent, "--site", SITE, "--zone", "zone:1"], succeeds=False)
        assert not absent.exists()
        schema = Path(__file__).resolve().parents[1] / "schemas" / "coverage_set_selection.v1.json"
        validator = schema.parent.parent / "scripts" / "json_instance_validate.py"
        report_file = work / "selection.json"
        report_file.write_bytes(raw)
        import sys
        validated = subprocess.run([sys.executable, "-B", str(validator), str(schema), str(report_file)],
                                   capture_output=True, timeout=30, check=False)
        assert validated.returncode == 0, validated.stderr.decode(errors="replace")
    print("PASS: native retained-source set-cover scenarios, deterministic reports, failure semantics and read-only state checks")


if __name__ == "__main__":
    main()
