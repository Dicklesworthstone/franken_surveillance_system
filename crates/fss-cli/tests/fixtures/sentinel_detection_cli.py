"""Real-binary sentinel contract. Python is only a test JSON/filesystem oracle.

The static color-bars fixture deliberately has the existing package test's three
uncalibrated `tie` outputs. This tests candidate recovery and provenance wiring,
not the truth of that class label or real-world threat recall.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

SITE = "site:sentinel-cli"
SENSOR = "sensor:sentinel-cli"
PACKAGE_SHA = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74"


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pairs(fields):
    out = {}
    for name, value in fields:
        assert name not in out, ("duplicate JSON key", name)
        out[name] = value
    return out


def document(data):
    return json.loads(data, object_pairs_hook=pairs)


def values(data, name):
    prefix = name + "="
    return [line[len(prefix):] for line in data.decode().splitlines() if line.startswith(prefix)]


def one(data, name):
    found = values(data, name)
    assert len(found) == 1, (name, found, data.decode())
    return found[0]


def snapshot(root):
    result = {}
    for path in sorted([root, *root.rglob("*")]):
        stat = path.lstat()
        assert not path.is_symlink(), path
        content = sha(path.read_bytes()) if path.is_file() else "directory"
        result[str(path.relative_to(root))] = (
            stat.st_mode, stat.st_size, stat.st_mtime_ns, stat.st_ino, content
        )
    return result


def run(command, ok=True):
    output = subprocess.run([str(arg) for arg in command], capture_output=True, timeout=300)
    assert (output.returncode == 0) == ok, (
        command, output.returncode, output.stdout.decode(errors="replace"),
        output.stderr.decode(errors="replace"),
    )
    if not ok:
        assert not output.stdout, "a refusal printed a success/partial report"
    return output


def main():
    file_bin, infer_bin, event_bin, fixture, package, scratch = sys.argv[1:]
    scratch = Path(scratch)
    root = scratch / "deployment"
    source = scratch / "quiet.mjpeg"
    source.write_bytes(Path(fixture).read_bytes() * 20)
    imported = run([
        file_bin, "import", "--root", root, "--site", SITE, "--input", source,
        "--sensor", SENSOR, "--stream", "stream:sentinel-cli", "--media-format", "mjpeg",
        "--receive-time-ns", "10000000000000", "--capture-start-ns", "1000000000",
        "--capture-uncertainty-ns", "1000000", "--assumed-fps", "10",
    ])
    import_id = one(imported.stdout, "import_identity")
    source.unlink()  # Subsequent analysis must use retained custody, not the input file.
    base = ["--root", root, "--site", SITE]
    before = snapshot(root)
    quiet = run([
        event_bin, "watch", *base, "--import-id", import_id, "--interpretation", "ycbcr",
        "--zone", "whole:0,0,64,48", "--segment-count", "20",
    ])
    assert document(quiet.stdout)["candidates"] == [], "static scene unexpectedly needs a motion candidate"

    def detection(sentinel=True, first=0, count=20):
        command = [
            infer_bin, "package-detect", *base, "--import-id", import_id,
            "--first-segment", str(first), "--frames", str(count), "--interpretation", "ycbcr",
            "--package", package, "--package-digest", PACKAGE_SHA,
        ]
        if sentinel:
            command += ["--sentinel-every-frames", "8", "--sentinel-burst-frames", "3",
                        "--sentinel-max-inferences", "6"]
        return command

    computed = run(detection())
    repeat = run(detection())
    assert computed.stdout == repeat.stdout, "identical sentinel inputs changed report bytes"
    assert snapshot(root) == before, "computation mutated custody"
    report = document(computed.stdout)
    assert report["schema"] == "fss.sentinel_detection_report.v1"
    assert report["source_import"] == import_id
    assert report["sampling"]["motion_independent"] is True
    assert report["sampling"]["admitted_inferences"] == report["executed_inferences"] == 6
    assert report["scheduled_bursts_complete"] is False
    for key in ("absence_certifiable", "effects_authorized", "continuous_coverage", "tracking_across_bursts"):
        assert report[key] is False, key
    assert report["quality_claim"] == "none"
    bursts = report["bursts"]
    assert [(b["first_segment"], b["segment_count"], b["status"]) for b in bursts] == [
        (0, 3, "completed"), (8, 3, "completed"), (16, 3, "budget_exhausted")
    ]
    assert bursts[2]["report"] is None and bursts[2]["report_digest"] is None
    selected = {0, 1, 2, 8, 9, 10}
    assert report["unsampled_segments"] == [i for i in range(20) if i not in selected]
    for burst in bursts[:2]:
        child = burst["report"]
        assert [f["segment"] for f in child["frames"]] == list(range(burst["first_segment"], burst["first_segment"] + 3))
        assert all(len(f["detections"]) == 3 for f in child["frames"])
        assert all(d["label"] == "tie" for f in child["frames"] for d in f["detections"])
        assert child["complete"] is True and child["effects_authorized"] is False
    # Ordinary package detection and the first burst share exactly the old report contract.
    ordinary = run(detection(False, 0, 3))
    assert document(ordinary.stdout) == bursts[0]["report"]
    assert sha(ordinary.stdout) == bursts[0]["report_digest"]
    assert snapshot(root) == before

    for option, bad in [("--sentinel-every-frames", "0"), ("--sentinel-burst-frames", "9"),
                        ("--sentinel-max-inferences", "2"), ("--sentinel-max-inferences", "65")]:
        command = detection()
        command[command.index(option) + 1] = bad
        run(command, ok=False)
    run(detection() + ["--max-macs", "0"], ok=False)
    assert snapshot(root) == before, "refused work changed retained authority"

    retained = run(detection() + ["--retain", "yes"])
    assert retained.stdout == computed.stdout, "retention changed computation identity"
    child_ids = [b["report_digest"] for b in bursts[:2]]
    assert values(retained.stderr, "package_detection_retained") == child_ids
    after_retention = snapshot(root)
    retried = run(detection() + ["--retain", "yes"])
    assert retried.stdout == computed.stdout
    assert values(retried.stderr, "root") == values(retained.stderr, "root")
    assert snapshot(root) == after_retention, "an exact retry republished children"

    # Independent child reports flow through the existing confirmed-track event path.
    # No event is created by sentinel computation or child retention alone.
    analyses = []
    for index, child_id in enumerate(child_ids):
        path = scratch / f"burst-{index}.bin"
        analyzed = run([
            event_bin, "report", *base, "--package-report", child_id, "--label", "tie",
            "--confirmation-hits", "3", "--report-out", path,
        ])
        tracks = values(analyzed.stdout, "track")
        assert tracks, "motion-independent detections never reach confirmed candidate tracks"
        assert one(analyzed.stdout, "frames") == "3"
        analyses.append((path, one(analyzed.stdout, "report_digest"), tracks))
    assert set(analyses[0][2]).isdisjoint(analyses[1][2]), "track identity bridged a sampling gap"
    assert snapshot(root) == after_retention, "tracking published an event without approval"
    path, analysis_digest, tracks = analyses[0]
    prepare_args = [*base, "--report", path, "--report-digest", analysis_digest, "--track", tracks[0]]
    prepared = run([event_bin, "prepare", *prepare_args])
    proposal = one(prepared.stdout, "proposal_digest")
    assert snapshot(root) == after_retention, "preparation was not read-only"
    published = run([event_bin, "publish", *prepare_args, "--proposal-digest", proposal])
    assert one(published.stdout, "operation") == "published"
    assert one(published.stdout, "event_kind") == "unclassified"
    assert one(published.stdout, "failure_domains") == "1"
    assert one(published.stdout, "corroborated") == "false"
    assert one(published.stdout, "effects_authorized") == "false"
    after_event = snapshot(root)
    replay = run([event_bin, "publish", *prepare_args, "--proposal-digest", proposal])
    assert one(replay.stdout, "operation") == "already_published"
    assert snapshot(root) == after_event, "event retry duplicated authority"

    # An explicitly approved mask must alter lineage and screen every emitted detection.
    mask_args = [*base, "--sensor", SENSOR, "--resolution", "64x48", "--rect", "0,0,64,1"]
    preview = document(run([event_bin, "privacy-mask", "declare", *mask_args]).stdout)
    run([event_bin, "privacy-mask", "declare", *mask_args, "--approve", preview["approval_digest"]])
    after_mask = snapshot(root)
    masked = document(run(detection()).stdout)
    assert masked["privacy_mask"] != report["privacy_mask"]
    assert masked["bursts"][0]["report_digest"] != bursts[0]["report_digest"]
    for burst in masked["bursts"]:
        if burst["report"] is None:
            continue
        assert burst["report"]["privacy_mask"] == masked["privacy_mask"]
        for frame in burst["report"]["frames"]:
            for detection_row in frame["detections"]:
                assert detection_row["bounds_subpixel"][1] >= 256, "detection touches masked first row"
    assert snapshot(root) == after_mask
    print("PASS: real-binary sentinel scheduling, static recovery, custody, event approval, retry and privacy contracts")


if __name__ == "__main__":
    main()
