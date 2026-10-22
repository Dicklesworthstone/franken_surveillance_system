"""Native whole-recording sentinel process contract.

Python supplies a JSON/filesystem oracle only. The deliberately static color-bar
fixture has the native package's existing three uncalibrated `tie` outputs. These
are useful for testing candidate routing and exact replay, not class accuracy.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys


SITE = "site:long-sentinel-cli"
SENSOR = "sensor:long-sentinel-cli"
PACKAGE_SHA = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74"


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pairs(fields):
    result = {}
    for name, value in fields:
        assert name not in result, ("duplicate JSON key", name)
        result[name] = value
    return result


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
        assert not output.stdout, "a refused invocation printed a partial/success report"
    return output


def main():
    file_bin, infer_bin, event_bin, fixture, package_source, scratch = sys.argv[1:]
    scratch = Path(scratch)
    root = scratch / "deployment"
    source = scratch / "quiet.mjpeg"
    source.write_bytes(Path(fixture).read_bytes() * 170)
    package = scratch / "model.fmpk"
    package.write_bytes(Path(package_source).read_bytes())
    assert sha(package.read_bytes()) == PACKAGE_SHA
    imported = run([
        file_bin, "import", "--root", root, "--site", SITE, "--input", source,
        "--sensor", SENSOR, "--stream", "stream:long-sentinel-cli", "--media-format", "mjpeg",
        "--receive-time-ns", "10000000000000", "--capture-start-ns", "1000000000",
        "--capture-uncertainty-ns", "1000000", "--assumed-fps", "10",
    ])
    import_id = one(imported.stdout, "import_identity")
    source.unlink()
    base = ["--root", root, "--site", SITE]
    before = snapshot(root)
    quiet = run([
        event_bin, "watch", *base, "--import-id", import_id, "--interpretation", "ycbcr",
        "--zone", "whole:0,0,64,48", "--segment-count", "170", "--stream-watch",
    ])
    assert document(quiet.stdout)["candidates"] == [], "the static fixture unexpectedly needs a motion gate"

    def detection(long=True, first=0, count=170):
        command = [
            infer_bin, "package-detect", *base, "--import-id", import_id,
            "--first-segment", str(first), "--frames", str(count), "--interpretation", "ycbcr",
            "--package", package, "--package-digest", PACKAGE_SHA,
        ]
        if long:
            command += ["--stream-sentinel", "yes", "--sentinel-every-frames", "130",
                        "--sentinel-burst-frames", "3", "--sentinel-max-inferences", "6",
                        "--max-frame-pixels", "3072"]
        return command

    # The opt-in does not relax the established short-package or sentinel range.
    run(detection(False), ok=False)
    run(detection(False) + ["--sentinel-every-frames", "8", "--sentinel-burst-frames", "3",
                           "--sentinel-max-inferences", "6"], ok=False)
    computed = run(detection())
    report_digest = sha(computed.stdout)
    report = document(computed.stdout)
    assert report["schema"] == "fss.long_sentinel_detection_report.v1"
    assert report["source_import"] == import_id
    assert report["sampling"]["motion_independent"] is True
    assert report["sampling"]["every_frames"] == 130
    assert report["sampling"]["admitted_inferences"] == report["executed_inferences"] == 6
    assert report["scheduled_bursts_complete"] is True
    for key in ("absence_certifiable", "effects_authorized", "continuous_coverage", "tracking_across_bursts"):
        assert report[key] is False, key
    assert report["model_outputs"] == "uncalibrated"
    assert report["quality_claim"] == "none"
    bursts = report["bursts"]
    assert [(b["first_segment"], b["segment_count"], b["status"]) for b in bursts] == [
        (0, 3, "completed"), (130, 3, "completed")
    ]
    assert report["unsampled_ranges"] == [
        {"first_segment": 3, "segment_count": 127},
        {"first_segment": 133, "segment_count": 37},
    ]
    for burst in bursts:
        child = burst["report"]
        assert [f["segment"] for f in child["frames"]] == list(range(burst["first_segment"], burst["first_segment"] + 3))
        assert all(len(f["detections"]) == 3 for f in child["frames"])
        assert all(d["label"] == "tie" for f in child["frames"] for d in f["detections"])
        assert child["complete"] is True and child["effects_authorized"] is False
    ordinary = run(detection(False, 0, 3))
    assert document(ordinary.stdout) == bursts[0]["report"]
    assert sha(ordinary.stdout) == bursts[0]["report_digest"]
    assert snapshot(root) == before, "analysis changed retained authority"

    for option in ("--stream-read-bytes", "--stream-pixel-budget", "--max-report-bytes"):
        run(detection() + [option, "1"], ok=False)
    run(detection() + ["--max-macs", "0"], ok=False)
    assert snapshot(root) == before, "resource refusal changed custody"

    retained = run(detection() + ["--retain", "yes"])
    assert retained.stdout == computed.stdout
    assert one(retained.stderr, "long_sentinel_retained") == report_digest
    assert one(retained.stderr, "status") == "retained"
    assert one(retained.stderr, "children") == "2"
    assert one(retained.stderr, "package") == PACKAGE_SHA
    after_retention = snapshot(root)
    retried = run(detection() + ["--retain", "yes"])
    assert retried.stdout == computed.stdout
    assert one(retried.stderr, "status") == "already_retained"
    for field in ("root", "recipe", "package", "children", "authority_sequence"):
        assert one(retried.stderr, field) == one(retained.stderr, field), field
    assert snapshot(root) == after_retention, "an exact retry republished evidence"

    # Every child remains usable by the existing candidate investigation workflow.
    # Tracking is local to each sampled burst and cannot bridge 127 unseen frames.
    tracks_by_burst = []
    for index, burst in enumerate(bursts):
        analyzed = run([
            event_bin, "report", *base, "--package-report", burst["report_digest"],
            "--label", "tie", "--confirmation-hits", "3", "--report-out", scratch / f"burst-{index}.bin",
        ])
        assert one(analyzed.stdout, "frames") == "3"
        tracks = values(analyzed.stdout, "track")
        assert tracks, "the motion-independent child cannot produce candidate tracks"
        tracks_by_burst.append(set(tracks))
    assert tracks_by_burst[0].isdisjoint(tracks_by_burst[1])
    assert snapshot(root) == after_retention, "candidate investigation created an event"

    # Separate processes reconstruct from the root-last aggregate; loose inputs are gone.
    package.unlink()
    replay = [infer_bin, "sentinel-replay", *base, "--report-digest", report_digest]
    cold = run(replay)
    assert cold.stdout == computed.stdout, "cold numerical replay did not reproduce exact report bytes"
    assert snapshot(root) == after_retention, "replay published new authority"
    for option in ("--stream-read-bytes", "--stream-pixel-budget", "--max-report-bytes",
                   "--max-macs", "--max-tensor-bytes", "--max-metadata-bytes"):
        run(replay + [option, "1"], ok=False)
    run(replay + ["--max-frame-pixels", "256"], ok=False)
    assert snapshot(root) == after_retention, "a refused replay changed custody"

    # Saved model evidence cannot override the sensor's current approved privacy generation.
    mask_args = [*base, "--sensor", SENSOR, "--resolution", "64x48", "--rect", "0,0,64,1"]
    preview = document(run([event_bin, "privacy-mask", "declare", *mask_args]).stdout)
    run([event_bin, "privacy-mask", "declare", *mask_args, "--approve", preview["approval_digest"]])
    after_mask = snapshot(root)
    run(replay, ok=False)
    assert snapshot(root) == after_mask, "stale-privacy refusal changed authority"
    print("PASS: long native sentinel candidates, bounded work, independent bursts, aggregate custody and cold model replay")


if __name__ == "__main__":
    main()
