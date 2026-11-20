#!/usr/bin/env python3
"""Exercise public class fusion on two recorded views of the same staged person.

Usage: python scripts/check_residential_class_fusion.py --bins /path/to/release
Pass --work /new/directory to keep the complete native reports and fixture films.

Both fixtures hold source frame 240 seven times, then play source frames 343–347
of the same rendered take. The edited clock is a fixture assumption. Each camera's
calibration labels come from other frames of that camera, outside a buffer around
both cuts. These dependent, frame-level samples qualify wiring and arithmetic only.
"""

import argparse
import hashlib
import json
import math
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TAKE = ROOT / "website/public/watch/intrusion"
CAMERAS = ("entry", "porch")
MODEL = ROOT / "models/yolox-nano/yolox_nano.fmpk"
SITE = ["--root", "deployment", "--site", "site:class-fixture"]
REFERENCE_FRAME, HELD_FRAMES = 240, 7
MOVING_FRAMES = range(343, 348)
SOURCE_FRAMES = [REFERENCE_FRAME] * HELD_FRAMES + list(MOVING_FRAMES)
SCENE_SHA = "094e0ccabd9bc09b67876e15d3f6191a0a0b32f5c6d4d1f804bb3a2a14a4c35d"


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def checked_json(path, expected):
    data = path.read_bytes()
    assert sha(data) == expected, path
    return json.loads(data)


def normalized(bounds, size, subpixels=256):
    return [v / (dim * subpixels) for v, dim in zip(bounds, size * 2, strict=True)]


def iou(a, b):
    intersection = max(0, min(a[2], b[2]) - max(a[0], b[0])) * max(0, min(a[3], b[3]) - max(a[1], b[1]))
    if not intersection:
        return 0
    return intersection / ((a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - intersection)


def calibration(camera, camera_data, scene, model_digest):
    """Label raw emitted person boxes one-to-one against visible, camera-specific authored boxes."""
    bins = [dict(lo_ppm=lower, true_positives=0, false_positives=0) for lower in (0, 350_000)]
    seen = set()
    for ref in camera_data["detections"]["reports"]:
        path = TAKE / ref["report"]
        report = checked_json(path, "sha256:" + path.stem)
        assert report["complete"] and report["package_digest"] == model_digest
        assert report["source_import"] == camera_data["custody"]["import_id"]
        for frame in report["frames"]:
            index = frame["segment"]
            assert index not in seen
            seen.add(index)
            if 225 <= index <= 252 or 325 <= index <= 365:
                continue
            people = [
                track[index][:4]
                for track in scene["boxes"][camera].values()
                if track[index] and track[index][4] > 0
            ]
            for det in sorted(frame["detections"], key=lambda d: -d["score"]):
                if det["class_index"] != 0:
                    continue
                assert det["label"] == "person"
                box = normalized(det["bounds_subpixel"], frame["dimensions"], report["box_subpixels"])
                overlap, actor = max(
                    ((iou(box, person), i) for i, person in enumerate(people)), default=(0, None)
                )
                hit = overlap >= 0.3
                if hit:
                    people.pop(actor)
                bins[int(det["score"] >= 0.35)]["true_positives" if hit else "false_positives"] += 1
    assert seen == set(range(scene["clock"]["frames"]))
    return dict(
        sensor="sensor:" + camera,
        failure_domains=[],
        calibration=dict(
            schema="fss.score_calibration_counts.v1",
            generation=f"residential-replay:{camera}:frame-box-iou30:v1",
            bins=bins,
        ),
    )


def fixture(camera, source_digest, work):
    source = TAKE / (camera + ".mp4")
    assert sha(source.read_bytes()) == source_digest

    def frames(select, count):
        return subprocess.run(
            [
                "ffmpeg",
                "-loglevel",
                "error",
                "-nostdin",
                "-i",
                source,
                "-vf",
                select,
                "-frames:v",
                str(count),
                "-fps_mode",
                "passthrough",
                "-threads",
                "1",
                "-q:v",
                "2",
                "-f",
                "mjpeg",
                "pipe:1",
            ],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout

    reference = frames(f"select='eq(n,{REFERENCE_FRAME})'", 1)
    moving = frames(f"select='between(n,{MOVING_FRAMES[0]},{MOVING_FRAMES[-1]})'", len(MOVING_FRAMES))
    jpeg = reference * HELD_FRAMES + moving
    out = work / (camera + ".mp4")
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-f",
            "mjpeg",
            "-framerate",
            "12",
            "-i",
            "pipe:0",
            "-pix_fmt",
            "yuv420p",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-crf",
            "12",
            "-threads",
            "2",
            "-x264-params",
            "bframes=0:keyint=12:scenecut=0",
            out,
        ],
        input=jpeg,
        check=True,
    )
    return out


def prepare_camera_replay(bins, work):
    """Import the two edited clips and return the native shared-render corroboration command."""
    scene = checked_json(TAKE / "scene.json", "sha256:" + SCENE_SHA)
    native = json.loads((TAKE / "native.json").read_bytes())
    model = native["fss"]["model"]["digest"]
    assert sha(MODEL.read_bytes()) == model
    shutil.copyfile(MODEL, work / "model.fmpk")

    args = [
        "corroborate",
        *SITE,
        "--stream-corroborate",
        "--interpretation",
        "ycbcr",
        "--time-gate-ns",
        "500000000",
        "--distance-gate",
        "1.5",
        "--pixel-threshold",
        "18",
        "--threshold-sigma",
        "3",
        "--min-region-pixels",
        "220",
        "--failure-domain",
        "replay:render=entry,porch",
    ]
    for camera in CAMERAS:
        row = native["cameras"][camera]
        spec = next(c for c in scene["cameras"] if c["id"] == camera)
        assert "sha256:" + spec["video_sha256"] == row["custody"]["sha256"]
        film = fixture(camera, row["custody"]["sha256"], work)
        imported = subprocess.check_output(
            [
                bins / "fss-file",
                "import",
                *SITE,
                "--input",
                film,
                "--sensor",
                "sensor:" + camera,
                "--stream",
                "stream:" + camera,
                "--media-format",
                "mp4avc",
                "--receive-time-ns",
                "1794640502000000000",
                "--capture-start-ns",
                "1794640460000000000",
                "--capture-uncertainty-ns",
                "1000000",
                "--assumed-fps",
                "12",
            ],
            cwd=work,
        )
        receipt = dict(line.split("=", 1) for line in imported.decode().splitlines() if "=" in line)
        assert receipt["verified_source_sha256"] == sha(film.read_bytes()) and int(
            receipt["segment_count"]
        ) == len(SOURCE_FRAMES)
        matrix = ",".join(str(v) for axis in row["ground_projection"]["image_to_ground"] for v in axis)
        args.extend(["--camera", camera + ":" + receipt["import_identity"], "--ground", camera + ":" + matrix])
    args += [
        "--zone",
        "approach:-6,4,8,8",
        "--detector-package",
        "model.fmpk",
        "--detector-digest",
        model,
        "--detector-max-inferences",
        "64",
        "--detector-frames-per-track",
        "1",
        "--stream-pixel-budget",
        "2147483648",
    ]
    return scene, native, model, args


def qualify(bins, work):
    scene, native, model, args = prepare_camera_replay(bins, work)
    bindings = [calibration(c, native["cameras"][c], scene, model) for c in CAMERAS]

    def run(tool, args, *, data=None):
        return subprocess.run(
            [bins / tool, *args], cwd=work, input=data, stdout=subprocess.PIPE, check=True
        ).stdout

    def capture(name, data):
        (work / name).write_bytes(data)
        return json.loads(data)

    def journals():
        return tuple(
            sha((work / "deployment" / plane / "journal.fssj").read_bytes()) for plane in ("ledger", "effects")
        )

    before = journals()
    base = capture("native.json", run("fss-event", args))
    query_path = TAKE / native["fusion"]["variants"][0]["query"]
    sample = checked_json(query_path, "sha256:" + query_path.stem)
    policy = dict(sample["policy"], max_wait_ns=int(sample["policy"]["max_wait_ns"]))
    counts = json.dumps(
        dict(
            schema="fss.event_class_fusion_counts.v1",
            class_index=0,
            prior=sample["prior"],
            looks=1,
            now_ns=1,
            policy=policy,
            severity=sample["severity"],
            calibrations=bindings,
        ),
        separators=(",", ":"),
    ).encode()
    capture("counts.json", counts)
    profile = run(
        "fss-fusion-profile",
        [
            "--scope",
            "corroborate",
            "--counts-digest",
            sha(counts),
            "--analysis-digest",
            base["analysis_digest"],
            "--detector-recipe-digest",
            base["detector_cascade"]["recipe_digest"],
            "--analysis-roots",
            ",".join(c["analysis_root"] for c in base["cameras"]),
        ],
        data=counts,
    )
    capture("profile.json", profile)
    profiled_args = [*args, "--fusion-profile", "profile.json", "--fusion-digest", sha(profile)]
    report = run("fss-event", profiled_args)
    for local in (str(ROOT), str(work), "/home/", "/data/", "/tmp/"):
        assert local.encode() not in report, "native report contains a machine-local path"
    fused = json.loads(report)
    advice = fused.pop("calibrated_class_advice")
    assert fused == base and journals() == before
    assert not any(
        advice[k] for k in ("effect_authority", "event_policy_changed", "published", "class_absence_certified")
    )
    assert base["published_count"] == 0 and not base["alert_authorized"]
    assert all(c["frames_decoded"] == len(SOURCE_FRAMES) for c in base["cameras"])
    (event,) = base["candidates"]
    (derived,) = advice["candidates"]
    assert (event["event_state"], event["policy_action"]) == ("witnessed", "hold")
    assert (derived["native_proposal"], derived["native_provenance_root"]) == (
        event["proposal_digest"],
        event["provenance_root"],
    )
    for binding in bindings:
        output = next(c["calibration"] for c in advice["calibrations"] if c["sensor"] == binding["sensor"])
        for source, returned in zip(binding["calibration"]["bins"], output["bins"], strict=True):
            assert all(value == returned[key] for key, value in source.items())
    result = verify_positive(scene, model, base, advice, event, derived, native, work)

    # The exported candidate query is directly replayable with the public ablation command.
    q = json.dumps(derived["query"]).encode()
    loss = capture(
        "without-package.json",
        run("fss-fuse", ["--query", "-", "--without-domain", "package:" + model], data=q),
    )["ablation"]
    lost = loss["counterfactual"]["outcome"]
    assert loss["baseline"]["outcome"] == derived["outcome"]
    assert lost["posterior_log_odds_millibans"] == derived["query"]["prior"]
    assert not lost["clusters"] and not loss["effect_authority"] and not loss["event_policy_changed"]
    refused = subprocess.run(
        [bins / "fss-event", *profiled_args, "--approve", event["proposal_digest"]],
        cwd=work,
        capture_output=True,
    )
    assert (
        refused.returncode != 0 and not refused.stdout and b"calibrated fusion is read-only" in refused.stderr
    )
    assert journals() == before
    report_name = "fusion-replay/" + sha(report)[7:] + ".json"
    (work / "fusion-replay").mkdir()
    (work / report_name).write_bytes(report)
    result.update(
        report=dict(path=report_name, sha256=sha(report), advice_digest=advice["report_digest"]),
        scene_sha256="sha256:" + SCENE_SHA,
        source_frames=SOURCE_FRAMES,
        calibration_excluded_frames=[[225, 252], [325, 365]],
        scope="Two edited views from one renderer. Calibration counts come from labelled detector boxes in other frames of the same films. Repeated frames and shared scene conditions limit their independence. The Wilson intervals describe this fixture and do not establish deployed-camera performance.",
    )
    (work / "fusion-replay.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["cluster"], indent=2))


def verify_positive(scene, model, base, advice, event, derived, native, work):
    """Check unrounded source observations, reference intervals, cluster hull and native counterfactual."""
    scores = {s["sensor"]: s for s in derived["scores"]}
    assert len(derived["scores"]) == 2 and set(scores) == {"sensor:" + c for c in CAMERAS}
    observations = {e["id"]: e for e in derived["query"]["evidence"]}
    intervals = []
    cameras = []
    for i in event["entries"]:
        entry = base["entries"][i]
        camera = entry["camera"]
        (record,) = entry["class_evidence"]
        assert (record["outcome"], record["label"], record["supports"]) == ("associated", "person", True)
        frame = SOURCE_FRAMES[record["segment"]]
        assert frame in MOVING_FRAMES
        box = normalized(record["bounds_subpixel"], [1280, 720])
        assert iou(box, scene["boxes"][camera]["a"][frame]) >= 0.3
        binding = scores["sensor:" + camera]
        assert binding["source_record"] == binding["evidence_id"] == record["evidence_digest"]
        (bits,) = struct.unpack("!I", struct.pack("!f", record["score"]))
        (score,) = struct.unpack("!f", struct.pack("!I", bits))
        assert binding["score_f32_bits"] == bits
        assert binding["score_ppm_outward"] == [math.floor(score * 1e6), math.ceil(score * 1e6)]
        cal = next(c["calibration"] for c in advice["calibrations"] if c["sensor"] == binding["sensor"])
        assert (
            cal["interval"] == "wilson_z2_per_bin_not_simultaneous"
            and cal["digest"] == binding["calibration_digest"]
        )
        measured_bin = next(
            b for b in cal["bins"] if b["lo_ppm"] <= binding["score_ppm_outward"][0] <= b["hi_ppm"]
        )
        check_wilson_bins(cal)
        obs = observations[binding["evidence_id"]]
        assert (
            obs["observability"] == "observed" and obs["calibration"]["llr"] == measured_bin["llr_millibans"]
        )
        intervals.append(measured_bin["llr_millibans"])
        cameras.append(
            dict(
                camera=camera,
                source_film_sha256=native["cameras"][camera]["custody"]["sha256"],
                fixture_sha256=sha((work / (camera + ".mp4")).read_bytes()),
                frame=record["segment"],
                source_frame=frame,
                evidence_digest=record["evidence_digest"],
                score_ppm_outward=binding["score_ppm_outward"],
                calibration=cal,
                llr_millibans=measured_bin["llr_millibans"],
            )
        )
    assert intervals and set(observations) == {s["evidence_id"] for s in scores.values()}
    outcome = derived["outcome"]
    (cluster,) = outcome["clusters"]
    assert set(cluster["members"]) == set(observations)
    native_domains = {c["failure_domain"] for c in base["cameras"]}
    assert len(native_domains) == 1
    shared = "native:" + sha(native_domains.pop().encode())
    assert {shared, "package:" + model, "cascade:" + base["detector_cascade"]["recipe_digest"]} <= set(
        cluster["failure_domains"]
    )
    hull = [min(v[0] for v in intervals), max(v[1] for v in intervals)]
    assert cluster["llr_millibans"] == hull and outcome["supporting_clusters"] == 1
    prior = derived["query"]["prior"]
    assert outcome["posterior_log_odds_millibans"] == [x + y for x, y in zip(prior, hull, strict=True)]
    (removed,) = outcome["counterfactuals"]
    assert removed["removed_cluster"] == cluster["label"] and removed["posterior_log_odds_millibans"] == prior
    return dict(
        schema="fss.website.residential_class_fusion.v1",
        cameras=cameras,
        cluster=dict(
            members=cluster["members"],
            llr_millibans=hull,
            supporting_clusters=outcome["supporting_clusters"],
            posterior_millibans=outcome["posterior_log_odds_millibans"],
            without_cluster_millibans=prior,
            decision=outcome["decision"]["kind"],
            without_cluster_decision=removed["decision"]["kind"],
        ),
        native=dict(
            event_state=event["event_state"],
            policy_action=event["policy_action"],
            effect_authority=advice["effect_authority"],
        ),
    )


def check_wilson_bins(cal):
    """Independent floating-point oracle for these fixed counts; Rust rounds conservatively in whole millibans."""

    def wilson(success, total):
        center = (success + 2) / (total + 4)
        half = 2 * math.sqrt(success * (total - success) / total + 1) / (total + 4)
        return max(0, center - half), min(1, center + half)

    for b in cal["bins"]:
        tl, th = wilson(b["true_positives"], cal["true_positives"])
        fl, fh = wilson(b["false_positives"], cal["false_positives"])
        lo = math.floor(1000 * math.log10(tl / fh)) if tl else -100_000
        hi = math.ceil(1000 * math.log10(th / fl)) if fl else 100_000
        actual_lo, actual_hi = b["llr_millibans"]
        assert 0 <= lo - actual_lo <= 1 and 0 <= actual_hi - hi <= 1


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Run with Python assertions enabled.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bins", type=Path, required=True)
    parser.add_argument("--work", type=Path, help="new directory for the full replay")
    options = parser.parse_args()
    if options.work:
        options.work.mkdir()
        qualify(options.bins.resolve(), options.work.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="fss-residential-fusion-") as temp:
            qualify(options.bins.resolve(), Path(temp))
