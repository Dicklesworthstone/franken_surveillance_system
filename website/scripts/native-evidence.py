"""Run FSS on synchronized virtual cameras and each pair's shared ground zone."""

from hashlib import sha256
from itertools import combinations
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory

WEB = Path(__file__).resolve().parents[1]
MODEL = WEB.parent / "models/yolox-nano/yolox_nano.fmpk"
PIN = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74"
FILMS = WEB / "public/films"
OUT = WEB / "public/evidence"
BINS = Path(os.environ.get("FSS_BIN_DIR", WEB.parent / "target/debug")).resolve()
SCOPE = ["--root", "deployment", "--site", "site:juniper-demo"]


def digest(path):
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def run(args, cwd):
    return subprocess.run(
        args, cwd=cwd, check=True, stdout=subprocess.PIPE, text=True
    ).stdout


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def import_clip(case, camera, stem, spec, tmp, stage):
    film = FILMS / (stem + ".mp4")
    frames = stage / (stem + ".mjpeg")
    width, height, rate = spec["nativeWidth"], spec["nativeHeight"], spec["nativeFps"]
    step, remainder = divmod(spec["fps"], rate)
    if not step or remainder:
        raise ValueError("Native samples must coincide with film frames")
    # Sample exactly film frames 0, step, 2*step, ... . A rate-conversion
    # filter alone can choose a different frame from each interval.
    select = f"select=not(mod(n\\,{step})),setpts=N/({rate}*TB),scale={width}:{height}"
    run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-n",
            "-i",
            film,
            "-vf",
            select,
            "-r",
            str(rate),
            "-c:v",
            "mjpeg",
            "-q:v",
            "4",
            "-pix_fmt",
            "yuvj420p",
            "-threads",
            "1",
            "-f",
            "mjpeg",
            frames,
        ],
        tmp,
    )
    shutil.copyfile(frames, tmp / (camera + ".mjpeg"))
    result = run(
        [
            BINS / "fss-file",
            "import",
            *SCOPE,
            "--input",
            camera + ".mjpeg",
            "--sensor",
            "sensor:" + camera,
            "--stream",
            "stream:" + case + "-" + camera,
            "--media-format",
            "mjpeg",
            "--receive-time-ns",
            "1700000020000000000",
            "--capture-start-ns",
            "1700000000000000000",
            "--capture-uncertainty-ns",
            "1000000",
            "--assumed-fps",
            str(rate),
        ],
        tmp,
    )
    identity = next(
        line.split("=", 1)[1]
        for line in result.splitlines()
        if line.startswith("import_identity=")
    )
    return {
        "asset": stem,
        "importId": identity,
        "filmDigest": digest(film),
        "inputDigest": digest(frames),
    }


def analyze_case(case, scene, rig, tmp, stage):
    spec = rig["recording"]
    zone = scene["zone"]
    views = {}
    for camera, view in scene["views"].items():
        views[camera] = import_clip(case, camera, view["asset"], spec, tmp, stage)

    # All three imports exist before any preview reads this deployment.
    for camera, view in views.items():
        name = view["asset"] + ".json"
        report = json.loads(
            run(
                [
                    BINS / "fss-event",
                    "watch",
                    *SCOPE,
                    "--import-id",
                    view["importId"],
                    "--interpretation",
                    "ycbcr",
                    "--zone",
                    f"image:0,0,{spec['nativeWidth']},{spec['nativeHeight']}",
                    "--detector-package",
                    "model.fmpk",
                    "--detector-digest",
                    PIN,
                    "--detector-max-inferences",
                    "2",
                ],
                tmp,
            )
        )
        if (
            report["import_identity"] != view["importId"]
            or report["frames_decoded"] != rig["duration"] * spec["nativeFps"]
        ):
            raise ValueError("Watch report did not cover its camera recording")
        write(stage / name, report)
        view.update(
            {
                "reportDigest": digest(stage / name),
                "candidates": report["candidate_count"],
                "frames": report["frames_decoded"],
                "visibility": scene["views"][camera]["visibility"],
                "entries": [
                    {
                        "time": row["entry_segment"] / spec["nativeFps"],
                        "track": row["track_id"],
                        "kind": row["event_kind"],
                    }
                    for row in report["candidates"]
                ],
            }
        )
        print(case, camera, view["candidates"], "single-camera candidates", flush=True)

    pairs = {}
    for first, second in combinations(sorted(views), 2):
        pair = first + "-" + second
        args = [
            BINS / "fss-event",
            "corroborate",
            *SCOPE,
            "--interpretation",
            "ycbcr",
            "--zone",
            zone["id"] + ":" + ",".join(map(str, zone["rect"])),
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "1",
            "--failure-domain",
            "replay:juniper-scene=" + first + "," + second,
            "--failure-domain",
            "clock:juniper-timeline=" + first + "," + second,
        ]
        for camera in (first, second):
            args += [
                "--camera",
                camera + ":" + views[camera]["importId"],
                "--ground",
                camera
                + ":"
                + ",".join(map(str, rig["cameras"][camera]["imageToGround"])),
            ]
        report = json.loads(run(args, tmp))
        if any(
            c["policy_action"] != "hold" or c["alert_prepared"]
            for c in report["candidates"]
        ):
            raise ValueError(
                "Shared synthetic sources cannot establish independent confirmation"
            )
        name = case + "-" + pair + ".json"
        write(stage / name, report)
        pairs[pair] = {"report": name, "reportDigest": digest(stage / name)}
        print(case, pair, report["candidate_count"], "paired candidates", flush=True)
    primary = views[scene["primary"]]
    return {
        **{k: primary[k] for k in ("candidates", "frames", "entries", "visibility")},
        "views": views,
        "pairs": pairs,
    }


def main():
    if digest(MODEL) != PIN:
        raise ValueError("Detector package differs from the reviewed digest")
    rig = json.loads((FILMS / "rig.json").read_text())
    OUT.mkdir(exist_ok=True)
    summary = {}
    with TemporaryDirectory(prefix=".evidence-", dir=WEB) as scratch:
        stage = Path(scratch)
        for case, scene in rig["cases"].items():
            with TemporaryDirectory(prefix="fss-showcase-") as directory:
                tmp = Path(directory)
                shutil.copyfile(MODEL, tmp / "model.fmpk")
                summary[case] = analyze_case(case, scene, rig, tmp, stage)
        write(stage / "index.json", summary)
        for path in sorted(stage.iterdir()):
            if path.name != "index.json":
                path.replace(OUT / path.name)
        (stage / "index.json").replace(OUT / "index.json")


if __name__ == "__main__":
    main()
