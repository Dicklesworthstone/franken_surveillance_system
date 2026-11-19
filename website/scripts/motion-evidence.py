"""Run the pinned native detector on the motion study's two fixed camera films."""

from pathlib import Path
import json
from runpy import run_path
import shutil
from tempfile import TemporaryDirectory

native = run_path(str(Path(__file__).with_name("native-evidence.py")))
out = native["WEB"] / "public/motion"
digest = native["digest"]
spec = dict(nativeWidth=160, nativeHeight=90, nativeFps=4, fps=24)


def main():
    capture = json.loads((out / "capture.json").read_text())
    assert digest(native["MODEL"]) == native["PIN"]
    analysis = dict(
        capture=digest(out / "capture.json"), model=native["PIN"], sampleFps=4, views={}
    )
    with TemporaryDirectory(dir=out.parent) as staging, TemporaryDirectory() as working:
        tmp, stage = Path(working), Path(staging)
        shutil.copyfile(native["MODEL"], tmp / "model.fmpk")
        for cam in ("porch", "drive"):
            view = native["import_clip"](
                "motion", cam, cam, spec, tmp, stage, films=out
            )
            assert view["filmDigest"] == "sha256:" + capture["files"][cam + ".mp4"]
            analysis["views"][cam] = view
        for cam, view in analysis["views"].items():
            report = json.loads(
                native["run"](
                    [
                        native["BINS"] / "fss-event",
                        "watch",
                        *native["SCOPE"],
                        "--import-id",
                        view["importId"],
                        "--interpretation",
                        "ycbcr",
                        "--zone",
                        "image:0,0,160,90",
                        "--detector-package",
                        "model.fmpk",
                        "--detector-digest",
                        native["PIN"],
                        "--detector-max-inferences",
                        "2",
                    ],
                    tmp,
                )
            )
            assert report["import_identity"] == view["importId"]
            assert report["frames_decoded"] == capture["seconds"] * spec["nativeFps"]
            path = stage / (cam + ".json")
            native["write"](path, report)
            # The reference plate is the JPEG actually imported at one second.
            plate = stage / (cam + "-sample.jpg")
            native["run"](
                [
                    "ffmpeg",
                    "-v",
                    "error",
                    "-f",
                    "mjpeg",
                    "-i",
                    stage / (cam + ".mjpeg"),
                    "-c:v",
                    "copy",
                    "-f",
                    "image2",
                    "-start_number",
                    "0",
                    tmp / (cam + "-%02d.jpg"),
                ],
                tmp,
            )
            shutil.copyfile(tmp / (cam + "-04.jpg"), plate)
            view.update(
                reportDigest=digest(path),
                frames=report["frames_decoded"],
                sampleDigest=digest(plate),
                plateSegment=4,
                candidates=report["candidate_count"],
                samples=[
                    dict(
                        segment=f["segment"],
                        status=f["status"],
                        classes=sorted({d["label"] for d in f.get("detections", [])}),
                        detections=[
                            {k: d[k] for k in ("label", "score", "bounds_subpixel")}
                            for d in f.get("detections", [])
                        ],
                    )
                    for f in report["detector_cascade"]["frames"]
                ],
            )
        native["write"](stage / "analysis.json", analysis)
        for path in sorted(stage.iterdir()):
            if path.name != "analysis.json":
                path.replace(out / path.name)
        (stage / "analysis.json").replace(out / "analysis.json")


if __name__ == "__main__":
    main()
