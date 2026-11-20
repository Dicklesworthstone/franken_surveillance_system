"""Cut a short site film from the same estate photograph and fixed camera takes."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

WEB = Path(__file__).resolve().parents[1]
PUBLIC = WEB / "public"
MEDIA = PUBLIC / "night-media"
WIDTH, HEIGHT, FPS = 1280, 720, 24
SHOTS = (
    ("after-hours", "porch", "02:14. A resident reports a possible armed intruder."),
    ("delivery", "entry", "A courier carries a parcel toward the entrance."),
    ("wildlife", "garden", "A raccoon crosses the planting bed."),
)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def timestamp(seconds):
    return f"00:{seconds // 60:02d}:{seconds % 60:02d}.000"


def main():
    plan_path = PUBLIC / "estate/estate.json"
    capture_path = MEDIA / "capture.json"
    plan_bytes = plan_path.read_bytes()
    capture_bytes = capture_path.read_bytes()
    estate = json.loads(plan_bytes)
    capture = json.loads(capture_bytes)
    if (
        capture["inputs"]["/estate/estate.json"]["sha256"]
        != sha256(plan_bytes).hexdigest()
    ):
        raise ValueError("Estate plan differs from the registered capture")
    hero = estate.get("hero", "/estate/hero.jpg")
    shots = [
        (hero, 3, "A light is on over the front door of the simulated property.", None)
    ]
    for case, camera, caption in SHOTS:
        (take,) = [
            row
            for row in capture["captures"]
            if row["caseId"] == case and row["camera"] == camera
        ]
        shots.append(
            (take["film"], min(8, int(take["seconds"])), caption, take["videoSha256"])
        )
    filters, inputs, chapters, cues = [], [], [], ["WEBVTT", ""]
    snapshots = {}
    clock = 0
    for i, (url, duration, caption, expected) in enumerate(shots):
        path = PUBLIC / url.lstrip("/")
        data = path.read_bytes()
        source_hash = sha256(data).hexdigest()
        if i and source_hash != expected:
            raise ValueError(f"Camera film differs from its capture receipt: {url}")
        filename = f"shot-{i}{path.suffix}"
        snapshots[filename] = data
        inputs += (["-loop", "1", "-framerate", str(FPS)] if i == 0 else []) + [
            "-t",
            str(duration),
            "-i",
            filename,
        ]
        filters.append(
            f"[{i}:v]scale={WIDTH}:{HEIGHT}:force_original_aspect_ratio=increase,crop={WIDTH}:{HEIGHT},setsar=1,fps={FPS},format=yuv420p,setpts=PTS-STARTPTS[s{i}]"
        )
        chapters.append(
            dict(
                start=clock,
                seconds=duration,
                source=url,
                sha256=source_hash,
                caption=caption,
            )
        )
        cues.extend(
            [f"{timestamp(clock)} --> {timestamp(clock + duration)}", caption, ""]
        )
        clock += duration
    filters.append(
        "".join(f"[s{i}]" for i in range(len(shots)))
        + f"concat=n={len(shots)}:v=1:a=0[out]"
    )
    with TemporaryDirectory(dir=MEDIA, prefix=".briefing-") as temp:
        stage = Path(temp)
        for filename, data in snapshots.items():
            (stage / filename).write_bytes(data)
        film = stage / "estate-briefing.mp4"
        subprocess.run(
            [
                "ffmpeg",
                "-nostdin",
                "-v",
                "error",
                *inputs,
                "-filter_complex_threads",
                "2",
                "-filter_complex",
                ";".join(filters),
                "-map",
                "[out]",
                "-an",
                "-c:v",
                "libx264",
                "-threads",
                "4",
                "-preset",
                "slow",
                "-crf",
                "19",
                "-movflags",
                "+faststart",
                str(film),
            ],
            check=True,
            cwd=stage,
        )
        captions = stage / "estate-briefing.vtt"
        captions.write_text("\n".join(cues))
        receipt = dict(
            film="/night-media/" + film.name,
            filmSha256=digest(film),
            seconds=clock,
            fps=FPS,
            captions="/night-media/" + captions.name,
            captionsSha256=digest(captions),
            captureSha256=sha256(capture_bytes).hexdigest(),
            chapters=chapters,
        )
        encoded = json.loads(
            subprocess.check_output(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "stream=nb_frames,r_frame_rate",
                    "-of",
                    "json",
                    str(film),
                ]
            )
        )["streams"][0]
        if (
            int(encoded["nb_frames"]) != clock * FPS
            or encoded["r_frame_rate"] != f"{FPS}/1"
        ):
            raise ValueError("The briefing duration differs from the registered cuts")
        if (
            plan_path.read_bytes() != plan_bytes
            or capture_path.read_bytes() != capture_bytes
            or any(
                digest(PUBLIC / shot["source"].lstrip("/")) != shot["sha256"]
                for shot in chapters
            )
        ):
            raise ValueError("Briefing sources changed during encoding")
        (stage / "briefing.json").write_text(json.dumps(receipt, indent=2) + "\n")
        for output in [film, captions, stage / "briefing.json"]:
            output.replace(MEDIA / output.name)
    print(f"Cut {clock} seconds of original estate and camera footage")


if __name__ == "__main__":
    main()
