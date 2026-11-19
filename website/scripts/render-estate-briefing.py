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
    estate = json.loads((PUBLIC / "estate/estate.json").read_bytes())
    captures = json.loads((MEDIA / "capture.json").read_bytes())["captures"]
    hero = estate.get("hero", "/estate/hero.jpg")
    shots = [(hero, 3, "A light is on over the front door of the simulated property.")]
    for case, camera, caption in SHOTS:
        take = next(
            row for row in captures if row["caseId"] == case and row["camera"] == camera
        )
        shots.append((take["film"], min(8, int(take["seconds"])), caption))
    filters, inputs, chapters, cues = [], [], [], ["WEBVTT", ""]
    clock = 0
    for i, (url, duration, caption) in enumerate(shots):
        path = PUBLIC / url.lstrip("/")
        inputs += (["-loop", "1", "-framerate", str(FPS)] if i == 0 else []) + [
            "-t",
            str(duration),
            "-i",
            str(path),
        ]
        filters.append(
            f"[{i}:v]scale={WIDTH}:{HEIGHT}:force_original_aspect_ratio=increase,crop={WIDTH}:{HEIGHT},setsar=1,fps={FPS},format=yuv420p,setpts=PTS-STARTPTS[s{i}]"
        )
        chapters.append(
            dict(
                start=clock,
                seconds=duration,
                source=url,
                sha256=digest(path),
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
        (stage / "briefing.json").write_text(json.dumps(receipt, indent=2) + "\n")
        for output in [film, captions, stage / "briefing.json"]:
            output.replace(MEDIA / output.name)
    print(f"Cut {clock} seconds of original estate and camera footage")


if __name__ == "__main__":
    main()
