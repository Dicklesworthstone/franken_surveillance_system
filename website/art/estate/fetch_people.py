"""Download the people and motion inputs and check them against people.lock.json.

    python3 -B website/art/estate/fetch_people.py            # fetch what is missing, verify everything
    python3 -B website/art/estate/fetch_people.py --update   # pin the bytes now on disk

Files land under assets/ (git-ignored). A file whose SHA-256 differs from the lock stops the
run: delete it to fetch it again, or pass --update if the new bytes are the ones to pin.
"""
from contextlib import nullcontext
import hashlib
import json
import pathlib
import sys
import urllib.request
import render_files

HERE = pathlib.Path(__file__).resolve().parent
ASSETS = HERE / "assets"

PACKT = "https://raw.githubusercontent.com/PacktPublishing/Godot-4-Game-Development-Cookbook/e752af943e8cf035def41f17d9efa8e50b1bc135/Chapter%209"
CMU = "https://raw.githubusercontent.com/una-dinosauria/cmu-mocap/master"

RENDERPEOPLE = "CC BY 4.0, Renderpeople"
CMU_TERMS = ("CMU Graphics Lab Motion Capture Database, mocap.cs.cmu.edu, created with funding from NSF EIA-0196217; "
             "free to use, not to be resold as data. BVH conversion by Bruce Hahne (cgspeed.com).")

# Clips the published films use; the rest were auditioned.
USED = ["91_17", "77_28", "77_02", "77_05", "77_10", "09_01", "35_01", "40_10", "16_55"]
AUDITIONED = ["07_01", "07_02", "08_01", "35_02", "16_08", "16_15", "16_17", "16_19", "16_21", "16_35", "16_36", "16_45",
              "16_56", "16_57", "09_02", "09_03", "02_01", "12_01", "13_10", "13_35", "15_06", "15_07", "26_09", "36_02",
              "37_01", "39_01", "69_68", "69_70", "70_01", "77_01", "77_04", "77_06", "77_09", "77_11", "77_14", "77_25",
              "77_26", "77_29", "77_30", "77_34", "79_73", "83_27", "83_34", "91_22"]


def inputs():
    rows = []
    for who, title, page, stem, fbx in (
        ("eric", "Eric Rigged 001 - Rigged 3D Business Man", "https://sketchfab.com/3d-models/a46bc9f67aaa415bb4f3241eef900e7f",
         "rp_eric_rigged_001", "rp_eric_rigged_001_zup_t.fbx"),
        ("nathan", "Nathan Animated 003 - Walking 3D Man", "https://sketchfab.com/3d-models/143a2b1ea5eb4385ae90a73657aca3bc",
         "rp_nathan_animated_003", "rp_nathan_animated_003_walking.fbx"),
    ):
        folder = who.capitalize()
        rows.append(dict(path=f"scans/{who}/{fbx}", url=f"{PACKT}/{folder}/{fbx}", licence=RENDERPEOPLE, work=title, source=page, used=True))
        for kind in ("dif", "gloss", "mask01", "mask02", "norm"):
            # scans.py tints the lookout through mask01 only; his second mask is fetched and not read.
            rows.append(dict(path=f"scans/{who}/{stem}_{kind}.jpg", url=f"{PACKT}/{folder}/tex/{stem}_{kind}.jpg",
                             licence=RENDERPEOPLE, work=title, source=page, used=(who, kind) != ("nathan", "mask02")))
    for clip in USED + AUDITIONED:
        subject = int(clip.split("_")[0])
        rows.append(dict(path=f"mocap/{clip}.bvh", url=f"{CMU}/data/{subject:03d}/{clip}.bvh", licence=CMU_TERMS, used=clip in USED))
    for name in ("cmu-mocap-index-text.txt", "READMEFIRST.txt"):
        rows.append(dict(path=f"mocap/{name}", url=f"{CMU}/{name}", licence=CMU_TERMS, used=False))
    return rows


def main():
    update = "--update" in sys.argv[1:]
    out = HERE / "people.lock.json"
    pinned = {row["path"]: row["sha256"] for row in json.loads(out.read_text())["files"]} if out.exists() else {}
    locked = []
    for row in inputs():
        target = ASSETS / row["path"]
        missing = not target.exists()
        if missing:
            target.parent.mkdir(parents=True, exist_ok=True)
        destination = render_files.output_file(target) if missing else nullcontext(target)
        with destination as path:
            if missing:
                print("fetch", row["url"])
                request = urllib.request.Request(row["url"], headers={"User-Agent": "estate-asset-fetch"})
                with urllib.request.urlopen(request, timeout=300) as response:
                    path.write_bytes(response.read())
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            want = pinned.get(row["path"])
            if want and want != digest and not update:
                raise SystemExit(f"{row['path']} is not the pinned file: SHA-256 {digest}, people.lock.json has {want}.")
            if not want and pinned and not update:
                raise SystemExit(f"{row['path']} is not in people.lock.json. Pass --update to pin it.")
        locked.append(dict(row, bytes=len(data), sha256=digest))
    if update or not pinned:
        render_files.write_text(out, json.dumps(dict(schema="fss.website.estate_people_lock.v1", files=locked), indent=1) + "\n")
        print("wrote", out, len(locked), "files,", sum(r["bytes"] for r in locked) // 1_000_000, "MB")
    else:
        print("verified", len(locked), "files against", out.name)


if __name__ == "__main__":
    main()
