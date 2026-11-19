"""Download the CC0 source assets the estate is built from.

    python3 -B website/art/estate/fetch_assets.py

Everything comes from Poly Haven (https://polyhaven.com, CC0). Files land in
`art/estate/assets/`, which is not committed. `assets.lock.json` records each
file's URL, size and SHA-256 so a rebuild can prove it used the same inputs.
A file that is already present with the locked digest is not fetched again.
"""
import hashlib
import json
import pathlib
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = pathlib.Path(__file__).resolve().parent
ASSETS = HERE / "assets"
LOCK = HERE / "assets.lock.json"
AGENT = {"User-Agent": "estate-asset-fetch"}

TEXTURES = [
    "roof_slates_03", "large_red_bricks", "stone_wall", "gravel_floor_02", "asphalt_02",
    "stone_tiles_02", "leafy_grass", "wood_chips", "floor_pattern_01", "concrete_pavers_02",
]
TEXTURE_MAPS = ["Diffuse", "nor_gl", "Rough", "Displacement"]
HDRIS = ["qwantani_night_puresky"]
# Indoor panoramas shown behind lit windows as glimpses of furnished rooms.
ROOMS = ["lythwood_lounge", "lythwood_room", "reading_room", "hotel_room", "fireplace", "entrance_hall",
         "cabin", "wooden_lounge", "kiara_interior"]
MODELS = [
    "pine_tree_01", "fir_tree_01", "island_tree_01", "island_tree_02", "jacaranda_tree", "tree_small_02",
    "shrub_01", "shrub_02", "shrub_03", "shrub_04", "fern_02", "grass_medium_01",
    "potted_plant_01", "potted_plant_02", "planter_box_01", "outdoor_table_chair_set_01",
    "painted_wooden_bench", "stone_fire_pit", "street_lamp_01", "street_lamp_02",
    "security_camera_01", "security_camera_02", "security_light", "exterior_aircon_unit",
    "fire_hydrant", "metal_trash_can", "modular_electricity_poles", "large_iron_gate", "covered_car",
    "garden_hose_wall_mounted_01", "crowbar_01", "Lantern_01", "utility_box_01", "power_box_01",
    "watering_can_metal_01", "wooden_ladder", "wooden_picnic_table",
]


def api(path):
    req = urllib.request.Request("https://api.polyhaven.com/" + path, headers=AGENT)
    return json.load(urllib.request.urlopen(req, timeout=60))


def plan():
    """Yield (relative path, url) for every file to fetch."""
    for slug in TEXTURES:
        files = api("files/" + slug)
        for name in TEXTURE_MAPS:
            entry = files.get(name, {}).get("2k", {}).get("jpg")
            if entry:
                yield f"textures/{slug}/{name}.jpg", entry["url"]
    for slug in HDRIS:
        files = api("files/" + slug)
        yield f"hdris/{slug}.exr", files["hdri"]["2k"]["exr"]["url"]
    for slug in ROOMS:
        files = api("files/" + slug)
        yield f"rooms/{slug}.hdr", files["hdri"]["1k"]["hdr"]["url"]
    for slug in MODELS:
        files = api("files/" + slug)
        sizes = files["blend"]
        size = "1k" if "1k" in sizes else sorted(sizes)[0]
        entry = sizes[size]["blend"]
        yield f"models/{slug}/{slug}.blend", entry["url"]
        for rel, inc in entry.get("include", {}).items():
            yield f"models/{slug}/{rel}", inc["url"]


def fetch(item, locked):
    rel, url = item
    dest = ASSETS / rel
    known = locked.get(rel)
    if dest.exists() and known:
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        if digest == known["sha256"]:
            return rel, known
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = urllib.request.urlopen(urllib.request.Request(url, headers=AGENT), timeout=300).read()
    dest.write_bytes(data)
    return rel, {"url": url, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


CAR_URL = "https://download.blender.org/demo/test/BMW27_2.blend.zip"
CAR_SHA256 = "74f5dc6d718fc565e0ff50e355be7f8b1a58983cc9ae79775608d8905c269ee4"


def fetch_car():
    """The CC0 Blender benchmark car, verified against its pinned digest."""
    import zipfile

    folder = ASSETS / "vehicles"
    archive = folder / "BMW27_2.blend.zip"
    folder.mkdir(parents=True, exist_ok=True)
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != CAR_SHA256:
        data = urllib.request.urlopen(urllib.request.Request(CAR_URL, headers=AGENT), timeout=300).read()
        if hashlib.sha256(data).hexdigest() != CAR_SHA256:
            raise SystemExit("car archive does not match its pinned digest")
        archive.write_bytes(data)
    with zipfile.ZipFile(archive) as z:
        z.extractall(folder)


def main():
    fetch_car()
    locked = json.loads(LOCK.read_text())["files"] if LOCK.exists() else {}
    items = list(plan())
    print(len(items), "files")
    with ThreadPoolExecutor(8) as pool:
        results = dict(pool.map(lambda item: fetch(item, locked), items))
    LOCK.write_text(json.dumps({
        "source": "https://polyhaven.com",
        "license": "CC0-1.0",
        "files": dict(sorted(results.items())),
    }, indent=1) + "\n")
    total = sum(v["bytes"] for v in results.values())
    print("ok", len(results), "files", round(total / 1e6, 1), "MB")


if __name__ == "__main__":
    sys.exit(main())
