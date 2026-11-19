"""Replay the three authored ball-center correspondences with native fss-scene-fuse."""

from hashlib import sha256
import json
import os
from pathlib import Path
from runpy import run_path
import subprocess
from tempfile import TemporaryDirectory

WEB = Path(__file__).resolve().parents[1]
DATA = WEB / "public/stereo"
encode = run_path(str(WEB.parent / "scripts/twin_interchange.py"))["encode_twin"]


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def write(path, data):
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")
    return digest(path.read_bytes())


def native_xyz(vector):
    x, y, z = vector
    return [x, -z, y]


def main():
    source = DATA / "capture.json"
    cap = json.loads(source.read_text())
    pin = digest(source.read_bytes())
    binary = (
        Path(os.environ.get("FSS_BIN_DIR", WEB.parent / "target/debug"))
        / "fss-scene-fuse"
    )
    scope = "Juniper Court synthetic floor only"
    floor = cap["floor"]
    w, d = floor["width"] / 2, floor["depth"] / 2
    with TemporaryDirectory(dir=DATA.parent) as tmp:
        stage = Path(tmp)
        twin = stage / "floor.fsstwin"
        twin.write_bytes(
            encode(
                source_sha256=pin[7:],
                scope=scope,
                epoch="reference-pass",
                scale=dict(status="estimated", metres_per_unit=1, error=None),
                geometry_error=None,
                features=[dict(id="court", surface="pedestrian_path")],
                objects=[dict(id="slab", feature="court", support=True, opaque=True)],
                vertices=[
                    [x, y, floor["y"]] for x, y in [(-w, -d), (w, -d), (w, d), (-w, d)]
                ],
                triangles=[[0, 1, 2, "slab"], [0, 2, 3, "slab"]],
            )
        )
        cameras = []
        for i, (name, c) in enumerate(cap["cameras"].items(), 1):
            rotation = [
                native_xyz(c["right"]),
                native_xyz([-n for n in c["up"]]),
                native_xyz(c["forward"]),
            ]
            center = native_xyz(c["position"])
            cameras.append(
                dict(
                    camera=i,
                    calibration=1,
                    image_domain=1,
                    clock=1,
                    privacy_domain=1,
                    validity_ns=[0, 4000000000],
                    source_object_id=name,
                    image_model="undistorted_pinhole",
                    world_to_camera=dict(
                        rotation=rotation,
                        translation=[
                            -sum(a * b for a, b in zip(row, center)) for row in rotation
                        ],
                    ),
                    intrinsics=dict(
                        width=896,
                        height=504,
                        fx=c["focal"],
                        fy=c["focal"],
                        cx=448,
                        cy=252,
                    ),
                    error=None,
                    status="authored_nominal",
                )
            )
        rig = stage / "rig.json"
        rig_digest = write(
            rig,
            dict(
                schema="fss.scene_camera_rig.v1",
                source_scene_digest=pin,
                twin_digest=digest(twin.read_bytes()),
                geometry_basis=dict(property=1, revision=1),
                coordinate_frame="RH_Z_UP",
                evaluation_scope=scope,
                cameras=cameras,
            ),
        )
        for moment in cap["moments"]:
            n = moment["frame"]
            time = round(n * 1000000000 / cap["fps"])
            observations = []
            for i, (name, xy) in enumerate(moment["marks"].items(), 1):
                proof = dict(
                    camera=name,
                    frame=n,
                    source=cap["files"][f"{name}-{n}.png"],
                    pixel=xy,
                    method="authored projection of ball centre",
                )
                observer = write(stage / f"{name}-{n}-mark.json", proof)
                observations.append(
                    dict(
                        source_digest=proof["source"],
                        evidence_digest=observer,
                        camera=i,
                        track=1,
                        exposure=n,
                        image_domain=1,
                        capture_ns=[time, time],
                        pixel_min=xy,
                        pixel_max=xy,
                        visible_contact=True,
                        sigma_pixels=0.5,
                    )
                )
            query = stage / f"query-{n}.json"
            write(
                query,
                dict(
                    schema="fss.scene_fusion_query.v1",
                    camera_rig_digest=rig_digest,
                    privacy_domain=1,
                    clock=1,
                    clock_evidence=pin,
                    reference_time_ns=time,
                    hypotheses=[
                        dict(
                            id="feature:ball-centre",
                            association_evidence=pin,
                            max_capture_span_ns=0,
                            motion=dict(kind="static"),
                            observations=observations,
                        )
                    ],
                ),
            )
            subprocess.run(
                [
                    binary,
                    "--twin",
                    twin,
                    "--rig",
                    rig,
                    "--observations",
                    query,
                    "--report-out",
                    stage / f"report-{n}.json",
                ],
                stdout=subprocess.DEVNULL,
                check=True,
            )
        for file in sorted(stage.iterdir()):
            file.replace(DATA / file.name)


if __name__ == "__main__":
    main()
