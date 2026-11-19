"""Alder House site plan: the single source for the estate's layout.

Pure Python with no Blender imports. The Blender builder reads these numbers
to construct the model, and `emit_plan.py` writes them to
`public/estate/estate.json` for the website.

Frame: metres, right-handed, +x east, +y up, +z south toward the street.
The origin is finished grade directly below the centre of the front door
threshold. Blender uses (x, -z, y).

Alder House is fictional. Its massing, plan and grounds were authored for
this project and do not reproduce any real property.
"""

SCHEMA = "fss.website.estate_plan.v1"
NAME = "Alder House"
FIRST_FLOOR = 0.62  # finished first-floor level above grade

# Buildings: axis-aligned volumes. x and z give the footprint, eave and ridge
# are heights above grade, and ridge_axis names the direction the ridge runs.
BUILDINGS = {
    "main": dict(x=(-8.4, 8.4), z=(-10.8, 0.0), eave=6.75, ridge=10.45, ridge_axis="x", storeys=2),
    "east_wing": dict(x=(8.4, 16.2), z=(-9.4, -1.6), eave=3.95, ridge=7.2, ridge_axis="x", storeys=1),
    "sunroom": dict(x=(9.8, 15.0), z=(-14.2, -9.4), eave=3.55, ridge=4.75, ridge_axis="z", storeys=1),
    "connector": dict(x=(-13.4, -8.4), z=(-8.8, -2.4), eave=3.55, ridge=5.55, ridge_axis="x", storeys=1),
    "garage": dict(x=(-25.2, -13.4), z=(-10.6, -2.0), eave=3.45, ridge=7.15, ridge_axis="x", storeys=1),
    "pool_house": dict(x=(12.6, 18.6), z=(-32.4, -27.6), eave=2.75, ridge=4.3, ridge_axis="x", storeys=1),
    "shed": dict(x=(23.0, 26.6), z=(-42.6, -39.8), eave=2.2, ridge=3.3, ridge_axis="x", storeys=1),
}
PORTICO = dict(x=(-2.5, 2.5), z=(0.0, 2.7), floor=0.57, eave=3.3, ridge=4.28)

# Hard landscape. Polygons are (x, z) rings on the ground.
LOT = dict(x=(-36.0, 31.0), z=(-52.0, 38.0))
STREET = dict(z=(40.2, 47.2), sidewalk_z=(38.2, 40.2))
TERRACE = dict(x=(-7.2, 9.8), z=(-17.6, -10.8), level=0.45)
POOL = dict(x=(-2.0, 10.0), z=(-31.6, -26.6), deck=2.6, depth=1.5)
MOTOR_COURT = [(-26.4, -2.0), (-8.9, -2.0), (-8.9, 6.4), (-11.2, 9.6), (-17.4, 9.6), (-26.4, 6.2)]
# Driveway centre line from the motor court to the gate, 4.4 m wide.
DRIVEWAY_WIDTH = 4.4
DRIVEWAY = [(-14.4, 9.2), (-14.9, 14.0), (-16.6, 19.5), (-17.6, 25.0), (-16.2, 30.5), (-13.2, 34.6), (-12.0, 38.0)]
GATE = dict(x=-12.0, z=38.0, opening=4.6, pillar=0.8, pillar_height=2.25)
# Flagstone walk from the portico to the motor court.
FRONT_WALK_WIDTH = 1.5
FRONT_WALK = [(0.0, 2.7), (0.0, 7.2), (-1.6, 9.4), (-5.4, 9.9), (-8.9, 8.0)]
SIDE_FENCE_EAST = dict(z=-1.6, x=(16.2, 31.0), gate_x=(18.2, 19.4), height=1.8)
SIDE_FENCE_WEST = dict(z=-2.0, x=(-36.0, -25.2), gate_x=(-28.4, -27.2), height=1.8)

TREES = [
    # kind, x, z, height
    ("oak", 13.5, 17.5, 15.5),
    ("maple", 23.5, 7.5, 12.0),
    ("oak", -27.5, 22.0, 14.0),
    ("birch", -6.5, 30.5, 9.5),
    ("birch", -4.4, 32.4, 8.6),
    ("birch", -7.8, 33.0, 9.0),
    ("pine", -33.0, 8.0, 16.0),
    ("pine", -33.5, -6.0, 17.5),
    ("pine", -33.2, -20.0, 15.0),
    ("pine", -32.8, -34.0, 16.5),
    ("maple", 26.5, -12.5, 11.5),
    ("oak", 24.0, -47.0, 16.0),
    ("pine", 8.0, -49.0, 17.0),
    ("pine", -8.0, -49.5, 18.0),
    ("pine", -22.0, -48.5, 16.0),
    ("maple", -16.0, -22.0, 10.5),
    ("oak", -24.0, -30.0, 15.0),
    ("oak", 20.0, 28.0, 13.5),
    ("maple", 4.5, 26.0, 9.0),
    ("birch", 27.0, 33.5, 8.5),
    ("birch", 25.2, 35.0, 9.2),
    ("maple", -29.0, 33.0, 10.0),
    ("pine", 28.5, 20.0, 15.5),
    ("pine", 28.8, -30.0, 16.0),
    ("maple", 19.5, -36.0, 9.5),
    ("birch", -27.0, -41.0, 9.0),
    ("oak", -2.0, -41.0, 14.5),
    ("maple", -21.0, 15.5, 8.0),
]

# Houses across the street, for context in the gate and driveway views.
NEIGHBOURS = {
    "neighbour_a": dict(x=(-34.0, -19.0), z=(57.5, 66.5), eave=5.9, ridge=9.0, ridge_axis="x", storeys=2),
    "neighbour_b": dict(x=(6.0, 20.0), z=(58.5, 67.0), eave=3.6, ridge=6.9, ridge_axis="x", storeys=1),
    "neighbour_c": dict(x=(42.0, 56.0), z=(57.0, 66.0), eave=5.9, ridge=8.8, ridge_axis="x", storeys=2),
}

# Fixed cameras. Position and aim in the site frame; vfov in degrees for a
# 16:9 sensor. `mount` says what the camera is fixed to.
CAMERAS = [
    dict(id="porch", label="Front porch", mount="portico soffit, east side",
         position=(1.95, 2.72, 2.35), look_at=(-0.6, 0.9, 10.5), vfov=64.0),
    dict(id="driveway", label="Driveway", mount="garage eave, south-east corner",
         position=(-13.58, 2.6, -1.84), look_at=(-15.4, 0.4, 20.0), vfov=62.0),
    dict(id="gate", label="Gate", mount="post inside the street wall",
         position=(-17.6, 3.0, 30.6), look_at=(-11.6, 1.0, 38.2), vfov=60.0),
    dict(id="side", label="East side yard", mount="east wing, north-east corner",
         position=(16.45, 3.2, -9.2), look_at=(20.2, 0.7, 2.5), vfov=64.0),
    dict(id="terrace", label="Rear terrace", mount="main block rear eave, west end",
         position=(-7.0, 3.6, -11.0), look_at=(2.0, 0.6, -19.0), vfov=66.0),
    dict(id="pool", label="Pool and rear lawn", mount="sunroom, north-east corner",
         position=(15.2, 3.0, -14.4), look_at=(3.6, 0.2, -29.5), vfov=62.0),
    dict(id="service", label="West service yard", mount="garage, north-west corner",
         position=(-25.35, 2.75, -10.4), look_at=(-29.0, 0.4, 1.5), vfov=64.0),
    dict(id="entry", label="Entry walk", mount="lamp post beside the front walk",
         position=(-2.80, 2.35, 13.80), look_at=(-1.40, 1.55, 5.00), vfov=52.0),
    dict(id="garden", label="Garden border", mount="low post at the front garden border",
         position=(2.60, 1.10, 10.60), look_at=(-0.30, 0.23, 6.65), vfov=47.0),
]

OVERVIEW = dict(
    id="overview", label="Estate survey", position=(-10.0, 12.0, 23.5),
    look_at=(-3.2, 2.8, -3.0), vfov=47.0, aspect="16:9",
)

# Named ground zones for association and policy.
ZONES = {
    "gate_entry": [(-15.6, 33.2), (-8.6, 33.2), (-8.6, 38.0), (-15.6, 38.0)],
    "driveway": [(-17.2, 9.6), (-11.8, 9.6), (-12.6, 20.0), (-15.0, 26.0), (-13.4, 33.2), (-19.0, 33.2), (-20.2, 25.0), (-18.8, 18.0)],
    "motor_court": MOTOR_COURT,
    "front_walk": [(-1.2, 2.7), (1.2, 2.7), (1.2, 8.0), (-0.6, 10.6), (-8.9, 9.4), (-8.9, 7.0), (-2.2, 8.2), (-1.2, 7.0)],
    "porch": [(-2.5, 0.0), (2.5, 0.0), (2.5, 2.7), (-2.5, 2.7)],
    "east_side": [(16.2, -14.2), (22.4, -14.2), (22.4, -1.6), (16.2, -1.6)],
    "terrace": [(-7.2, -17.6), (9.8, -17.6), (9.8, -10.8), (-7.2, -10.8)],
    "pool_deck": [(-4.6, -34.2), (12.6, -34.2), (12.6, -24.0), (-4.6, -24.0)],
    "rear_lawn": [(-12.0, -24.0), (12.0, -24.0), (12.0, -17.6), (-12.0, -17.6)],
    "service_yard": [(-31.0, -11.0), (-25.2, -11.0), (-25.2, -2.0), (-31.0, -2.0)],
}

# The case roles are author-supplied ground truth for synthetic footage.
# Paths use metre coordinates. The flagstone surface is 45 mm above grade.
def take(actor, height, speed, cameras, waypoints, surface):
    return dict(
        seconds=8.0, cameras=cameras, actors=[dict(
            id=actor, height_m=height, speed_m_per_s=speed,
            path=[dict(x=x, y=surface, z=z) for x, z in waypoints],
        )],
    )


INCIDENTS = [
    dict(id="after-hours", title="The 02:14 intrusion report", local_time="02:14",
         motion={"terminal": "stand", "braking_seconds": 0.80}, **take(
        "visitor", 1.78, 1.49, ["porch", "entry", "driveway"],
        [(-4.20, 9.71), (-3.20, 9.55), (-1.60, 9.35), (-0.18, 7.55),
         (0.0, 6.00), (0.0, 4.10)], 0.045,
    )),
    dict(id="delivery", title="The evening delivery", **take(
        "courier", 1.74, 1.18, ["porch", "entry"],
        [(-5.10, 9.72), (-3.40, 9.64), (-1.60, 9.25), (-0.25, 7.45),
         (0.0, 5.70), (0.0, 3.25)], 0.045,
    )),
    dict(id="wildlife", title="Movement in the garden", **take(
        "raccoon", 0.30, 0.58, ["garden", "porch"],
        [(2.55, 6.15), (1.48, 6.74), (0.23, 7.10), (-0.85, 7.65), (-1.70, 8.04)], 0.025,
    )),
]


def as_json():
    """The plan as a JSON-ready dictionary."""
    def ring(points):
        return [[round(x, 3), round(z, 3)] for x, z in points]

    return {
        "schema": SCHEMA,
        "name": NAME,
        "status": "authored_reconstruction",
        "fictional": True,
        "frame": {
            "units": "metres",
            "axes": "+x east, +y up, +z south toward the street",
            "origin": "finished grade below the centre of the front door threshold",
        },
        "first_floor_level": FIRST_FLOOR,
        "buildings": {k: {"x": list(v["x"]), "z": list(v["z"]), "eave": v["eave"], "ridge": v["ridge"],
                          "ridge_axis": v["ridge_axis"], "storeys": v["storeys"]} for k, v in BUILDINGS.items()},
        "lot": LOT,
        "street": STREET,
        "gate": GATE,
        "driveway": {"width": DRIVEWAY_WIDTH, "centre_line": ring(DRIVEWAY)},
        "front_walk": {"width": FRONT_WALK_WIDTH, "centre_line": ring(FRONT_WALK)},
        "terrace": TERRACE,
        "pool": POOL,
        "cameras": [
            {**{k: v for k, v in c.items() if k not in ("position", "look_at")},
             "position": list(c["position"]), "look_at": list(c["look_at"]), "aspect": "16:9"}
            for c in CAMERAS
        ],
        "zones": {k: ring(v) for k, v in ZONES.items()},
        "overview": OVERVIEW,
        "incidents": INCIDENTS,
    }
