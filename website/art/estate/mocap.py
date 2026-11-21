"""Motion capture for the films: read CMU BVH clips, lay them along site paths,
and retarget them onto a rigged figure.

Everything here is numpy; only `Retarget` touches Blender. Axes follow Blender:
+z up, a T-posed figure faces -y. Rotations are 3x3 matrices that act on column
vectors. A clip stores, per frame and joint, the joint's world rotation relative
to its orientation in the clip's T-pose frame, so a pose can be carried to any
skeleton that can be put in the same T-pose.
"""
import math
import pathlib

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
CLIPS = HERE / "assets" / "mocap"
RATE = 24  # clip sample rate after loading, frames per second
INCH = 0.0254
CMU_UNIT = INCH / 0.45  # CMU skeleton files are in inches divided by 0.45

# BVH (x right, y up, z toward the viewer) to Blender (x right, y away, z up).
AXES = np.array([[1.0, 0.0, 0.0], [0.0, 0.0, -1.0], [0.0, 1.0, 0.0]])


def rot_x(a):
    c, s = math.cos(a), math.sin(a)
    return np.array([[1, 0, 0], [0, c, -s], [0, s, c]], dtype=float)


def rot_y(a):
    c, s = math.cos(a), math.sin(a)
    return np.array([[c, 0, s], [0, 1, 0], [-s, 0, c]], dtype=float)


def rot_z(a):
    c, s = math.cos(a), math.sin(a)
    return np.array([[c, -s, 0], [s, c, 0], [0, 0, 1]], dtype=float)


def euler_stack(order, angles):
    """Rotation matrices for (N, 3) angles in degrees applied in BVH channel order."""
    n = len(angles)
    out = np.broadcast_to(np.eye(3), (n, 3, 3)).copy()
    for axis, column in zip(order, np.radians(angles).T):
        c, s = np.cos(column), np.sin(column)
        m = np.zeros((n, 3, 3))
        if axis == "X":
            m[:, 0, 0] = 1; m[:, 1, 1] = c; m[:, 1, 2] = -s; m[:, 2, 1] = s; m[:, 2, 2] = c
        elif axis == "Y":
            m[:, 1, 1] = 1; m[:, 0, 0] = c; m[:, 0, 2] = s; m[:, 2, 0] = -s; m[:, 2, 2] = c
        else:
            m[:, 2, 2] = 1; m[:, 0, 0] = c; m[:, 0, 1] = -s; m[:, 1, 0] = s; m[:, 1, 1] = c
        out = out @ m
    return out


def quat_from_matrix(m):
    """(..., 3, 3) rotation matrices to (..., 4) quaternions, w first."""
    m = np.asarray(m)
    shape = m.shape[:-2]
    m = m.reshape(-1, 3, 3)
    q = np.empty((len(m), 4))
    trace = m[:, 0, 0] + m[:, 1, 1] + m[:, 2, 2]
    for i in range(len(m)):
        a = m[i]
        if trace[i] > 0:
            s = math.sqrt(trace[i] + 1.0) * 2
            q[i] = (0.25 * s, (a[2, 1] - a[1, 2]) / s, (a[0, 2] - a[2, 0]) / s, (a[1, 0] - a[0, 1]) / s)
        elif a[0, 0] > a[1, 1] and a[0, 0] > a[2, 2]:
            s = math.sqrt(1.0 + a[0, 0] - a[1, 1] - a[2, 2]) * 2
            q[i] = ((a[2, 1] - a[1, 2]) / s, 0.25 * s, (a[0, 1] + a[1, 0]) / s, (a[0, 2] + a[2, 0]) / s)
        elif a[1, 1] > a[2, 2]:
            s = math.sqrt(1.0 + a[1, 1] - a[0, 0] - a[2, 2]) * 2
            q[i] = ((a[0, 2] - a[2, 0]) / s, (a[0, 1] + a[1, 0]) / s, 0.25 * s, (a[1, 2] + a[2, 1]) / s)
        else:
            s = math.sqrt(1.0 + a[2, 2] - a[0, 0] - a[1, 1]) * 2
            q[i] = ((a[1, 0] - a[0, 1]) / s, (a[0, 2] + a[2, 0]) / s, (a[1, 2] + a[2, 1]) / s, 0.25 * s)
    return q.reshape(*shape, 4)


def matrix_from_quat(q):
    q = np.asarray(q, dtype=float)
    q = q / np.linalg.norm(q, axis=-1, keepdims=True)
    w, x, y, z = q[..., 0], q[..., 1], q[..., 2], q[..., 3]
    m = np.empty(q.shape[:-1] + (3, 3))
    m[..., 0, 0] = 1 - 2 * (y * y + z * z); m[..., 0, 1] = 2 * (x * y - z * w); m[..., 0, 2] = 2 * (x * z + y * w)
    m[..., 1, 0] = 2 * (x * y + z * w); m[..., 1, 1] = 1 - 2 * (x * x + z * z); m[..., 1, 2] = 2 * (y * z - x * w)
    m[..., 2, 0] = 2 * (x * z - y * w); m[..., 2, 1] = 2 * (y * z + x * w); m[..., 2, 2] = 1 - 2 * (x * x + y * y)
    return m


def slerp(a, b, t):
    """Blend quaternion arrays (..., 4); t is a scalar or broadcasts over the leading axes."""
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    t = np.asarray(t, dtype=float)
    if t.ndim:
        t = t.reshape(t.shape + (1,) * (a.ndim - t.ndim))
    dot = np.sum(a * b, axis=-1, keepdims=True)
    b = np.where(dot < 0, -b, b)
    dot = np.clip(np.abs(dot), 0.0, 1.0)
    theta = np.arccos(dot)
    sin = np.sin(theta)
    near = sin < 1e-5
    safe = np.where(near, 1.0, sin)
    wa = np.where(near, 1.0 - t, np.sin((1.0 - t) * theta) / safe)
    wb = np.where(near, t, np.sin(t * theta) / safe)
    out = wa * a + wb * b
    return out / np.linalg.norm(out, axis=-1, keepdims=True)


def shortest_arc(a, b):
    """Rotation matrix that turns unit vector a onto unit vector b by the shortest path."""
    a, b = a / np.linalg.norm(a), b / np.linalg.norm(b)
    v = np.cross(a, b)
    c = float(np.dot(a, b))
    if c < -0.999999:
        axis = np.cross(a, [1.0, 0.0, 0.0])
        if np.linalg.norm(axis) < 1e-6:
            axis = np.cross(a, [0.0, 1.0, 0.0])
        axis /= np.linalg.norm(axis)
        return 2.0 * np.outer(axis, axis) - np.eye(3)
    k = np.array([[0, -v[2], v[1]], [v[2], 0, -v[0]], [-v[1], v[0], 0]])
    return np.eye(3) + k + k @ k / (1.0 + c)


# Limb bones whose T-pose direction is matched between clip and character, and
# the bones that ride along with them. Feet, spine, head and clavicles keep the
# character's own rest orientation: both figures stand upright with flat feet.
ALIGN = ["Arm", "ForeArm", "UpLeg", "Leg"]
DIRECTION_CHILD = {"Arm": "ForeArm", "ForeArm": "Hand", "UpLeg": "Leg", "Leg": "Foot"}


def side_of(name):
    """Split a CMU joint name into its side and the rest."""
    for side in ("Left", "Right"):
        if name.startswith(side):
            return side, name[len(side):]
    return "", name

FOLLOW = {"Hand": "ForeArm", "FingerBase": "ForeArm", "HandFinger1": "ForeArm", "HandIndex1": "ForeArm"}
SOURCE_NAME = {"LeftHandFinger1": "LeftHandIndex1", "RightHandFinger1": "RightHandIndex1"}


def canonical(name):
    """Canonical T-pose direction of an aligned limb bone."""
    if name.endswith("Arm"):
        return np.array([1.0 if name.startswith("Left") else -1.0, 0.0, 0.0])
    return np.array([0.0, 0.0, -1.0])


class Motion:
    """A stretch of motion in world axes at RATE frames per second.

    root: (F, 3) hip joint position in metres for a figure of `hip_height`.
    quat: (F, J, 4) world rotation of each joint relative to the T-pose.
    """

    def __init__(self, names, root, quat, hip_height, t_dirs, label=""):
        self.names, self.root, self.quat = names, root, quat
        self.hip_height, self.t_dirs, self.label = hip_height, t_dirs, label

    def __len__(self):
        return len(self.root)

    def cut(self, start, stop):
        return Motion(self.names, self.root[start:stop].copy(), self.quat[start:stop].copy(), self.hip_height, self.t_dirs, self.label)

    def index(self, name):
        return self.names.index(name)

    def yaw(self):
        """Heading of the hips per frame: 0 facing -y, counter-clockwise from above."""
        forward = matrix_from_quat(self.quat[:, self.index("Hips")]) @ np.array([0.0, -1.0, 0.0])
        return np.unwrap(np.arctan2(forward[:, 0], -forward[:, 1]))

    def scaled(self, factor):
        """The same motion for a figure `factor` times the size."""
        root = self.root * factor
        return Motion(self.names, root, self.quat.copy(), self.hip_height * factor, self.t_dirs, self.label)

    def raised(self, height):
        root = self.root.copy()
        root[:, 2] += height
        return Motion(self.names, root, self.quat.copy(), self.hip_height, self.t_dirs, self.label)


def load(name):
    """Parse CLIPS/<name>.bvh into a Motion, resampled to RATE, T-pose frame removed."""
    lines = (CLIPS / f"{name}.bvh").read_text().split("\n")
    names, parents, offsets, orders, channel_at = [], [], [], {}, {}
    stack, cursor, root_channels = [], 0, None
    i = 0
    while not lines[i].startswith("MOTION"):
        tokens = lines[i].split()
        i += 1
        if not tokens:
            continue
        if tokens[0] in ("ROOT", "JOINT"):
            names.append(tokens[1]); parents.append(stack[-1] if stack else -1)
            stack.append(len(names) - 1)
        elif tokens[0] == "End":
            names.append(names[stack[-1]] + "_end"); parents.append(stack[-1])
            stack.append(len(names) - 1)
        elif tokens[0] == "OFFSET":
            offsets.append([float(v) for v in tokens[1:4]])
        elif tokens[0] == "CHANNELS":
            kinds = tokens[2:]
            joint = stack[-1]
            moves = [k[0] for k in kinds if k.endswith("position")]
            if moves:
                root_channels = (cursor, moves)
            orders[joint] = "".join(k[0] for k in kinds if k.endswith("rotation"))
            channel_at[joint] = cursor + len(moves)
            cursor += len(kinds)
        elif tokens[0] == "}":
            stack.pop()
    frame_count = int(lines[i + 1].split()[1])
    frame_time = float(lines[i + 2].split()[2])
    data = np.array([[float(v) for v in line.split()] for line in lines[i + 3:i + 3 + frame_count] if line.strip()])
    offsets = np.array(offsets)
    count = len(names)
    local = np.broadcast_to(np.eye(3), (len(data), count, 3, 3)).copy()
    for j, order in orders.items():
        local[:, j] = euler_stack(order, data[:, channel_at[j]:channel_at[j] + 3])
    world = np.empty_like(local)
    position = np.zeros((len(data), count, 3))
    start, axes = root_channels
    root_position = np.zeros((len(data), 3))
    for k, axis in enumerate(axes):
        root_position[:, "XYZ".index(axis)] = data[:, start + k]
    for j in range(count):
        p = parents[j]
        if p < 0:
            world[:, j] = local[:, j]
            position[:, j] = root_position
        else:
            world[:, j] = world[:, p] @ local[:, j]
            position[:, j] = position[:, p] + np.einsum("fij,j->fi", world[:, p], offsets[j])
    # Frame 0 is the conversion's T-pose. Express later frames relative to it.
    relative = world @ np.swapaxes(world[0:1], -1, -2)
    relative = AXES @ relative @ AXES.T
    position = position @ AXES.T * CMU_UNIT
    t_pose = position[0]
    children = {}
    for j, p in enumerate(parents):
        children.setdefault(p, []).append(j)
    t_dirs = {}
    for j, name_j in enumerate(names):
        kids = children.get(j, [])
        if len(kids) == 1:
            d = t_pose[kids[0]] - t_pose[j]
            if np.linalg.norm(d) > 1e-6:
                t_dirs[name_j] = d / np.linalg.norm(d)
    # Re-express limb rotations against one canonical T-pose (arms level along
    # x, legs plumb) so clips from different subjects can be joined.
    for j, name_j in enumerate(names):
        side = "Left" if name_j.startswith("Left") else "Right" if name_j.startswith("Right") else ""
        kind = name_j[len(side):]
        if name_j in ("LThumb", "RThumb"):
            side, kind = ("Left" if name_j[0] == "L" else "Right"), "Hand"
        owner = side + FOLLOW.get(kind, kind) if side else ""
        if owner in t_dirs and FOLLOW.get(kind, kind) in ALIGN:
            fix = shortest_arc(canonical(owner), t_dirs[owner])
            relative[:, j] = relative[:, j] @ fix
    feet = [names.index(n) for n in ("LeftToeBase", "RightToeBase", "LeftFoot", "RightFoot")]
    floor = np.percentile(position[1:, feet, 2].min(axis=1), 5)
    hip_height = float(t_pose[0, 2] - min(t_pose[f, 2] for f in feet))
    step = max(1, round(1.0 / frame_time / RATE))
    keep = np.arange(1, len(data), step)
    root = position[keep, 0].copy()
    root[:, 2] -= floor
    quat = quat_from_matrix(relative[keep])
    for f in range(1, len(quat)):
        flip = np.sum(quat[f] * quat[f - 1], axis=-1) < 0
        quat[f, flip] *= -1
    return Motion(names, root, quat, hip_height, t_dirs, name)


def heading(direction):
    """Angle about +z that turns a figure facing -y to face `direction` (xy)."""
    return math.atan2(direction[0], -direction[1])


def turned(motion, angle, pivot=None):
    """Rotate a motion about the vertical through `pivot` (xy), default its first root position."""
    pivot = motion.root[0, :2] if pivot is None else np.asarray(pivot)
    r = rot_z(angle)
    root = motion.root.copy()
    root[:, :2] = (root[:, :2] - pivot) @ r[:2, :2].T + pivot
    q = quat_from_matrix(r @ matrix_from_quat(motion.quat))
    return Motion(motion.names, root, q, motion.hip_height, motion.t_dirs, motion.label)


def moved(motion, xy):
    """Translate so the first root position sits at xy."""
    root = motion.root.copy()
    root[:, :2] += np.asarray(xy) - root[0, :2]
    return Motion(motion.names, root, motion.quat.copy(), motion.hip_height, motion.t_dirs, motion.label)


def straight_axis(motion):
    """Best-fit direction of travel (unit xy) and that direction's angle from -y."""
    xy = motion.root[:, :2]
    d = xy[-1] - xy[0]
    d /= np.linalg.norm(d)
    return d, heading(d)


def cycle(motion, low, high, search=None):
    """Find frames (a, b) whose poses and velocities match best, with low <= (b - a) / RATE <= high seconds."""
    m = matrix_from_quat(motion.quat)
    feature = m.reshape(len(m), -1)
    vel = np.gradient(feature, axis=0)
    height = motion.root[:, 2:3] * 4.0
    feature = np.concatenate([feature, vel * 6.0, height], axis=1)
    lo, hi = (0, len(motion)) if search is None else search
    best = None
    for a in range(lo + 6, hi - int(low * RATE)):
        for b in range(a + int(low * RATE), min(hi, a + int(high * RATE) + 1)):
            cost = float(np.sum((feature[a] - feature[b]) ** 2))
            if best is None or cost < best[0]:
                best = (cost, a, b)
    return best


def along(motion, path, a, b, start=0.0, distance=None, duration=None, seam=5, stride=1.0, steps=None, phase=0):
    """Loop the gait cycle motion[a:b] along a path.

    path: object with length, point(s) -> (x, y), tangent(s) -> unit (x, y), height(x, y).
    start: arc length where the first frame stands. Stops after `distance` metres
    of travel or `duration` seconds, whichever is given. `stride` scales step
    length (keep within about 0.85 to 1.15). `steps` replaces the clip's own
    forward travel per frame (see Retarget.strides); `phase` is the cycle frame
    to begin on. Returns (Motion, arc length per frame).
    """
    direction, axis_yaw = straight_axis(motion.cut(a, b + 1))
    normal = np.array([-direction[1], direction[0]])
    xy = motion.root[:, :2]
    progress = (xy - xy[a]) @ direction
    lateral = (xy - xy[a]) @ normal
    lateral = lateral - np.mean(lateral[a:b])
    step = np.diff(progress) if steps is None else np.asarray(steps)
    n = b - a
    step_c = step[a:b].copy()
    lat_c = lateral[a:b].copy()
    z_c = motion.root[a:b, 2].copy()
    q_c = motion.quat[a:b].copy()
    seam = min(seam, a)
    for k in range(seam):
        w = (k + 1) / (seam + 1)
        src = a - seam + k
        dst = n - seam + k
        step_c[dst] = (1 - w) * step_c[dst] + w * step[src]
        lat_c[dst] = (1 - w) * lat_c[dst] + w * lateral[src]
        z_c[dst] = (1 - w) * z_c[dst] + w * motion.root[src, 2]
        q_c[dst] = slerp(q_c[dst], motion.quat[src], w)
    unturn = rot_z(-axis_yaw)
    local = unturn @ matrix_from_quat(q_c)
    per_cycle = float(np.sum(step_c)) * stride
    if duration is not None:
        frames = int(round(duration * RATE))
    else:
        frames = int(math.ceil(distance / per_cycle * n))
    roots, quats, arcs = [], [], []
    s = start
    for f in range(frames):
        k = (f + phase) % n
        arcs.append(s)
        s_clamped = min(max(s, 0.0), path.length)
        px, py = path.point(s_clamped)
        tx, ty = path.tangent(s_clamped)
        nx, ny = -ty, tx
        x, y = px + nx * lat_c[k], py + ny * lat_c[k]
        psi = heading((tx, ty))
        roots.append((x, y, z_c[k] + path.height(px, py)))
        quats.append(quat_from_matrix(rot_z(psi) @ local[k]))
        s += step_c[k] * stride
    quats = np.array(quats)
    for f in range(1, len(quats)):
        flip = np.sum(quats[f] * quats[f - 1], axis=-1) < 0
        quats[f, flip] *= -1
    return Motion(motion.names, np.array(roots), quats, motion.hip_height, motion.t_dirs, motion.label), np.array(arcs)


def join(parts, blend=10):
    """Concatenate motions, cross-fading `blend` frames at each seam.

    Each later part is shifted in xy so it starts where the previous part
    ends; the cross-fade then eases from one into the other without losing
    ground. A part may be (motion, blend) to set its
    own lead-in blend, or (motion, blend, False) to keep its own position.
    """
    out = None
    for part in parts:
        motion, k, snap = (part, blend, True) if isinstance(part, Motion) else (tuple(part) + (True,))[:3]
        if out is None:
            out = Motion(motion.names, motion.root.copy(), motion.quat.copy(), motion.hip_height, motion.t_dirs, motion.label)
            continue
        k = min(k, len(out), len(motion))
        nxt_root = motion.root.copy()
        if snap:
            nxt_root[:, :2] += out.root[-1, :2] - nxt_root[0, :2]
        w = (np.arange(k) + 1.0) / (k + 1.0)
        w = w * w * (3 - 2 * w)
        root = np.concatenate([out.root[:-k], (1 - w)[:, None] * out.root[-k:] + w[:, None] * nxt_root[:k], nxt_root[k:]])
        mixed = slerp(out.quat[-k:], motion.quat[:k], w)
        quat = np.concatenate([out.quat[:-k], mixed, motion.quat[k:]])
        for f in range(1, len(quat)):
            flip = np.sum(quat[f] * quat[f - 1], axis=-1) < 0
            quat[f, flip] *= -1
        out = Motion(out.names, root, quat, out.hip_height, out.t_dirs, out.label)
    return out


def hold(motion, frames, at=-1):
    """A still pose repeated for `frames` frames."""
    root = np.repeat(motion.root[at:at + 1] if at != -1 else motion.root[-1:], frames, axis=0)
    quat = np.repeat(motion.quat[at:at + 1] if at != -1 else motion.quat[-1:], frames, axis=0)
    return Motion(motion.names, root, quat, motion.hip_height, motion.t_dirs, motion.label)


class Path:
    """A smooth ground path through xy points with an arc-length parameter."""

    def __init__(self, points, height=None, spacing=0.05):
        pts = np.asarray(points, dtype=float)
        # Catmull-Rom through the points, then resample by arc length.
        padded = np.vstack([2 * pts[0] - pts[1], pts, 2 * pts[-1] - pts[-2]])
        dense = []
        for i in range(1, len(padded) - 2):
            p0, p1, p2, p3 = padded[i - 1], padded[i], padded[i + 1], padded[i + 2]
            for t in np.linspace(0, 1, 40, endpoint=False):
                dense.append(0.5 * ((2 * p1) + (-p0 + p2) * t + (2 * p0 - 5 * p1 + 4 * p2 - p3) * t * t + (-p0 + 3 * p1 - 3 * p2 + p3) * t ** 3))
        dense.append(pts[-1])
        dense = np.array(dense)
        seg = np.linalg.norm(np.diff(dense, axis=0), axis=1)
        arc = np.concatenate([[0.0], np.cumsum(seg)])
        self.length = float(arc[-1])
        self.s = np.arange(0.0, self.length, spacing)
        self.xy = np.stack([np.interp(self.s, arc, dense[:, 0]), np.interp(self.s, arc, dense[:, 1])], axis=1)
        self.spacing = spacing
        self.height = height or (lambda x, y: 0.0)

    def point(self, s):
        i = min(len(self.s) - 1, max(0.0, s / self.spacing))
        lo = int(i)
        hi = min(lo + 1, len(self.s) - 1)
        t = i - lo
        return tuple((1 - t) * self.xy[lo] + t * self.xy[hi])

    def tangent(self, s):
        a = np.array(self.point(max(0.0, s - 0.4)))
        b = np.array(self.point(min(self.length, s + 0.4)))
        d = b - a
        return tuple(d / (np.linalg.norm(d) or 1.0))


def key_curves(owner, curves, first_frame=1, name=None):
    """Write per-frame values straight into F-curves: {(data_path, index): array}.

    One key per scene frame, linear between them. Any animation already on the
    owner is replaced.
    """
    import bpy

    action = bpy.data.actions.new(name or f"{owner.name}_take")
    slot = action.slots.new(id_type=owner.id_type, name=owner.name)
    strip = action.layers.new("take").strips.new(type="KEYFRAME")
    bag = strip.channelbag(slot, ensure=True)
    for (path, index), values in curves.items():
        curve = bag.fcurves.new(path, index=index)
        count = len(values)
        curve.keyframe_points.add(count)
        co = np.empty(count * 2)
        co[0::2] = first_frame + np.arange(count)
        co[1::2] = values
        curve.keyframe_points.foreach_set("co", co)
        curve.keyframe_points.foreach_set("interpolation", np.ones(count, dtype=np.int32))
        curve.update()
    owner.animation_data_create()
    owner.animation_data.action = action
    owner.animation_data.action_slot = slot
    return action


def on_ground(motion, ground, smooth=5):
    """Lift a motion laid out on flat ground onto `ground(x, y)`."""
    lift = np.array([ground(x, y) for x, y in motion.root[:, :2]])
    if smooth > 1:
        lift = np.convolve(np.pad(lift, smooth // 2, mode="edge"), np.ones(smooth) / smooth, mode="valid")
    root = motion.root.copy()
    root[:, 2] += lift
    return Motion(motion.names, root, motion.quat.copy(), motion.hip_height, motion.t_dirs, motion.label)


def facing(motion, yaw, frame=0):
    """Turn a motion about its first root position so the hips face `yaw` at `frame`."""
    return turned(motion, yaw - float(motion.yaw()[frame]))


class Retarget:
    """Carries Motions onto one armature.

    The armature object must sit at the world origin, unrotated and unscaled,
    with its rest pose upright, facing -y, feet flat. Arms may rest in a T or
    an A pose: limbs are aligned to the clips' T-pose before rotations are
    applied.

    names: CMU joint name -> this rig's bone name. Read from the rig's
    "cmu_map" property (JSON) when present; a rig with no map is taken to use
    the CMU names themselves.
    Finger chains come from the rig's "finger_chains" property, base to tip
    per finger, per side. curl[side] holds the cumulative bend in radians at
    each joint of a chain, or None to leave that hand as modelled.
    """

    def __init__(self, rig, names=None):
        import json

        self.rig = rig
        bones = rig.data.bones
        if names is None and "cmu_map" in rig:
            names = json.loads(rig["cmu_map"])
        self.names = dict(names) if names else {b.name: b.name for b in bones}
        self.cmu = {bone: cmu for cmu, bone in self.names.items()}
        self.order = []
        pending = [b for b in bones if b.parent is None]
        while pending:
            bone = pending.pop(0)
            self.order.append(bone.name)
            pending.extend(bone.children)
        self.rest = {b.name: np.array(b.matrix_local.to_3x3()) for b in bones}
        self.head = {b.name: np.array(b.head_local) for b in bones}
        self.parent = {b.name: (b.parent.name if b.parent else None) for b in bones}
        align = {}
        for cmu, bone in self.names.items():
            side, kind = side_of(cmu)
            child = self.names.get(side + DIRECTION_CHILD.get(kind, "?"))
            if side and kind in ALIGN and child:
                align[bone] = shortest_arc(self.head[child] - self.head[bone], canonical(cmu))
        if "finger_chains" in rig:
            self.fingers = json.loads(rig["finger_chains"])
            self.curl = {"Left": None, "Right": None}
        else:
            self.fingers = {side: [[side + "FingerBase", side + "HandFinger1"]] for side in ("Left", "Right")}
            self.curl = {"Left": (0.45, 1.2), "Right": (0.45, 1.2)}
        self.finger_of = {}
        for side, chains in self.fingers.items():
            forearm = self.names.get(side + "ForeArm")
            hand = self.names.get(side + "Hand")
            if forearm in align:
                align[hand] = align[forearm]
            for chain in chains:
                for joint, bone in enumerate(chain):
                    self.finger_of[bone] = (side, joint)
                    if forearm in align:
                        align[bone] = align[forearm]
        self.reference = {name: align.get(name, np.eye(3)) @ self.rest[name] for name in self.order}
        up, low, foot, ball, hips = (self.names[k] for k in ("LeftUpLeg", "LeftLeg", "LeftFoot", "LeftToeBase", "Hips"))
        self.ankle = float(self.head[foot][2])
        self.ball = float(self.head[ball][2])
        leg = float(np.linalg.norm(self.head[up] - self.head[low]) + np.linalg.norm(self.head[low] - self.head[foot]))
        self.hip_height = leg + self.ankle + float(self.head[hips][2] - self.head[up][2])

    def fit(self, motion):
        """Scale a clip to this character's leg length and stand it on flat ground.

        The lower ankle rests at the character's own ankle height, which removes
        the float or sink that differing proportions would leave.
        """
        fitted = motion.scaled(self.hip_height / motion.hip_height)
        pose, hips = self.solve(fitted)
        joints = self.joints(pose, hips)
        low = np.minimum(joints["LeftFoot"][:, 2], joints["RightFoot"][:, 2])
        return fitted.raised(self.ankle - float(np.percentile(low, 8)))

    def solve(self, motion):
        """World matrix per bone (F, 3, 3) and hip positions (F, 3). The motion must already be fitted.

        Bones with no counterpart in the clip ride rigidly on their parents.
        The clips carry no finger data: a hand with a curl gets that bend on
        every finger, otherwise it keeps its modelled shape.
        """
        world = matrix_from_quat(motion.quat)
        index = {n: i for i, n in enumerate(motion.names)}
        frames = len(motion)
        pose = {}
        for name in self.order:
            cmu = self.cmu.get(name)
            source = index.get(SOURCE_NAME.get(cmu, cmu)) if cmu else None
            finger = self.finger_of.get(name)
            parent = self.parent[name]
            if finger and self.curl[finger[0]] is not None:
                side, joint = finger
                bends = self.curl[side]
                bend = bends[min(joint, len(bends) - 1)] * (1.0 if side == "Left" else -1.0)
                pose[name] = world[:, index[side + "Hand"]] @ rot_y(bend) @ self.reference[name]
            elif finger or source is None:
                if parent is None:
                    pose[name] = np.broadcast_to(self.rest[name], (frames, 3, 3))
                else:
                    pose[name] = pose[parent] @ (self.rest[parent].T @ self.rest[name])
            else:
                pose[name] = world[:, source] @ self.reference[name]
        return pose, motion.root.copy()

    def strides(self, motion, a, b):
        """Forward travel per frame that keeps the supporting foot still.

        For walks: the hips advance by exactly as much as the planted foot moves
        back under the body, whatever the character's proportions, so feet do
        not slide along the direction of travel. The contact point is the ankle
        while the foot is flat and the ball of the foot once the heel lifts.
        """
        direction, _ = straight_axis(motion.cut(a, b + 1))
        pose, hips = self.solve(motion)
        hips[:, :2] = 0.0
        joints = self.joints(pose, hips)
        # Whichever foot point is moving back fastest under the body is the one on the ground.
        back = []
        for side in ("Left", "Right"):
            for joint in (side + "Foot", side + "ToeBase"):
                back.append(-np.diff(joints[joint][:, :2] @ direction))
        steps = np.max(np.array(back), axis=0)
        kernel = np.array([0.25, 0.5, 0.25])
        return np.convolve(np.pad(steps, 1, mode="edge"), kernel, mode="valid")

    def joints(self, pose, hips):
        """World head position of every bone per frame, under its CMU name where it has one."""
        out = {}
        hip_bone = self.names["Hips"]
        for name in self.order:
            p = self.parent[name]
            if name == hip_bone:
                out[name] = hips
            elif p is None:
                out[name] = np.broadcast_to(self.head[name], hips.shape)
            else:
                offset = self.rest[p].T @ (self.head[name] - self.head[p])
                out[name] = out[p] + np.einsum("fij,j->fi", pose[p], offset)
        for cmu, bone in self.names.items():
            out[cmu] = out[bone]
        return out

    def apply(self, motion, first_frame=1):
        """Key a fitted motion onto the rig starting at scene frame `first_frame`.

        Returns the solved joint positions and hip positions per frame.
        """
        pose, hips = self.solve(motion)
        joints = self.joints(pose, hips)
        self.last_pose = pose
        rig = self.rig
        for bone in rig.pose.bones:
            bone.rotation_mode = "QUATERNION"
        frames = len(hips)
        curves = {}
        for name in self.order:
            p = self.parent[name]
            if p is None:
                m = self.rest[name].T @ pose[name]
            else:
                m = (self.rest[name].T @ self.rest[p]) @ np.swapaxes(pose[p], -1, -2) @ pose[name]
            q = quat_from_matrix(m)
            for f in range(1, frames):
                if np.dot(q[f], q[f - 1]) < 0:
                    q[f] *= -1
            for axis in range(4):
                curves[(f'pose.bones["{name}"].rotation_quaternion', axis)] = q[:, axis]
        root_name = self.names["Hips"]
        location = (hips - self.head[root_name]) @ self.rest[root_name]
        for axis in range(3):
            curves[(f'pose.bones["{root_name}"].location', axis)] = location[:, axis]
        key_curves(rig, curves, first_frame)
        return joints, hips
