"""Run the native FSS tools over one rendered take and write its native.json.

    FSS_BIN_DIR=/path/to/release/binaries \\
        python3 -B website/scripts/watch-evidence.py website/public/watch/intrusion

The take directory holds scene.json (camera calibration and scripted ground truth) and
one H.264 film per camera. This script never edits either. It imports the published
film bytes into a new, private FSS deployment and calls the project's own binaries:

    fss-file import          source custody over the exact MP4 bytes
    fss-event privacy-mask   owner mask over on-screen clocks and everything above the horizon
    fss-event watch          whole-recording motion watch with the detector cascade
    fss-infer package-detect YOLOX-Nano at full frame on a regular schedule, reports retained
    fss query                tracks, events and footage through the agent query surface
    fss-event corroborate    whole-recording two-camera corroboration on the ground plane
    fss-fuse                 fusion queries and source-loss ablations
    fss-custody audit        custody audit of each published event
    fss session/plan/commit  an agent session that attempts an alert to a loopback relay
                             started by this script when a corroborated event is available

What is written to native.json is a summary of tool outputs saved under native/objects/,
each named by its SHA-256, with one exception: the comparisons against scene.json's
scripted boxes and positions (found counts, box overlap, nearest scripted person) are
computed here. Refusals and failures are recorded as such.
The script is offline and deterministic apart from wall-clock timings and the relay port.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import combinations
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory, mkdtemp
import threading
import time

WEB = Path(__file__).resolve().parents[1]
REPO = WEB.parent
MODEL = REPO / "models/yolox-nano/yolox_nano.fmpk"
PIN = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74"
TOOLS = ("fss", "fss-file", "fss-event", "fss-infer", "fss-fuse", "fss-custody")
RECTILINEAR = {"pinhole", "rectilinear", "perspective", "persp"}

# Operator settings. None of these is calibrated; each is recorded in native.json.
BASE = dict(width=1280, height=720)
MOTION = dict(pixel_threshold=18, threshold_sigma=3, min_region_pixels=220)
TIME_GATE_NS = 500_000_000
DISTANCE_GATE_M = 1.5
ZONE_CELL_M = 2.0  # finest ground cell tried; it grows by 1 m until a pair needs at most 16 zones
COARSE_CELL_M = 4.0  # second, coarser grid previewed per pair to show how much the grid matters
CASCADE_PIXEL_BUDGET = 2_147_483_648  # whole-scan luma samples; the default cannot also re-decode cascade frames
ZONE_RANGE_M = 30.0
HORIZON_MARGIN = 0.02  # of image height, kept unmasked above nothing: mask ends this far below the horizon
ILLUSTRATIVE_LLR = [600, 800]  # millibans per positive camera; an assumption, not a calibration
ILLUSTRATIVE_PRIOR = [-602, -602]  # 20 %
APPROVAL_TEXT = b"owner approves the plaintext loopback relay"


def digest(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def pick(source, *names, default=...):
    for name in names:
        if isinstance(source, dict) and name in source and source[name] is not None:
            return source[name]
    if default is ...:
        keys = sorted(source) if isinstance(source, dict) else type(source).__name__
        raise KeyError(f"expected one of {names}; found {keys}")
    return default


# ---------------------------------------------------------------- scene.json


def load_scene(take: Path):
    data = (take / "scene.json").read_bytes()
    raw = json.loads(data)
    clock = pick(raw, "clock")
    fps = pick(clock, "fps")
    frames = pick(clock, "frames", "frame_count", "frameCount")
    start = pick(clock, "start", "start_iso", "iso_start", "iso", default=None)
    cameras = pick(raw, "cameras")
    if isinstance(cameras, dict):
        cameras = [dict(value, id=key) for key, value in cameras.items()]
    actors = pick(raw, "actors", default=[])
    if isinstance(actors, dict):
        actors = [dict(value, id=key) for key, value in actors.items()]
    return dict(raw=raw, source_digest=digest(data), fps=fps, frames=frames, start=start, cameras=cameras, actors=actors)


def per_frame(series, frame):
    """One frame of a per-frame series stored as a list or as columns."""
    if series is None:
        return None
    if isinstance(series, dict):
        if "frames" in series:
            return per_frame(series["frames"], frame)
        columns = {k: v[frame] for k, v in series.items() if isinstance(v, list) and frame < len(v)}
        return columns or None
    return series[frame] if frame < len(series) else None


def ground_truth(scene, actor, frame):
    """Scripted ground position (plan x, z) of one actor at one frame, or None."""
    raw = scene["raw"]
    series = pick(raw, "tracks", "truth", "ground_truth", "paths", default={}).get(actor)
    if series is None:
        entry = next((a for a in scene["actors"] if a.get("id") == actor), {})
        series = pick(entry, "frames", "track", "path", default=None)
    row = per_frame(series, frame)
    if row is None:
        return None
    if isinstance(row, dict):
        position = pick(row, "position", "ground", "xz", default=None)
        if position is not None:
            return (position[0], position[-1])
        x, z = pick(row, "x", default=None), pick(row, "z", default=None)
        return None if x is None or z is None else (x, z)
    return (row[0], row[-1]) if len(row) in (2, 3) else (row[0], row[1])


def scripted_box(scene, camera, actor, frame):
    """Scripted box [x0, y0, x1, y1] normalised 0..1 and its visible fraction, or None."""
    raw = scene["raw"]
    boxes = pick(raw, "boxes", "projections", default={})
    series = pick(boxes.get(camera, {}), actor, default=None) if isinstance(boxes, dict) else None
    if series is None:
        entry = next((c for c in scene["cameras"] if c["id"] == camera), {})
        series = pick(pick(entry, "boxes", default={}), actor, default=None)
    row = per_frame(series, frame)
    if row is None:
        return None
    if isinstance(row, dict):
        box = pick(row, "box", "bbox", "xyxy", default=None)
        if box is None:
            return None
        return list(box[:4]), pick(row, "visible", "visible_fraction", "visibility", default=1.0)
    return list(row[:4]), (row[4] if len(row) > 4 else 1.0)


# ---------------------------------------------------------------- geometry


def unit(v):
    n = math.sqrt(sum(c * c for c in v))
    return [c / n for c in v]


def cross(a, b):
    return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]


def dot(a, b):
    return sum(x * y for x, y in zip(a, b))


def invert3(m):
    (a, b, c), (d, e, f), (g, h, i) = m
    det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)
    if abs(det) < 1e-12:
        raise ValueError("singular ground projection")
    return [
        [(e * i - f * h) / det, (c * h - b * i) / det, (b * f - c * e) / det],
        [(f * g - d * i) / det, (a * i - c * g) / det, (c * d - a * f) / det],
        [(d * h - e * g) / det, (b * g - a * h) / det, (a * e - b * d) / det],
    ]


def ground_to_image(camera, width, height):
    """3x3 map from plan ground (x, z, 1) to homogeneous pixels; third row is depth (> 0 in view)."""
    eye, target = pick(camera, "position", "eye"), pick(camera, "look_at", "target", "lookAt")
    lens = pick(camera, "lens", default={})
    vfov = pick(lens, "vfov", "vfov_deg", default=None) or pick(camera, "vfov", "vfov_deg")
    forward = unit([t - e for t, e in zip(target, eye)])
    right = unit(cross(forward, [0, 1, 0]))
    up = cross(right, forward)
    ty = math.tan(math.radians(vfov) / 2)
    tx = ty * width / height
    shift_x = pick(lens, "shift_x", default=0.0)
    shift_y = pick(lens, "shift_y", default=0.0)

    def row(v):
        return [v[0], v[2], -dot(v, eye)]

    depth = row(forward)
    x = [(width / 2 + shift_x * width) * d + width / (2 * tx) * r for d, r in zip(depth, row(right))]
    y = [(height / 2 + shift_y * width) * d - height / (2 * ty) * u for d, u in zip(depth, row(up))]
    return [x, y, depth]


def project(matrix, point):
    x, y, w = (dot(row, [point[0], point[1], 1.0]) for row in matrix)
    return None if w <= 1e-9 else (x / w, y / w, w)


def horizon_row(image_to_ground, width):
    """Lowest image row of the ground horizon across the frame width (rows grow downward)."""
    a, b, c = image_to_ground[2]
    if abs(b) < 1e-12:
        return 0.0
    return max(-(a * x + c) / b for x in (0.0, width))


# ---------------------------------------------------------------- tool runner


class Run:
    def __init__(self, bins: Path, work: Path, objects: Path, site: str):
        self.bins, self.work, self.objects, self.site = bins, work, objects, site
        self.commands, self.notes, self.scrub = [], [], []
        self.root = ["--root", "deployment", "--site", site]
        self.agent = ["--json", "--root", str(work / "deployment")]

    def save(self, data: bytes, suffix: str) -> str:
        name = digest(data)[7:] + "." + suffix
        (self.objects / name).write_bytes(data)
        return "native/objects/" + name

    def call(self, tool, args, *, stdin=None, timeout=3600):
        started = time.monotonic()
        result = subprocess.run(
            [self.bins / tool, *map(str, args)], cwd=self.work, input=stdin,
            capture_output=True, text=True, timeout=timeout,
        )
        # Recorded commands never carry this machine's directories: the private working
        # directory is dropped and repository files are written relative to the repository.
        shown = " ".join([tool, *map(str, args)]).replace(str(self.work) + "/", "")
        shown = shown.replace(str(REPO) + "/", "")
        for prefix in self.scrub:
            shown = shown.replace(prefix, "")
        refusal = next(
            (line.split("=", 1)[1] for line in result.stderr.splitlines() if line.startswith("refusal_id=")),
            None,
        )
        self.commands.append(dict(
            command=shown, exit=result.returncode, seconds=round(time.monotonic() - started, 2),
            **({"refusal": refusal} if refusal else {}),
        ))
        return result

    def json(self, tool, args, **kw):
        """Run a tool that prints one JSON document. Returns (parsed or None, object path, result)."""
        result = self.call(tool, args, **kw)
        text = result.stdout if result.stdout.strip() else result.stderr
        try:
            parsed = json.loads(result.stdout)
        except ValueError:
            parsed = None
        suffix = "json" if parsed is not None else "txt"
        return parsed, self.save(text.encode(), suffix), result

    def failure(self, what, result):
        lines = [line for line in result.stderr.splitlines() if line.strip()]
        refusal = next((line.split("=", 1)[1] for line in lines if line.startswith("refusal_id=")), None)
        reason = lines[0] if lines else (result.stdout.strip()[:300] or "no output")
        try:  # agent operations answer with an envelope on stdout, also when they refuse
            envelope = json.loads(result.stdout)
            refusal = envelope.get("errorId") or refusal
            reason = ((envelope.get("degradation") or envelope.get("warnings") or [reason])[0])[:300]
        except (ValueError, AttributeError):
            pass
        self.notes.append(f"{what}: {reason}" + (f" ({refusal})" if refusal else ""))
        return dict(outcome="refused" if refusal else "failed", reason=reason, refusal=refusal)


# ---------------------------------------------------------------- stages


def probe(film: Path):
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
         "stream=codec_name,profile,width,height,r_frame_rate,pix_fmt,duration:packet=flags", "-of", "json", film],
        check=True, capture_output=True, text=True,
    ).stdout
    info = json.loads(out)
    stream = info["streams"][0]
    num, den = map(int, stream["r_frame_rate"].split("/"))
    keys = [i for i, p in enumerate(info["packets"]) if "K" in p["flags"]]
    return dict(
        codec=stream["codec_name"], profile=stream.get("profile"), pix_fmt=stream.get("pix_fmt"),
        width=stream["width"], height=stream["height"], fps=num / den,
        frames=len(info["packets"]), key_segments=keys, duration_seconds=float(stream["duration"]),
    )


def import_film(run: Run, take, cam, film, meta, epoch_ns):
    fps = meta["fps"]
    duration_ns = round(meta["duration_seconds"] * 1e9)
    result = run.call("fss-file", [
        "import", *run.root, "--input", film, "--sensor", "sensor:" + cam,
        "--stream", f"stream:{take}-{cam}", "--media-format", "auto",
        "--receive-time-ns", epoch_ns + duration_ns + 1_000_000_000,
        "--capture-start-ns", epoch_ns, "--capture-uncertainty-ns", 1_000_000,
        "--assumed-fps", int(fps) if float(fps).is_integer() else fps,
    ])
    if result.returncode:
        return run.failure(f"{cam}: import", result)
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    data = film.read_bytes()
    if fields["verified_source_sha256"] != digest(data) or fields["omission_count"] != "0":
        raise ValueError(f"{cam}: retained source differs from the published film")
    return dict(
        outcome="ok", sha256=digest(data), bytes=len(data), codec=f"{meta['codec']} {meta['profile']}",
        frames=meta["frames"], segments=int(fields["segment_count"]), fps=fps, duration_seconds=meta["duration_seconds"],
        width=meta["width"], height=meta["height"], import_id=fields["import_identity"],
        import_root=fields["import_root"], capture_time_class=fields.get("capture_time_class"),
        absence_certifiable=fields.get("absence_certifiable") == "true",
        receipt=run.save(result.stdout.encode(), "txt"),
    )


def declare_mask(run: Run, cam, width, height, rects):
    args = ["privacy-mask", "declare", *run.root, "--sensor", "sensor:" + cam,
            "--resolution", f"{width}x{height}"]
    for rect in rects:
        args += ["--rect", ",".join(str(int(v)) for v in rect)]
    preview, _, result = run.json("fss-event", args)
    if preview is None:
        return run.failure(f"{cam}: privacy mask", result)
    retained, link, result = run.json("fss-event", [*args, "--approve", preview["approval_digest"]])
    if retained is None:
        return run.failure(f"{cam}: privacy mask approval", result)
    return dict(outcome="ok", rectangles=rects, policy_digest=retained["policy_digest"],
                generation=retained["generation"], report=link)


def motion_args(width, height):
    scale = (width * height) / (BASE["width"] * BASE["height"])
    return ["--pixel-threshold", MOTION["pixel_threshold"], "--threshold-sigma", MOTION["threshold_sigma"],
            "--min-region-pixels", max(16, round(MOTION["min_region_pixels"] * scale))]


def retain_coverage(run: Run, cam, custody, meta, zone, epoch_ns):
    """Retain CoverageWitness records from bounded watches (at most 128 frames each, IDR-led).

    Each window restarts the background model, so its warm-up frames stay uncovered. A
    witness says one sensor decoded one zone without a gap over one interval. Whether
    absence is certified inside those domains is the tool's statement, taken from each
    retained report; this script claims nothing about it on its own.
    """
    keys = meta["key_segments"] + [meta["frames"]]
    starts, at = [], 0
    while at < len(keys) - 1:
        end = at + 1
        while end < len(keys) - 1 and keys[end + 1] - keys[at] <= 128:
            end += 1
        starts.append((keys[at], min(128, keys[end] - keys[at])))
        at = end
    witnesses, reports, retained, failed, certified = [], [], 0, [], []
    for first, count in starts:
        args = ["watch", *run.root, "--import-id", custody["import_id"], "--interpretation", "ycbcr",
                "--zone", "view:" + ",".join(map(str, zone)), "--first-segment", first, "--segment-count", count,
                *motion_args(custody["width"], custody["height"])]
        preview, _, result = run.json("fss-event", args)
        if preview is None:
            failed.append(dict(first_segment=first, frames=count,
                               **run.failure(f"{cam}: coverage watch of frames {first}..{first + count - 1}", result)))
            continue
        kept, link, result = run.json("fss-event", [*args, "--retain-coverage", preview["coverage"]["approval_digest"]])
        if kept is None:
            failed.append(dict(first_segment=first, frames=count,
                               **run.failure(f"{cam}: coverage retention of frames {first}..{first + count - 1}", result)))
            continue
        reports.append(link)
        cover = kept["coverage"]
        retained += cover["coverage_status"] in ("retained", "already_retained")
        certified.append(cover.get("absence_certified_for_witness_domains"))
        for record in cover["records"]:
            for z in record["zones"]:
                for w in z["witnesses"]:
                    witnesses.append(dict(t0=round((int(w["covered_ns"][0]) - epoch_ns) / 1e9, 3),
                                          t1=round((int(w["covered_ns"][1]) - epoch_ns) / 1e9, 3), frames=w["frames"]))
    witnesses.sort(key=lambda w: w["t0"])
    return dict(
        outcome="ok" if not failed else ("partial" if reports else "refused"), zone=zone,
        windows=len(starts), windows_retained=retained, windows_failed=failed, reports=reports,
        witness_count=len(witnesses), witnesses=witnesses,
        covered_seconds=round(sum(w["t1"] - w["t0"] for w in witnesses), 2),
        # The tool's flag, when every retained report gives the same answer. None means not stated.
        absence_certified_for_witness_domains=(
            certified[0] if certified and isinstance(certified[0], bool) and all(c is certified[0] for c in certified)
            else None),
        # When no window was retained, the first refusal stands for the film.
        refusal=(failed[0].get("refusal") or failed[0].get("reason")) if failed and not reports else None,
        note="Intervals outside a witness are unobserved for this purpose: background warm-up at the start of each "
             "window, confirmation latency, and frames with a tracking gap.",
    )


def take_seconds(capture, epoch_ns):
    lo, hi = (int(v) for v in capture)
    return ((lo + hi) / 2 - epoch_ns) / 1e9


def stream_watch(run: Run, cam, custody, zone, epoch_ns, cascade):
    width, height = custody["width"], custody["height"]
    args = ["watch", *run.root, "--stream-watch", "--import-id", custody["import_id"],
            "--interpretation", "ycbcr", "--zone", "view:" + ",".join(map(str, zone)),
            *motion_args(width, height)]
    if cascade:
        args += ["--detector-package", "model.fmpk", "--detector-digest", PIN,
                 "--detector-max-inferences", cascade, "--detector-frames-per-track", 1,
                 "--stream-pixel-budget", CASCADE_PIXEL_BUDGET]
    report, link, result = run.json("fss-event", args)
    if report is None:
        what = "whole-recording motion watch with the detector cascade" if cascade else "whole-recording motion watch"
        return run.failure(f"{cam}: {what}", result), None, None
    candidates = []
    for c in report["candidates"]:
        cx, cy, w, h = c["filtered_box"]
        candidates.append(dict(
            event_id=c["event_id"], track=c["track_id"], frame_segment=c["entry_segment"],
            capsule=c["entry_capsule_digest"],
            t=round(take_seconds([c["capture_earliest_ns"], c["capture_latest_ns"]], epoch_ns), 4),
            box=[round(max(0, cx - w / 2) / width, 5), round(max(0, cy - h / 2) / height, 5),
                 round(min(width, cx + w / 2) / width, 5), round(min(height, cy + h / 2) / height, 5)],
            class_evidence=[
                dict(label=e.get("label"), score=e.get("score"), outcome=e.get("outcome"),
                     supports=e.get("supports"))
                for e in c.get("class_evidence", [])
            ],
            status=c["status"],
        ))
    summary = dict(
        outcome="ok", report=link, zone=zone, frames_decoded=report["frames_decoded"],
        candidate_count=report["candidate_count"], candidates=candidates,
        event_kind=report["event_kind"], event_state=report["event_state"],
        policy_action=report["policy_action"], corroborated=report["corroborated"],
        absence_certifiable=report["absence_certifiable"], alert_authorized=report["alert_authorized"],
        detector_cascade=({k: report["detector_cascade"].get(k) for k in
                           ("inference_count", "budget_skipped", "cascade_skipped", "package_digest")
                           if k in report["detector_cascade"]}
                          if report.get("detector_cascade") else None),
    )
    return summary, args, report


def detect(run: Run, cam, custody, meta, epoch_ns, take_fps, threads, limit):
    """Full-frame detector over every IDR-led range the tool admits (at most 64 frames per call)."""
    fps = take_fps
    keys = meta["key_segments"] + [meta["frames"]]
    rows, reports, unreached, seconds = [], [], 0, 0.0
    calls, model = 0, None
    for start, stop in zip(keys, keys[1:]):
        count = min(64, stop - start)
        unreached += stop - start - count
        if limit is not None and calls >= limit:
            unreached += count
            continue
        calls += 1
        args = ["package-detect", *run.root, "--import-id", custody["import_id"],
                "--first-segment", start, "--frames", count, "--interpretation", "ycbcr",
                "--package", "model.fmpk", "--package-digest", PIN, "--threads", threads, "--retain", "yes"]
        began = time.monotonic()
        report, link, result = run.json("fss-infer", args)
        seconds += time.monotonic() - began
        if report is None:
            run.failure(f"{cam}: detector at segment {start}", result)
            unreached += count
            continue
        children = report.get("reports") or report.get("bursts") or [report]
        retained = [line.split("=", 1)[1] for line in result.stderr.splitlines()
                    if line.startswith("package_detection_retained=")]
        reports.append(dict(first_segment=start, frames=count, report=link, retained=retained))
        for child in children:
            child = child.get("report", child)
            for frame in child.get("frames", []):
                t = take_seconds([frame["capture"]["earliest_ns"], frame["capture"]["latest_ns"]], epoch_ns)
                w, h = frame["dimensions"]
                rows.append(dict(
                    t=round(t, 4), frame=round(t * fps), segment=frame["segment"],
                    capsule=frame["capsule_digest"],
                    detections=[dict(
                        label=d["label"], score=round(d["score"], 4),
                        box=[round(d["bounds_subpixel"][0] / (w * 256), 5), round(d["bounds_subpixel"][1] / (h * 256), 5),
                             round(d["bounds_subpixel"][2] / (w * 256), 5), round(d["bounds_subpixel"][3] / (h * 256), 5)],
                    ) for d in frame["detections"]],
                ))
        last = children[-1].get("report", children[-1])
        model = dict(id=last.get("model_id"), generation=last.get("generation"),
                     minimum_score_ppm=last.get("minimum_score_ppm"), nms_iou_ppm=last.get("nms_iou_ppm"))
    rows.sort(key=lambda r: r["frame"])
    return dict(
        outcome="ok" if rows else "not_run",
        schedule="every frame of each IDR-led range, at most 64 frames per call; frames further than 64 from an IDR cannot be reached",
        frames_inferred=len(rows), frames_not_inferred=meta["frames"] - len(rows),
        frames_beyond_reach=unreached,
        seconds=round(seconds, 1), model=model if rows else None, reports=reports, frames=rows,
    )


def parse_statement(statement):
    head, _, tail = statement.partition(": ")
    try:
        return json.loads(tail)
    except ValueError:
        return None


def query_tracks(run: Run, cam, custody, detection, epoch_ns, take_fps, keep_raw=2):
    width, height, fps = custody["width"], custody["height"], take_fps
    tracks, calls, tokens, raw = {}, 0, 0, []
    recipe = None
    for window, report in enumerate(detection["reports"]):
        for retained in report["retained"]:
            cursor = None
            while True:
                args = ["query", "--target", "tracks", *run.agent, "--report-digest", retained,
                        "--label", "person", "--verify-tracks-source=yes", "--max-entries", 32]
                if cursor:
                    args += ["--continuation", cursor]
                envelope, link, result = run.json("fss", args)
                calls += 1
                if envelope is None or envelope.get("outcome") not in ("ok", "partial"):
                    run.failure(f"{cam}: track query", result)
                    break
                tokens += envelope["budgets"]["consumed"]["tokens"]
                if len(raw) < keep_raw:
                    raw.append(link)
                else:
                    (run.objects / Path(link).name).unlink()
                for p in envelope["payload"]["epistemic"]["propositions"]:
                    row = parse_statement(p["statement"])
                    if p["id"] == "claim:tracks:tracking":
                        recipe = row
                    if not p["id"].startswith("claim:tracks:observation:") or row is None:
                        continue
                    t = take_seconds([row["capture_earliest_ns"], row["capture_latest_ns"]], epoch_ns)
                    cx, cy, w, h = row["filtered_box_cx_cy_w_h_pixels"]
                    key = f"w{window}-t{row['track_id']}"
                    track = tracks.setdefault(key, dict(
                        id=key, window=window, native_track_id=row["track_id"],
                        identity=row["track_identity"], state="tentative", samples=[]))
                    if row["track_ever_confirmed"]:
                        track["state"] = "confirmed"
                    track["samples"].append(dict(
                        t=round(t, 4), frame=round(t * fps), confirmed=row["sample_confirmed"],
                        knowledge_state=p["state"],
                        box=[round((cx - w / 2) / width, 5), round((cy - h / 2) / height, 5),
                             round((cx + w / 2) / width, 5), round((cy + h / 2) / height, 5)],
                    ))
                cursor = envelope.get("continuation")
                if not cursor:
                    break
    for track in tracks.values():
        track["samples"].sort(key=lambda s: s["frame"])
    return dict(
        outcome="ok" if calls else "not_run", operation="AOP-005 query --target tracks", label="person",
        recipe=recipe, calls=calls, tokens=tokens, sample_envelopes=raw,
        note="One query per retained detection report. A report covers at most 64 frames, so track "
             "identities restart at each window; the tool does not bridge them.",
        tracks=sorted(tracks.values(), key=lambda t: (t["window"], t["native_track_id"])),
    )


def nearest_scripted(scene, t, ground):
    """Nearest scripted person to a ground point at a take time. Checked afterwards, never fed to a tool."""
    frame = min(scene["frames"] - 1, max(0, round(t * scene["fps"])))
    best = None
    for actor in scene["actors"]:
        name = actor["id"] if isinstance(actor, dict) else actor
        at = ground_truth(scene, name, frame)
        if at and at[0] is not None and at[1] is not None:
            distance = math.dist(at, ground)
            if best is None or distance < best[0]:
                best = (distance, name)
    return None if best is None else dict(actor=best[1], distance_m=round(best[0], 2))


def against_script(scene, result):
    for candidate in (result or {}).get("candidates") or []:
        if candidate.get("ground") and candidate.get("t"):
            candidate["nearest_scripted_person"] = nearest_scripted(scene, min(candidate["t"]), candidate["ground"])
    for entry in (result or {}).get("entries") or []:
        entry["nearest_scripted_person"] = nearest_scripted(scene, entry["t"], entry["ground"])
    return result


def zones_for(pair, views, cell=None):
    """Ground cells both cameras can see: centre inside both frames below the mask and within range."""
    def seen(cam, x, z):
        view = views[cam]
        p = project(view["g2i"], (x, z))
        if p is None or math.hypot(x - view["eye"][0], z - view["eye"][2]) > ZONE_RANGE_M:
            return False
        return (0.04 * view["width"] <= p[0] <= 0.96 * view["width"]
                and view["zone"][1] + 4 <= p[1] <= view["zone"][1] + view["zone"][3] - 4)

    cell = cell or ZONE_CELL_M
    while True:
        cells = []
        for i in range(int(-60 // cell), int(60 // cell) + 1):
            for j in range(int(-80 // cell), int(60 // cell) + 1):
                x, z = (i + 0.5) * cell, (j + 0.5) * cell
                if all(seen(cam, x, z) for cam in pair):
                    cells.append((f"g{len(cells):02d}", round(i * cell, 3), round(j * cell, 3), cell, cell))
        if len(cells) <= 16:
            return cells, cell
        cell += 1.0


def corroborate(run: Run, pair, views, customs, zones, declaration, epoch_ns, approve=None):
    a, b = pair
    args = ["corroborate", *run.root, "--stream-corroborate", "--interpretation", "ycbcr",
            "--time-gate-ns", TIME_GATE_NS, "--distance-gate", DISTANCE_GATE_M,
            *motion_args(customs[a]["width"], customs[a]["height"])]
    for cam in pair:
        matrix = views[cam]["i2g"]
        args += ["--camera", f"{cam}:{customs[cam]['import_id']}",
                 "--ground", cam + ":" + ",".join(repr(float(v)) for row in matrix for v in row)]
    for zone in zones:
        args += ["--zone", f"{zone[0]}:{zone[1]},{zone[2]},{zone[3]},{zone[4]}"]
    if declaration == "shared_render":
        args += ["--failure-domain", f"replay:render={a},{b}"]
    if approve:
        args += ["--approve", approve]
    report, link, result = run.json("fss-event", args)
    if report is None:
        return run.failure(f"{a}+{b} corroboration ({declaration})", result), None
    entries = [dict(
        camera=e["camera"], zone=e["zone_id"], track=e["track_id"],
        t=round(take_seconds(e["capture_ns"], epoch_ns), 4),
        ground=[round(e["ground"][0], 3), round(e["ground"][1], 3)],
        disposition=e["disposition"],
    ) for e in report["entries"]]
    candidates = []
    for c in report["candidates"]:
        members = [report["entries"][i] for i in c.get("entries", [])] if c.get("entries") else []
        grounds = [m["ground"] for m in members]
        residual = (math.dist(grounds[0], grounds[1]) if len(grounds) == 2 else None)
        candidates.append(dict(
            event_id=c.get("event_id"), zone=c.get("zone_id"), status=c.get("status"),
            event_state=c.get("event_state", report.get("event_state")),
            policy_action=c.get("policy_action"), alert_prepared=c.get("alert_prepared"),
            proposal=c.get("proposal_digest"),
            t=[round(take_seconds(m["capture_ns"], epoch_ns), 4) for m in members],
            ground=([round(sum(g[0] for g in grounds) / len(grounds), 3),
                     round(sum(g[1] for g in grounds) / len(grounds), 3)] if grounds else None),
            residual_m=round(residual, 3) if residual is not None else None,
            time_difference_s=(round(abs(take_seconds(members[0]["capture_ns"], epoch_ns)
                                         - take_seconds(members[1]["capture_ns"], epoch_ns)), 4)
                               if len(members) == 2 else None),
        ))
    return dict(
        outcome="ok", declaration=declaration, report=link, cameras=list(pair),
        zones=[dict(id=z[0], x=z[1], z=z[2], size=z[3]) for z in zones],
        confirmed_tracks={c["camera"]: c["confirmed_tracks"] for c in report["cameras"]},
        entry_count=report["entry_count"], entries=entries,
        candidate_count=report["candidate_count"], candidates=candidates,
        published_count=report.get("published_count"), already_published_count=report.get("already_published_count"),
        dependency_basis=report["dependencies"].get("basis"),
        declarations=report["dependencies"].get("declarations"),
        alert_authorized=report["alert_authorized"], absence_certifiable=report["absence_certifiable"],
    ), (args, report)


def envelope_summary(name, envelope, link, result):
    if envelope is None:
        return dict(call=name, outcome="error", summary=(result.stderr.strip().splitlines() or ["no output"])[0],
                    envelope=link)
    if envelope.get("schema") == "fss.cli_diagnostic.v1":
        reason = next((line for line in result.stderr.splitlines() if line.strip()), "")
        return dict(call=name, operation=None, view=None, outcome="error", error=envelope.get("error_id"),
                    summary=reason or "The command exited %s with %s and printed no reason."
                    % (envelope.get("exit_code"), envelope.get("error_id")),
                    envelope=link)
    payload = envelope.get("payload") or {}
    props = (payload.get("epistemic") or {}).get("propositions") or []
    states = {}
    for p in props:
        states[p["state"]] = states.get(p["state"], 0) + 1
    receipt = payload.get("compressionReceipt") or {}
    situation = None
    frame = payload.get("situationFrame")
    if frame:
        control = payload.get("controlEnvelope") or {}
        world = frame.get("worldEnvelope") or {}
        situation = dict(
            knowledge_cells=[dict(id=c["cellId"], state=c["knowledgeState"], provenance=c["provenanceClass"],
                                  value=str(c["value"])[:240]) for c in frame.get("knowledgeCells") or []],
            salient=[dict(id=e["entityId"], state=e["state"], summary=e["summary"]) for e in frame.get("salientEntities") or []],
            unknowns=frame.get("unknowns") or [], not_observable=frame.get("notObservableDomains") or [],
            coverage=dict(status=(frame.get("coverage") or {}).get("status"),
                          absence_claims_certified=(frame.get("coverage") or {}).get("absenceClaimsCertified")),
            contradictions=len(frame.get("contradictions") or []),
            alternative_worlds=[w.get("worldId") or w.get("id") for w in world.get("materialAlternativeWorlds") or []],
            adversarial_residuals=[r.get("residualId") for r in world.get("adversarialResiduals") or []],
            attention=[dict(priority=a.get("priorityClass"), reason=a.get("reason")) for a in payload.get("attentionFrontier") or []],
            epistemic_debt=[dict(assumption=x.get("assumption"), cheapest_test=x.get("cheapestTest")) for x in payload.get("epistemicDebt") or []],
            obligations=len(payload.get("obligations") or []), active_plans=payload.get("activePlans") or [],
            indeterminate_effects=len(payload.get("indeterminateEffects") or []),
            control=dict(robust=control.get("robustAffordanceIds"), conditional=control.get("conditionalAffordanceIds"),
                         information_gathering=control.get("informationGatheringAffordanceIds"),
                         wait=control.get("waitAffordanceIds"), blocked=control.get("blockedAffordanceIds"),
                         invariants=control.get("robustInvariants")),
            compression=dict(target_tokens=receipt.get("targetTokens"), actual_tokens=receipt.get("actualTokens"),
                             omitted_classes=receipt.get("omittedClasses"),
                             critical=receipt.get("criticalPreservation"), stop_reason=receipt.get("stopReason")),
        )
    return dict(
        call=name, operation=envelope.get("operationId"), view=envelope.get("effectiveViewId"),
        outcome=envelope.get("outcome"), error=envelope.get("errorId"),
        epistemic_state=envelope.get("epistemicState"), completeness=envelope.get("completeness"),
        tokens=((envelope.get("budgets") or {}).get("consumed") or {}).get("tokens"),
        target_tokens=receipt.get("targetTokens"),
        knowledge_states=states, affordances=[a.get("affordanceId") for a in envelope.get("affordances") or []],
        warnings=envelope.get("warnings") or [], degradation=envelope.get("degradation") or [],
        **({"situation": situation} if situation else {}),
        envelope=link,
    )


class Relay:
    """Loopback relay owned by this script. It accepts POSTs, keeps them, and answers 200."""

    def __init__(self):
        relay = self
        self.requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                relay.requests.append(dict(path=self.path, headers=dict(self.headers.items()), body=body))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.address = "127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


def observe_relay_call(run, relay, alert, phase, command, *args):
    """Count requests over this invocation, including when the native command refuses."""
    before = len(relay.requests)
    result = command(*args)
    received = relay.requests[before:]
    alert[f"{phase}_requests_received"] = len(received)
    alert["requests_received"] = alert.get("requests_received", 0) + len(received)
    if phase == "retry":
        alert["resend_on_retry"] = bool(received)
    if received and "request" not in alert:
        first = received[0]
        alert["request"] = run.save(first["body"], "json")
        alert["request_headers"] = {key: value for key, value in first["headers"].items()
                                    if key.lower() in ("content-type", "idempotency-key", "content-length")}
    return result


def agent_session(run: Run, take, single_event, joint_event, relay: Relay):
    calls, facts = [], {}

    def step(name, args, expect_refusal=False):
        envelope, link, result = run.json("fss", args)
        summary = envelope_summary(name, envelope, link, result)
        calls.append(summary)
        return envelope

    opening = ["session", "open", *run.agent,
               "--mission-text", "Watch the property overnight and tell the owner when a person is on the grounds.",
               "--objective", "Corroborate across cameras before alerting. Preserve uncertainty. "
                              "Take no physical action without the owner's approval."]
    # The smallest view is tried first. When its critical context does not fit, the tool
    # refuses instead of truncating, and the session is opened with the next view up.
    opened = None
    for view in ("pulse", "brief", "epistemic_map"):
        opened = step(f"session.open {view}", [*opening, "--view", view])
        if opened is not None and opened.get("outcome") == "ok":
            facts["opened_with_view"] = view
            break
    if opened is None or opened.get("outcome") != "ok":
        return dict(calls=calls, facts=facts)
    session = opened["sessionId"]
    facts["session"] = session
    for view in ("pulse", "brief", "epistemic_map"):
        step(f"session.orient {view}", ["session", "orient", *run.agent, "--session", session, "--view", view])
    step("query events", ["query", *run.agent, "--target", "events"])
    step("query footage", ["query", *run.agent, "--target", "footage"])
    approval = digest(APPROVAL_TEXT)

    def plan(event, extra=()):
        return ["plan", *run.agent, "--session", session, "--intent", "alert", "--event-id", event,
                "--relay", relay.address, "--path", "/fss/alert", "--plaintext-approval", approval,
                "--deadline-ms", 5000, *extra]

    if single_event:
        step("explain single-camera event", ["explain", *run.agent, "--event-id", single_event, "--view", "decision_diff"])
        step("explain single-camera event (forensic)", ["explain", *run.agent, "--event-id", single_event, "--view", "forensic"])
        step("plan alert for the single-camera event", plan(single_event))
        facts["single_camera_alert"] = dict(
            event_id=single_event, outcome=calls[-1]["outcome"], error=calls[-1].get("error"))
    if joint_event:
        step("explain corroborated event", ["explain", *run.agent, "--event-id", joint_event, "--view", "decision_diff"])
        step("explain corroborated event (forensic)", ["explain", *run.agent, "--event-id", joint_event, "--view", "forensic", "--custody", "yes"])
        proposed = step("plan alert (preview)", plan(joint_event))
        alert = dict(event_id=joint_event, relay="loopback, owned by this script", stage="proposed",
                     outcome=calls[-1]["outcome"], error=calls[-1].get("error"))
        if proposed and proposed.get("outcome") == "ok":
            plan_id = proposed["payload"]["planId"]
            prepared = step("plan alert (script approves the plan)", plan(joint_event, ["--approve", proposed["proofPointers"][2]]))
            alert.update(stage="preparation_attempted", outcome=calls[-1]["outcome"], error=calls[-1].get("error"))
            if prepared and prepared.get("outcome") == "ok":
                before = len(relay.requests)
                dispatch = ["commit", *run.agent, "--plan", plan_id, "--approve", prepared["proofPointers"][-1]]
                committed = observe_relay_call(run, relay, alert, "dispatch", step, "commit (script approves dispatch)", dispatch)
                receipt = (committed or {}).get("payload") or {}
                alert.update(stage="dispatch_attempted", outcome=calls[-1]["outcome"], error=calls[-1].get("error"),
                             effect_state=receipt.get("state"), operation=receipt.get("operationId"))
                if committed and committed.get("outcome") == "ok":
                    alert["stage"] = "dispatched"
                    observe_relay_call(run, relay, alert, "retry", step, "commit again", dispatch)
                    alert["retry_outcome"] = calls[-1]["outcome"]
                    if alert.get("operation"):
                        step("wait", ["wait", *run.agent, "--operation", alert["operation"], "--deadline-ms", 150])
                        step("plan close (before reconciliation)", ["plan", *run.agent, "--session", session, "--close", plan_id])
                        # A 2xx is relay acceptance only. The obligation stays open until the owner
                        # attests what happened. Here the attestation is this script's: its own
                        # relay holds the request, and no person was notified.
                        if relay.requests[before:]:
                            reconcile = ["commit", *run.agent, "--reconcile", "delivered", "--operation", alert["operation"],
                                         "--evidence", digest(relay.requests[before]["body"]), "--statement",
                                         "The loopback relay run by the evidence script holds this request. No person was notified."]
                            preview = step("commit reconcile (preview)", reconcile)
                            if preview and preview.get("outcome") == "ok" and preview.get("proofPointers"):
                                done = step("commit reconcile (script attests to loopback receipt)",
                                            [*reconcile, "--approve", preview["proofPointers"][0]])
                                if done and done.get("outcome") == "ok":
                                    alert["reconciled_state"] = (done.get("payload") or {}).get("state")
                                    alert["attestation_source"] = "evidence_script_loopback_receipt"
                        closed = step("plan close", ["plan", *run.agent, "--session", session, "--close", plan_id])
                        alert["episode_recorded"] = bool(closed and closed.get("outcome") == "ok")
        facts["alert"] = alert
    handed = step("handoff", ["handoff", *run.agent, "--session", session, "--note",
                              "Night review of the " + take + " take. Alert commands target only the script's loopback relay."])
    if handed and handed.get("outcome") == "ok":
        step("session.resume", ["session", "resume", *run.agent, "--handoff", handed["payload"]["handoffId"]])
        step("session.orient brief (after resume)", ["session", "orient", *run.agent, "--session", session, "--view", "brief"])
    return dict(calls=calls, facts=facts)


def operator_alert(run, event_id, relay):
    """Exercise the operator path on this script's relay and retain each native report."""
    # Dispatch inspects the durable operation under the exact absolute deployment root.
    base = ["alert", "--root", str(run.work / "deployment"), "--site", run.site,
            "--event-id", event_id, "--relay", relay.address, "--path", "/fss/alert",
            "--plaintext-approval", digest(APPROVAL_TEXT), "--deadline-ms", 5000]
    operator = dict(path="fss-event alert (operator command)", reports=[])

    def step(phase, args):
        report, link, result = run.json("fss-event", args)
        operator["reports"].append(link)
        native_report = isinstance(report, dict) and report.get("format") == "fss.alert_operation_report.v1"
        if phase != "retry":
            # A failed dispatch without a receipt makes the final effect unknown, even
            # when the previous preparation returned a successful "not_dispatched" report.
            receipt = report if native_report else {}
            operator.update(stage=receipt.get("stage"), effect_state=receipt.get("effect_state"),
                            outcome=(receipt.get("evidence") or {}).get("outcome"),
                            delivery_claim=receipt.get("delivery_claim"))
        if not native_report or result.returncode:
            failure = run.failure("operator alert " + phase, result)
            operator[phase + "_outcome"] = failure["outcome"]
            operator[phase + "_reason"] = failure["reason"]
        else:
            operator[phase + "_outcome"] = "ok"
        return report if isinstance(report, dict) else {}

    proposed = step("preview", base)
    if operator["preview_outcome"] != "ok" or proposed.get("stage") != "proposed" or not proposed.get("plan_digest"):
        return operator
    approved = [*base, "--approve", proposed["plan_digest"]]
    prepared = step("prepare", approved)
    if operator["prepare_outcome"] != "ok" or prepared.get("stage") != "prepared" or not prepared.get("dispatch_digest"):
        return operator
    dispatch = [*approved, "--dispatch", prepared["dispatch_digest"]]
    sent = observe_relay_call(run, relay, operator, "dispatch", step, "dispatch", dispatch)
    if operator["dispatch_outcome"] == "ok" and sent.get("stage") == "dispatched":
        again = observe_relay_call(run, relay, operator, "retry", step, "retry", dispatch)
        operator["retry_stage"] = again.get("stage")
    return operator


def fusion(run: Run, cameras, positives, blind):
    """Fusion queries built from native detector evidence. LLR intervals are an assumption."""
    base = json.loads((REPO / "fixtures/fusion_sequence/first.json").read_bytes())["steps"][0]["query"]

    def query(mode, calibrated):
        evidence = []
        for cam, row in positives.items():
            domains = ["device:" + cam] + (["render:one-scene"] if mode == "shared_render" else [])
            calibration = ({"generation": "example:illustrative-llr", "llr": ILLUSTRATIVE_LLR} if calibrated
                           else {"uncalibrated": "YOLOX-Nano scores have no calibration for this site"})
            evidence.append(dict(id=row["capsule"], sensor="camera:" + cam, failure_domains=domains,
                                 observability="observed", calibration=calibration))
        for cam, reason in blind.items():
            evidence.append(dict(id="coverage:" + cam, sensor="camera:" + cam, failure_domains=["device:" + cam],
                                 observability={"not_observable": reason},
                                 calibration={"uncalibrated": "no observation"}))
        return dict(base, hypothesis="event:person-on-grounds", kind="person_presence",
                    prior=ILLUSTRATIVE_PRIOR,
                    coverage={"state": "degraded", "reason": "Rendered frames; no field calibration."},
                    evidence=evidence)

    variants = []
    for name, mode, calibrated in (
        ("measured_scores_uncalibrated", "separate_devices", False),
        ("illustrative_separate_devices", "separate_devices", True),
        ("illustrative_shared_render", "shared_render", True),
    ):
        raw = json.dumps(query(mode, calibrated), indent=2) + "\n"
        result = run.call("fss-fuse", ["--query", "-"], stdin=raw)
        row = dict(id=name, declaration=mode, calibrated_inputs=calibrated, query=run.save(raw.encode(), "json"))
        try:
            out = json.loads(result.stdout)
        except ValueError:
            row.update(run.failure(f"fusion {name}", result))
            variants.append(row)
            continue
        row.update(
            outcome="ok", report=run.save(result.stdout.encode(), "json"), decision=out["decision"]["kind"],
            reasons=out.get("reasons"), knowledge_state=out.get("knowledge_state"),
            provenance_class=out.get("provenance_class"),
            posterior_log_odds_millibans=out.get("posterior_log_odds_millibans"),
            probability_ppm=out.get("probability_ppm"), supporting_clusters=out.get("supporting_clusters"),
            uncalibrated=len(out.get("uncalibrated") or []), excluded=len(out.get("excluded") or []),
            counterfactuals=[dict(removed_cluster=c["removed_cluster"],
                                  posterior_log_odds_millibans=c["posterior_log_odds_millibans"],
                                  decision=c["decision"]["kind"]) for c in out.get("counterfactuals") or []],
            effect_authority=out.get("effect_authority"),
        )
        variants.append(row)
        if name == "illustrative_separate_devices" and positives:
            lost = next(iter(positives))
            ablation = run.call("fss-fuse", ["--query", "-", "--without-sensor", "camera:" + lost], stdin=raw)
            try:
                parsed = json.loads(ablation.stdout)
                row["ablation"] = dict(without_sensor=lost, report=run.save(ablation.stdout.encode(), "json"),
                                       schema=parsed.get("schema"))
            except ValueError:
                row["ablation"] = run.failure(f"fusion ablation without {lost}", ablation)
    return dict(
        hypothesis="A person is on the grounds during this take.",
        units="integer millibans (thousandths of log10 odds); probability in parts per million, as an interval",
        assumptions=f"Prior {ILLUSTRATIVE_PRIOR} mB (20 %). In the illustrative variants each camera with a "
                    f"detector-positive frame contributes {ILLUSTRATIVE_LLR} mB. That interval is an assumption; "
                    "the detector has no calibration for this site, which the first variant states to the tool.",
        observations=positives,
        observations_meaning="Chosen per camera without the script. scripted_iou is the overlap of that box with a "
                             "scripted person in the same frame, checked afterwards; 0 means the script has no "
                             "person there, so that observation is a false positive fed to the tool as given.",
        not_observable=blind, variants=variants,
    )


def iou(a, b):
    w = min(a[2], b[2]) - max(a[0], b[0])
    h = min(a[3], b[3]) - max(a[1], b[1])
    if w <= 0 or h <= 0:
        return 0.0
    inter = w * h
    return inter / ((a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter)


def compare(scene, cam, detection, min_visible=0.25, min_height=0.05, match_iou=0.3):
    """Detector person boxes against the scripted boxes, on inferred frames only.

    A scripted person counts as in view when at least a quarter of the body is visible and
    the box is at least 5 % of the frame height, the rule the page uses. Smaller or more
    hidden scripted boxes are counted separately and never as misses.
    """
    actors = [a["id"] if isinstance(a, dict) else a for a in scene["actors"]]
    truth = matched = people = frames_in_view = small = small_matched = 0
    overlaps, loose = [], []
    sizes = {"5_to_8_percent": [0, 0], "8_to_20_percent": [0, 0], "over_20_percent": [0, 0]}
    for row in detection["frames"]:
        wanted, tiny = [], []
        for actor in actors:
            scripted = scripted_box(scene, cam, actor, row["frame"])
            if not scripted or scripted[1] is None or scripted[1] <= 0:
                continue
            box, visible = scripted
            (wanted if visible >= min_visible and box[3] - box[1] >= min_height else tiny).append(box)
        found = [d for d in row["detections"] if d["label"] == "person"]
        people += len(found)
        truth += len(wanted)
        frames_in_view += bool(wanted)
        used = set()
        for group, strict in ((wanted, True), (tiny, False)):
            for box in group:
                best = max(((iou(box, f["box"]), i) for i, f in enumerate(found) if i not in used), default=(0, None))
                hit = best[0] >= match_iou
                if hit:
                    used.add(best[1])
                if strict:
                    tall = box[3] - box[1]
                    bucket = sizes["5_to_8_percent" if tall < 0.08 else "8_to_20_percent" if tall < 0.2 else "over_20_percent"]
                    bucket[0] += 1
                    bucket[1] += hit
                    matched += hit
                    if hit:
                        overlaps.append(best[0])
                else:
                    small += 1
                    small_matched += hit
        loose += [(row["frame"], f) for i, f in enumerate(found) if i not in used]
    # Unmatched person boxes that keep returning to one place are reported as such.
    clusters = []
    for frame, det in loose:
        for cluster in clusters:
            if iou(cluster["box"], det["box"]) >= 0.5:
                cluster["frames"].append(frame)
                cluster["scores"].append(det["score"])
                break
        else:
            clusters.append(dict(box=det["box"], frames=[frame], scores=[det["score"]]))
    inferred = len(detection["frames"])
    persistent = [dict(box=c["box"], frames=len(c["frames"]), first_frame=min(c["frames"]), last_frame=max(c["frames"]),
                       share_of_inferred_frames=round(len(c["frames"]) / inferred, 4),
                       mean_score=round(sum(c["scores"]) / len(c["scores"]), 3))
                  for c in clusters if inferred and len(c["frames"]) >= max(12, inferred * 0.05)]
    persistent.sort(key=lambda c: -c["frames"])
    return dict(
        frames_inferred=inferred, frames_compared=frames_in_view, scripted_boxes=truth, matched=matched,
        recall=round(matched / truth, 4) if truth else None,
        mean_iou=round(sum(overlaps) / len(overlaps), 4) if overlaps else None,
        by_scripted_height={name: dict(scripted_boxes=n, matched=m, recall=round(m / n, 4) if n else None)
                            for name, (n, m) in sizes.items()},
        by_scripted_height_meaning="scripted box height as a share of the frame height",
        scripted_boxes_below_floor=dict(count=small, matched=small_matched,
                                        meaning="scripted person visible but under the in-view rule; not counted as a miss"),
        person_detections=people, unmatched_person_detections=len(loose),
        persistent_unmatched=persistent,
        persistent_unmatched_meaning="unmatched person boxes that stay in one place (IoU >= 0.5) for at least 5 % of the "
                                     "inferred frames: the detector calling a fixed object a person",
        rule=f"inferred frames only; a scripted person is in view at visibility >= {min_visible} and box height >= "
             f"{min_height} of the frame; a person detection matches at IoU >= {match_iou}; frames_compared counts "
             "inferred frames with at least one scripted person in view",
    )


def summarise(cameras, associations, events, ledger, agent, seconds):
    """The numbers a reader wants first. Every one is derived from the sections below it."""
    ok = {cid: c for cid, c in cameras.items() if c.get("custody", {}).get("outcome") == "ok"}
    pairs = {}
    for row in associations:
        name = "+".join(row["cameras"])
        pairs[name] = {}
        for declaration in ("shared_render", "separate_devices"):
            result = row.get(declaration)
            if not result or result.get("outcome") != "ok":
                pairs[name][declaration] = dict(outcome=(result or row).get("outcome", "not_run"),
                                                reason=(result or row).get("reason"))
                continue
            residuals = [c["residual_m"] for c in result["candidates"] if c["residual_m"] is not None]
            gaps = [c["time_difference_s"] for c in result["candidates"] if c["time_difference_s"] is not None]
            pairs[name][declaration] = dict(
                entries=result["entry_count"], candidates=result["candidate_count"],
                states=sorted({c["event_state"] for c in result["candidates"] if c["event_state"]}),
                policy_actions=sorted({c["policy_action"] for c in result["candidates"] if c["policy_action"]}),
                min_residual_m=min(residuals) if residuals else None,
                max_residual_m=max(residuals) if residuals else None,
                max_time_difference_s=max(gaps) if gaps else None,
            )
    outcomes, kinds = {}, {}
    for call in agent.get("calls", []):
        outcomes[call["outcome"]] = outcomes.get(call["outcome"], 0) + 1
    for event in events:
        kinds[event["kind"]] = kinds.get(event["kind"], 0) + 1
    alert = agent.get("facts", {}).get("alert", {})
    return dict(
        films=dict(count=len(ok), total_bytes=sum(c["custody"]["bytes"] for c in ok.values()),
                   total_frames=sum(c["custody"]["frames"] for c in ok.values())),
        custody_all_verified=bool(events) and all(e.get("custody", {}).get("all_verified") is True for e in events),
        motion_candidates={cid: c.get("motion", {}).get("candidate_count") for cid, c in ok.items()},
        coverage_witnesses={cid: c.get("coverage", {}).get("witness_count") for cid, c in ok.items()},
        frames_inferred={cid: c.get("detections", {}).get("frames_inferred") for cid, c in ok.items()},
        person_detections={cid: c.get("comparison", {}).get("person_detections") for cid, c in ok.items()},
        frames_with_scripted_person_in_view={cid: c.get("comparison", {}).get("frames_compared") for cid, c in ok.items()},
        scripted_boxes={cid: c.get("comparison", {}).get("scripted_boxes") for cid, c in ok.items()},
        matched={cid: c.get("comparison", {}).get("matched") for cid, c in ok.items()},
        unmatched_person_detections={cid: c.get("comparison", {}).get("unmatched_person_detections") for cid, c in ok.items()},
        persistent_unmatched={cid: [dict(box=p["box"], frames=p["frames"], mean_score=p["mean_score"])
                                    for p in c.get("comparison", {}).get("persistent_unmatched", [])]
                              for cid, c in ok.items()},
        recall={cid: c.get("comparison", {}).get("recall") for cid, c in ok.items()},
        mean_iou={cid: c.get("comparison", {}).get("mean_iou") for cid, c in ok.items()},
        corroboration=pairs,
        events_published=kinds,
        ledger=dict(root=ledger.get("root"), sequence=ledger.get("sequence")),
        alert={field: alert[field] for field in
               ("stage", "outcome", "error", "effect_state", "dispatch_requests_received", "retry_requests_received",
                "requests_received", "retry_outcome", "resend_on_retry", "reconciled_state", "attestation_source",
                "operator_fallback") if field in alert},
        agent_calls=outcomes,
        seconds=seconds,
    )


def browser_boxes(name, scene, cameras):
    """Person boxes only, keyed by take frame, small enough for a phone to fetch."""
    out = {}
    for cid, entry in cameras.items():
        frames = entry.get("detections", {}).get("frames", [])
        person = {}
        for row in frames:
            boxes = [[round(v, 3) for v in d["box"]] + [round(d["score"], 2)]
                     for d in row["detections"] if d["label"] == "person"]
            if boxes:
                person[str(row["frame"])] = boxes
        out[cid] = dict(inferred=sorted({row["frame"] for row in frames}), person=person)
    return dict(schema="fss.website.watch_native_boxes.v1", take=name, fps=scene["fps"],
                frames=scene["frames"], cameras=out)


# ---------------------------------------------------------------- main


def camera_film(take, camera):
    """Resolve the take's public URL against the directory selected for this run."""
    fallback = camera["id"] + ".mp4"
    video = pick(camera, "video", "film", "path", default=None) or fallback
    prefix = f"/watch/{take.name}/"
    if video.startswith(prefix):
        return take / video[len(prefix):], video
    if video.startswith("/"):
        return WEB / "public" / video.lstrip("/"), video
    return take / video, prefix + video


def publish_take(take, stage, native, boxes):
    """Publish immutable objects first and replace the summary only after its inputs exist."""
    name = sha256(boxes).hexdigest() + ".json"
    (stage / name).write_bytes(boxes)
    native["detector_boxes"] = "native/objects/" + name
    files = sorted(stage.iterdir())
    native["retained_objects"] = ["native/objects/" + file.name for file in files]
    target = take / "native" / "objects"
    target.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=take, prefix=".native-publish-") as scratch:
        pending = Path(scratch)
        # Keep the preceding generation readable if any later copy or rename fails.
        # A verified file with the same content address can be shared by concurrent runs.
        for source in files:
            copy = pending / source.name
            shutil.copyfile(source, copy)
            if sha256(copy.read_bytes()).hexdigest() != source.stem:
                raise ValueError(f"Object bytes disagree with their name: {source.name}")
            copy.replace(target / source.name)
        summary = pending / "native.json"
        summary.write_text(json.dumps(native, indent=1) + "\n")
        alias = pending / "native-boxes.json"
        alias.write_bytes(boxes)
        # Until this rename, a legacy summary still points at the mutable alias.
        # New summaries name an immutable object, so an interrupted alias refresh
        # leaves the committed root readable. A retry or export refreshes the alias.
        summary.replace(take / summary.name)
        alias.replace(take / alias.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("take", type=Path)
    parser.add_argument("--bins", type=Path, default=Path(os.environ.get("FSS_BIN_DIR", "/tmp/fss-watch-native/target/release")))
    parser.add_argument("--work", type=Path, help="private working directory (default: a new temporary directory)")
    parser.add_argument("--detect-limit", type=int, help="development only: at most this many detector calls per camera")
    parser.add_argument("--threads", default="auto")
    parser.add_argument("--cascade", type=int, default=32, help="detector inferences the motion cascade may spend per recording")
    args = parser.parse_args()

    take = args.take.resolve()
    name = take.name
    bins = args.bins.resolve()
    for tool in TOOLS:
        if not (bins / tool).exists():
            raise SystemExit(f"missing {bins / tool}; build with cargo build --release -p fss-cli")
    if digest(MODEL.read_bytes()) != PIN:
        raise SystemExit("pinned YOLOX-Nano package digest differs")
    scene = load_scene(take)
    work = (args.work or Path(mkdtemp(prefix="fss-watch-"))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    if (work / "deployment").exists():
        raise SystemExit(f"{work} already holds a deployment; use an empty --work directory")
    shutil.copyfile(MODEL, work / "model.fmpk")
    stage = work / "objects"
    stage.mkdir()
    run = Run(bins, work, stage, "site:watch-" + name)
    run.scrub = [str(take) + "/", str(Path.home()) + "/"]
    started = time.monotonic()
    try:
        epoch_ns = int(datetime.fromisoformat(scene["start"]).timestamp() * 1e9) if scene["start"] else 1_700_000_000_000_000_000
    except ValueError:
        epoch_ns = 1_700_000_000_000_000_000

    cameras, views, customs, metas, pending_masks = {}, {}, {}, {}, {}
    films = {}
    for cam in scene["cameras"]:
        cid = cam["id"]
        film, film_url = camera_film(take, cam)
        films[cid] = film
        meta = probe(film)
        lens = pick(cam, "lens", default={})
        model = str(pick(lens, "model", "type", "kind", default=pick(cam, "lens_model", "model", default="rectilinear"))).lower()
        rectilinear = model in RECTILINEAR
        entry = dict(lens_model=model, rectilinear=rectilinear, film=film_url)
        entry["custody"] = import_film(run, name, cid, film, meta, epoch_ns)
        declared = pick(cam, "video_sha256", default=None)
        if declared and entry["custody"].get("outcome") == "ok":
            entry["custody"]["matches_scene_json"] = entry["custody"]["sha256"] == "sha256:" + declared
            if not entry["custody"]["matches_scene_json"]:
                raise SystemExit(f"{cid}: film bytes differ from scene.json video_sha256; the take is still being written")
        held = pick(cam, "held_spans", default=[])
        if held:
            count = sum(int(b) - int(a) + 1 for a, b in held)
            entry["held_frames"] = dict(count=count, spans=held)
            run.notes.append(f"{cid}: {count} of {meta['frames']} film frames repeat a held picture (scene.json held_spans); "
                             "the renderer skipped spans in which no person is in view, so nothing can move there.")
        cameras[cid], metas[cid] = entry, meta
        if entry["custody"]["outcome"] != "ok":
            continue
        customs[cid] = entry["custody"]
        width, height = meta["width"], meta["height"]
        rects = [list(map(int, r)) for r in pick(cam, "osd", "overlays", default=[])]
        overlays = [list(r) for r in rects]
        top, bottom = 0, height
        for x, y, w, h in rects:
            if y + h / 2 < height / 2:
                top = max(top, y + h)
            else:
                bottom = min(bottom, y)
        if rectilinear:
            g2i = ground_to_image(cam, width, height)
            i2g = invert3(g2i)
            horizon = horizon_row(i2g, width)
            band = min(height - 64, max(0, math.ceil(horizon + HORIZON_MARGIN * height)))
            if band > 0:
                rects.append([0, 0, width, band])
                top = max(top, band)
            eye = pick(cam, "position", "eye")
            views[cid] = dict(g2i=g2i, i2g=i2g, eye=eye, width=width, height=height)
            entry["ground_projection"] = dict(
                image_to_ground=[[float(v) for v in row] for row in i2g], horizon_row=round(horizon, 2),
                source="scene.json position, look_at and vertical field of view; ground plane y = 0",
                status="owner_supplied_not_a_calibration_certificate",
            )
        else:
            entry["ground_projection"] = dict(
                status="not_modelled",
                reason=f"{model} lens: the corroboration tool takes a planar homography or a pinhole pose, "
                       "so this camera joins custody, motion and detection only",
            )
        zone = [0, top, width, bottom - top]
        entry["zone"] = zone
        if cid in views:
            views[cid]["zone"] = zone
        # Two mask generations. The detector runs under the first, which hides only the
        # burned-in clock, so it sees the picture a viewer sees. The second adds everything
        # above the ground horizon and is declared just before the motion and ground-plane
        # stages: whole-recording corroboration refuses a run in which any confirmed motion
        # track has its foot point above the horizon, and lit windows produce such tracks.
        entry["privacy_mask"] = declare_mask(run, cid, width, height, overlays) if overlays else dict(outcome="none_declared")
        pending_masks[cid] = (width, height, rects) if rects != overlays else None
        if not pick(cam, "osd", "overlays", default=[]):
            run.notes.append(f"{cid}: scene.json lists no on-screen overlay rectangles, so any burned-in clock is unmasked and can register as motion.")

    # Calibration self-check against the scripted boxes: the scripted ground point should
    # project to the bottom centre of the scripted box.
    actors = [a["id"] if isinstance(a, dict) else a for a in scene["actors"]]
    for cid, view in views.items():
        errors = []
        for frame in range(0, scene["frames"], 6):
            for actor in actors:
                ground, box = ground_truth(scene, actor, frame), scripted_box(scene, cid, actor, frame)
                if not ground or not box or (box[1] or 0) < 0.9:
                    continue
                p = project(view["g2i"], ground)
                if p:
                    errors.append(math.hypot(p[0] - (box[0][0] + box[0][2]) / 2 * view["width"],
                                             p[1] - box[0][3] * view["height"]))
        errors.sort()
        cameras[cid]["ground_projection"]["self_check_px"] = dict(
            samples=len(errors), median=round(errors[len(errors) // 2], 2) if errors else None,
            meaning="pixels between the scripted hip position dropped to the ground plane and the bottom centre of "
                    "the scripted box. Feet lead and trail the hips while walking, and anyone on the raised porch "
                    "stands above the plane, so this bounds the ground error of a foot point; the projection itself "
                    "agrees with the camera matrix in scene.json to under 0.1 px.",
        )

    for cid, custody in customs.items():
        detection = detect(run, cid, custody, metas[cid], epoch_ns, scene["fps"], args.threads, args.detect_limit)
        cameras[cid]["detections"] = detection
        cameras[cid]["tracks"] = query_tracks(run, cid, custody, detection, epoch_ns, scene["fps"])
        cameras[cid]["comparison"] = compare(scene, cid, detection)
        print(f"{cid}: detector on {detection['frames_inferred']} frames in {detection['seconds']} s, "
              f"recall {cameras[cid]['comparison']['recall']}", flush=True)

    for cid, pending in pending_masks.items():
        if pending is None:
            continue
        first = cameras[cid]["privacy_mask"]
        final = declare_mask(run, cid, *pending)
        final["detector_stage"] = ({k: first.get(k) for k in ("rectangles", "policy_digest", "generation")}
                                   if first.get("outcome") == "ok" else dict(rectangles=[], policy_digest=None))
        final["note"] = ("The detector ran under detector_stage. Motion, coverage and ground-plane corroboration "
                         "ran under these rectangles, which also hide everything above the ground horizon.")
        cameras[cid]["privacy_mask"] = final

    watches = {}
    for cid, custody in customs.items():
        summary, wargs, report = stream_watch(run, cid, custody, cameras[cid]["zone"], epoch_ns, args.cascade)
        if summary.get("outcome") != "ok" and args.cascade:
            # Unapproved whole-recording previews run under the tool's own 60 s deadline and
            # fixed report bounds. When the cascade does not fit, the motion stage runs alone.
            refused = summary
            summary, wargs, report = stream_watch(run, cid, custody, cameras[cid]["zone"], epoch_ns, 0)
            summary["detector_cascade"] = dict(outcome=refused["outcome"], reason=refused["reason"],
                                               refusal=refused["refusal"], requested_inferences=args.cascade)
        cameras[cid]["motion"] = summary
        if wargs:
            watches[cid] = (wargs, report)
        for candidate in summary.get("candidates") or []:
            # Afterwards only: how much of this moving region lies inside a scripted person's box.
            box, share = candidate["box"], 0.0
            area = max(1e-9, (box[2] - box[0]) * (box[3] - box[1]))
            for actor in actors:
                scripted = scripted_box(scene, cid, actor, round(candidate["t"] * scene["fps"]))
                if scripted and scripted[1]:
                    wide = min(box[2], scripted[0][2]) - max(box[0], scripted[0][0])
                    tall = min(box[3], scripted[0][3]) - max(box[1], scripted[0][1])
                    if wide > 0 and tall > 0:
                        share = max(share, wide * tall / area)
            candidate["inside_scripted_person"] = round(share, 3)
        print(f"{cid}: motion candidates {summary.get('candidate_count')}", flush=True)

    # Single-camera event: publish the earliest motion candidate that carries person evidence,
    # else the earliest candidate. It stays unclassified, indeterminate, single-sensor.
    events, single_event = [], None
    choices = []
    for cid, (wargs, report) in watches.items():
        for c, s in zip(report["candidates"], cameras[cid]["motion"]["candidates"]):
            person = any(e.get("label") == "person" and e.get("supports") for e in s["class_evidence"])
            choices.append((not person, s["t"], cid, c))
    if choices:
        _, t, cid, candidate = min(choices, key=lambda row: row[:3])
        wargs = watches[cid][0]
        published, link, result = run.json("fss-event", [*wargs, "--approve", candidate["proposal_digest"]])
        if published is None:
            run.failure(f"{cid}: publish single-camera event", result)
        else:
            repeat, repeat_link, _ = run.json("fss-event", [*wargs, "--approve", candidate["proposal_digest"]])
            single_event = candidate["event_id"]

            def status_of(report):
                return next((c["status"] for c in (report or {}).get("candidates", [])
                             if c["event_id"] == single_event), None)
            events.append(dict(
                id=single_event, kind="single_camera_motion", cameras=[cid], t=t,
                state=published.get("event_state"), event_kind=published.get("event_kind"),
                policy_action=published.get("policy_action"), corroborated=published.get("corroborated"),
                evidence_class="observed", publication=link, authority_sequence=published.get("authority_sequence"),
                status=status_of(published),
                idempotent_retry=dict(report=repeat_link, status=status_of(repeat)),
            ))

    associations, joint_event, pending = [], None, []
    for pair in combinations(sorted(views), 2):
        zones, cell = zones_for(pair, views)
        if not zones:
            associations.append(dict(cameras=list(pair), outcome="not_run",
                                     reason="no ground cell lies inside both frames within range"))
            continue
        shared, _ = corroborate(run, pair, views, customs, zones, "shared_render", epoch_ns)
        separate, context = corroborate(run, pair, views, customs, zones, "separate_devices", epoch_ns)
        against_script(scene, shared)
        against_script(scene, separate)
        row = dict(cameras=list(pair), cell_m=cell, shared_render=shared, separate_devices=separate)
        coarse_zones, coarse_cell = zones_for(pair, views, COARSE_CELL_M)
        if coarse_zones and coarse_cell > cell:
            coarse, _ = corroborate(run, pair, views, customs, coarse_zones, "separate_devices", epoch_ns)
            against_script(scene, coarse)
            row["coarser_grid"] = dict(
                cell_m=coarse_cell, preview_only=True,
                meaning="Same recordings, gates and declaration on a coarser ground grid. Nothing was approved from it.",
                **{k: coarse.get(k) for k in ("outcome", "reason", "report", "zones", "entry_count",
                                              "candidate_count", "candidates") if k in coarse})
        associations.append(row)
        print(f"{pair[0]}+{pair[1]}: entries {separate.get('entry_count')}, candidates {separate.get('candidate_count')}", flush=True)
        if context and separate.get("candidates"):
            first = min(separate["candidates"], key=lambda c: min(c["t"]) if c["t"] else 1e9)
            pending.append((min(first["t"]) if first["t"] else 1e9, pair, context[0], first, row))
    # One corroborated event is published: the earliest candidate over all pairs. The other
    # candidates stay as previews, which write nothing.
    for _, pair, cargs, first, row in sorted(pending, key=lambda item: item[0])[:1]:
        published, link, result = run.json("fss-event", [*cargs, "--approve", first["proposal"]])
        if published is None:
            row["publication"] = run.failure(f"{pair[0]}+{pair[1]}: publish corroborated event", result)
            continue
        done = next((c for c in published["candidates"] if c.get("proposal_digest") == first["proposal"]), {})
        event = dict(
            id=first["event_id"], kind="two_camera_corroboration", cameras=list(pair),
            t=min(first["t"]) if first["t"] else None, ground=first["ground"], residual_m=first["residual_m"],
            time_difference_s=first["time_difference_s"],
            nearest_scripted_person=first.get("nearest_scripted_person"),
            state=done.get("event_state", published.get("event_state")), policy_action=done.get("policy_action"),
            evidence_class="corroborated" if done.get("event_state") == "corroborated" else "observed",
            declaration="separate_devices", publication=link, authority_sequence=published.get("authority_sequence"),
            status=done.get("status"),
        )
        events.append(event)
        row["publication"] = dict(outcome="ok", event_id=event["id"], report=link)
        if event["state"] == "corroborated" and (joint_event is None or (event["t"] or 0) < joint_event[0]):
            joint_event = (event["t"] or 0, event["id"])

    ledger = dict(entries=[])
    for event in events:
        audit, link, result = run.json("fss-custody", ["audit", *run.root, "--event-id", event["id"]])
        if audit is None:
            event["custody"] = run.failure(f"custody audit of {event['id'][:28]}", result)
            continue
        event["custody"] = dict(outcome="ok", report=link, all_verified=audit["all_verified"],
                                objects=len(audit["objects"]),
                                states=sorted({o["state"] for o in audit["objects"]}))
        ledger.update(root=audit["ledger_root"], sequence=audit["anchor"]["capsuleSequence"])
        ledger["entries"].append(dict(seq=event.get("authority_sequence"), kind=event["kind"], event_id=event["id"],
                                      digest=audit.get("event_revision") or audit.get("revision_digest"), t=event.get("t")))

    relay = Relay()
    try:
        agent = agent_session(run, name, single_event, joint_event[1] if joint_event else None, relay)
        alert = agent["facts"].get("alert")
        if joint_event and alert and alert.get("stage") == "proposed" and alert.get("outcome") == "refused":
            alert["operator_fallback"] = operator_alert(run, joint_event[1], relay)
    finally:
        relay.close()

    # Coverage is retained last on purpose. With witnesses for several sensors in the ledger the
    # critical context grows, and the bounded agent views refuse instead of truncating it, which
    # would also block the alert plan above. The orient calls after it record that effect.
    for cid, custody in customs.items():
        cameras[cid]["coverage"] = retain_coverage(run, cid, custody, metas[cid], cameras[cid]["zone"], epoch_ns)
        print(f"{cid}: coverage witnesses {cameras[cid]['coverage'].get('witness_count')}", flush=True)
    if agent["facts"].get("session"):
        for view in ("brief", "epistemic_map"):
            envelope, link, result = run.json("fss", ["session", "orient", *run.agent, "--session",
                                                       agent["facts"]["session"], "--view", view])
            after = envelope_summary(f"session.orient {view} (after coverage retained)", envelope, link, result)
            agent["calls"].append(after)
            if after["outcome"] != "ok":
                run.notes.append(f"After coverage witnesses were retained, session.orient --view {view} ended "
                                 f"{after['outcome']} ({after.get('error')}); the same call succeeded before retention.")
    covered = {cid: c["coverage"] for cid, c in cameras.items() if "coverage" in c}
    run.notes.append(
        "Coverage: " + "; ".join(
            f"{cid} has {c.get('witness_count', 0)} witnesses over {c.get('covered_seconds', 0)} s"
            + (f" and {len(c['windows_failed'])} window(s) refused" if c.get("windows_failed") else "")
            for cid, c in covered.items())
        + ". A witness records that one sensor decoded its zone without a gap over one interval. Each retained "
          "report states whether absence is certified inside its witness domains; intervals without a witness "
          "are unobserved.")

    # Fusion observations are chosen without looking at the script: per camera, a moving track
    # that the detector cascade labelled person, else the highest-scoring person box in any
    # inferred frame. The overlap with the scripted boxes is computed afterwards and reported.
    positives, blind = {}, {}
    for cid, entry in cameras.items():
        chosen = None
        for candidate in (entry.get("motion") or {}).get("candidates") or []:
            for evidence in candidate["class_evidence"]:
                if evidence.get("label") == "person" and evidence.get("supports") and (
                        chosen is None or evidence["score"] > chosen["score"]):
                    chosen = dict(t=candidate["t"], frame=round(candidate["t"] * scene["fps"]),
                                  score=round(evidence["score"], 4), capsule=candidate["capsule"], box=candidate["box"],
                                  source="moving track with person class evidence from the detector cascade")
        if chosen is None:
            rows = [(d["score"], f["frame"], f, d) for f in (entry.get("detections") or {}).get("frames", [])
                    for d in f["detections"] if d["label"] == "person"]
            if rows:
                score, _, frame, det = max(rows, key=lambda r: r[:2])
                chosen = dict(t=frame["t"], frame=frame["frame"], score=score, capsule=frame["capsule"], box=det["box"],
                              source="highest-scoring person box in any inferred frame; not tied to motion")
        if chosen:
            overlaps = [iou(chosen["box"], scripted[0]) for actor in actors
                        if (scripted := scripted_box(scene, cid, actor, chosen["frame"]))]
            chosen["scripted_iou"] = round(max(overlaps, default=0.0), 3)
            positives[cid] = chosen
        elif entry.get("custody", {}).get("outcome") == "ok":
            blind[cid] = "no person label in any inferred frame; this is not evidence of absence"
    fused = fusion(run, cameras, positives, blind) if positives else dict(outcome="not_run", reason="no detector-positive frame")

    status, link, _ = run.json("fss", ["status", *run.agent])
    # `root` and `sequence` above are from the last event custody audit. The ledger moves on after it
    # (alert, agent session, coverage), so the position at the end of the run is recorded separately.
    anchor = (status or {}).get("anchor") or {}
    if anchor.get("commit_sequence") is not None:
        ledger["final"] = dict(sequence=anchor["commit_sequence"], root=anchor.get("ledger_root"))
    version =subprocess.run([bins / "fss", "version"], capture_output=True, text=True).stdout.strip()
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    crates = subprocess.run(["git", "log", "-1", "--format=%H", "--", "crates", "Cargo.toml", "Cargo.lock"],
                            cwd=REPO, capture_output=True, text=True).stdout.strip()
    native = dict(
        schema="fss.website.watch_native.v1",
        take=name,
        source="Rendered camera films of a fictional property. Values are output of the FSS binaries run on "
               "those film files, except the comparisons with scene.json's scripted boxes and positions, which "
               "this script computes. Nothing was measured on a physical camera.",
        fss=dict(
            version=version, repository_commit=commit, crates_commit=crates,
            build="release" if "release" in str(bins) else "debug",
            qualification="unqualified reference implementation",
            model=dict(name="YOLOX-Nano COCO-80", package="models/yolox-nano/yolox_nano.fmpk", digest=PIN),
            site=run.site, capture_epoch_ns=str(epoch_ns),
            capture_time="operator hint taken from the render's shared clock, +/- 1 ms; the on-screen camera clocks are not used",
            settings=dict(motion=MOTION, motion_reference_frame=BASE, time_gate_ns=TIME_GATE_NS,
                          distance_gate_m=DISTANCE_GATE_M, zone_cell_m=ZONE_CELL_M, coarser_grid_cell_m=COARSE_CELL_M,
                          zone_range_m=ZONE_RANGE_M, cascade_inferences=args.cascade,
                          cascade_stream_pixel_budget=CASCADE_PIXEL_BUDGET),
            commands=run.commands,
        ),
        cameras=cameras,
        associations=associations,
        events=events,
        fusion=fused,
        ledger=dict(ledger, status=link),
        agent=agent,
        seconds=round(time.monotonic() - started, 1),
        notes=run.notes,
    )
    native = dict(list(native.items())[:3] + [("summary", summarise(
        cameras, associations, events, ledger, agent, native["seconds"]))] + list(native.items())[3:])
    for cid, custody in customs.items():
        if digest(films[cid].read_bytes()) != custody["sha256"]:
            raise SystemExit(f"{cid}: the film changed during analysis; rerun on the finished take")
    native["scene_sha256"] = scene["source_digest"]
    if digest((take / "scene.json").read_bytes()) != native["scene_sha256"]:
        raise SystemExit("The scene changed during analysis; rerun on the finished take")
    boxes = (json.dumps(browser_boxes(name, scene, cameras), separators=(",", ":")) + "\n").encode()
    publish_take(take, stage, native, boxes)
    print(f"wrote {take / 'native.json'} and {len(native['retained_objects'])} objects in {native['seconds']} s", flush=True)
    print("working deployment kept at", work, flush=True)


if __name__ == "__main__":
    main()
