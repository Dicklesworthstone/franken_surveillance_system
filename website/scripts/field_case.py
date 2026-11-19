"""Capture the Juniper House fusion, ledger and agent exhibits in an isolated deployment."""

from __future__ import annotations

from itertools import chain
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

WEB = Path(__file__).resolve().parents[1]
BINS = Path(os.environ.get("FSS_BIN_DIR", WEB.parent / "target/debug")).resolve()
EVIDENCE = WEB / "public/evidence"
DESTINATION = WEB / "public/field"
SCOPE = ["--root", "deployment", "--site", "site:juniper-demo"]


def read(path):
    return json.loads(path.read_bytes())


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def execute(tool, args, cwd, *, stdin=None, refusal=None):
    result = subprocess.run(
        [BINS / tool, *args],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if refusal:
        parsed = json.loads(result.stdout)
        if (
            result.returncode == 0
            or parsed.get("errorId") != refusal
            or parsed.get("outcome") != "refused"
        ):
            raise ValueError("Expected the native alert-eligibility refusal")
    else:
        result.check_returncode()
    return result.stdout


def render_pair(out, pair, views, spec):
    """Use the same sampled film frames for the native entry cards and split-screen cut."""
    candidate = pair["candidates"][0]
    entries = sorted(
        (pair["entries"][i] for i in candidate["entries"]), key=lambda e: e["segment"]
    )
    step = spec["fps"] // spec["nativeFps"]
    inputs, filters = [], []
    matched_at = max(e["segment"] for e in entries) / spec["nativeFps"]
    gate_ms = pair["time_gate_ns"] // 1_000_000
    font = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    for i, entry in enumerate(entries):
        cam = entry["camera"]
        movie = WEB / "public/films" / (views[cam]["asset"] + ".mp4")
        frame = entry["segment"] * step
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-i",
                movie,
                "-vf",
                f"select=eq(n\\,{frame})",
                "-frames:v",
                "1",
                "-q:v",
                "2",
                out / (cam + ".jpg"),
            ],
            check=True,
        )
        inputs.extend(["-i", movie])
        cx, cy, w, h = entry["track_box_cxcywh"]
        scale = 512 / spec["nativeWidth"]
        rect = ":".join(str(round(k * scale)) for k in (cx - w / 2, cy - h / 2, w, h))
        color = "0xb6ff94" if cam == "porch" else "0xffbd78"
        name = "PORCH" if cam == "porch" else "DRIVEWAY"
        filters.append(
            f"[{i}:v]scale=512:288,drawbox={rect}:color={color}:t=2:enable='eq(n,{frame})',pad=512:324:0:36:color=0x10201e,drawtext=fontfile={font}:text='{name} CAMERA':x=14:y=9:fontsize=15:fontcolor={color}[v{i}]"
        )
    filters.append(
        f"[v0][v1]hstack,pad=1024:372:0:0:color=0x10201e,drawtext=fontfile={font}:text='Juniper House  /  Ground-zone observations':x=14:y=337:fontsize=16:fontcolor=white:enable='lt(t,{matched_at})',drawtext=fontfile={font}:text='Porch + driveway  /  {gate_ms} ms window  /  Shared source - alert held':x=14:y=337:fontsize=16:fontcolor=white:enable='gte(t,{matched_at})'[film]"
    )
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            *inputs,
            "-filter_complex",
            ";".join(filters),
            "-map",
            "[film]",
            "-an",
            "-c:v",
            "libx264",
            "-threads",
            "2",
            "-crf",
            "20",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            out / "doorstep-review.mp4",
        ],
        check=True,
    )


def capture(tmp, out):
    rig = read(WEB / "public/films/rig.json")
    views = read(EVIDENCE / "index.json")["delivery"]["views"]
    # Import in the original rig order to reproduce the original authority anchor.
    for camera in rig["cases"]["delivery"]["views"]:
        view = views[camera]
        clip = camera + ".mjpeg"
        data = (EVIDENCE / (view["asset"] + ".mjpeg")).read_bytes()
        if digest(data) != view["inputDigest"]:
            raise ValueError("Source changed for " + camera)
        (tmp / clip).write_bytes(data)
        result = execute(
            "fss-file",
            [
                "import",
                *SCOPE,
                "--input",
                clip,
                "--sensor",
                "sensor:" + camera,
                "--stream",
                "stream:delivery-" + camera,
                "--media-format",
                "mjpeg",
                "--receive-time-ns",
                "1700000020000000000",
                "--capture-start-ns",
                "1700000000000000000",
                "--capture-uncertainty-ns",
                "1000000",
                "--assumed-fps",
                str(rig["recording"]["nativeFps"]),
            ],
            tmp,
        )
        if "import_identity=" + view["importId"] not in result.splitlines():
            raise ValueError("Mismatched import for " + camera)

    def record(name, tool, args, **kwargs):
        raw = execute(tool, args, tmp, **kwargs)
        (out / (name + ".json")).write_text(raw)
        return json.loads(raw)

    zone = rig["cases"]["delivery"]["zone"]
    args = [
        "corroborate",
        *SCOPE,
        "--interpretation",
        "ycbcr",
        "--zone",
        zone["id"] + ":" + ",".join(map(str, zone["rect"])),
        "--time-gate-ns",
        "500000000",
        "--distance-gate",
        "1",
        "--failure-domain",
        "replay:juniper-scene=drive,porch",
        "--failure-domain",
        "clock:juniper-timeline=drive,porch",
    ]
    for camera in ("drive", "porch"):
        args.extend(
            [
                "--camera",
                camera + ":" + views[camera]["importId"],
                "--ground",
                camera
                + ":"
                + ",".join(map(str, rig["cameras"][camera]["imageToGround"])),
            ]
        )
    pair = record("association", "fss-event", args)
    if len(pair["candidates"]) != 1 or pair["candidates"][0]["policy_action"] != "hold":
        raise ValueError("Review the changed fixture before publishing it")
    render_pair(out, pair, views, rig["recording"])
    candidate = pair["candidates"][0]
    event = candidate["event_id"]
    approved = [*args, "--approve", candidate["proposal_digest"]]
    published = record("publication", "fss-event", approved)
    retry = record("repeat", "fss-event", approved)
    if (
        published["published_count"] != 1
        or retry["already_published_count"] != 1
        or retry["authority_sequence"] != published["authority_sequence"]
    ):
        raise ValueError("Native publication failed its replay check")
    custody = record("custody", "fss-custody", ["audit", *SCOPE, "--event-id", event])
    if (
        not custody["all_verified"]
        or custody["revision_digest"] != candidate["event_revision_digest"]
    ):
        raise ValueError("Custody did not verify the published revision")
    # Export only the audited event manifest and its witness payload. The on-disk
    # spool record wraps each payload; check its exact size and hash before export.
    for obj in custody["objects"]:
        h = obj["digest"][7:]
        spool = (tmp / "deployment/objects/spool/objects" / h).read_bytes()
        payload = spool[-obj["verified_payload_bytes"] :]
        if obj["state"] != "verified" or digest(payload) != obj["digest"]:
            raise ValueError("Exported bytes do not match the audited object")
        (out / (h + ".bin")).write_bytes(payload)

    agent = ["--root", "deployment", "--json"]
    record(
        "explain", "fss", ["explain", *agent, "--event-id", event, "--view", "forensic"]
    )
    session = json.loads(
        execute(
            "fss",
            [
                "session",
                "open",
                *agent,
                "--mission-text",
                "Review the two camera observations at Juniper House.",
                "--objective",
                "Explain the porch entry and preserve uncertainty.",
            ],
            tmp,
        )
    )["sessionId"]
    record(
        "orient",
        "fss",
        ["session", "orient", *agent, "--session", session, "--view", "brief"],
    )
    record(
        "alert",
        "fss",
        [
            "plan",
            *agent,
            "--session",
            session,
            "--intent",
            "alert",
            "--event-id",
            event,
            "--relay",
            "127.0.0.1:1",
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            digest(b"owner approves the plaintext loopback relay"),
            "--deadline-ms",
            "100",
        ],
        refusal="ERR-ALERT-NOT-ELIGIBLE-001",
    )
    handoff = record(
        "handoff",
        "fss",
        [
            "handoff",
            *agent,
            "--session",
            session,
            "--note",
            "Review the shared porch and driveway observations. Hold physical actions.",
        ],
    )
    resumed = record(
        "resume",
        "fss",
        ["session", "resume", *agent, "--handoff", handoff["payload"]["handoffId"]],
    )
    if resumed["sessionId"] != session or resumed["outcome"] != "ok":
        raise ValueError("Frozen handoff did not resume the case")

    # An explicitly hypothetical sensitivity exercise, independent of the
    # Juniper inference scores. Reuse the repository's example policy contract.
    base = read(WEB.parent / "fixtures/fusion_sequence/first.json")["steps"][0]["query"]
    for mode in ("single", "shared", "independent"):
        query = {
            **base,
            "prior": [-602, -602],
            "coverage": {
                "state": "degraded",
                "reason": "Illustrative inputs without field calibration.",
            },
        }
        query["evidence"] = [
            {
                "id": c + "-observation",
                "sensor": "camera:" + c,
                "failure_domains": ["device:" + c]
                + (["replay:shared"] if mode == "shared" else []),
                "observability": "observed",
                "calibration": {"generation": "example:assumed-llr", "llr": [600, 800]},
            }
            for c in (["porch"] if mode == "single" else ["porch", "drive"])
        ]
        raw = json.dumps(query, indent=2) + "\n"
        (out / ("input-" + mode + ".json")).write_text(raw)
        record("belief-" + mode, "fss-fuse", ["--query", "-"], stdin=raw)


def main():
    DESTINATION.mkdir(exist_ok=True)
    with (
        TemporaryDirectory(prefix="fss-case-") as temp,
        TemporaryDirectory(dir=WEB, prefix=".evidence-") as stage,
    ):
        out = Path(stage)
        capture(Path(temp), out)
        index = {f.name: digest(f.read_bytes()) for f in sorted(out.iterdir())}
        (out / "index.json").write_text(json.dumps(index, indent=2) + "\n")
        for name in chain(index, ["index.json"]):
            (out / name).replace(DESTINATION / name)


if __name__ == "__main__":
    main()
