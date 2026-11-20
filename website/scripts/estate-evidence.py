"""Regenerate the public residential replay evidence from its exact rendered camera films.

    FSS_BIN_DIR=/path/to/native/binaries python3 scripts/estate-evidence.py

FFmpeg prepares a disclosed sampled input. FSS imports that byte stream, watches its
whole duration, inspects fixed frames and publishes a candidate only to a new, local
replay ledger. All native reports remain downloadable alongside the media they cite.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction
from hashlib import sha256
import json
from itertools import combinations
from pathlib import Path
from runpy import run_path
import shutil
import subprocess
from tempfile import TemporaryDirectory

from field_case import execute

WEB = Path(__file__).resolve().parents[1]
NATIVE = run_path(str(Path(__file__).with_name("native-evidence.py")))
MODEL, PIN = NATIVE["MODEL"], NATIVE["PIN"]
CASES = ("after-hours", "delivery", "wildlife")
SCOPE = ["--root", "deployment", "--site", "site:alder-house-replay"]
AGENT = ["--root", "deployment", "--json"]
PREFIX = "/night-evidence/objects/"


def hashed(data):
    return "sha256:" + sha256(data).hexdigest()


def command(args, directory):
    return subprocess.run(args, cwd=directory, check=True, capture_output=True).stdout


def save(stage, data, suffix):
    name = hashed(data)[7:] + "." + suffix
    (stage / name).write_bytes(data)
    return PREFIX + name


def record(stage, tmp, tool, args):
    try:
        raw = execute(tool, args, tmp)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"{tool} {args[0]} failed: {error.stderr or error.stdout}"
        ) from error
    return json.loads(raw), save(stage, raw.encode(), "json")


def import_film(case, cam, movie, tmp, stage, expected_digest):
    # All decoders must open the same bytes, including when a new film generation
    # is published between the probe, JPEG extraction and native file import.
    source_bytes = movie.read_bytes()
    film_digest = hashed(source_bytes)
    if film_digest != expected_digest:
        raise ValueError(f"{movie.name} differs from the captured film digest")
    movie = tmp / movie.name
    movie.write_bytes(source_bytes)
    source = json.loads(
        command(
            [
                "ffprobe",
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=width,height,r_frame_rate:frame=best_effort_timestamp_time",
                "-of",
                "json",
                movie,
            ],
            tmp,
        )
    )
    meta = source["streams"][0]
    fps = Fraction(meta["r_frame_rate"])
    timestamps = [float(f["best_effort_timestamp_time"]) for f in source["frames"]]
    if (
        not timestamps
        or fps.denominator != 1
        or meta["width"] * 9 != meta["height"] * 16
        or any(abs(t - n / fps) > 0.00001 for n, t in enumerate(timestamps))
    ):
        raise ValueError(
            f"{movie.name} must be a 16:9, zero-based constant-rate recording"
        )
    fps = int(fps)
    rate = max(i for i in range(1, min(fps, 4) + 1) if fps % i == 0)
    step = fps // rate
    camera_file = cam + ".mjpeg"
    select = f"select=not(mod(n\\,{step})),setpts=N/({rate}*TB),scale=160:90"
    command(
        [
            "ffmpeg",
            "-v",
            "error",
            "-n",
            "-i",
            movie,
            "-vf",
            select,
            "-r",
            str(rate),
            "-c:v",
            "mjpeg",
            "-q:v",
            "4",
            "-pix_fmt",
            "yuvj420p",
            "-threads",
            "1",
            "-f",
            "mjpeg",
            camera_file,
        ],
        tmp,
    )
    command(
        [
            "ffmpeg",
            "-v",
            "error",
            "-f",
            "mjpeg",
            "-i",
            camera_file,
            "-c:v",
            "copy",
            "-f",
            "image2",
            "-start_number",
            "0",
            cam + "-%05d.jpg",
        ],
        tmp,
    )
    data = (tmp / camera_file).read_bytes()
    receipt = execute(
        "fss-file",
        [
            "import",
            *SCOPE,
            "--input",
            camera_file,
            "--sensor",
            "sensor:" + cam,
            "--stream",
            f"stream:{case}-{cam}",
            "--media-format",
            "mjpeg",
            "--receive-time-ns",
            "1700000120000000000",
            "--capture-start-ns",
            "1700000000000000000",
            "--capture-uncertainty-ns",
            "1000000",
            "--assumed-fps",
            str(rate),
        ],
        tmp,
    )
    fields = dict(line.split("=", 1) for line in receipt.splitlines() if "=" in line)
    frames = (len(timestamps) + step - 1) // step
    if (
        fields["verified_source_sha256"] != hashed(data)
        or fields["input_sha256"] != hashed(data)
        or int(fields["segment_count"]) != frames
        or fields["omission_count"] != "0"
    ):
        raise ValueError(
            "Native source verification differs from the disclosed film sampling"
        )
    return dict(
        film="/night-media/" + movie.name,
        filmDigest=film_digest,
        filmFps=fps,
        filmFrames=len(timestamps),
        nativeFps=rate,
        frames=frames,
        input=save(stage, data, "mjpeg"),
        inputDigest=hashed(data),
        importId=fields["import_identity"],
        importReceipt=save(stage, receipt.encode(), "txt"),
    )


def inspect(view, cam, tmp, stage):
    args = [
        "watch",
        *SCOPE,
        "--import-id",
        view["importId"],
        "--interpretation",
        "ycbcr",
        "--zone",
        "image:0,0,160,90",
        "--detector-package",
        "model.fmpk",
        "--detector-digest",
        PIN,
        "--detector-max-inferences",
        "1",
    ]
    watch, link = record(stage, tmp, "fss-event", args)
    if (
        watch["import_identity"] != view["importId"]
        or watch["frames_decoded"] != view["frames"]
        or watch["effects_authorized"]
        or watch["absence_certifiable"]
    ):
        raise ValueError("Unexpected native watch source, coverage or decision")
    view.update(watch=link, candidateCount=watch["candidate_count"], samples=[])
    cascade = watch["detector_cascade"]
    if cascade["package_digest"] != PIN or cascade["inference_count"] > 1:
        raise ValueError(
            "Motion-triggered detector exceeded its disclosed package or budget"
        )
    view["trackLabels"] = [
        dict(
            candidate=c["candidate_id"],
            frame=e["segment"],
            time=e["segment"] / view["nativeFps"],
            label=e["label"],
            score=e["score"],
            supports=e["supports"],
            overlapPpm=e["iou_ppm"],
            evidenceDigest=e["evidence_digest"],
            capsule=next(
                row["capsule_digest"]
                for row in c["evidence"]
                if row["segment"] == e["segment"]
            ),
        )
        for c in watch["candidates"]
        for e in c["class_evidence"]
        if e["outcome"] == "associated"
    ]
    for fraction in (1, 2):
        n = min(view["frames"] - 1, view["frames"] * fraction // 3)
        if any(s["frame"] == n for s in view["samples"]):
            continue
        report, url = record(
            stage,
            tmp,
            "fss-infer",
            [
                "package-detect",
                *SCOPE,
                "--import-id",
                view["importId"],
                "--first-segment",
                str(n),
                "--frames",
                "1",
                "--interpretation",
                "ycbcr",
                "--package",
                "model.fmpk",
                "--package-digest",
                PIN,
                "--threads",
                "2",
            ],
        )
        [frame] = report["frames"]
        if (
            not report["complete"]
            or report["package_digest"] != PIN
            or report["source_import"] != view["importId"]
            or frame["segment"] != n
            or report["effects_authorized"]
            or report["absence_certifiable"]
        ):
            raise ValueError("Detector returned an incomplete or unrelated frame")
        view["modelGeneration"] = report["generation"]
        view["minimumScorePpm"] = report["minimum_score_ppm"]
        jpg = (tmp / f"{cam}-{n:05d}.jpg").read_bytes()
        offset = sum((tmp / f"{cam}-{i:05d}.jpg").stat().st_size for i in range(n))
        with (tmp / (cam + ".mjpeg")).open("rb") as source:
            source.seek(offset)
            if source.read(len(jpg)) != jpg:
                raise ValueError(
                    "The displayed plate must be the exact imported JPEG at this segment"
                )
        view["samples"].append(
            dict(
                time=n / view["nativeFps"],
                frame=n,
                filmFrame=n * view["filmFps"] // view["nativeFps"],
                image=save(stage, jpg, "jpg"),
                inputOffset=offset,
                inputBytes=len(jpg),
                report=url,
                capsule=frame["capsule_digest"],
                detections=[
                    {k: d[k] for k in ("label", "score", "bounds_subpixel")}
                    for d in frame["detections"]
                ],
            )
        )
    return args, watch


def publish_event(args, candidate, tmp, stage):
    args = [*args, "--approve", candidate["proposal_digest"]]
    first, receipt = record(stage, tmp, "fss-event", args)
    second, repeat = record(stage, tmp, "fss-event", args)
    if (
        first["published_count"] != 1
        or second["already_published_count"] != 1
        or first["authority_sequence"] != second["authority_sequence"]
    ):
        raise ValueError("Publication or idempotent retry could not be verified")
    event = candidate["event_id"]
    audit, custody = record(
        stage, tmp, "fss-custody", ["audit", *SCOPE, "--event-id", event]
    )
    if (
        not audit["all_verified"]
        or audit["event_id"] != event
        or audit["site"] != SCOPE[-1]
        or audit["anchor"]["capsuleSequence"] != first["authority_sequence"]
    ):
        raise ValueError("Native custody audit did not verify every referenced object")
    objects = []
    for obj in audit["objects"]:
        spool = (
            tmp / "deployment/objects/spool/objects" / obj["digest"][7:]
        ).read_bytes()
        payload = spool[-obj["verified_payload_bytes"] :]
        if obj["state"] != "verified" or hashed(payload) != obj["digest"]:
            raise ValueError("Custody bytes differ from immutable payload digest")
        objects.append(dict(digest=obj["digest"], file=save(stage, payload, "bin")))
    _, explain = record(
        stage,
        tmp,
        "fss",
        ["explain", *AGENT, "--event-id", event, "--view", "forensic"],
    )
    return dict(
        status="verified",
        eventId=event,
        publication=receipt,
        repeat=repeat,
        custody=custody,
        sequence=first["authority_sequence"],
        root=audit["ledger_root"],
        objects=objects,
        explain=explain,
    )


def sampled_dwell(view, tmp, stage):
    maximum_gap = round(1_000_000_000 / view["nativeFps"]) + 2_000_000
    result, link = record(
        stage,
        tmp,
        "fss-event",
        [
            "watch",
            *SCOPE,
            "--import-id",
            view["importId"],
            "--interpretation",
            "ycbcr",
            "--zone",
            "image:0,0,160,90",
            "--dwell-for-ns",
            "1000000000",
            "--dwell-min-observations",
            "5",
            "--dwell-max-gap-ns",
            str(maximum_gap),
        ],
    )
    if (
        result["import_identity"] != view["importId"]
        or result["frames_decoded"] != view["frames"]
        or result["continuous_occupancy_certified"]
        or result["absence_certifiable"]
        or result["alert_authorized"]
    ):
        raise ValueError(
            "Sampled dwell proof differs from the source or exceeds what the samples establish"
        )
    longest = max(
        (int(c["minimum_duration_ns"]) for c in result["candidates"]), default=None
    )
    return dict(
        report=link,
        count=result["candidate_count"],
        longestSeconds=longest / 1e9 if longest is not None else None,
        source="Sampled image-zone tracks. At least five observations spanning one second, "
        "with gaps bounded by the sample interval and clock uncertainty. A track can move inside this zone.",
    )


def agent_session(case, ledger, tmp, stage):
    opened, opening = record(
        stage,
        tmp,
        "fss",
        [
            "session",
            "open",
            *AGENT,
            "--mission-text",
            f"Review the {case} recording from the simulated residential cameras.",
            "--objective",
            "Inspect source evidence and preserve uncertainty. Hold physical actions.",
        ],
    )
    session = opened["sessionId"]
    _, orient = record(
        stage,
        tmp,
        "fss",
        ["session", "orient", *AGENT, "--session", session, "--view", "brief"],
    )
    agent = dict(open=opening, orient=orient)
    if ledger["status"] == "verified":
        # Exercise the plan gate on a loopback-only, deliberately ineligible replay.
        # There is no effect commit or network-delivery command in this exporter.
        refusal = execute(
            "fss",
            [
                "plan",
                *AGENT,
                "--session",
                session,
                "--intent",
                "alert",
                "--event-id",
                ledger["eventId"],
                "--relay",
                "127.0.0.1:1",
                "--path",
                "/fss/alert",
                "--plaintext-approval",
                hashed(b"owner approves the plaintext loopback relay"),
                "--deadline-ms",
                "100",
            ],
            tmp,
            refusal="ERR-ALERT-NOT-ELIGIBLE-001",
        )
        agent["notification"] = save(stage, refusal.encode(), "json")
    hand, handoff = record(
        stage,
        tmp,
        "fss",
        [
            "handoff",
            *AGENT,
            "--session",
            session,
            "--note",
            "Review the recorded case and its shared synthetic origin. No physical actions are authorized.",
        ],
    )
    result, resume = record(
        stage,
        tmp,
        "fss",
        ["session", "resume", *AGENT, "--handoff", hand["payload"]["handoffId"]],
    )
    if result["sessionId"] != session or result["outcome"] != "ok":
        raise ValueError("Native workspace handoff did not resume")
    return dict(**agent, handoff=handoff, resume=resume)


def compare_views(rows, views, tmp, stage):
    # Model positions only supply the calibration and a predeclared inspection
    # region. Track entries and associations are computed from decoded film pixels.
    optics = {
        r["camera"]: dict(
            id=r["camera"],
            position=r["sample"]["eye"],
            target=r["sample"]["target"],
            fov=r["sample"]["verticalFovDegrees"],
        )
        for r in rows
    }
    script = """import {imageToGround} from './lib/cameras.js';
        const cameras = JSON.parse(process.argv[1]);
        console.log(JSON.stringify(Object.fromEntries(Object.entries(cameras)
          .map(([k, camera]) => [k, imageToGround(camera, 160, 90)]))));"""
    matrices = json.loads(
        command(["node", "--input-type=module", "-e", script, json.dumps(optics)], WEB)
    )
    x, _, z = rows[0]["sample"]["subjectFoot"]
    zone = [x - 2, z - 2, 4, 4]
    pairs, publish = {}, None
    for first, second in combinations(sorted(views), 2):
        pair = first + "+" + second
        args = [
            "corroborate",
            *SCOPE,
            "--interpretation",
            "ycbcr",
            "--zone",
            "review:" + ",".join(map(str, zone)),
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "1",
            "--failure-domain",
            f"replay:alder={first},{second}",
            "--failure-domain",
            f"clock:alder={first},{second}",
        ]
        for cam in (first, second):
            args += [
                "--camera",
                cam + ":" + views[cam]["importId"],
                "--ground",
                cam + ":" + ",".join(map(str, matrices[cam])),
            ]
        result, link = record(stage, tmp, "fss-event", args)
        if result["effects_authorized"] or any(
            c["policy_action"] != "hold" or c["alert_prepared"]
            for c in result["candidates"]
        ):
            raise ValueError(
                "Native corroboration disagrees with shared replay failure domains"
            )
        pairs[pair] = dict(
            report=link, cameras=[first, second], count=result["candidate_count"]
        )
        if not publish and result["candidates"]:
            publish = (args, result["candidates"][0], pair)
    return dict(
        pairs=pairs,
        zone=zone,
        referenceCamera=rows[0]["camera"],
        referenceSeconds=rows[0]["stillSeconds"],
        projections=matrices,
        method="Four-metre square around the authored reference pose, on the y=0 plane. "
        "FSS matches decoded track entries within one metre and 250 ms. The cameras share a render and clock.",
    ), publish


def belief_experiment(views, tmp, stage):
    observations = []
    for camera, view in views.items():
        person_rows = [
            (d["score"], s)
            for s in view["samples"]
            for d in s["detections"]
            if d["label"] == "person"
        ]
        person_rows += [
            (e["score"], dict(e, report=view["watch"]))
            for e in view["trackLabels"]
            if e["label"] == "person" and e["supports"]
        ]
        if person_rows:
            score, sample = max(person_rows, key=lambda row: row[0])
            observations.append(
                dict(
                    camera=camera,
                    frame=sample["frame"],
                    time=sample["time"],
                    report=sample["report"],
                    score=score,
                    capsule=sample["capsule"],
                )
            )
    observations.sort(key=lambda o: (-o["score"], o["camera"]))
    lab = dict(
        status="illustrative" if observations else "no_person_label",
        hypothesis="A person is visible in these camera recordings.",
        assumptions="This sensitivity exercise uses an illustrative 20% prior and a 600–800 milliban "
        "log-likelihood interval per positive camera. The package scores select observations; "
        "they do not set likelihoods. All cameras share a render and clock. Independent failures "
        "are a counterfactual. These probabilities have no field calibration or effect authority.",
        observations=observations,
        variants=[],
    )
    if not observations:
        return lab
    reference = WEB.parent / "fixtures/fusion_sequence/first.json"
    base = json.loads(reference.read_bytes())["steps"][0]["query"]
    modes = [("single", "One observed camera")]
    if len(observations) > 1:
        modes += [
            ("shared", "Observed cameras with shared failure domains"),
            ("independent", "Counterfactual independent cameras"),
        ]
    for mode, label in modes:
        selected = observations[:1] if mode == "single" else observations
        query = dict(
            base,
            hypothesis="event:visible-person",
            kind="person_presence",
            prior=[-602, -602],
            coverage={
                "state": "degraded",
                "reason": "Synthetic frames without field calibration.",
            },
            evidence=[
                dict(
                    id=o["capsule"],
                    sensor="camera:" + o["camera"],
                    failure_domains=["device:" + o["camera"]]
                    + (["render:alder", "clock:alder"] if mode == "shared" else []),
                    observability="observed",
                    calibration={
                        "generation": "example:alder-illustrative-llr",
                        "llr": [600, 800],
                    },
                )
                for o in selected
            ],
        )
        raw = json.dumps(query, indent=2) + "\n"
        output = execute("fss-fuse", ["--query", "-"], tmp, stdin=raw)
        result = json.loads(output)
        if result["effect_authority"] or result["supporting_clusters"] != (
            len(selected) if mode == "independent" else 1
        ):
            raise ValueError(
                "Native fusion experiment did not preserve source dependence and effect boundaries"
            )
        lab["variants"].append(
            dict(
                id=mode,
                label=label,
                input=save(stage, raw.encode(), "json"),
                report=save(stage, output.encode(), "json"),
                decision=result["decision"]["kind"],
                probabilityPpm=result["probability_ppm"],
                supportingClusters=result["supporting_clusters"],
            )
        )
    return lab


def capture(case, films, rows, stage):
    with TemporaryDirectory(prefix="fss-alder-replay-") as directory:
        tmp = Path(directory)
        shutil.copyfile(MODEL, tmp / "model.fmpk")
        views = {
            row["camera"]: import_film(
                case, row["camera"], films[row["camera"]], tmp, stage, "sha256:" + row["videoSha256"]
            )
            for row in rows
        }
        for row in rows:
            view = views[row["camera"]]
            if (
                view["filmDigest"] != "sha256:" + row["videoSha256"]
                or view["film"] != row["film"]
                or view["filmFps"] != row["fps"]
                or view["filmFrames"] != row["frames"]
            ):
                raise ValueError(
                    "Camera bytes or recording timing differ from the published capture"
                )
        if len({Fraction(v["filmFrames"], v["filmFps"]) for v in views.values()}) != 1:
            raise ValueError("Camera durations disagree in " + case)
        watches = {cam: inspect(v, cam, tmp, stage) for cam, v in views.items()}
        if case == "after-hours":
            for view in views.values():
                view["dwell"] = sampled_dwell(view, tmp, stage)
        associations, choice = compare_views(rows, views, tmp, stage)
        count = sum(v["candidateCount"] for v in views.values())
        samples = [s for v in views.values() for s in v["samples"]]
        labels = sorted({d["label"] for s in samples for d in s["detections"]})
        model_summary = (
            f"The {len(samples)} scheduled frame inspections returned {', '.join(labels)}."
            if labels
            else f"The {len(samples)} scheduled frame inspections returned no class above the package threshold."
        )
        ledger = dict(status="no_candidate")
        if not choice:
            choice = next(
                (
                    (a, w["candidates"][0], cam)
                    for cam, (a, w) in watches.items()
                    if w["candidates"]
                ),
                None,
            )
        if choice:
            args, candidate, source = choice
            ledger = publish_event(args, candidate, tmp, stage)
            ledger.update(
                source=source,
                selection="First native paired candidate when available, "
                "otherwise first image-zone candidate. Camera IDs sorted lexically.",
            )
        agent = agent_session(case, ledger, tmp, stage)
        belief = belief_experiment(views, tmp, stage)
        print(
            f"{case}: {len(views)} lenses, {count} image-zone candidates, ledger {ledger['status']}",
            flush=True,
        )
        return dict(
            views=views,
            belief=belief,
            associations=associations,
            agent=agent,
            ledger=ledger,
            decision=dict(
                summary=f"{len(views)} camera recordings yielded {count} image-zone motion candidate"
                + ("" if count == 1 else "s")
                + ". "
                + model_summary
                + " All views share one synthetic scene and clock.",
                authority="Offline replay. No physical effects authorized.",
                observedLabels=labels,
                effectsAuthorized=False,
                absenceCertified=False,
                independentConfirmation=False,
            ),
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media", type=Path, default=WEB / "public/night-media")
    parser.add_argument("--out", type=Path, default=WEB / "public/night-evidence")
    args = parser.parse_args()
    if hashed(MODEL.read_bytes()) != PIN:
        raise ValueError("Pinned YOLOX package digest differs")
    media, out = args.media.resolve(), args.out.resolve()
    capture_bytes = (media / "capture.json").read_bytes()
    captures = json.loads(capture_bytes)["captures"]
    cases_by_id = {
        c: sorted(
            (r for r in captures if r["caseId"] == c and r["camera"] != "overview"),
            key=lambda r: r["camera"],
        )
        for c in CASES
    }
    films = {
        c: {r["camera"]: media / (c + "-" + r["camera"] + ".mp4") for r in rows}
        for c, rows in cases_by_id.items()
    }
    if any(len(cams) < 2 for cams in films.values()):
        raise ValueError("Each case requires at least two completed camera recordings")
    out.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=out, prefix=".capture-") as directory:
        stage = Path(directory)
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                c: pool.submit(capture, c, cameras, cases_by_id[c], stage)
                for c, cameras in films.items()
            }
            cases = {c: reports.result() for c, reports in futures.items()}
        if capture_bytes != (media / "capture.json").read_bytes() or any(
            hashed(movie.read_bytes()) != cases[c]["views"][cam]["filmDigest"]
            for c, cameras in films.items()
            for cam, movie in cameras.items()
        ):
            raise ValueError(
                "Camera captures changed during analysis; rerun against the completed generation"
            )
        index = dict(
            schema="fss.web.alder_evidence.v1",
            modelDigest=PIN,
            capture="/night-media/capture.json",
            captureDigest=hashed(capture_bytes),
            ledgerScope="Each case has its own isolated native replay deployment and ledger root. "
            "Cameras in that case share the deployment. Ledger sequence numbers are local to each case.",
            sampleSelection="Fixed one-third and two-thirds frame positions in each sampled camera clip.",
            bounds=dict(width=160, height=90, subpixels=256),
            source="Fictional rendered camera views. Capture times use an explicitly shared synthetic epoch.",
            cases=cases,
        )
        objects = out / "objects"
        objects.mkdir(exist_ok=True)
        for path in stage.iterdir():
            path.replace(objects / path.name)
        root = stage / "index.json"
        root.write_text(json.dumps(index, indent=2) + "\n")
        root.replace(out / root.name)


if __name__ == "__main__":
    main()
