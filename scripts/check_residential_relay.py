#!/usr/bin/env python3
"""Exercise an owner-approved notification against a process-owned HTTP listener.

Run python scripts/check_residential_relay.py --bins /path/to/native/release --work /new/private/directory.
The public index and its digest-named receipts appear there after all branches pass.
"""

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Event, Lock, Thread
from time import monotonic_ns

from check_residential_class_fusion import SOURCE_FRAMES, TAKE, checked_json, prepare_camera_replay, sha

DEADLINE_MS = 5000
OBSERVE_DEADLINE_MS = 150
RELAY_PATH = "/fss/alert"


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def object_ref(folder, data):
    digest = sha(data)
    name = f"relay-replay/{digest[7:]}.json"
    assert not any(marker in data for marker in (b"/data/", b"/tmp/", b"/home/"))
    (folder / name).write_bytes(data)
    return {"path": name, "sha256": digest}


@contextmanager
def listener(port):
    records = []
    lock = Lock()
    acknowledge = Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            with lock:
                # Count a partially read or malformed request too. It must fail the drill.
                records.append((b"", {"path": self.path, "response_disposition": "incomplete_post"}))
                self.connection.settimeout(3)
                length = int(self.headers["Content-Length"])
                if not 0 < length <= 4096:
                    raise ValueError("unexpected alert body length")
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("incomplete POST")
                if self.path != RELAY_PATH:
                    self.send_error(404)
                    disposition, status = "unexpected_request", 404
                elif acknowledge.is_set():
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    self.wfile.flush()
                    disposition, status = "http_200_sent", 200
                else:
                    self.close_connection = True
                    disposition, status = "connection_closed_without_response", None
                records[-1] = (
                    body,
                    {
                        "path": self.path,
                        "body_bytes": length,
                        "body_sha256": sha(body),
                        "idempotency_key": self.headers.get("Idempotency-Key"),
                        "response_disposition": disposition,
                        "response_status": status,
                    },
                )

    def snapshot():
        with lock:
            return list(records)

    with HTTPServer(("127.0.0.1", port), Handler) as server:
        done = Event()
        server.timeout = 0.1

        def serve():
            while not done.is_set():
                server.handle_request()

        worker = Thread(target=serve)
        worker.start()
        try:
            yield f"127.0.0.1:{server.server_port}", snapshot, acknowledge
        finally:
            done.set()
            worker.join()


def prepare_events(bins, work):
    seed = work / "source"
    seed.mkdir()
    _, _, _, command = prepare_camera_replay(bins, seed)
    fusion = json.loads((TAKE / "fusion-replay.json").read_bytes())
    original = checked_json(TAKE / fusion["report"]["path"], fusion["report"]["sha256"])
    assert fusion["source_frames"] == SOURCE_FRAMES
    for c in fusion["cameras"]:
        assert sha((seed / (c["camera"] + ".mp4")).read_bytes()) == c["fixture_sha256"]
    events = {}
    for kind in ("held", "eligible"):
        cwd = work / kind
        cwd.mkdir()
        shutil.copytree(seed / "deployment", cwd / "deployment")
        shutil.copyfile(seed / "model.fmpk", cwd / "model.fmpk")
        args = command.copy()
        if kind == "eligible":
            # This counterfactual changes only the declared failure domains.
            index = args.index("--failure-domain")
            assert args[index + 1] == "replay:render=entry,porch"
            del args[index : index + 2]
        base = json.loads(subprocess.check_output([bins / "fss-event", *args], cwd=cwd))
        if kind == "held":
            assert base == {k: v for k, v in original.items() if k != "calibrated_class_advice"}
        (candidate,) = base["candidates"]
        raw = subprocess.check_output(
            [bins / "fss-event", *args, "--approve", candidate["proposal_digest"]], cwd=cwd
        )
        published = json.loads(raw)
        (event,) = published["candidates"]
        assert published["published_count"] == 1 and event["event_id"] == candidate["event_id"]
        assert (event["event_state"], event["policy_action"]) == (
            ("witnessed", "hold") if kind == "held" else ("corroborated", "prepare_alert")
        )
        events[kind] = dict(
            id=event["event_id"],
            state=event["event_state"],
            policy_action=event["policy_action"],
            proposal_digest=event["proposal_digest"],
            revision_digest=event["event_revision_digest"],
            publication=object_ref(work, raw),
        )
    return fusion, events


def branch(name, event, work, bins, address, snapshot):
    directory = work / name / "deployment"
    agent = ["--json", "--root", str(directory.resolve())]
    first = len(snapshot())
    observations = []
    steps = []

    def call(phase, args):
        before = len(snapshot())
        start = monotonic_ns()
        result = subprocess.run([bins / "fss", *args], cwd=directory, stdout=subprocess.PIPE)
        elapsed_us = (monotonic_ns() - start) // 1000
        envelope = json.loads(result.stdout)
        payload = envelope.get("payload") or {}
        native = object_ref(work, result.stdout)
        received = snapshot()[before:]
        print(
            f"{name}.{phase}  exit={result.returncode}  outcome={envelope['outcome']}  "
            f"state={payload.get('state')}  observed_posts={len(received)}",
            file=sys.stderr,
        )
        steps.append(
            dict(
                phase=phase,
                outcome=envelope["outcome"],
                error_id=envelope.get("errorId"),
                effect_state=payload.get("state"),
                requests_received=len(received),
                exit_code=result.returncode,
                native=native,
            )
        )
        observations.append(
            dict(
                phase=phase,
                native_sha256=native["sha256"],
                elapsed_us=elapsed_us,
                requests_before=before - first,
                requests_after=before - first + len(received),
                received=[dict(row, body=object_ref(work, body)) for body, row in received],
            )
        )
        return envelope

    opened = call(
        "open",
        [
            "session",
            "open",
            *agent,
            "--mission-text",
            "Review the staged residential alert.",
            "--objective",
            "Notify the owned loopback relay only after approval.",
            "--view",
            "brief",
        ],
    )
    assert opened["outcome"] == "ok", opened
    plan = [
        "plan",
        *agent,
        "--session",
        opened["sessionId"],
        "--intent",
        "alert",
        "--event-id",
        event["id"],
        "--relay",
        address,
        "--path",
        RELAY_PATH,
        "--plaintext-approval",
        sha(b"owner approves this isolated plaintext loopback exercise"),
        "--deadline-ms",
        str(DEADLINE_MS),
    ]
    proposed = call("plan", plan)
    if name == "held":
        assert proposed["outcome"] == "refused" and proposed.get("errorId") == "ERR-ALERT-NOT-ELIGIBLE-001", (
            proposed
        )
        assert len(snapshot()) == first
    else:
        assert proposed["outcome"] == "ok", proposed
        plan_id = proposed["payload"]["planId"]
        prepared = call("prepare", [*plan, "--approve", proposed["proofPointers"][2]])
        assert prepared["outcome"] == "ok" and len(snapshot()) == first, prepared
        dispatch = ["commit", *agent, "--plan", plan_id, "--approve", prepared["proofPointers"][-1]]
        sent = call("dispatch", dispatch)
        assert len(snapshot()) == first + 1, sent
        expected = "adapter_accepted" if name == "accepted" else "indeterminate"
        assert sent["payload"]["state"] == expected, sent
        body, wire = snapshot()[first]
        receipt, request = sent["payload"], json.loads(body)
        assert receipt["schema"] == "fss.operation_receipt.v1" and receipt["effectClass"] == "alert.dispatch"
        assert wire["path"] == RELAY_PATH and request["schema"] == "fss.webhook-alert.v1"
        assert sha(receipt["idempotencyKey"].encode())[7:] == wire["idempotency_key"]
        assert sha(receipt["operationId"].encode())[7:] == request["operation_sha256"]
        assert "sha256:" + request["event_revision_sha256"] == event["revision_digest"]
        assert "sha256:" + request["request_sha256"] == receipt["requestDigest"]
        assert "sha256:" + request["precondition_sha256"] == receipt["preconditionDigest"]
        # A fresh CLI process opens the durable operation for this repeated approval.
        journal = (directory / "effects/journal.fssj").read_bytes()
        retry = call("repeat", dispatch)
        inspect = call(
            "inspect",
            ["wait", *agent, "--operation", receipt["operationId"], "--deadline-ms", str(OBSERVE_DEADLINE_MS)],
        )
        for again in (retry, inspect):
            assert again["payload"] == receipt, (again["payload"], receipt)
        assert len(snapshot()) == first + 1 and (directory / "effects/journal.fssj").read_bytes() == journal
        if name == "lost-ack":
            for response in (sent, retry):
                assert (
                    response["outcome"] == "indeterminate"
                    and response["errorId"] == "ERR-EFFECT-INDETERMINATE-001"
                )
            assert sent["executionBoundary"]["possiblyOccurred"] and wire["response_status"] is None
        else:
            assert sent["outcome"] == retry["outcome"] == "ok" and wire["response_status"] == 200
        assert inspect["outcome"] == "partial" and inspect["errorId"] == "ERR-OP-TIMEOUT-001"
        assert [s["requests_received"] for s in steps] == [0, 0, 0, 1, 0, 0]
    transcript = object_ref(
        work,
        encode(
            dict(
                schema="fss.website.relay_listener.v1",
                branch=name,
                timing="Monotonic microseconds around each completed native process invocation.",
                observations=observations,
            )
        ),
    )
    received = snapshot()[first:]
    wire = received[0][1] if received else {}
    return dict(
        id=name,
        event=event,
        steps=steps,
        listener=transcript,
        relay=dict(
            requests_received=len(received),
            response_disposition=wire.get("response_disposition"),
            response_status=wire.get("response_status"),
            body_sha256=wire.get("body_sha256"),
        ),
    )


def qualify(bins, work, port):
    (work / "relay-replay").mkdir()
    fusion, events = prepare_events(bins, work)
    with listener(port) as (address, snapshot, acknowledge):
        branches = []
        for name in ("held", "accepted", "lost-ack"):
            if name == "lost-ack":
                acknowledge.clear()
            else:
                acknowledge.set()
            if name != "held":
                (work / name).mkdir()
                shutil.copytree(work / "eligible/deployment", work / name / "deployment")
            branches.append(
                branch(name, events["held" if name == "held" else "eligible"], work, bins, address, snapshot)
            )
        accepted, ambiguous = snapshot()
        assert accepted[0] == ambiguous[0]
        assert accepted[1]["idempotency_key"] == ambiguous[1]["idempotency_key"]
    source = dict(
        fusion_replay_sha256=sha((TAKE / "fusion-replay.json").read_bytes()),
        report_sha256=fusion["report"]["sha256"],
        source_frames=SOURCE_FRAMES,
        cameras=[
            {k: c[k] for k in ("camera", "source_frame", "frame", "source_film_sha256", "fixture_sha256")}
            for c in fusion["cameras"]
        ],
    )
    result = dict(
        schema="fss.website.residential_relay.v1",
        source=source,
        deadline_ms=DEADLINE_MS,
        observe_deadline_ms=OBSERVE_DEADLINE_MS,
        branches=branches,
        scope="The local listener records requests from native processes. Both camera views come from one renderer. The two eligible runs declare separate devices and start from copies of the same published event. The relay receives the same request at the same endpoint in both runs. Only its response changes. All requests remain on loopback.",
    )
    (work / "relay-replay.json").write_bytes(encode(result))
    print([(b["id"], b["relay"]["requests_received"], b["steps"][-1]["outcome"]) for b in branches])


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Python assertions must be enabled.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bins", type=Path, required=True)
    parser.add_argument("--work", type=Path, help="new directory to retain the receipts")
    parser.add_argument("--port", type=int, default=0, help="loopback port (default: kernel assigned)")
    opt = parser.parse_args()
    if opt.work:
        opt.work.mkdir()
        qualify(opt.bins.resolve(), opt.work.resolve(), opt.port)
    else:
        with tempfile.TemporaryDirectory(prefix="fss-notification-replay-") as tmp:
            qualify(opt.bins.resolve(), Path(tmp), opt.port)
