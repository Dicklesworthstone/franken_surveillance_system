"""Exercise the evidence driver's per-command observations on its real loopback relay."""

from http.client import HTTPConnection
import os
from pathlib import Path
from runpy import run_path
from shutil import copytree
from tempfile import TemporaryDirectory
import unittest

driver = run_path(str(Path(__file__).with_name("watch-evidence.py")))


class AlertRequests(unittest.TestCase):
    def test_first_dispatch_and_retry_have_independent_counts(self):
        relay = driver["Relay"]()
        self.addCleanup(lambda: self.assertFalse(relay.thread.is_alive()))
        self.addCleanup(relay.close)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            run = driver["Run"](root, root, root, "site:alert-test")

            def post(count, body):
                for _ in range(count):
                    client = HTTPConnection(relay.address, timeout=2)
                    try:
                        client.request("POST", "/fss/alert", body=body, headers={"Content-Type": "application/json"})
                        self.assertEqual(client.getresponse().status, 200)
                    finally:
                        client.close()

            post(1, b'{"earlier":"outside both attempts"}')
            for first, retry in ((2, 0), (0, 1), (1, 0), (1, 1), (0, 0)):
                with self.subTest(first=first, retry=retry):
                    alert = {}
                    observe = driver["observe_relay_call"]
                    observe(run, relay, alert, "dispatch", post, first, b'{"phase":"dispatch"}')
                    self.assertNotIn("resend_on_retry", alert)
                    observe(run, relay, alert, "retry", post, retry, b'{"phase":"retry"}')
                    self.assertEqual(alert["dispatch_requests_received"], first)
                    self.assertEqual(alert["retry_requests_received"], retry)
                    self.assertEqual(alert["requests_received"], first + retry)
                    self.assertIs(alert["resend_on_retry"], retry > 0)
                    if first or retry:
                        expected = b'{"phase":"dispatch"}' if first else b'{"phase":"retry"}'
                        self.assertEqual((root / Path(alert["request"]).name).read_bytes(), expected)
                    else:
                        self.assertNotIn("request", alert)

    @unittest.skipUnless(os.environ.get("FSS_BIN_DIR"), "set FSS_BIN_DIR to run the native CLI integration")
    def test_native_agent_and_operator_on_separate_copies_of_one_corroborated_event(self):
        from PIL import Image

        bins = Path(os.environ["FSS_BIN_DIR"]).resolve()
        with TemporaryDirectory() as directory:
            work = Path(directory)
            objects = work / "objects"
            objects.mkdir()
            run = driver["Run"](bins, work, objects, "site:alert-test")
            camera_args = []
            # Same mirrored moving rectangles and ground maps as corroborate_cli_contract.rs.
            for side in ("east", "west"):
                film = work / (side + ".mjpeg")
                with film.open("wb") as stream:
                    for frame in range(14):
                        image = Image.new("L", (96, 48), 40)
                        if frame >= 3:
                            x = (frame - 3) * 8 if side == "east" else 80 - (frame - 3) * 8
                            image.paste(220, (x, 8, x + 16, 24))
                        image.save(stream, "JPEG", quality=90)
                imported = run.call("fss-file", ["import", *run.root, "--input", film, "--sensor", "sensor:" + side,
                                    "--stream", "stream:" + side, "--receive-time-ns", "10000000000000",
                                    "--capture-start-ns", "1000000000", "--capture-uncertainty-ns", "1000000",
                                    "--assumed-fps", "10", "--media-format", "mjpeg"])
                self.assertEqual(imported.returncode, 0, imported.stderr)
                identity = next(row.split("=", 1)[1] for row in imported.stdout.splitlines()
                                if row.startswith("import_identity="))
                camera_args.extend(["--camera", side + ":" + identity])
            command = ["corroborate", *run.root, *camera_args, "--ground", "east:1,0,0,0,1,0,0,0,1",
                       "--ground", "west:-1,0,96,0,1,0,0,0,1", "--zone", "door:56,0,40,48",
                       "--interpretation", "gray", "--time-gate-ns", "250000000", "--distance-gate", "16"]
            proposed, _, result = run.json("fss-event", command)
            self.assertEqual(result.returncode, 0, result.stderr)
            proposal = proposed["candidates"][0]["proposal_digest"]
            published, _, result = run.json("fss-event", [*command, "--approve", proposal])
            self.assertEqual(result.returncode, 0, result.stderr)
            event = published["candidates"][0]["event_id"]
            operator_work = work / "operator"
            copytree(work / "deployment", operator_work / "deployment")
            operator_run = driver["Run"](bins, operator_work, objects, run.site)
            relay = driver["Relay"]()
            self.addCleanup(relay.close)
            session = driver["agent_session"](run, "alert-test", None, event, relay)
            agent = session["facts"]["alert"]
            operator = driver["operator_alert"](operator_run, event, relay)
            for alert in (agent, operator):
                self.assertEqual(alert.get("dispatch_requests_received"), 1, alert)
                self.assertEqual(alert["retry_requests_received"], 0)
                self.assertEqual(alert["requests_received"], 1)
                self.assertIs(alert["resend_on_retry"], False)
                self.assertEqual(alert["effect_state"], "adapter_accepted")
                self.assertEqual(alert["retry_outcome"], "ok")
            self.assertEqual(agent["reconciled_state"], "verified")
            self.assertEqual(agent["attestation_source"], "evidence_script_loopback_receipt")
            self.assertEqual(operator["delivery_claim"], "relay_acceptance_only")
            self.assertEqual(operator["retry_stage"], "already_dispatched")
            self.assertEqual(len(relay.requests), 2)
            refused = driver["operator_alert"](operator_run, "event:absent", relay)
            self.assertEqual(refused["preview_outcome"], "refused", refused)
            self.assertNotIn("retry_requests_received", refused)
            self.assertEqual(len(relay.requests), 2)


if __name__ == "__main__":
    unittest.main()
