import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { AlertRun, MeasuredSummary } from "../components/site/Measured.jsx";
import { distill } from "../lib/watch/native.js";
import { readRelayReplay } from "../lib/watch/relay-replay.mjs";

const raw = JSON.parse(readFileSync(new URL("../public/watch/intrusion/native.json", import.meta.url)));
const historical = distill(raw);

function render(native) {
  return [AlertRun, MeasuredSummary].map((View) => renderToStaticMarkup(<View native={native} />));
}

test("the historical alert keeps its provenance when the separate relay comparison is missing", () => {
  const page = renderToStaticMarkup(<AlertRun native={historical} />);
  assert.match(page, /No separate retry and acknowledgement comparison was published/);
  assert.match(page, /Alert calls in the original five-camera run/);
  assert.doesNotMatch(page, /data-relay-case|relay-replay\.json/);
});

test("the published relay comparison checks native outcomes, receiver identity and the actual POST bytes", async (t) => {
  const take = fileURLToPath(new URL("../public/watch/intrusion/", import.meta.url));
  const sceneBytes = await readFile(join(take, "scene.json"));
  const folder = await mkdtemp(join(tmpdir(), "fss-relay-comparison-"));
  t.after(() => rm(folder, { recursive: true, force: true }));
  assert.equal(readRelayReplay(folder, sceneBytes), null);
  await symlink(join(take, "fusion-replay"), join(folder, "fusion-replay"));
  await cp(join(take, "fusion-replay.json"), join(folder, "fusion-replay.json"));
  await cp(join(take, "relay-replay"), join(folder, "relay-replay"), { recursive: true });
  const original = await readFile(join(take, "relay-replay.json"));
  const publication = join(folder, "relay-replay.json");
  await writeFile(publication, original);
  const verified = readRelayReplay(folder, sceneBytes);
  const accepted = verified.branches.find((b) => b.id === "accepted");
  const lost = verified.branches.find((b) => b.id === "lost-ack");
  assert.equal(accepted.relay.response_status, 200);
  assert.equal(lost.relay.response_disposition, "connection_closed_without_response");
  assert.equal(lost.steps.find((s) => s.phase === "inspect").effect_state, "indeterminate");
  const raw = JSON.parse(original);
  const acceptedIndex = raw.branches.findIndex((b) => b.id === "accepted");
  raw.branches[acceptedIndex].listener = lost.listener;
  await writeFile(publication, JSON.stringify(raw));
  assert.throws(() => readRelayReplay(folder, sceneBytes), /listener branch/);
  raw.branches[acceptedIndex].listener = accepted.listener;
  raw.branches[acceptedIndex].steps.find((s) => s.phase === "repeat").requests_received += 1;
  await writeFile(publication, JSON.stringify(raw));
  assert.throws(() => readRelayReplay(folder, sceneBytes), /requests observed/);
  await writeFile(publication, Buffer.concat([original, Buffer.from("\n")]));
  assert.throws(() => readRelayReplay(folder, sceneBytes), /qualified capture/);
  await writeFile(publication, original);
  const nativeCall = accepted.steps.find((step) => step.phase === "dispatch").native;
  await writeFile(join(folder, lost.receivedBody.path), await readFile(join(folder, nativeCall.path)));
  assert.throws(() => readRelayReplay(folder, sceneBytes), /object differs/);
});

test("the retained run distinguishes the script’s receipt from delivery to a person", () => {
  const { facts, calls } = raw.agent;
  const retryCall = calls.find((row) => row.call.startsWith("commit again"));
  const report = JSON.parse(readFileSync(new URL("../public/watch/intrusion/" + retryCall.envelope, import.meta.url)));
  assert.equal(report.payload.operationId, facts.alert.operation);
  for (const page of render(historical)) {
    assert.match(page, /The script attested to its own relay receipt/);
    assert.match(page, /No person was notified/);
    assert.doesNotMatch(page, /The owner (attested|approved)|undefined|null requests/);
    if (!Object.hasOwn(facts.alert, "retry_requests_received")) {
      assert.match(page, /recorded 1 request in total/);
      assert.match(page, /no separate request count for the retry/);
    }
  }
});

test("an explicit refusal and a missing outcome never imply sending or a successful preview", () => {
  for (const outcome of ["refused", null]) {
    const alert = { stage: "proposed", outcome };
    for (const page of render({ ...historical, alert, single: null, calls: [] })) {
      assert.match(page, outcome ? /Agent alert preview returned refused/ : /no recorded outcome/);
      assert.match(page, /relay request count is unknown/);
      assert.doesNotMatch(page, /alert sent|nothing resent|no more requests|Nothing was sent|script attested|0 requests/);
    }
  }
  for (const page of render({ ...historical, alert: null, single: { outcome: "refused" }, calls: [] })) {
    assert.match(page, /single-camera alert preview returned refused/);
  }
});

test("a later preparation refusal takes precedence over a successful historical preview", () => {
  const calls = [
    { call: "plan alert (preview)", outcome: "ok" },
    { call: "plan alert (owner approves the plan)", outcome: "refused" },
  ];
  const alert = { stage: "proposed", outcome: "ok" };
  for (const page of render({ ...historical, calls, alert })) {
    assert.match(page, /Agent alert preparation returned refused/);
    assert.doesNotMatch(page, /dispatch returned ok|owner approved|owner attested/);
  }
});

test("the previous effect state in a refused reconciliation does not become an attestation", () => {
  const alert = { stage: "dispatched", requests_received: 1, reconciled_state: "adapter_accepted",
                  relay: "loopback, owned by this script" };
  const calls = [{ call: "commit reconcile (owner attests)", outcome: "refused" }];
  for (const page of render({ ...historical, alert, calls })) {
    assert.match(page, /Reconciliation returned refused/);
    assert.doesNotMatch(page, /script attested|Reconciliation recorded|recorded reconciliation state/i);
  }
});

test("agent and operator observations stay distinct, including retry-only receipt", () => {
  const alert = {
    stage: "proposed", outcome: "refused",
    operator_fallback: {
      stage: "dispatched", dispatch_outcome: "ok", delivery_claim: "indeterminate", retry_outcome: "partial",
      dispatch_requests_received: 0, retry_requests_received: 1, requests_received: 1, resend_on_retry: true,
    },
  };
  for (const page of render({ ...historical, alert, calls: [] })) {
    assert.match(page, /Agent alert preview returned refused/);
    assert.match(page, /Operator alert dispatch returned ok/);
    assert.match(page, /first dispatch attempt the loopback relay received 0 requests/);
    assert.match(page, /During the retry the relay received 1 request/);
    assert.match(page, /operator command recorded indeterminate/);
    assert.match(page, /operator retry returned partial/i);
    assert.doesNotMatch(page, /a second request|script attested/);
  }
});

test("the legacy resend flag cannot substitute for a missing phase count on either path", () => {
  for (const resend_on_retry of [false, true]) {
    const alert = { stage: "dispatched", requests_received: 2, resend_on_retry };
    for (const record of [alert, { stage: "proposed", outcome: "refused", operator_fallback: alert }]) {
      for (const page of render({ ...historical, alert: record, calls: [] })) {
        assert.match(page, /recorded 2 requests in total/);
        assert.match(page, /no separate request count for the retry/);
        assert.doesNotMatch(page, /During the retry the relay received/);
      }
    }
  }
});
