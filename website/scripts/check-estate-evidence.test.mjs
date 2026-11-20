import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("a valid report from another incident cannot complete an evidence bundle", async (t) => {
  const publicDir = fileURLToPath(new URL("../public/", import.meta.url));
  const verifier = fileURLToPath(new URL("./check-estate-evidence.mjs", import.meta.url));
  const fixture = await mkdtemp(join(tmpdir(), "fss-case-bindings-"));
  t.after(() => rm(fixture, { recursive: true, force: true }));
  await mkdir(join(fixture, "night-evidence"));
  for (const path of ["night-evidence/objects", "night-media"])
    await symlink(join(publicDir, path), join(fixture, path), "dir");
  const index = "night-evidence/index.json";
  const source = await readFile(join(publicDir, index), "utf8");
  async function verify(change) {
    const bundle = JSON.parse(source);
    if (change) change(bundle.cases["after-hours"], bundle.cases.delivery);
    await writeFile(join(fixture, index), JSON.stringify(bundle));
    const result = spawnSync(process.execPath, [verifier, fixture], { encoding: "utf8" });
    assert.ifError(result.error);
    assert.equal(result.status, change ? 1 : 0, result.stderr);
    if (change) assert.match(result.stderr, /AssertionError/);
  }
  await verify();
  await verify((incident, delivery) => {
    incident.ledger = delivery.ledger;
    incident.agent = delivery.agent;
  });
  await verify((incident, delivery) => { incident.ledger.explain = delivery.ledger.explain; });
  await verify((incident) => { delete incident.associations.pairs["entry+porch"]; });
  await verify((incident) => { incident.decision.observedLabels.push("unobserved"); });
});
