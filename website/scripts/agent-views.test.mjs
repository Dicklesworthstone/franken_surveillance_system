// The page's copy of the agent views must say exactly what the registry says.
//   node --test scripts/agent-views.test.mjs
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { AGENT_VIEWS, HYDRATION_LEVELS } from "../lib/watch/agent-views.mjs";

const registry = new URL("../../architecture/agent_views.json", import.meta.url);
const hydration = new URL("../../architecture/semantic_hydration.json", import.meta.url);

test("the page's hydration ladder matches architecture/semantic_hydration.json", (t) => {
  if (!existsSync(hydration)) return t.skip("architecture/semantic_hydration.json is not in this checkout");
  const { levels } = JSON.parse(readFileSync(hydration, "utf8"));
  assert.deepEqual(
    HYDRATION_LEVELS.map(({ id, meaning, raw }) => ({ id, meaning, raw })),
    levels.map((l) => ({ id: l.id, meaning: l.meaning, raw: l.raw_private_media })),
  );
});

test("the page's agent views match architecture/agent_views.json", (t) => {
  // A checkout of the website alone has no registry to compare against.
  if (!existsSync(registry)) return t.skip("architecture/agent_views.json is not in this checkout");
  const { views } = JSON.parse(readFileSync(registry, "utf8"));
  assert.deepEqual(
    AGENT_VIEWS,
    views.map((v) => ({
      id: v.id,
      name: v.name,
      owner: v.owner,
      purpose: v.purpose,
      target: v.targetTokens,
      max: v.maximumTokens,
      sections: v.requiredSections,
    })),
  );
});
