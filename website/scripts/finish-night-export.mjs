// Next copies the entire historical public fixture archive. Only the media the home page plays belongs in the deployed site.
import { copyFile, mkdir, mkdtemp, readFile, readdir, rename, stat } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyWatchTake } from "./verify-watch-evidence.mjs";
import { verifyRenderedTake } from "../lib/watch/retained.mjs";
import { readDeliveryDropout } from "../lib/watch/delivery-dropout.mjs";
import assert from "node:assert/strict";
const web = fileURLToPath(new URL("../", import.meta.url));
const live = new Set(["watch"]);
const out = join(web, "out");
const take = join(out, "watch", "intrusion");
const verified = verifyWatchTake(take);
const html = await readFile(join(out, "index.html"), "utf8");
verifyRenderedTake(html, verified.renderDigest);
const dropout = readDeliveryDropout(join(out, "watch/delivery-dropout"), join(take, "scene.json"));
const panels = (html.match(/<section\b[^>]*>/g) ?? []).filter(tag => tag.includes(' id="delivery-dropout"'));
assert.ok(panels.length === 1 && panels[0].includes(` data-dropout-digest="${dropout.digest}"`),
  "Rendered delivery replay and exported recording belong to different generations");
console.log("Verified", verified.cameras, "replay cameras and", verified.frames, "native frames in the export.");
const retired = (await readdir(join(web, "public"))).filter(
  (name) => !live.has(name),
);
await mkdir(join(web, ".next", "retired"), { recursive: true });
const archive = await mkdtemp(join(web, ".next", "retired", "export-"));
if (verified.retainedObjects) {
  const objects = join(take, "native", "objects");
  for (const name of await readdir(objects))
    if (!verified.retainedObjects.has("native/objects/" + name))
      await rename(join(objects, name), join(archive, name));
}
if (verified.detectorBoxes)
  await copyFile(join(take, verified.detectorBoxes), join(take, "native-boxes.json"));
for (const name of await readdir(take))
  if (name.startsWith(".native-publish-")) await rename(join(take, name), join(archive, name));
for (const name of retired) await rename(join(out, name), join(archive, name));
async function check(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) await check(path);
    else if ((await stat(path)).size > 25 * 1024 * 1024)
      throw Error("Cloudflare static asset exceeds 25 MiB: " + path);
  }
}
await check(out);
