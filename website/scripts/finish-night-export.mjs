// Next copies the entire historical public fixture archive. Only the current estate belongs in the deployed site.
import { mkdir, mkdtemp, readdir, rename, stat } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
const web = fileURLToPath(new URL("../", import.meta.url));
const live = new Set(["estate", "night-evidence", "night-media"]);
const out = join(web, "out");
const retired = (await readdir(join(web, "public"))).filter(
  (name) => !live.has(name),
);
await mkdir(join(web, ".next", "retired"), { recursive: true });
const archive = await mkdtemp(join(web, ".next", "retired", "export-"));
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
