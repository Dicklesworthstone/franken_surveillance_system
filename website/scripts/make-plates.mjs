// Makes the web-sized pictures behind the chapter openers, and the camera thumbnails,
// from renders already in the repository. No picture is drawn or retouched: each is a
// resize of one source, and plates.json records the SHA-256 of both. The page's grain
// tile is the one file made here rather than resized.
//
//   node scripts/make-plates.mjs
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const root = fileURLToPath(new URL("../public/", import.meta.url));
const out = join(root, "watch", "plates");
const PLATES = {
  gate: "watch/intrusion/stills/watch.jpg",
  lawn: "watch/intrusion/stills/floods.jpg",
  drive: "watch/intrusion/stills/drive.jpg",
  door: "watch/intrusion/stills/door.jpg",
  dusk: "estate/stills/overview.jpg",
  house: "estate/hero.jpg",
};
const CAMERAS = ["gate", "driveway", "doorbell", "porch", "entry"];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

await mkdir(out, { recursive: true });
const receipt = { schema: "fss.site.plates.v1", made_by: "website/scripts/make-plates.mjs", files: {} };
async function emit(name, source, width, quality) {
  const bytes = await readFile(join(root, source));
  const buffer = await sharp(bytes).resize({ width, withoutEnlargement: true }).webp({ quality, effort: 6 }).toBuffer();
  await writeFile(join(out, name), buffer);
  receipt.files[name] = { source, source_sha256: sha256(bytes), sha256: sha256(buffer), bytes: buffer.length };
  console.log(name, buffer.length);
}
// The page tells the browser each width, so a file is never named for more than its source has.
for (const [name, source] of Object.entries(PLATES)) {
  const { width: full } = await sharp(await readFile(join(root, source))).metadata();
  for (const [width, quality] of [[960, 70], [1600, 72], [Math.min(2400, full), 70]])
    await emit(`${name}-${width}.webp`, source, width, quality);
}
for (const id of CAMERAS) await emit(`cam-${id}.webp`, `watch/intrusion/${id}.jpg`, 640, 74);
await emit("model.webp", "watch/intrusion/twin/axo_lit.jpg", 1600, 78);

// The page's grain: one tile of noise in eight greys, nearly transparent. Seeded, so it is the same every time.
const size = 96;
const tile = Buffer.alloc(size * size * 4);
let seed = 20261114;
for (let i = 0; i < size * size; i++) {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  tile.fill(Math.round(((seed >>> 24) / 255) * 7) * 36, i * 4, i * 4 + 3);
  tile[i * 4 + 3] = 7;
}
const grain = await sharp(tile, { raw: { width: size, height: size, channels: 4 } }).png({ palette: true, colours: 8 }).toBuffer();
await writeFile(join(out, "grain.png"), grain);
receipt.files["grain.png"] = { source: null, sha256: sha256(grain), bytes: grain.length };
await writeFile(join(out, "plates.json"), JSON.stringify(receipt, null, 2) + "\n");
