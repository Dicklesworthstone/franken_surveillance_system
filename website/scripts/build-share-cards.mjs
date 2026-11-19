// Prerender each social image once. Next's page metadata, gallery and image routes then reuse the same PNG bytes.
import { build } from "esbuild";
import { mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
const root = process.cwd(),
  directory = join(root, ".next", "cache", "estate-covers");
await mkdir(directory, { recursive: true });
const output = join(directory, "render.cjs");
await build({
  entryPoints: ["lib/share-card.jsx"],
  outfile: output,
  platform: "node",
  format: "cjs",
  bundle: true,
  packages: "external",
  jsx: "automatic",
});
const { imageMeta } = createRequire(import.meta.url)(output);
const { exhibits } = await import("../lib/night/catalog.js");
for (const id of Object.keys(exhibits))
  await Promise.all([imageMeta(id, 630), imageMeta(id, 600)]);
console.log(
  "Generated social images for " + Object.keys(exhibits).length + " pages.",
);
