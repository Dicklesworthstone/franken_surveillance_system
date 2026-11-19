// Reduce a single UV-seamed material primitive from the source tree or prop.
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { MeshoptSimplifier } from "three/addons/libs/meshopt_simplifier.module.js";
const [source, dest] = process.argv.slice(2);
const bytes = readFileSync(source),
  view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const vertices = view.getUint32(0, true),
  count = view.getUint32(4, true),
  target = view.getUint32(8, true);
const cache = join(tmpdir(), "fss-estate-lod-" + userInfo().uid);
mkdirSync(cache, { recursive: true, mode: 0o700 });
const id = createHash("sha256")
  .update("metric-meshopt-v2")
  .update(bytes)
  .digest("hex");
const hit = join(cache, id);
if (existsSync(hit)) {
  copyFileSync(hit, dest);
} else {
  const xyz = new Float32Array(
    bytes.buffer,
    bytes.byteOffset + 12,
    3 * vertices,
  );
  const uv = new Float32Array(
    bytes.buffer,
    bytes.byteOffset + 12 + 12 * vertices,
    2 * vertices,
  );
  const indices = new Uint32Array(
    bytes.buffer,
    bytes.byteOffset + 12 + 20 * vertices,
    count,
  );
  await MeshoptSimplifier.ready;
  let out;
  if (count > 240000) {
    [out] = MeshoptSimplifier.simplifySloppy(
      indices,
      xyz,
      3,
      null,
      target,
      0.18,
    );
  }
  if (
    !out ||
    out.length < Math.min(target / 4, 768) ||
    out.length > target * 1.5
  ) {
    [out] = MeshoptSimplifier.simplifyWithAttributes(
      indices,
      xyz,
      3,
      uv,
      2,
      [0.006, 0.006],
      null,
      target,
      0.2,
      ["Permissive", "Prune"],
    );
  }
  if (!out.length) throw Error("Source material lost every face");
  writeFileSync(
    hit + "." + process.pid,
    Buffer.from(out.buffer, out.byteOffset, out.byteLength),
  );
  renameSync(hit + "." + process.pid, hit);
  copyFileSync(hit, dest);
}
