// From website/: node scripts/render-night-estate.mjs. A local Chromium and FFmpeg are required.
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { chromium } from "playwright-core";
import { registeredTakes } from "../lib/night-scene/takes.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const publicDir =
  process.argv.includes("--preview") && process.env.FSS_PREVIEW_PUBLIC
    ? resolve(process.env.FSS_PREVIEW_PUBLIC)
    : join(root, "public");
const filmDir = join(publicDir, "night-media");
const width = 960,
  height = 540,
  fps = 24;
const sha = (data) => createHash("sha256").update(data).digest("hex");
const sources = new Map();
const inputs = {};
async function freezeSource(url) {
  if (sources.has(url)) return;
  if (!/^\/(estate|night-media)\/[\w./-]+$/.test(url) || url.includes(".."))
    throw Error("Unexpected asset URL " + url);
  const bytes = await readFile(join(publicDir, url));
  sources.set(url, bytes);
  inputs[url] = { sha256: sha(bytes), bytes: bytes.length };
  if (url === "/night-media/plates/index.json") {
    const plate = JSON.parse(bytes);
    if (
      plate.glbSha256 !== inputs["/estate/estate.glb"].sha256 ||
      plate.planSha256 !== inputs["/estate/estate.json"].sha256
    )
      throw Error(
        "Regenerate architectural plates for the current estate model and calibration",
      );
    for (const row of Object.values(plate.views)) {
      await freezeSource(row.url);
      if (inputs[row.url].sha256 !== row.sha256)
        throw Error("Unexpected architectural plate bytes " + row.url);
    }
  }
  if (url.endsWith(".glb")) {
    if (bytes.toString("ascii", 0, 4) !== "glTF" || bytes.readUInt32LE(4) !== 2)
      throw Error("Invalid GLB " + url);
    const json = JSON.parse(
      bytes.toString("utf8", 20, 20 + bytes.readUInt32LE(12)),
    );
    for (const object of [...(json.buffers || []), ...(json.images || [])]) {
      if (!object.uri || object.uri.startsWith("data:")) continue;
      const child = new URL(object.uri, "http://capture.local" + url);
      if (child.origin !== "http://capture.local")
        throw Error("External dependency " + child);
      await freezeSource(decodeURIComponent(child.pathname));
    }
  }
}
await freezeSource("/estate/estate.json");
const nightCases = registeredTakes(
  JSON.parse(sources.get("/estate/estate.json")),
);
for (const url of [
  "/estate/estate.glb",
  "/night-media/night-sky.hdr",
  ...Object.values(nightCases).map(
    (c) => "/night-media/actors/" + c.actor + ".glb",
  ),
])
  await freezeSource(url);
try {
  await freezeSource("/night-media/plates/index.json");
} catch (error) {
  if (error.code !== "ENOENT" || sources.has("/night-media/plates/index.json"))
    throw error;
}
const { outputFiles } = await build({
  stdin: {
    contents: `
      import { createNightStage } from "./lib/night-scene/stage.js";
      import { cameraFrameReader } from "./scripts/capture-night-frame.js";
      const canvas=document.querySelector("canvas");
      createNightStage(canvas,{interactive:false, recording:true}).then(stage=>{
        stage.resize(${width},${height});
        window.cameras=stage.cameras;
        window.frame=cameraFrameReader(stage,canvas,${0.5 / fps});
      }).catch(error=>window.bootError=String(error));`,
    resolveDir: root,
  },
  bundle: true,
  minify: true,
  write: false,
});
const server = createServer((req, res) => {
  const url = new URL(req.url, "http://localhost").pathname;
  if (url === "/") {
    res.setHeader("content-type", "text/html");
    res.end(
      '<!doctype html><link rel="icon" href="data:,"><canvas></canvas><script src="/replay.js"></script>',
    );
  } else if (url === "/replay.js") {
    res.setHeader("content-type", "text/javascript");
    res.end(outputFiles[0].contents);
  } else {
    const bytes = sources.get(url);
    if (!bytes) {
      res.writeHead(404).end();
      return;
    }
    if (url.endsWith(".json"))
      res.setHeader("content-type", "application/json");
    else if (url.endsWith(".glb"))
      res.setHeader("content-type", "model/gltf-binary");
    res.end(bytes);
  }
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
const mode = process.env.FSS_CHROME_ANGLE || "gl-egl";
const browser = await chromium.launch({
  executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome",
  args: [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--enable-gpu",
    "--ignore-gpu-blocklist",
    "--use-gl=angle",
    "--use-angle=" + mode,
    ...(mode === "vulkan"
      ? ["--enable-features=Vulkan", "--disable-vulkan-surface"]
      : []),
    "--enable-unsafe-swiftshader",
  ],
});
const work = await mkdtemp(join(root, ".night-capture-"));
const previewIndex = process.argv.indexOf("--preview");
const previewDir = previewIndex < 0 ? null : process.argv[previewIndex + 1];
if (previewIndex >= 0 && !previewDir)
  throw Error("--preview requires a destination directory");
async function raster(page, id, camera, config) {
  const stem = id + "-" + camera,
    filename = stem + ".mp4";
  const encoder = spawn(
    "ffmpeg",
    [
      "-v",
      "error",
      "-y",
      "-f",
      "image2pipe",
      "-framerate",
      String(fps),
      "-vcodec",
      "mjpeg",
      "-i",
      "pipe:0",
      "-an",
      "-c:v",
      "libx264",
      "-threads",
      "3",
      "-crf",
      "19",
      "-preset",
      "fast",
      "-pix_fmt",
      "yuv420p",
      "-movflags",
      "+faststart",
      join(work, filename),
    ],
    { stdio: ["pipe", "ignore", "inherit"] },
  );
  const finished = once(encoder, "close");
  let sample,
    stillBytes,
    stillT = config.still[camera] ?? config.still.overview;
  const total = config.seconds * fps,
    stillIndex = Math.min(total - 1, Math.round(stillT * fps));
  const trajectory = [];
  try {
    for (let i = 0; i < total; i++) {
      const result = await page.evaluate((args) => window.frame(args), {
        id,
        t: i / fps,
        camera,
      });
      const bytes = Buffer.from(result.jpeg, "base64");
      if (i % (fps / 4) === 0 || i === total - 1) {
        const {
          subjectFoot,
          movementPhase,
          speedMps,
          distanceM,
          stopAtSeconds,
        } = result.sample;
        trajectory.push({
          seconds: i / fps,
          subjectFoot,
          movementPhase,
          speedMps,
          distanceM,
          stopAtSeconds,
        });
      }
      if (i === stillIndex) {
        sample = result.sample;
        stillBytes = bytes;
      }
      if (!encoder.stdin.write(bytes)) await once(encoder.stdin, "drain");
    }
    encoder.stdin.end();
    const [code] = await finished;
    if (code !== 0) throw Error("FFmpeg exited with " + code + " for " + stem);
    const film = await readFile(join(work, filename));
    await writeFile(join(work, stem + ".jpg"), stillBytes);
    console.log("Captured", stem, film.length);
    return {
      caseId: id,
      camera,
      seconds: config.seconds,
      fps,
      frames: total,
      width,
      height,
      stillSeconds: stillIndex / fps,
      trajectory,
      sample,
      film: "/night-media/" + filename,
      poster: "/night-media/" + stem + ".jpg",
      videoSha256: sha(film),
      posterSha256: sha(stillBytes),
    };
  } finally {
    if (encoder.exitCode === null) encoder.kill();
  }
}
try {
  await mkdir(filmDir, { recursive: true });
  const page = await browser.newPage();
  page.on("pageerror", (error) => console.error(error.message));
  page.on("console", (msg) => {
    if (msg.type() === "error") console.error(msg.text());
  });
  await page.goto("http://127.0.0.1:" + server.address().port);
  await page.waitForFunction(
    () => typeof window.frame === "function" || window.bootError,
    {},
    { timeout: 180000 },
  );
  const init = await page.evaluate(() => ({
    error: window.bootError,
    cameras: window.cameras,
  }));
  if (init.error) throw Error(init.error);
  if (previewDir) await mkdir(previewDir, { recursive: true });
  const captures = [];
  for (const [id, config] of Object.entries(nightCases)) {
    for (const camera of ["overview", ...config.lenses]) {
      if (!init.cameras.includes(camera))
        throw Error("Missing calibrated camera " + camera);
      if (previewDir) {
        const t = config.still[camera] ?? config.still.overview;
        const snapshot = await page.evaluate((args) => window.frame(args), {
          id,
          camera,
          t,
        });
        await writeFile(
          join(previewDir, id + "-" + camera + ".jpg"),
          Buffer.from(snapshot.jpeg, "base64"),
        );
        console.log(id, camera, t, snapshot.sample.subjectPixel);
      } else captures.push(await raster(page, id, camera, config));
    }
  }
  if (!previewDir) {
    for (const [url, receipt] of Object.entries(inputs)) {
      if (sha(await readFile(join(publicDir, url))) !== receipt.sha256)
        throw Error("Source changed during capture: " + url);
    }
    const capture = {
      schema: "fss.fictional-estate-capture.v1",
      seconds: 8,
      fps,
      width,
      height,
      site: "Residential security simulation",
      exposure: { shutterSeconds: 0.5 / fps, samples: 3 },
      rendering: sources.has("/night-media/plates/index.json")
        ? "Calibrated Cycles architecture, WebGL occlusion and articulated subjects, FFmpeg H.264"
        : "WebGL architecture and articulated subjects, FFmpeg H.264",
      source:
        "Authored synthetic scene and calibrated WebGL projections. No physical sensors or detector inference.",
      inputs,
      captures,
    };
    for (const row of captures)
      for (const url of [row.film, row.poster])
        await rename(join(work, basename(url)), join(filmDir, basename(url)));
    await writeFile(
      join(work, "capture.json"),
      JSON.stringify(capture, null, 2) + "\n",
    );
    await rename(join(work, "capture.json"), join(filmDir, "capture.json"));
  }
} finally {
  await browser.close();
  server.close();
  await rm(work, { recursive: true, force: true });
}
