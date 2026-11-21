import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";
import { CoverageRuns, Custody, FusionRuns, MeasuredSummary } from "../components/site/Measured.jsx";
import Feed from "../components/site/Feed.jsx";
import FilmFrame from "../components/site/FilmFrame.jsx";
import { distill } from "../lib/watch/native.js";
import { fromReports, objectReader } from "../lib/watch/retained.mjs";

const source = readFileSync(new URL("../public/watch/intrusion/native.json", import.meta.url));

test("fusion preserves a skipped run and a refused query beside a measured interval", () => {
  const raw = JSON.parse(source);
  const render = () => renderToStaticMarkup(<FusionRuns native={distill(raw)} />);
  assert.match(render(), /16\.6337 to 20\.0761%/);
  raw.fusion.variants[1] = { id: "illustrative_separate_devices", outcome: "refused", reason: "Missing calibration" };
  const mixed = render();
  assert.match(mixed, /Missing calibration/);
  assert.match(mixed, /Unavailable/);
  assert.match(mixed, /16\.6337 to 20\.0761%/);
  assert.doesNotMatch(mixed, /99\.5013|undefined|NaN/);
  raw.fusion = { outcome: "not_run", reason: "no detector-positive frame" };
  const skipped = render();
  assert.match(skipped, /no detector-positive frame/);
  assert.doesNotMatch(skipped, /%|<table/);
});

test("a poster cannot stand in for a missing or unverified camera frame", () => {
  const camera = { id: "gate", width: 1280, height: 720, poster: "/swapped-camera.jpg" };
  for (const video of [undefined, "/gate.mp4"]) {
    const input = { ...camera, video };
    const feed = renderToStaticMarkup(<Feed camera={input} summary={{ actors: [] }} />);
    const still = renderToStaticMarkup(<FilmFrame camera={input} t={23.5} caption="Gate at 23.5 s" />);
    assert.doesNotMatch(feed + still, /swapped-camera|feed__osd|<img|feed__marks/);
    if (!video) {
      assert.match(feed, /No recording is available/);
      assert.match(still, /No recording is available/);
      assert.doesNotMatch(feed + still, /Load this film again/);
    }
  }
});

test("coverage links to its native zone-entry predicate", () => {
  const dir = fileURLToPath(new URL("../public/watch/intrusion/", import.meta.url));
  const read = objectReader(dir);
  const raw = fromReports(JSON.parse(source), read);
  const first = raw.cameras.gate.coverage.reports[0];
  const [{ zones }] = JSON.parse(read(first)).coverage.records;
  assert.match(zones[0].witnesses[0].witness.negativePredicate, /no confirmed foreground-track entry/);
  const html = renderToStaticMarkup(<CoverageRuns native={distill(raw)} names={{ gate: "Gate" }} />);
  assert.ok(html.includes("/watch/intrusion/" + first));
  assert.match(html, /no confirmed foreground-track entry/);
  assert.doesNotMatch(html, /Time outside them remains unobserved/);
});

function partialImport(count) {
  const raw = JSON.parse(source);
  const ids = Object.keys(raw.cameras);
  ids.slice(0, count).forEach((id, i) => {
    raw.cameras[id] = { custody: { outcome: i ? "failed" : "refused", reason: "Unable to open recording" } };
  });
  const native = distill(raw);
  const names = Object.fromEntries(ids.map((id) => [id, id]));
  return [Custody, MeasuredSummary, CoverageRuns].map((View) =>
    renderToStaticMarkup(<View native={native} names={names} />));
}

test("one refused film keeps its reason beside the four successful imports", () => {
  const [custody, summary, coverage] = partialImport(1);
  assert.match(custody, /Import refused/);
  assert.match(custody, /Unable to open recording/);
  assert.match(summary, /4 films, 2,928 frames/);
  assert.match(summary, /1 unsuccessful import/);
  assert.match(coverage, /55.2 of 61/);
  assert.doesNotMatch(summary + custody + coverage, /NaN|undefined/);
});

test("an entirely unsuccessful import records neither custody nor detector measurements", () => {
  const [custody, summary, coverage] = partialImport(5);
  assert.match(custody, /Import failed/);
  assert.match(summary, /No film entered SHA-256 custody/);
  assert.match(summary, /No detector run was recorded/);
  assert.doesNotMatch(summary, /person was in view 0 times|NaN/);
  assert.equal(coverage, "");
});
