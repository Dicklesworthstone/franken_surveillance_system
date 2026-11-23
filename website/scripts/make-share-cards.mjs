// Draws the pictures other sites show for a link to this one: the home page's
// (app/opengraph-image.jpg, app/twitter-image.jpg) and one pair for each chapter's share page
// (app/chapter/<slug>/…). Each card is the page's own design drawn from the page's own data: the
// hero still with T1's scripted outline at the still's frame, the minute's camera lanes, the five
// cameras wired into the model, the assessment's steps, the scripted agent's lines and the ledger
// rows with their digests. Every card carries the badge the page puts on that figure.
//
// It writes the alt text beside each picture as <name>.alt.txt, so the description is made from the
// same values as the picture.
//
//   node scripts/make-share-cards.mjs          (from website/, after the take is in public/watch)
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { CHAPTERS } from "../components/site/chapters.js";
import { SHARE, SHARE_LINE } from "../components/site/share.js";
import { loadTake } from "../lib/watch/load.js";
import { stamp } from "../lib/watch/take.js";

const file = (path) => fileURLToPath(new URL("../" + path, import.meta.url));
const data = async (path, type) => `data:${type};base64,${(await readFile(file(path))).toString("base64")}`;
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const lit = (title) => esc(title).replace(/\[([^\]]+)\]/g, '<span class="lit">$1</span>');
const plain = (title) => title.replace(/[[\]]/g, "");
const upper = (s) => s.charAt(0).toUpperCase() + s.slice(1);

const STILL_FRAME = 112; // components/site/Home.jsx: the frame of the hero loop the still was taken from
const take = loadTake();
const { summary, story, spans, heroTruth } = take;
const at = heroTruth.frames[STILL_FRAME];
const heroClock = stamp(summary, heroTruth.start + STILL_FRAME / heroTruth.fps, 0, true);
const lightsOn = heroTruth.start + STILL_FRAME / heroTruth.fps >= heroTruth.lights;

const tokens = await readFile(file("app/styles/tokens.css"), "utf8");
const font = await data("node_modules/@fontsource-variable/inter/files/inter-latin-opsz-normal.woff2", "font/woff2");
const mono = await data("node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2", "font/woff2");
const mark = await data("app/icon.svg", "image/svg+xml");
const still = await data("public/watch/intrusion/hero-still.jpg", "image/jpeg");
const cams = Object.fromEntries(
  await Promise.all(summary.cameras.map(async (c) => [c.id, await data(`public/watch/plates/cam-${c.id}.webp`, "image/webp")])),
);
const model = await data("public/watch/plates/model.webp", "image/webp");
const plates = Object.fromEntries(
  await Promise.all(CHAPTERS.map(async (c) => [c.id, await data(`public/watch/plates/${c.plate}-1600.webp`, "image/webp")])),
);

const BASE = `
${tokens}
@font-face { font-family: "Card"; src: url(${font}); font-weight: 100 900; }
@font-face { font-family: "Card Mono"; src: url(${mono}); font-weight: 100 800; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { position: relative; width: 100vw; height: 100vh; overflow: hidden; background: var(--ink); color: var(--text);
  font-family: "Card"; font-optical-sizing: auto; -webkit-font-smoothing: antialiased; }
.mono { font-family: "Card Mono"; font-variant-numeric: tabular-nums; }
.micro { font: 500 13px/1 "Card Mono"; letter-spacing: .2em; text-transform: uppercase; }
.brand { display: flex; align-items: center; gap: 13px; font-size: 23px; font-weight: 800; letter-spacing: -.03em; color: #fff; }
.brand img { width: 38px; height: 38px; filter: drop-shadow(0 0 14px rgb(255 194 77 / .45)); }
.sphere { display: inline-block; width: 11px; height: 11px; border-radius: 50%; flex: none;
  background: radial-gradient(circle at 35% 30%, #fff 0, var(--tone) 42%, color-mix(in srgb, var(--tone) 40%, #000) 100%);
  box-shadow: 0 0 12px color-mix(in srgb, var(--tone) 70%, transparent); }
.lit { color: var(--lamp); }
.lit--glow { background: linear-gradient(98deg, #fff0c8 0%, #ffd577 28%, #ffb23f 58%, #ff8352 100%);
  -webkit-background-clip: text; background-clip: text; color: transparent; padding-bottom: .12em; margin-bottom: -.12em;
  filter: drop-shadow(0 0 26px rgb(255 178 63 / .32)); }
.reticle { position: absolute; inset: 10px; pointer-events: none; z-index: 3; }
.reticle i { position: absolute; width: 16px; height: 16px; border: 0 solid var(--ret, rgb(255 255 255 / .7)); }
.reticle i:nth-child(1) { top: 0; left: 0; border-width: 1.5px 0 0 1.5px; }
.reticle i:nth-child(2) { top: 0; right: 0; border-width: 1.5px 1.5px 0 0; }
.reticle i:nth-child(3) { bottom: 0; left: 0; border-width: 0 0 1.5px 1.5px; }
.reticle i:nth-child(4) { bottom: 0; right: 0; border-width: 0 1.5px 1.5px 0; }
.badge { display: inline-flex; align-items: center; gap: 8px; flex: none; padding: 5px 12px 5px 10px; border-radius: 999px;
  border: 1px solid color-mix(in srgb, var(--tone) 45%, transparent); background: color-mix(in srgb, var(--tone) 12%, rgb(5 7 11 / .7));
  font: 500 12.5px/1.3 "Card Mono"; color: color-mix(in srgb, var(--tone) 82%, #fff); white-space: nowrap; }
.badge::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--tone); flex: none; }
.badge--staged { --tone: #b8c4d6; }
.badge--staged::before { background: none; border: 1.5px dashed var(--tone); width: 6px; height: 6px; }
.url { font: 500 15px/1 "Card Mono"; color: rgb(238 242 248 / .6); letter-spacing: .02em; }
`;
const RETICLE = "<span class=reticle><i></i><i></i><i></i><i></i></span>";
const badge = (text) => `<span class="badge badge--staged">${esc(text)}</span>`;

/* The home page: the security room from the top of the page, at the still's own moment. */
function home() {
  // At card size the whole frame leaves him a few pixels tall, so the monitor shows the same frame
  // closer: ZOOM times, centred on him where the frame allows. The outline moves with the picture.
  const ZOOM = 1.4;
  const view = 1 / ZOOM;
  const [bx, by, bw, bh] = at.box;
  const ox = Math.min(Math.max(bx + bw / 2 - view / 2, 0), 1 - view);
  const oy = Math.min(Math.max(by + bh / 2 - 0.03 - view / 2, 0), 1 - view);
  const [left, top, width, height] = [(bx - ox) * ZOOM, (by - oy) * ZOOM, bw * ZOOM, bh * ZOOM];
  const frame = `width:${ZOOM * 100}%;height:${ZOOM * 100}%;left:${-ox * ZOOM * 100}%;top:${-oy * ZOOM * 100}%`;
  const tiles = summary.cameras
    .map(
      (c, i) => `<li${at.seen.includes(i) ? " class=on" : ""}><img src="${cams[c.id]}"><span><b></b>${esc(c.name)}</span></li>`,
    )
    .join("");
  return `<!doctype html><meta charset="utf-8"><style>${BASE}
body { background:
  radial-gradient(760px 520px at 0% 0%, rgb(255 194 77 / .16), transparent 70%),
  radial-gradient(900px 600px at 78% 46%, rgb(255 140 70 / .09), transparent 70%), var(--ink); }
.grid { position: absolute; inset: 0; opacity: .5;
  background-image: linear-gradient(rgb(196 214 255 / .045) 1px, transparent 1px), linear-gradient(90deg, rgb(196 214 255 / .045) 1px, transparent 1px);
  background-size: 48px 48px; -webkit-mask-image: radial-gradient(900px 600px at 30% 40%, #000, transparent 80%); }
.words { position: absolute; left: 60px; top: var(--pad); bottom: var(--pad); width: 520px; display: flex; flex-direction: column; }
.eyebrow { display: flex; align-items: center; gap: 12px; color: var(--lamp); margin-top: auto; margin-bottom: 22px; --tone: var(--lamp); }
h1 { font-size: 70px; font-weight: 800; line-height: .98; letter-spacing: -.055em; color: #fff; }
.foot { margin-top: 26px; display: flex; gap: 14px; align-items: center; }
.foot .rule { flex: 1; height: 1px; background: linear-gradient(90deg, rgb(255 194 77 / .5), transparent); }
.room { position: absolute; right: 56px; width: 548px; top: 50%; transform: translateY(-50%); display: flex; flex-direction: column; gap: 10px; }
.monitor { position: relative; aspect-ratio: 16 / 9; border-radius: 16px; overflow: hidden; border: 1px solid rgb(255 214 150 / .28);
  box-shadow: 0 0 0 1px rgb(0 0 0 / .6), 0 34px 80px -24px rgb(0 0 0 / .9), 0 0 90px -18px rgb(255 170 60 / .42); }
.monitor img { position: absolute; max-width: none; }
.monitor::after { content: ""; position: absolute; inset: 0; background: radial-gradient(120% 90% at 50% 45%, transparent 55%, rgb(0 0 0 / .55)); }
.box { position: absolute; z-index: 2; border: 2px dashed var(--track-a); border-radius: 3px; box-shadow: 0 0 18px rgb(255 122 77 / .45); }
.box b { position: absolute; left: -2px; bottom: 100%; margin-bottom: 4px; padding: 2px 6px; background: var(--track-a); color: #1a0800;
  font: 700 12px/1.2 "Card Mono"; border-radius: 3px; }
.credit { position: absolute; z-index: 4; left: 34px; top: 22px; }
.credit .badge { font-size: 11.5px; padding: 4px 10px 4px 9px; }
.wall { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; list-style: none; }
.wall li { position: relative; aspect-ratio: 16 / 10; border-radius: 9px; overflow: hidden; border: 1px solid rgb(196 214 255 / .14); background: #0b0f16; }
.wall img { width: 100%; height: 100%; object-fit: cover; filter: grayscale(.7) brightness(.5); }
.wall span { position: absolute; left: 7px; bottom: 6px; display: flex; align-items: center; gap: 5px; font: 600 11.5px/1 "Card"; color: rgb(238 242 248 / .75);
  text-shadow: 0 1px 4px #000; }
.wall b { width: 6px; height: 6px; border-radius: 50%; background: var(--unseen); }
.wall .on { border-color: var(--track-a); box-shadow: 0 0 0 1px rgb(255 122 77 / .5), 0 0 22px -4px rgb(255 122 77 / .7); }
.wall .on img { filter: none; }
.wall .on span { color: #fff; }
.wall .on b { background: var(--track-a); box-shadow: 0 0 8px var(--track-a); }
.hud { display: flex; gap: 30px; align-items: flex-end; padding: 13px 20px; border: 1px solid rgb(196 214 255 / .14); border-radius: 14px; background: rgb(9 13 19 / .9); }
.hud dt { font: 500 10.5px/1 "Card Mono"; letter-spacing: .22em; text-transform: uppercase; color: var(--faint); margin-bottom: 8px; }
.hud dd { font: 500 18px/1 "Card Mono"; color: #fff; }
.hud .on { color: var(--lamp); }
body.short .room { gap: 9px; width: 520px; }
</style>
<div class=grid></div>
<div class=words>
  <div class=brand><img src="${mark}">Franken Surveillance</div>
  <p class="eyebrow micro"><span class=sphere></span>Pure Rust · local first · open source</p>
  <h1>A security room for your house, built from <span class="lit lit--glow">$35 cameras</span>.</h1>
  <div class=foot><span class=url>franken-surveillance.com</span><span class=rule></span></div>
</div>
<div class=room>
  <div class=monitor>
    <img src="${still}" style="${frame}">
    <span class=box style="left:${left * 100}%;top:${top * 100}%;width:${width * 100}%;height:${height * 100}%"><b>${esc(heroTruth.track)}</b></span>
    ${RETICLE}
    <span class=credit>${badge("Rendered scene, fictional house, staged positions")}</span>
  </div>
  <ol class=wall>${tiles}</ol>
  <dl class=hud>
    <div><dt>Scene clock</dt><dd>${esc(heroClock)}</dd></div>
    <div><dt>Floodlights</dt><dd class="${lightsOn ? "on" : ""}">${lightsOn ? "On" : "Off"}</dd></div>
    <div><dt>${esc(heroTruth.track)}</dt><dd>${esc(upper(at.action ?? "out of the scene"))}</dd></div>
  </dl>
</div>`;
}

/* Each chapter's figure: the same data the chapter draws, at card size. */
const span = (s) => (s / summary.duration) * 100;
const FIGURES = {
  minute: () => {
    const lanes = summary.cameras
      .map((c) => {
        const bars = spans
          .filter((s) => s.camera === c.id)
          .map((s) => `<i class="bar bar--${s.actor}" style="left:${span(s.from)}%;width:${span(s.to - s.from)}%"></i>`)
          .join("");
        return `<div class=lane><span class=name>${esc(c.name)}</span><span class=track>${bars}</span></div>`;
      })
      .join("");
    const lights = story.markers.find((m) => m.label === "Lights on");
    const tick = (s) => `<span style="left:${span(s)}%">${esc(stamp(summary, s).slice(0, 8))}</span>`;
    const [a, b] = summary.actors;
    return {
      head: "Who each camera held, second by second",
      badge: "Staged script",
      body: `<div class=lanes>${lanes}
        ${lights ? `<span class=mark style="left:calc(96px + (100% - 96px) * ${span(lights.t) / 100})"><em>${esc(lights.label)}</em></span>` : ""}
        <div class=axis>${[0, 20, 40, 60].map(tick).join("")}</div></div>
        <p class=legend><span><i class="bar--a"></i>${esc(a.track)}</span><span><i class="bar--b"></i>${esc(b.track)}</span><em>Scripted positions, from 02:14:00</em></p>`,
    };
  },
  how: () => {
    const n = summary.cameras.length;
    const rows = summary.cameras
      .map((c) => `<li><img src="${cams[c.id]}"><span>${esc(c.name)}</span></li>`)
      .join("");
    const wires = Array.from({ length: n }, (_, i) => {
      const y = ((i + 0.5) / n) * 100;
      return `<path d="M0 ${y}C55 ${y} 45 50 100 50"/>`;
    }).join("");
    return {
      head: "Five cameras, one model",
      badge: "Rendered model, fictional house",
      body: `<div class=chain><ol class=cams>${rows}</ol>
        <svg class=wires viewBox="0 0 100 100" preserveAspectRatio="none">${wires}</svg>
        <div class=model><img src="${model}"><p><b>One model of the property</b><span>A person seen by two cameras is one track.</span></p></div></div>`,
    };
  },
  evidence: () => {
    const W = 440,
      H = 196;
    const x = (t) => (t / summary.duration) * W;
    const y = (p) => H - p * (H - 8);
    let line = "";
    for (const [i, step] of story.belief.entries())
      line += `${i ? "L" : "M"}${x(step.from).toFixed(1)} ${y(step.chance).toFixed(1)}H${x(step.to).toFixed(1)}`;
    const area = `${line}V${H}H0Z`;
    const first = story.belief[0];
    const last = story.belief.at(-1);
    const pctOf = (p) => (p * 100).toFixed(p > 0.995 ? 1 : 0) + "%";
    return {
      head: "Chance that a stranger is on the property",
      badge: "Staged script",
      body: `<div class=belief>
        <p class=big><b>${pctOf(last.chance)}</b><span>by ${esc(stamp(summary, last.from).slice(0, 8))}, up from ${pctOf(first.chance)} before any camera saw anyone</span></p>
        <svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}"><defs><linearGradient id=g x1=0 y1=0 x2=0 y2=1>
          <stop offset=0 stop-color="#d0a2ff" stop-opacity=".42"/><stop offset=1 stop-color="#d0a2ff" stop-opacity="0"/></linearGradient></defs>
          <path d="M0 ${y(0.5)}H${W}" class=half />
          <path d="${area}" fill="url(#g)"/><path d="${line}" class=step />
        </svg>
        <div class=axis>${[0, 20, 40, 60].map((s) => `<span style="left:${span(s)}%">${esc(stamp(summary, s).slice(0, 8))}</span>`).join("")}</div>
        <p class=legend><em>Each step is one piece of evidence, added in millibans.</em></p></div>`,
    };
  },
  watch: () => {
    const pick = ["agent-3", "agent-7", "agent-9", "agent-10"];
    const rows = story.agent
      .filter((a) => pick.includes(a.id))
      .map((a) => `<li><p><span class=clock>${esc(a.clock)}</span><b>${esc(a.opName)}</b></p><span class=line>${esc(a.line)}</span></li>`)
      .join("");
    return { head: "The agent's log", badge: "Staged script", body: `<ol class=log>${rows}</ol>` };
  },
  machine: () => {
    const pick = [1, 2, 3, 5, 6, 7, 10, 16];
    const rows = story.ledger
      .filter((r) => pick.includes(r.seq))
      .map(
        (r) =>
          `<li><span class=seq>${String(r.seq).padStart(2, "0")}</span><span class=clock>${esc(r.clock)}</span><span class=kind>${esc(r.kind)}</span><span class=dig>${r.digest.slice(0, 16)}…</span></li>`,
      )
      .join("");
    return {
      head: "The ledger, row by row",
      badge: "Staged script",
      body: `<ol class=ledger>${rows}</ol><p class=legend><em>Each digest is the SHA-256 of its row, exactly as the page shows it.</em></p>`,
    };
  },
};

function chapter(c) {
  const fig = FIGURES[c.id]();
  const rail = CHAPTERS.map(
    (o) => `<li${o.id === c.id ? " class=on" : ""} style="--tone: var(--${o.light})"><span class=sphere></span>${o.number}</li>`,
  ).join("");
  const thesis = SHARE_LINE[c.id];
  return `<!doctype html><meta charset="utf-8"><style>${BASE}
body { --tone: var(--${c.light}); --ret: color-mix(in srgb, var(--${c.light}) 70%, transparent); }
.plate { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; object-position: 50% 45%; }
.shade { position: absolute; inset: 0; background:
  linear-gradient(90deg, rgb(5 7 11 / .96) 0%, rgb(5 7 11 / .86) 34%, rgb(5 7 11 / .5) 58%, rgb(5 7 11 / .62) 100%),
  linear-gradient(0deg, rgb(5 7 11 / .9) 0%, transparent 40%),
  radial-gradient(700px 480px at 0% 100%, color-mix(in srgb, var(--${c.light}) 16%, transparent), transparent 70%); }
.top { position: absolute; left: 60px; right: 56px; top: var(--pad); display: flex; justify-content: space-between; align-items: center; }
.rail { display: flex; gap: 8px; list-style: none; }
.rail li { display: flex; align-items: center; gap: 7px; padding: 6px 11px; border-radius: 999px; font: 500 13px/1 "Card Mono"; color: rgb(238 242 248 / .45);
  border: 1px solid transparent; }
.rail li .sphere { width: 8px; height: 8px; opacity: .55; box-shadow: none; }
.rail li.on { color: #fff; border-color: color-mix(in srgb, var(--tone) 50%, transparent); background: color-mix(in srgb, var(--tone) 14%, rgb(5 7 11 / .8)); }
.rail li.on .sphere { opacity: 1; width: 10px; height: 10px; box-shadow: 0 0 12px var(--tone); }
.words { position: absolute; left: 60px; width: 560px; bottom: var(--pad); display: flex; flex-direction: column; }
.numeral { font: 500 150px/.8 "Card Mono"; letter-spacing: -.07em; color: transparent; -webkit-text-stroke: 1.5px color-mix(in srgb, var(--${c.light}) 75%, transparent);
  margin-bottom: 20px; margin-left: -6px; }
.eyebrow { display: flex; align-items: center; gap: 12px; color: var(--${c.light}); margin-bottom: 18px; }
h1 { font-size: 68px; font-weight: 800; line-height: .98; letter-spacing: -.052em; color: #fff; }
.thesis { margin-top: 20px; font-size: 21px; line-height: 1.4; color: var(--soft); max-width: 520px; }
.url { margin-top: 24px; }
.panel { position: absolute; right: 56px; width: 500px; top: calc(var(--pad) + 62px); bottom: var(--pad); padding: 24px 24px 22px;
  border-radius: 22px; border: 1px solid rgb(196 214 255 / .16); background: linear-gradient(180deg, rgb(13 18 27 / .94), rgb(7 10 15 / .94));
  box-shadow: 0 40px 90px -30px #000, 0 0 80px -30px color-mix(in srgb, var(--${c.light}) 50%, transparent); display: flex; flex-direction: column; }
.phead { display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; margin-bottom: 18px; }
.phead p { font: 500 11.5px/1.35 "Card Mono"; letter-spacing: .16em; text-transform: uppercase; color: var(--${c.light}); max-width: 270px; }
.pbody { flex: 1; display: flex; flex-direction: column; justify-content: center; min-height: 0; }
.legend { display: flex; gap: 16px; align-items: center; margin-top: 14px; font: 500 12.5px/1.4 "Card Mono"; color: var(--faint); }
.legend span { display: flex; align-items: center; gap: 7px; color: var(--soft); }
.legend i { width: 18px; height: 8px; border-radius: 3px; }
.legend em { font-style: normal; }
/* 01 */
.lanes { position: relative; display: flex; flex-direction: column; gap: 9px; padding-top: 22px; }
.lane { display: flex; align-items: center; gap: 12px; }
.name { width: 84px; flex: none; font: 600 14px/1 "Card"; color: var(--soft); }
.track { position: relative; flex: 1; height: 34px; border-radius: 6px; background: rgb(196 214 255 / .06); }
.bar { position: absolute; height: 12px; border-radius: 3px; }
.bar--a, .legend .bar--a { top: 3px; background: var(--track-a); box-shadow: 0 0 10px rgb(255 122 77 / .5); }
.bar--b, .legend .bar--b { bottom: 3px; background: var(--track-b); box-shadow: 0 0 10px rgb(76 195 245 / .45); }
.legend .bar--a, .legend .bar--b { position: static; }
.mark { position: absolute; top: 0; bottom: 18px; width: 0; border-left: 1.5px dashed rgb(255 194 77 / .8); }
.mark em { position: absolute; top: -2px; left: 7px; font: 500 11.5px/1 "Card Mono"; font-style: normal; color: var(--lamp); white-space: nowrap; }
.axis { position: relative; height: 16px; margin-left: 96px; margin-top: 2px; }
.axis span { position: absolute; transform: translateX(-50%); font: 500 11px/1 "Card Mono"; color: var(--faint); }
.axis span:first-child { transform: none; }
.axis span:last-child { transform: translateX(-100%); }
/* 02 */
.chain { display: grid; grid-template-columns: 120px 64px 1fr; align-items: center; }
.cams { list-style: none; display: flex; flex-direction: column; gap: 8px; }
.cams li { position: relative; aspect-ratio: 16 / 9; border-radius: 7px; overflow: hidden; border: 1px solid rgb(164 188 255 / .3); }
.cams img { width: 100%; height: 100%; object-fit: cover; }
.cams span { position: absolute; left: 6px; bottom: 4px; font: 600 10.5px/1 "Card"; color: #fff; text-shadow: 0 1px 3px #000; }
.wires { width: 64px; height: 100%; overflow: visible; }
.wires path { fill: none; stroke: var(--moon); stroke-width: 1.4; vector-effect: non-scaling-stroke; opacity: .75; filter: drop-shadow(0 0 4px var(--moon)); }
.model img { width: 100%; aspect-ratio: 16 / 10; object-fit: cover; border-radius: 10px; border: 1px solid rgb(164 188 255 / .4);
  box-shadow: 0 0 40px -10px rgb(164 188 255 / .55); }
.model p { margin-top: 12px; display: flex; flex-direction: column; gap: 5px; }
.model b { font-size: 16px; color: #fff; letter-spacing: -.01em; }
.model span { font-size: 13.5px; line-height: 1.35; color: var(--soft); }
/* 03 */
.belief { position: relative; }
.big { display: flex; align-items: flex-end; gap: 14px; margin-bottom: 12px; }
.big b { font: 700 58px/1.1 "Card"; font-variant-numeric: tabular-nums; letter-spacing: -.04em; color: #fff; text-shadow: 0 0 30px rgb(208 162 255 / .45); }
.big span { font-size: 13.5px; line-height: 1.35; color: var(--soft); max-width: 230px; padding-bottom: 2px; }
.belief svg { display: block; width: 100%; height: auto; overflow: visible; }
.step { fill: none; stroke: var(--infrared); stroke-width: 2.5; stroke-linejoin: round; filter: drop-shadow(0 0 6px rgb(208 162 255 / .7)); }
.half { stroke: rgb(196 214 255 / .14); stroke-width: 1; }
.belief .axis { margin-left: 0; margin-top: 8px; }
/* 04 */
.log { list-style: none; display: flex; flex-direction: column; gap: 12px; }
.log li { padding-left: 14px; border-left: 2px solid color-mix(in srgb, var(--phosphor) 55%, transparent); }
.log p { display: flex; gap: 10px; align-items: baseline; margin-bottom: 4px; font: 500 12.5px/1 "Card Mono"; }
.log .clock { color: var(--faint); }
.log b { color: var(--phosphor); font-weight: 600; }
.log .line { display: block; font-size: 14px; line-height: 1.36; color: var(--text); }
/* 05 */
.ledger { list-style: none; display: flex; flex-direction: column; }
.ledger li { display: grid; grid-template-columns: 28px 86px 1fr auto; gap: 10px; align-items: center; padding: 10px 2px; border-bottom: 1px solid rgb(196 214 255 / .08);
  font: 500 13px/1 "Card Mono"; }
.ledger li:first-child { border-top: 1px solid rgb(196 214 255 / .08); }
.ledger .seq { color: var(--faint); }
.ledger .clock { color: var(--soft); }
.ledger .kind { color: var(--dawn); }
.ledger .dig { color: rgb(238 242 248 / .55); letter-spacing: .02em; }
body.short .numeral { font-size: 128px; margin-bottom: 16px; }
body.short h1 { font-size: 64px; }
body.short .thesis { font-size: 20px; margin-top: 16px; }
body.short .lanes { gap: 7px; }
body.short .log { gap: 10px; }
body.short .ledger li { padding: 9px 2px; }
body.short .chain { grid-template-columns: 104px 60px 1fr; }
body.short .cams { gap: 6px; }
</style>
<img class=plate src="${plates[c.id]}"><div class=shade></div>
<div class=top><div class=brand><img src="${mark}">Franken Surveillance</div><ol class=rail>${rail}</ol></div>
<div class=words>
  <span class=numeral>${c.number}</span>
  <p class="eyebrow micro"><span class=sphere></span>Chapter ${c.number} · ${esc(c.label)}</p>
  <h1>${lit(c.title)}</h1>
  <p class=thesis>${esc(thesis)}</p>
  <span class=url>franken-surveillance.com/chapter/${SHARE[c.id]}/</span>
</div>
<section class=panel>${RETICLE}
  <div class=phead><p>${esc(fig.head)}</p>${badge(fig.badge)}</div>
  <div class=pbody>${fig.body}</div>
</section>`;
}

const ALT = {
  home: () =>
    `A security room on a dark page. The main monitor shows a rendered white house at night with its floodlights on and a man in dark clothes, outlined as ${heroTruth.track}, ${at.action ?? "out of the scene"} on the porch steps. Under it are five camera tiles; ${at.seen.map((i) => summary.cameras[i].name).join(" and ")} are lit. The readout says ${heroClock}, floodlights ${lightsOn ? "on" : "off"}. Headline: A security room for your house, built from $35 cameras.`,
  minute: () =>
    `Chapter 01, ${plain(CHAPTERS[0].title)} A chart of one staged minute from 02:14:00: for each of five cameras, the stretches in which it held the intruder (T1, orange) and the lookout (T2, blue), with the moment the lights came on.`,
  how: () =>
    `Chapter 02, ${plain(CHAPTERS[1].title)} Five camera thumbnails are wired into one rendered model of the property seen from above.`,
  evidence: () => {
    const last = story.belief.at(-1);
    return `Chapter 03, ${plain(CHAPTERS[2].title)} A step chart of the staged scene's chance that a stranger is on the property, rising from ${(story.belief[0].chance * 100).toFixed(0)}% to ${(last.chance * 100).toFixed(1)}% over the minute.`;
  },
  watch: () =>
    `Chapter 04, ${plain(CHAPTERS[3].title)} Four lines from the scripted agent's log: a briefing under 1,600 tokens, an owner alert, the exterior lights committed and verified.`,
  machine: () =>
    `Chapter 05, ${plain(CHAPTERS[4].title)} Six ledger rows with their times, kinds and SHA-256 digests, from the first observation to the handoff.`,
};

const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
const only = process.argv[2];
try {
  const jobs = [["", home, ALT.home], ...CHAPTERS.map((c) => [`chapter/${SHARE[c.id]}/`, () => chapter(c), ALT[c.id]])];
  for (const [dir, draw, alt] of jobs) {
    if (only && !dir.includes(only) && !(only === "home" && !dir)) continue;
    await mkdir(file("app/" + dir), { recursive: true });
    const html = draw();
    for (const [name, height] of [["opengraph-image", 630], ["twitter-image", 600]]) {
      const page = await browser.newPage({ viewport: { width: 1200, height } });
      await page.setContent(html.replace("<body", "<body").replace("</style>", `body { --pad: ${height === 630 ? 52 : 44}px; }</style>`), {
        waitUntil: "load",
      });
      if (height === 600) await page.evaluate(() => document.body.classList.add("short"));
      await page.evaluate(() => Promise.all([document.fonts.ready, ...[...document.images].map((image) => image.decode())]));
      // Nothing may be cut off: a clipped log line or ledger row would say less than the page does.
      const clipped = await page.evaluate(() =>
        [...document.querySelectorAll(".panel, .panel *, .words, .room")]
          .filter((el) => {
            const box = el.getBoundingClientRect();
            return el.scrollHeight > el.clientHeight + 4 || box.bottom > innerHeight - 8 || box.right > innerWidth - 8;
          })
          .map((el) => {
            const box = el.getBoundingClientRect();
            return `${el.className || el.tagName} (scroll ${el.scrollHeight}/${el.clientHeight}, bottom ${Math.round(box.bottom)}, right ${Math.round(box.right)})`;
          }),
      );
      if (clipped.length) throw Error(`${dir || "home"} ${height}: clipped ${clipped.join(", ")}`);
      await page.screenshot({ path: file(`app/${dir}${name}.jpg`), type: "jpeg", quality: 90 });
      await writeFile(file(`app/${dir}${name}.alt.txt`), alt());
      await page.close();
      console.log(`app/${dir}${name}.jpg 1200 by ${height}`);
    }
  }
} finally {
  await browser.close();
}
