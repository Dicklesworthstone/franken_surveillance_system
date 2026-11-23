import { ArrowDown } from "lucide-react";
import { loadTake } from "../../lib/watch/load";
import ArchitectureDeck from "./ArchitectureDeck";
import { CHAPTERS } from "./chapters";
import Console from "./Console";
import HeroMedia from "./HeroMedia";
import { MeasuredSummary } from "./Measured";
import RevealController from "./RevealController";
import Status, { Footer } from "./Status";
import Story from "./Story";
import TopBar from "./TopBar";
import { Badge, Chapter, Lit } from "./ui";

const CREDITS = (
  <ul>
    <li>House, grounds and details: modelled for this project in Blender and path-traced with Cycles. The house is fictional.</li>
    <li>
      People: <a href="https://sketchfab.com/3d-models/a46bc9f67aaa415bb4f3241eef900e7f">Eric Rigged 001</a> and{" "}
      <a href="https://sketchfab.com/3d-models/143a2b1ea5eb4385ae90a73657aca3bc">Nathan Animated 003</a> by{" "}
      <a href="https://sketchfab.com/renderpeople">Renderpeople</a>,{" "}
      <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>. Changes: clothes recoloured, colours
      darkened and regraded for the infrared cameras, meshes smoothed, a cap, backpack and torch added. Both men are
      models playing parts in a staged scene.
    </li>
    <li>
      Movement: motion capture from <a href="http://mocap.cs.cmu.edu">mocap.cs.cmu.edu</a>, a database created with
      funding from NSF EIA-0196217. The reach for the door handle is animated by hand.
    </li>
    <li>Textures, night sky, indoor panoramas, trees, shrubs and site furniture: Poly Haven, CC0.</li>
    <li>Cars: the BMW benchmark scene by Mike Pan, CC0, with badges removed.</li>
    <li>
      <a href="/watch/intrusion/CREDITS.txt">Full credits, licences and changes</a>
    </li>
  </ul>
);

const STEPS = [
  ["#inputs", "Take video from any mix of cameras and put it on one clock"],
  ["#fusion", "Place every camera in one model, and count each person once"],
  ["#coverage", "Know which ground it can see, and say so when it cannot"],
  ["#belief", "Weigh what each sighting means and show the arithmetic"],
  ["#agent", "Brief an AI agent in under 1,600 tokens"],
  ["#effects", "Let that agent act, inside limits you set"],
  ["#record", "Keep an append-only record of all of it"],
];

// The frame of the loop that the still was taken from.
const STILL_FRAME = 112;

/** Curves from each of `n` rows on one side to the middle of the other. */
function Wires({ n, fan }) {
  const rows = Array.from({ length: n }, (_, i) => ((i + 0.5) / n) * 100);
  const path = (y) => (fan ? `M0 50C55 50 45 ${y} 100 ${y}` : `M0 ${y}C55 ${y} 45 50 100 50`);
  return (
    <div className="chain__wires" aria-hidden="true">
      <svg viewBox="0 0 100 100" preserveAspectRatio="none">
        {rows.map((y) => (
          <path key={y} d={path(y)} />
        ))}
        {rows.map((y, i) => (
          <path key={"live" + y} d={path(y)} className="is-live" style={{ "--delay": `${-i * 0.67}s` }} />
        ))}
      </svg>
    </div>
  );
}

export default function Home() {
  const { summary, story, spans, sceneUrl, sceneDigest, renderDigest, native, boxesUrl, boxesDigest, hero, heroTruth, films } =
    loadTake();
  const measuredFrames = native
    ? native.cameras.reduce((sum, c) => sum + (c.custody === "ok" ? (c.frames ?? 0) : 0), 0)
    : null;
  const count = { 5: "Five" }[summary.cameras.length] ?? String(summary.cameras.length);
  const minute = CHAPTERS[0];
  // What the hero needs to print a clock and name the cameras; not the whole take.
  const heroTake = { start: summary.start, zone: summary.zone, cameras: summary.cameras.map(({ id, name }) => ({ id, name })) };
  return (
    <>
      <TopBar />
      <RevealController />
      <main id="top" data-take-digest={renderDigest}>
        <section className="hero" data-outside aria-labelledby="hero-title">
          <HeroMedia
            video={hero.video}
            still={hero.still}
            stillFrame={STILL_FRAME}
            truth={heroTruth}
            take={heroTake}
            alt="A large white clapboard house at night with its floodlights on. A man in dark clothes runs down the porch steps, away from the front door."
          />
          <div className="hero__words">
            <p className="hero__eyebrow rise">
              <span className="sphere" aria-hidden="true" />
              <span className="micro">Pure Rust · local first · open source</span>
            </p>
            <h1 className="display-1 rise" id="hero-title" style={{ "--delay": "60ms" }}>
              <Lit text="A security room for your house, built from [$35 cameras]." glow />
            </h1>
            <p className="lede hero__lede rise" style={{ "--delay": "140ms" }}>
              Franken Surveillance joins the cheap Wi-Fi cameras you already own, whatever the makers, into one calibrated
              model of your property. It records what it saw, says what it could not see, and gives an AI agent a bounded
              place to watch and act. No vendor cloud.
            </p>
            <div className="hero__actions rise" style={{ "--delay": "210ms" }}>
              <a className="button button--lamp" href="#console">
                Watch one minute at 02:14 <ArrowDown aria-hidden="true" />
              </a>
              <a className="button button--line" href="#architecture">
                Inspect the Rust stack
              </a>
            </div>
            <p className="hero__foot rise" style={{ "--delay": "270ms" }}>
              Open source and unfinished. The scene on this page is staged: a rendered house, motion-captured actors and a
              scripted agent. Each figure says whether the software measured it. <a href="#status">What runs today</a>
            </p>
          </div>
        </section>

        <section className="specs" data-outside aria-label="In four figures">
          <dl>
            <div>
              <dt className="micro">A camera</dt>
              <dd>
                <b>$35</b>
                <span>What a Wi-Fi camera costs now. The intelligence is in the software, on a machine you own.</span>
              </dd>
            </div>
            <div>
              <dt className="micro">Measured here</dt>
              <dd>
                <b>{measuredFrames == null ? "None yet" : measuredFrames.toLocaleString("en") + " frames"}</b>
                <span>
                  {measuredFrames == null
                    ? "The project's binaries have not been run over these films."
                    : `${count} films imported under SHA-256 custody by the project's own binaries. Rendered footage, so it says nothing about real cameras.`}
                </span>
              </dd>
            </div>
            <div>
              <dt className="micro">Unsafe code</dt>
              <dd>
                <b>Forbidden</b>
                <span>In all 22 of the project's own crates. No FFmpeg, OpenCV, Python or ONNX Runtime in production.</span>
              </dd>
            </div>
            <div>
              <dt className="micro">For an agent</dt>
              <dd>
                <b>14 operations</b>
                <span>One grammar by command line and local MCP. A model may propose. It never authorizes.</span>
              </dd>
            </div>
          </dl>
        </section>

        <section className="thesis" data-outside aria-label="The idea">
          <div className="wrap thesis__grid">
            <p className="thesis__line reveal">
              Airports and borders have had this for decades: many sensors joined into one picture, watched around the
              clock by trained staff. <em>The parts are cheap now, and an AI agent can do the watching.</em>
            </p>
            <div className="thesis__side reveal" style={{ "--delay": "0.1s" }}>
              <p className="prose">
                Franken Surveillance is the layer in between. It takes a bunch of cheap cameras from mixed makers, gives
                them one clock and one map, and keeps the evidence straight enough that an agent can act on it.
              </p>
            </div>
          </div>
        </section>

        <section className="chain" data-outside aria-label="From five cameras to one answer">
          <div className="wrap wrap--wide">
            <div className="chain__flow reveal">
              <div className="chain__cams">
                {summary.cameras.map((cam) => (
                  <div className="chain__cam" key={cam.id}>
                    <img src={`/watch/plates/cam-${cam.id}.webp`} width="640" height="360" loading="lazy" decoding="async" alt="" />
                    <span>
                      {cam.name}
                      <small>{cam.product}</small>
                    </span>
                  </div>
                ))}
              </div>
              <Wires n={summary.cameras.length} />
              <div className="chain__model">
                <img
                  src="/watch/plates/model.webp"
                  width="1600"
                  height="1000"
                  loading="lazy"
                  decoding="async"
                  alt="The model of the property from above at night: the house, drive, lawn, pool and street wall."
                />
                <Badge kind="staged">Rendered model, fictional house</Badge>
                <div>
                  <p className="micro micro--chapter">One model of the property</p>
                  <strong>Every sighting lands on the same ground.</strong>
                  <p>Two views of one person become one track, with a stated bound on where they are.</p>
                </div>
              </div>
              <Wires n={3} fan />
              <div className="chain__outs">
                <a className="chain__out" href="#belief">
                  <span className="micro micro--chapter">Evidence</span>
                  <strong>A probability you can take apart</strong>
                  <span>Each source can be removed, and the answer recomputed without it.</span>
                </a>
                <a className="chain__out" href="#agent">
                  <span className="micro micro--chapter">Agent</span>
                  <strong>A briefing sized to its budget</strong>
                  <span>What is known, what is not, and what it may do next.</span>
                </a>
                <a className="chain__out" href="#record">
                  <span className="micro micro--chapter">Record</span>
                  <strong>A ledger that only grows</strong>
                  <span>Sightings, decisions and actions, each under its own digest.</span>
                </a>
              </div>
            </div>
            <ol className="chain__steps" aria-label="What that software has to do">
              {STEPS.map(([href, text]) => (
                <li key={href}>
                  <a href={href}>{text}</a>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <Chapter chapter={minute}>
          <section className="replay" aria-label="The replay">
            <div className="wrap wrap--wide">
              <Console
                summary={summary}
                story={story}
                spans={spans}
                sceneUrl={sceneUrl}
                sceneDigest={sceneDigest}
                boxesUrl={boxesUrl}
                boxesDigest={boxesDigest}
              />
            </div>
          </section>
        </Chapter>

        <Story
          summary={summary}
          story={story}
          native={native}
          architecture={<ArchitectureDeck />}
          status={<Status measured={native && <MeasuredSummary native={native} />} films={films} />}
        />
      </main>
      <Footer credits={CREDITS} />
    </>
  );
}
