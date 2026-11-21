import { loadTake } from "../../lib/watch/load";
import { stamp } from "../../lib/watch/take";
import ArchitectureDeck from "./ArchitectureDeck";
import Console from "./Console";
import HeroMedia from "./HeroMedia";
import { MeasuredSummary } from "./Measured";
import Status, { Footer } from "./Status";
import Story from "./Story";
import TopBar, { REPO } from "./TopBar";

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
  ["#fusion", "Place every camera in one model of the site, and count each person once"],
  ["#coverage", "Know which ground it can see, and say so when it cannot"],
  ["#belief", "Weigh what each sighting means and show the arithmetic"],
  ["#agent", "Brief an AI agent in under 1,600 tokens"],
  ["#effects", "Let that agent act, inside limits you set"],
  ["#record", "Keep an append-only record of all of it"],
];

const PILLARS = [
  [
    "Pure-Rust substrate.",
    "First-party H.264/H.265/JPEG decoders, CPU model runtime, TUTK/Tuya/ONVIF/RTSP and 27 graph algorithms. Zero unsafe code, zero FFmpeg, OpenCV or Python in production.",
  ],
  [
    "Witnessed absence.",
    "A working camera that saw nobody and a dead, blocked or masked camera are never collapsed. Every claim carries one of nine typed knowledge states.",
  ],
  [
    "Decomposable belief.",
    "Evidence adds in whole millibans with Wilson intervals and common-cause ablation, so two cameras sharing a model or lighting change cannot double-count.",
  ],
  [
    "Prepared, bounded effects.",
    "Models propose and never authorize. Consequential actions commit by digest, verify against cameras, and stay indeterminate instead of resending blindly.",
  ],
];

export default function Home() {
  const { summary, story, spans, sceneUrl, sceneDigest, renderDigest, native, boxesUrl, boxesDigest, hero, plate, films } = loadTake();
  const names = Object.fromEntries(summary.cameras.map((cam) => [cam.id, cam.name]));
  const totalMeasuredFrames = native
    ? native.cameras.reduce((sum, c) => sum + (c.custody === "ok" ? (c.frames ?? 0) : 0), 0)
    : null;
  return (
    <>
      <TopBar />
      <main id="top" data-take-digest={renderDigest}>
        <section className="hero night">
          <HeroMedia
            video={hero.video}
            still={hero.still}
            alt="A large white clapboard house at night with its floodlights on. A man in dark clothes runs down the porch steps, away from the front door."
          />
          <div className="wrap hero__body">
            <div>
              <p className="hero__eyebrow data">PURE RUST · ZERO UNSAFE · LOCAL FIRST · 22 CRATES</p>
              <h1 className="display">A security room for your house, built from $35 cameras.</h1>
              <p className="hero__lede">
                Franken Surveillance joins the cheap Wi-Fi cameras you already own, whatever the makers, into one
                calibrated, local-first model of your property. It seals raw bytes before decode, separates silence from
                blind spots, and gives an AI agent a bounded place to watch and act without vendor clouds.
              </p>
              <div className="hero__actions">
                <a className="button button--sign" href="#minute">
                  Watch one minute at 02:14
                </a>
                <a className="button button--line" href="#architecture">
                  Inspect the Rust stack
                </a>
                <a className="button button--ghost" href={REPO}>
                  Read the source
                </a>
              </div>
            </div>
            <p className="hero__stamp">
              <strong>{stamp(summary, summary.beats.lights_on ?? 0)}</strong>
              Rendered scene, fictional house
            </p>
          </div>
          <div className="hero__status">
            <div className="wrap hero__status-row">
              <p>
                Open source and unfinished. The scene on this page is staged: a rendered house, motion-captured actors and
                a scripted agent. Each figure says whether the software measured it. <a href="#status">What runs today</a>
              </p>
              {totalMeasuredFrames != null && (
                <p className="hero__telemetry data">
                  {summary.cameras.length} films · {totalMeasuredFrames.toLocaleString("en")} frames measured · 14 fss/1 ops
                </p>
              )}
            </div>
          </div>
        </section>

        <section className="pitch night" aria-label="The idea">
          <div className="wrap">
            <div className="pitch__grid">
              <p className="pitch__thesis">
                Airports and borders have had this for decades: many sensors joined into one picture, watched around the
                clock by trained staff.{" "}
                <em>
                  The parts are cheap now. A Wi-Fi camera costs $35 and an AI agent can do the watching. Franken
                  Surveillance is the deterministic evidence fabric in between.
                </em>
              </p>
              <nav aria-labelledby="pitch-steps">
                <h2 id="pitch-steps">What that software has to do</h2>
                <ol>
                  {STEPS.map(([href, text]) => (
                    <li key={href}>
                      <a href={href}>{text}</a>
                    </li>
                  ))}
                </ol>
              </nav>
            </div>
            <ul className="pillars" aria-label="Core architectural differences">
              {PILLARS.map(([lead, body]) => (
                <li key={lead}>
                  <strong>{lead}</strong> {body}
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="minute night" id="minute" aria-labelledby="minute-title">
          <div className="wrap">
            <div className="minute__intro">
              <div>
                <p className="eyebrow data">SYNCHRONIZED REPLAY · 02:14:00 TO 02:15:01</p>
                <h2 className="title" id="minute-title">
                  One minute, {summary.cameras.length === 5 ? "five" : summary.cameras.length} cameras, two people who should not be there.
                </h2>
              </div>
              <div>
                <p className="prose soft">
                  At 02:14 one man comes in through the gate while another keeps watch outside it. Press play, step
                  between moments or drag the timeline. The films, the site model, the agent and the ledger all run off
                  one clock.
                </p>
                <p className="minute__key">
                  <span className="source source--staged">Dashed outline: staged position</span>
                  {boxesUrl && <span className="source source--measured">Solid outline: the detector's own box</span>}
                  <span className="source source--browser">Bounds: computed in your browser from camera geometry</span>
                  <span className="source source--staged">
                    Yellow fans: each lens on open ground, not cut by walls or trees
                  </span>
                </p>
              </div>
            </div>
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

        {plate && (
          <figure className="plate night">
            <img
              src={plate + "-1280.jpg"}
              srcSet={`${plate}-1280.jpg 1280w, ${plate}-2560.jpg 2560w`}
              sizes="100vw"
              width="2560"
              height="1097"
              loading="lazy"
              alt="The front of the house with the floodlights on. A man in dark clothes runs across the lawn away from the porch, throwing a long shadow. A security camera on a post stands in the foreground."
            />
            <figcaption className="wrap">
              <span className="data">{stamp(summary, summary.beats.a_turns_to_run + 3.6)}</span> from the lawn. A clean
              render of the scene the five cameras filmed.
            </figcaption>
          </figure>
        )}

        <Story summary={summary} story={story} native={native} />
        <ArchitectureDeck />
        <Status measured={native && <MeasuredSummary native={native} names={names} />} films={films} />
      </main>
      <Footer credits={CREDITS} />
    </>
  );
}
