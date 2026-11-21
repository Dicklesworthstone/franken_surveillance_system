import { stamp } from "../../lib/watch/take";
import { BeliefSum, ByteCheck, ClockStrip, FusionBench, SeekLink } from "./Benches";
import FilmFrame from "./FilmFrame";
import DeliveryDropout from "./DeliveryDropout";
import { readDeliveryDropout } from "../../lib/watch/delivery-dropout.mjs";
import { join } from "node:path";
import { AlertRun, Briefing, CoverageRuns, Custody, Detector, FusionRuns, Matches } from "./Measured";

const STATES = [
  ["known", "The gate is open. Two cameras show it.", true],
  ["estimated", "The person is behind the hedge, about here, give or take four metres."],
  ["unknown", "Who they are."],
  ["conflicted", "One camera shows a person at the door. Another with the same view shows nobody."],
  ["stale", "The side-yard camera last reported eleven minutes ago."],
  ["not_observable", "No camera covers the strip behind the garage."],
  ["redacted", "The neighbour's window is inside the frame and masked by your privacy rule."],
  ["indeterminate", "The alert was sent. No acknowledgement came back."],
  ["not_applicable", "Whether the gate is shut, on a property with no gate."],
];

const OPERATIONS = [
  ["session.open", "Start a watch with a stated mission and stated authority."],
  ["session.resume", "Pick up where the last agent stopped."],
  ["session.orient", "Get the current situation at a chosen size."],
  ["session.follow", "Receive only the changes that matter."],
  ["query", "Ask for tracks, sources, positions or reports."],
  ["investigate", "Open a case and keep competing explanations alive."],
  ["plan", "List what can be done next, with cost, risk and what would undo it."],
  ["commit", "Carry out one prepared plan, exactly as prepared."],
  ["wait", "Block until an outcome arrives or a deadline passes."],
  ["cancel", "Withdraw a plan or a wait."],
  ["explain", "Show the evidence behind one conclusion."],
  ["handoff", "Write down everything the next agent needs."],
  ["feedback", "Record that a conclusion turned out right or wrong."],
  ["doctor", "Check the installation and its stores."],
];

const EFFECTS = [
  ["Alert the owner", "runs", "One alert per corroborated event, through a webhook you approve. Plain HTTP only so far."],
  ["Exterior lights", "planned", "Off until you grant it. A model cannot switch them directly."],
  ["Siren", "planned", "Off until you grant it. A model cannot sound it directly."],
  ["Point a camera", "planned", "Pan, tilt and zoom on cameras that support it."],
  ["Close the gate", "demo", "Shown in this scene. Not in the project plan yet."],
];

function Standing({ rows }) {
  const label = { runs: "Runs in tests", built: "Built, not yet proven", planned: "Planned", demo: "This demo only" };
  return (
    <ul className="standing">
      {rows.map(([kind, text]) => (
        <li key={kind + text} className={"standing__row standing__row--" + kind}>
          <strong>{label[kind]}</strong>
          <span>{text}</span>
        </li>
      ))}
    </ul>
  );
}

function CalibratedExcerpt({ replay, summary }) {
  const { cluster } = replay;
  return (
    <section className="measured__excerpt" aria-labelledby="calibrated-excerpt">
      <h4 id="calibrated-excerpt">Two views of the same person</h4>
      <p>The front lawn and porch cameras caught the same staged performer. These are the original frames used in an edited {replay.source_frames.length}-frame replay.</p>
      <div className="frames frames--pair">
        {replay.cameras.map((source) => {
          const camera = summary.cameras.find((c) => c.id === source.camera);
          const score = (source.score_ppm_outward[0] / 1_000_000).toFixed(3);
          return (
            <FilmFrame key={camera.id} camera={camera} t={(source.source_frame + 0.5) / summary.fps}
              caption={`${camera.name}, frame ${source.source_frame}. Person score ${score}.`} />
          );
        })}
      </div>
      <p>Both detections use the same model. The fusion engine counts one supporting group and asks for operator confirmation. Remove that group and the estimate returns to its prior of {String(cluster.without_cluster_millibans[0]).replace("-", "−")} millibans. The resulting advice is to retain the event silently.</p>
      <p>The calibration uses other frames from this staged take. Its intervals describe this replay. The event policy held and the run issued no alert.</p>
      <p className="measured__links">
        <a href={`/watch/intrusion/${replay.report.path}`}>Read the native fusion report</a>
        {" · "}<a href="/watch/intrusion/fusion-replay.json">Inspect the source frames and calibration counts</a>
      </p>
    </section>
  );
}

function Beat({ id, summary, t, moment, title, children, standing, show, wide }) {
  return (
    <section className={"beat" + (wide ? " beat--wide" : "")} id={id} aria-labelledby={id + "-title"}>
      <div className="wrap beat__grid">
        <div className="beat__text">
          <p className="beat__when">
            <SeekLink t={t}>
              <span className="data">{stamp(summary, t)}</span>
              {moment}
            </SeekLink>
          </p>
          <h3 className="title" id={id + "-title"}>
            {title}
          </h3>
          {children}
          {standing && <Standing rows={standing} />}
        </div>
        <div className="beat__show">{show}</div>
      </div>
    </section>
  );
}

export default function Story({ summary, story, native }) {
  const b = summary.beats;
  const names = Object.fromEntries(summary.cameras.map((cam) => [cam.id, cam.name]));
  const lit = summary.cameras.find((cam) => cam.id === "driveway") ?? summary.cameras[0];
  // The largest disagreement between any two of the cameras' clocks, in seconds.
  const offsets = summary.cameras.map((cam) => cam.offset);
  const skew = Math.max(...offsets) - Math.min(...offsets);
  const lights = story.ledger.find((row) => row.subject.startsWith("Exterior lights"));
  const object = JSON.stringify(
    { seq: lights.seq, at: lights.clock, kind: lights.kind, subject: lights.subject, grant: "night-exterior-lights", plan: "sha256:" + lights.digest.slice(0, 24) },
    null,
    2,
  );
  return (
    <div className="story night" id="how">
      <div className="wrap story__intro">
        <h2 className="title">What the software has to do in that minute, one step at a time.</h2>
        <p className="prose soft">
          Each step below is tied to a moment in the recording. Press its time to see that moment in the console above.
        </p>
      </div>

      <Beat
        id="inputs"
        summary={summary}
        t={story.first.from}
        moment="The first camera sees movement"
        title="Five cameras from five makers, each with its own idea of the time."
        standing={[
          ["runs", "RTSP over TCP, HTTP MJPEG, recorded H.264, H.265 and MJPEG files, a Wyze Cam v4 over its peer-to-peer link, UniFi Protect, discovery on the local network."],
          ["planned", "Capture times kept as intervals and aligned from shared events. Today the demo films share one synthetic clock."],
        ]}
        show={
          <>
            <div className="frames frames--wall">
              {summary.cameras.map((cam) => (
                <FilmFrame
                  key={cam.id}
                  camera={cam}
                  t={story.together}
                  caption={`${cam.name}. ${cam.product}, ${cam.mode === "infrared" ? "infrared" : "colour"}${cam.fisheye ? ", fisheye" : ""}.`}
                />
              ))}
            </div>
            <p className="frames__note">
              All five at the same instant, <span className="data">{stamp(summary, story.together)}</span> true time.
            </p>
            <ClockStrip summary={summary} t={story.together} />
          </>
        }
      >
        <p className="prose">
          A cheap camera is built to work with its maker's app and nothing else. This scene uses five kinds of consumer
          product: a bullet camera, a floodlight camera, a fisheye doorbell, a turret camera and a battery camera. The
          bullet and battery cameras film in infrared. Their clocks disagree by up to {skew.toFixed(1)} seconds, which
          is ordinary for devices that set the time over Wi-Fi.
        </p>
        <p className="prose">
          Franken Surveillance pulls each stream itself and stores the original bytes under a SHA-256 digest before
          anything is decoded. In the design, a capture time is an interval with a stated basis, and the interval
          widens when the evidence for it gets worse.
        </p>
      </Beat>

      <Beat
        id="fusion"
        wide
        summary={summary}
        t={story.corroborated.t}
        moment="A second camera picks up the same person"
        title="One person, counted once."
        standing={[
          ["runs", "Two-camera corroboration through ground-plane homographies, with a distance gate and a time gate."],
          ["built", "Matching across three to eight cameras, and a moving-point fit in 3D from two to eight."],
        ]}
        show={
          <>
            <FusionBench summary={summary} />
            {native && <Matches native={native} names={names} staged={story.corroborated.cameras} />}
          </>
        }
      >
        <p className="prose">
          Five cameras that each see a person raise five alerts. Franken Surveillance maps every image onto the ground
          of a surveyed model of the site, so two sightings that land on the same patch of ground at the same time
          become one track.
        </p>
        <p className="prose">
          One camera fixes the direction to a person well and the distance badly. A second camera at another angle
          closes the gap. Drag the person around the plan and switch cameras off to see the bound change.
        </p>
      </Beat>

      <Beat
        id="coverage"
        summary={summary}
        t={story.unseen?.t ?? b.a_leaves_drive}
        moment={story.unseen?.moment ?? "The person leaves the drive"}
        title="It says what it cannot see."
        standing={[
          ["runs", "The nine knowledge states as a typed contract, not_observable accounting in evaluation, and a screen for frozen, dark or washed-out cameras."],
          ["planned", "Coverage drawn on the site model, including which ground is seen by one camera, by several, or by none."],
        ]}
        show={
          <>
            <dl className="states">
              {STATES.map(([state, example, acts]) => (
                <div key={state} className={acts ? "states__acts" : ""}>
                  <dt className="data">{state}</dt>
                  <dd>{example}</dd>
                </div>
              ))}
            </dl>
            {native && <CoverageRuns native={native} names={names} />}
            <DeliveryDropout replay={readDeliveryDropout(join(process.cwd(), "public/watch/delivery-dropout"),
              join(process.cwd(), "public/watch/intrusion/scene.json"))} />
          </>
        }
      >
        <p className="prose">
          A camera that saw nothing and a patch of ground that no camera covers are different facts. The record keeps
          them apart. Absence is only claimed where a working camera with a clear view could have seen someone and did
          not.
        </p>
        <p className="prose">
          Every statement the system makes carries one of nine knowledge states. Only one of them, known, can authorise
          an action that cannot be undone.
        </p>
      </Beat>

      <Beat
        id="belief"
        summary={summary}
        t={b.a_leaves_drive + 2.2}
        moment="The agent weighs what this is"
        title="A probability you can take apart."
        standing={[
          ["runs", "Fusion in whole millibans with Wilson score intervals and the conclusion recomputed without each source."],
          ["built", "One detector package, YOLOX-Nano, checked against its upstream graph. Its accuracy on real footage has not been measured."],
        ]}
        show={
          <>
            <BeliefSum />
            {native && <FusionRuns native={native}>
              {native.fusionReplay && <CalibratedExcerpt replay={native.fusionReplay} summary={summary} />}
            </FusionRuns>}
            {native && <Detector native={native} names={names} />}
          </>
        }
      >
        <p className="prose">
          A conclusion is a sum of evidence, counted in millibans. The ban is the unit the Bletchley Park codebreakers
          used for weighing evidence. Each sighting adds weight for or against an explanation. Two cameras that can fail
          together, the same detector fooled by the same glare for instance, count for less than two independent ones.
        </p>
        <p className="prose">
          Untick an item to see what the conclusion would have been without it. The software reports that comparison
          for every source it used.
        </p>
      </Beat>

      <Beat
        id="agent"
        summary={summary}
        t={story.corroborated.t + 1.8}
        moment="The agent asks for the situation"
        title="A briefing sized for an agent's context window."
        standing={[
          ["runs", "All fourteen operations through the fss command line and a local MCP server, in eight views from a short pulse to a full forensic record."],
          ["planned", "Remote, authenticated MCP."],
        ]}
        show={
          <>
            {native && <Briefing native={native} />}
            <h4 className="beat__label">The fourteen operations</h4>
            <ol className="operations">
              {OPERATIONS.map(([name, text]) => (
                <li key={name}>
                  <span className="data">{name}</span>
                  <span>{text}</span>
                </li>
              ))}
            </ol>
          </>
        }
      >
        <p className="prose">
          An AI agent cannot watch five video streams all night, and should not have to. It asks for the situation and
          gets a bounded briefing back: who is on the property, how that is known, what is uncertain, what it may do
          next and what each option costs.
        </p>
        <p className="prose">
          Every summary comes with a receipt listing what was left out and a handle to fetch it. Nothing the next agent
          needs is allowed to live only in a chat transcript. It goes in the handoff.
        </p>
      </Beat>

      <Beat
        id="effects"
        summary={summary}
        t={b.lights_on - 0.5}
        moment="The lights come on"
        title="It can act, inside what you allowed."
        standing={null}
        show={
          <div className="effects">
            <div className="frames frames--pair">
              <FilmFrame camera={lit} t={b.lights_on - 1.2} caption={`${lit.name} camera, ${stamp(summary, b.lights_on - 1.2)}. Before.`} />
              <FilmFrame camera={lit} t={b.lights_on + 1.6} caption={`${stamp(summary, b.lights_on + 1.6)}. After the lights were committed.`} />
            </div>
            <table>
              <caption className="visually-hidden">Actions and where each stands</caption>
              <tbody>
                {EFFECTS.map(([name, kind, text]) => (
                  <tr key={name} className={"effects__row effects__row--" + kind}>
                    <th scope="row">{name}</th>
                    <td>
                      <strong>{{ runs: "Runs in tests", planned: "Planned", demo: "This demo only" }[kind]}</strong>
                      {text}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="effects__never">
              <strong>Ruled out by the project:</strong> locking or unlocking doors, anything involving a weapon,
              pursuit, posing as the police. Calling emergency services needs a separate policy that does not exist
              yet.
            </p>
            {native && <AlertRun native={native} />}
          </div>
        }
      >
        <p className="prose">
          A recommendation from a model carries no authority. An action is a plan that names its preconditions. It is
          prepared against the current situation, committed by digest, dispatched once, and then checked against what
          the cameras show afterwards.
        </p>
        <p className="prose">
          In this scene the owner had granted two actions in advance: alerting them, and exterior lights at night for a
          corroborated person near the house. Closing the gate needed their approval. If an acknowledgement is lost,
          the outcome is recorded as indeterminate and the action is not blindly sent again.
        </p>
      </Beat>

      <Beat
        id="record"
        summary={summary}
        t={summary.duration - 2.5}
        moment="The session is handed off"
        title="Everything is written down once, and kept."
        standing={[
          ["runs", "An append-only journal that recovers from a torn write, SHA-256 custody of source media, content-addressed objects, and a root published last."],
          ["planned", "Encryption at rest and off-site copies. The journal is not hash-chained or signed."],
        ]}
        show={
          <>
            <ByteCheck text={object} />
            {native && <Custody native={native} names={names} />}
          </>
        }
      >
        <p className="prose">
          Each source segment, sighting, decision and action goes into an append-only journal. An object is stored
          under the SHA-256 of its own bytes, and the root that names the objects is published last, so a crash in the
          middle of a write leaves the previous root intact.
        </p>
        <p className="prose">A correction is a new revision. The old one stays where it was.</p>
      </Beat>
    </div>
  );
}
