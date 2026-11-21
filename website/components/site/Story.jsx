import { stamp } from "../../lib/watch/take";
import { BeliefSum, ByteCheck, ClockStrip, FusionBench, SeekLink } from "./Benches";
import FilmFrame from "./FilmFrame";
import DeliveryDropout from "./DeliveryDropout";
import { readDeliveryDropout } from "../../lib/watch/delivery-dropout.mjs";
import { join } from "node:path";
import { AlertRun, Briefing, CoverageRuns, Custody, Detector, FusionRuns, Matches } from "./Measured";
import ViewZoomBench from "./ViewZoomBench";

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
  ["session.resume", "Pick up where the last agent stopped, listing invalidated assumptions."],
  ["session.orient", "Get the current SituationCapsule at a chosen token budget."],
  ["session.follow", "Receive meaningful decision-impact deltas and qualified silence."],
  ["query", "Ask for events, tracks, sources, recordings, localizations or reports."],
  ["investigate", "Open a durable case and keep competing hypotheses, claims and findings alive."],
  ["plan", "Compile a witnessed contingent plan with cost, risk and invalidators."],
  ["commit", "Carry out one prepared plan by digest, exactly as prepared."],
  ["wait", "Block until an expected proof arrives or a bounded deadline passes."],
  ["cancel", "Request drain, reconciliation and terminalization of owned work."],
  ["explain", "Answer why, why-not, what-changed and what-if by evidence handles."],
  ["handoff", "Publish a root-last continuation graph so nothing critical lives only in chat."],
  ["feedback", "Append an advisory outcome or correction proposal without mutating policy."],
  ["doctor", "Diagnose system, store, coverage, plan and continuity failures."],
];

const EFFECTS = [
  ["Alert the owner", "runs", "One alert per corroborated event, through a webhook you approve. Plain HTTP loopback relay so far."],
  ["Exterior lights", "planned", "Off until you grant it. A model cannot switch them directly."],
  ["Siren", "planned", "Off until you grant it. A model cannot sound it directly."],
  ["Point a camera", "planned", "Pan, tilt and zoom on cameras that support it, with lease fences and readback."],
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

function Beat({ id, step, summary, t, moment, title, children, standing, show, wide }) {
  return (
    <section className={"beat" + (wide ? " beat--wide" : "")} id={id} aria-labelledby={id + "-title"}>
      <div className="wrap beat__grid">
        <div className="beat__text">
          <div className="beat__meta">
            <span className="beat__step data">{step} / 07</span>
            <p className="beat__when">
              <SeekLink t={t}>
                <span className="data">{stamp(summary, t)}</span>
                {moment}
              </SeekLink>
            </p>
          </div>
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
  const irCount = summary.cameras.filter((cam) => cam.mode === "infrared").length;
  const colourCount = summary.cameras.length - irCount;
  const lights = story.ledger.find((row) => row.subject.startsWith("Exterior lights"));
  const object = JSON.stringify(
    { seq: lights.seq, at: lights.clock, kind: lights.kind, subject: lights.subject, grant: "night-exterior-lights", plan: "sha256:" + lights.digest.slice(0, 24) },
    null,
    2,
  );
  return (
    <div className="story night" id="how">
      <div className="wrap story__intro">
        <div>
          <p className="eyebrow data">SEVEN STEPS THROUGH ONE MINUTE</p>
          <h2 className="title">What the software has to do in that minute, one step at a time.</h2>
        </div>
        <p className="prose soft">
          Each step below is tied to a moment in the recording. Press its yellow timestamp to seek the console above,
          and compare the staged behaviour with the green panels showing what the Rust binaries actually returned.
        </p>
      </div>

      <Beat
        id="inputs"
        step="01"
        summary={summary}
        t={story.first.from}
        moment="The first camera sees movement"
        title="Five cameras from five makers, each with its own idea of the time."
        standing={[
          ["runs", "First-party pure-Rust decoders for H.264 (Baseline, Main, High), H.265 Main and JPEG/MJPEG; RTSP over TCP, HTTP MJPEG, MP4/fMP4/MKV/MPEG-TS import, UniFi Protect bindings, ONVIF loopback onboarding, LAN discovery, and a live-proven Wyze Cam v4 TUTK-NEW/DTLS 1.2 LAN path."],
          ["built", "Tuya 3.4/3.5 LAN client (loopback-verified against HomebaseSim) and fss-provision A-to-F onboarding plans separating software flashing from data capture."],
          ["planned", "Capture times kept as conservative intervals aligned across live streams from shared visual events. Today the demo films share one synthetic clock."],
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
              <div className="frames__summary">
                <p className="frames__summary-eyebrow data">ONE INSTANT · {stamp(summary, story.together)}</p>
                <p className="frames__summary-body">
                  {summary.cameras.length} feeds ({irCount} infrared, {colourCount} colour), mixed rectilinear and
                  160-degree fisheye optics, drifting up to <span className="data">{skew.toFixed(1)} s</span> apart.
                </p>
                <p className="frames__summary-foot soft">
                  Raw bytes are sealed under SHA-256 before decode. No FFmpeg enters production.
                </p>
              </div>
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
          Franken Surveillance pulls each stream itself in first-party safe Rust and stores the original bytes under a
          SHA-256 digest before anything is decoded. Where a vendor locks down firmware, the onboarding model keeps
          custom software separate from live video capture instead of promising a universal flash.
        </p>
      </Beat>

      <Beat
        id="fusion"
        step="02"
        wide
        summary={summary}
        t={story.corroborated.t}
        moment="A second camera picks up the same person"
        title="One person, counted once."
        standing={[
          ["runs", "Two-camera corroboration through ground-plane homographies or calibrated poses, with a distance gate, time gate and covariance-aware visibility guard."],
          ["built", "Schur-complement bundle adjustment, Horn absolute orientation, Brown-Conrady and fisheye lens rectification, 3-to-8 camera static matching, 4-to-16 exposure moving-point 3D fitting, and portable FSATLAS1 camera localization."],
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
          of a surveyed digital twin, so two sightings that land on the same patch of ground at the same time become one
          track rather than an alert storm.
        </p>
        <p className="prose">
          One camera fixes the bearing to a person well and the range badly. A second camera at another angle closes the
          weak axis. Drag the person around the plan, try the presets, or switch cameras off to watch the one-sigma
          ellipse change.
        </p>
      </Beat>

      <Beat
        id="coverage"
        step="03"
        summary={summary}
        t={story.unseen?.t ?? b.a_leaves_drive}
        moment={story.unseen?.moment ?? "The person leaves the drive"}
        title="It says what it cannot see."
        standing={[
          ["runs", "Nine orthogonal knowledge states, CoverageWitness intervals bound to authenticated movie presentation times, conservative screen for frozen/dark/washed-out cameras, and all 27 certified graph algorithms (including single-point-of-failure sensor cuts and temporal reachability)."],
          ["planned", "Live physical coverage maps drawn across the property twin with full occlusion geometry and FrankenNetworkX differential qualification."],
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
          them apart. Absence is only claimed inside a CoverageWitness where a working camera decoded its zone without a
          gap and saw no confirmed track entry.
        </p>
        <p className="prose">
          Every statement carries one of nine typed knowledge states, orthogonal to provenance. Only one of them, known,
          can authorize an action that cannot be undone. Underneath, certified graph algorithms identify single cameras
          whose failure opens a blind route.
        </p>
      </Beat>

      <Beat
        id="belief"
        step="04"
        summary={summary}
        t={b.a_leaves_drive + 2.2}
        moment="The agent weighs what this is"
        title="A probability you can take apart."
        standing={[
          ["runs", "Exact integer milliban fusion with Wilson score intervals, split conformal prediction, sequential e-processes and automatic counterfactual recomputation without each shared failure domain."],
          ["built", "Pure-Rust frozen Model IR, offline ONNX importer and a 16x bit-identical (0 ULP) CPU executor shipping YOLOX-Nano COCO-80. Accuracy on real camera footage has not been measured."],
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
          A conclusion is a sum of evidence, counted in integer millibans so no floating-point drift reaches a decision.
          The ban is the log-odds unit Bletchley Park codebreakers used for weighing evidence. Two cameras that share a
          failure domain, such as the same detector fooled by the same floodlight glare, collapse into one cluster
          instead of pretending to be independent.
        </p>
        <p className="prose">
          Untick any item to see what the conclusion would have been without it. The native fusion engine emits that
          counterfactual ablation for every source group it used.
        </p>
      </Beat>

      <Beat
        id="agent"
        step="05"
        summary={summary}
        t={story.corroborated.t + 1.8}
        moment="The agent asks for the situation"
        title="A briefing sized for an agent's context window."
        standing={[
          ["runs", "All 14 registered fss/1 operations and 10 query targets across the fss CLI and local stdio MCP server (fss-mcp), in 8 token-budgeted views with SemanticCompressionReceipts and root-last HandoffCapsules."],
          ["planned", "Remote, authenticated MCP transport and live operator TUI."],
        ]}
        show={
          <>
            {native && <Briefing native={native} />}
            <ViewZoomBench native={native} />
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
          gets an anchor-pinned SituationCapsule back: what is established, which high-loss alternative worlds remain
          possible, what is unknown, what it may do next and what each option costs.
        </p>
        <p className="prose">
          Every compact briefing carries a SemanticCompressionReceipt listing what was omitted and priced handles to
          hydrate deeper evidence on demand. Nothing the next agent needs is allowed to live only in a chat transcript.
          It goes into a root-last handoff.
        </p>
      </Beat>

      <Beat
        id="effects"
        step="06"
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
              pursuit, autonomous drone flight, or posing as the police. Calling emergency services needs a separate
              policy that does not exist yet.
            </p>
            {native && <AlertRun native={native} />}
          </div>
        }
      >
        <p className="prose">
          A recommendation from a model carries no authority. An action is a witnessed plan that names its preconditions
          and binds the exact WorldEnvelope digest. It is prepared against the current situation, committed by digest,
          dispatched once, and then checked against what the cameras show afterwards.
        </p>
        <p className="prose">
          In this scene the owner had granted two actions in advance: alerting them, and exterior lights at night for a
          corroborated person near the house. Closing the gate needed their approval. If an acknowledgement is lost,
          the outcome is recorded as indeterminate and the action is not blindly sent again.
        </p>
      </Beat>

      <Beat
        id="record"
        step="07"
        summary={summary}
        t={summary.duration - 2.5}
        moment="The session is handed off"
        title="Everything is written down once, and kept."
        standing={[
          ["runs", "Append-only journal with torn-tail quarantine recovery, SHA-256 source custody, child-first/root-last StagingSpool, owner privacy masks before decode/export, graph-complete local deletion closure, evidence holds and fenced local backup/restore."],
          ["planned", "Encryption at rest, RaptorQ repair symbols, off-site Backblaze B2 and Cloudflare R2 archive roots, and hash-chained/signed journals."],
        ]}
        show={
          <>
            <ByteCheck text={object} />
            {native && <Custody native={native} names={names} />}
          </>
        }
      >
        <p className="prose">
          Each source segment, sighting, decision and action enters an append-only journal. Every large object is stored
          under the SHA-256 of its own bytes, and the root naming those objects is published last, so a crash mid-write
          leaves the previous root intact.
        </p>
        <p className="prose">
          Privacy and deletion follow the same graph discipline: owner-defined masks apply before pixels reach analysis
          or exports, evidence holds block premature removal, and deletion walks every derived reference before writing
          a tombstone root. A correction is always a new revision; the old one stays where it was.
        </p>
      </Beat>
    </div>
  );
}
