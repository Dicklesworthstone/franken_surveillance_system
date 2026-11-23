import { join } from "node:path";
import { readDeliveryDropout } from "../../lib/watch/delivery-dropout.mjs";
import { stamp } from "../../lib/watch/take";
import { BeliefSum, ByteCheck, ClockStrip, FusionBench, SeekLink } from "./Benches";
import { CHAPTERS } from "./chapters";
import DeliveryDropout from "./DeliveryDropout";
import FilmFrame from "./FilmFrame";
import LightsWipe from "./LightsWipe";
import { AlertRun, Briefing, CoverageRuns, Custody, Detector, FusionRuns, Matches } from "./Measured";
import { Badge, Chapter, Drawer, Figure, Section, standingLabel } from "./ui";
import ViewZoomBench from "./ViewZoomBench";

// Each state with an example line, and whether it can authorize an action that cannot be undone.
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
  [
    "Open the watch",
    [
      ["session.open", "Start a watch with a stated mission and stated authority."],
      ["session.resume", "Pick up where the last agent stopped, listing invalidated assumptions."],
      ["session.orient", "Get the current SituationCapsule at a chosen token budget."],
      ["session.follow", "Receive meaningful decision-impact deltas and qualified silence."],
    ],
  ],
  [
    "Understand",
    [
      ["query", "Ask for retained events, footage, recordings, tracks, sources, reports and four more kinds of record."],
      ["investigate", "Open a durable case and keep competing hypotheses, claims and findings alive."],
      ["explain", "Answer why, why-not, what-changed and what-if by evidence handles."],
    ],
  ],
  [
    "Act",
    [
      ["plan", "Compile a witnessed contingent plan with cost, risk and invalidators."],
      ["commit", "Carry out one prepared plan by digest, exactly as prepared."],
      ["wait", "Block until an expected proof arrives or a bounded deadline passes."],
      ["cancel", "Request drain, reconciliation and terminalization of owned work."],
    ],
  ],
  [
    "Close out",
    [
      ["handoff", "Publish a root-last continuation graph so nothing critical lives only in chat."],
      ["feedback", "Append an advisory outcome or correction proposal without mutating policy."],
      ["doctor", "Diagnose system, store, coverage, plan and continuity failures."],
    ],
  ],
];

const EFFECTS = [
  ["Alert the owner", "runs", "One alert per corroborated event, through a webhook you approve. Plain HTTP loopback relay so far."],
  ["Exterior lights", "planned", "Off until you grant it. A model cannot switch them directly."],
  ["Siren", "planned", "Off until you grant it. A model cannot sound it directly."],
  ["Point a camera", "planned", "Pan, tilt and zoom on cameras that support it, with lease fences and readback."],
  ["Close the gate", "demo", "Shown in this scene. Not in the project plan yet."],
];

/** A shape for each knowledge state, so no two are told apart by colour alone. */
function StateGlyph({ state }) {
  const ring = <circle cx="16" cy="16" r="11" />;
  const marks = {
    known: <circle cx="16" cy="16" r="11" className="is-solid" />,
    estimated: (
      <>
        <circle cx="16" cy="16" r="4.5" className="is-solid" />
        <circle cx="16" cy="16" r="11" strokeDasharray="3 3" />
      </>
    ),
    unknown: (
      <>
        {ring}
        <path d="M12.6 13.2a3.5 3.5 0 1 1 4.9 3.2c-1 .45-1.5 1-1.5 2.1" />
        <path d="M16 21.6v.1" strokeWidth="2.6" />
      </>
    ),
    conflicted: (
      <>
        <path d="M16 5a11 11 0 0 0 0 22z" className="is-solid" />
        <path d="M16 5a11 11 0 0 1 0 22" />
        <path d="M16 2v28" strokeDasharray="2.5 2.5" />
      </>
    ),
    stale: (
      <>
        {ring}
        <path d="M16 9.5V16l4.5 3" />
      </>
    ),
    not_observable: (
      <>
        <circle cx="16" cy="16" r="11" strokeDasharray="3 3" />
        <path d="M7.5 24.5l17-17" />
      </>
    ),
    redacted: <rect x="5" y="10" width="22" height="12" rx="2" className="is-solid" />,
    indeterminate: (
      <>
        <path d="M16 5a11 11 0 0 1 11 11" />
        <path d="M27 16a11 11 0 0 1-22 0A11 11 0 0 1 16 5" strokeDasharray="1.5 4" />
        <circle cx="16" cy="16" r="2" className="is-solid" />
      </>
    ),
    not_applicable: <path d="M8 16h16" />,
  };
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true">
      {marks[state]}
    </svg>
  );
}

function CalibratedExcerpt({ replay, summary }) {
  const { cluster } = replay;
  return (
    <section className="measured__excerpt" aria-labelledby="calibrated-excerpt">
      <div className="frames frames--pair">
        {replay.cameras.map((source) => {
          const camera = summary.cameras.find((c) => c.id === source.camera);
          const score = (source.score_ppm_outward[0] / 1_000_000).toFixed(3);
          return (
            <FilmFrame
              key={camera.id}
              camera={camera}
              t={(source.source_frame + 0.5) / summary.fps}
              caption={`${camera.name}, frame ${source.source_frame}. Person score ${score}.`}
            />
          );
        })}
      </div>
      <div>
        <h4 id="calibrated-excerpt">Two views of the same person</h4>
        <p>
          The front lawn and porch cameras caught the same staged performer. These are the original frames used in an
          edited {replay.source_frames.length}-frame replay.
        </p>
        <p>
          Both detections use the same model. The fusion engine counts one supporting group and asks for operator
          confirmation. Remove that group and the estimate returns to its prior of{" "}
          {String(cluster.without_cluster_millibans[0]).replace("-", "−")} millibans. The resulting advice is to retain
          the event silently.
        </p>
        <p>
          The calibration uses other frames from this staged take. Its intervals describe this replay. The event policy
          held and the run issued no alert.
        </p>
        <p className="measured__links">
          <a href={`/watch/intrusion/${replay.report.path}`}>Read the native fusion report</a>
          <a href="/watch/intrusion/fusion-replay.json">Inspect the source frames and calibration counts</a>
        </p>
      </div>
    </section>
  );
}

export default function Story({ summary, story, native, architecture, status }) {
  const b = summary.beats;
  const chapter = (id) => CHAPTERS.find((c) => c.id === id);
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
  const when = (t, moment) => (
    <SeekLink t={t} clock={stamp(summary, t)}>
      {moment}
    </SeekLink>
  );
  return (
    <>
      <Chapter chapter={chapter("how")}>
        <Section
          id="inputs"
          eyebrow="Taking video in"
          title="Five makers, [five clocks]."
          when={when(story.first.from, "The first camera sees movement")}
          standing={[
            ["runs", "First-party pure-Rust decoders for H.264 (Baseline, Main, High), H.265 Main and JPEG/MJPEG; RTSP over TCP, HTTP MJPEG, MP4/fMP4/MKV/MPEG-TS import, LAN discovery, and a live-proven Wyze Cam v4 TUTK-NEW/DTLS 1.2 LAN path."],
            ["built", "Tuya 3.4/3.5 LAN client (loopback-verified against HomebaseSim), ONVIF Media1/Media2 onboarding, UniFi Protect bindings, and fss-provision A-to-F onboarding plans separating software flashing from data capture."],
            ["planned", "Capture times kept as conservative intervals aligned across live streams from shared visual events. Today the demo films share one synthetic clock."],
          ]}
          words={
            <>
              <p className="prose">
                A cheap camera is built to work with its maker's app and nothing else. This scene uses five kinds of
                consumer product, two of them filming in infrared. Their clocks disagree by up to {skew.toFixed(1)}{" "}
                seconds, which is ordinary for devices that set the time over Wi-Fi.
              </p>
              <p className="prose">
                Franken Surveillance pulls each stream itself in first-party safe Rust and stores the original bytes
                under a SHA-256 digest before anything is decoded. Where a vendor locks down firmware, the onboarding
                model keeps custom software separate from live video capture.
              </p>
            </>
          }
        >
          <Figure
            className="inputs reveal"
            eyebrow={`One instant, ${stamp(summary, story.together)} true time`}
            title="Five films, and what each camera thought the time was."
            titleId="inputs-fig"
            badge={<Badge kind="staged">Staged films and offsets</Badge>}
            note="Raw bytes are sealed under SHA-256 before decode. No FFmpeg enters production."
          >
            <div className="frames frames--wall">
              {summary.cameras.map((cam) => (
                <FilmFrame
                  key={cam.id}
                  camera={cam}
                  t={story.together}
                  caption={
                    <>
                      <b>{cam.name}</b> {cam.product}, {cam.mode === "infrared" ? "infrared" : "colour"}
                      {cam.fisheye ? ", fisheye" : ""}
                    </>
                  }
                />
              ))}
            </div>
            <ClockStrip summary={summary} t={story.together} />
          </Figure>
        </Section>

        <Section
          id="fusion"
          eyebrow="Joining the views"
          title="One person, [counted once]."
          when={when(story.corroborated.t, "A second camera picks up the same person")}
          standing={[
            ["runs", "Two-camera corroboration through ground-plane homographies or calibrated poses, with a distance gate, time gate and covariance-aware visibility guard."],
            ["built", "Schur-complement bundle adjustment, Horn absolute orientation, Brown-Conrady and fisheye lens rectification, 3-to-8 camera static matching, 4-to-16 exposure moving-point 3D fitting, and portable FSATLAS1 camera localization."],
          ]}
          words={
            <>
              <p className="prose">
                Five cameras that each see a person raise five alerts. Franken Surveillance maps every image onto the
                ground of a surveyed digital twin, so two sightings that land on the same patch of ground at the same
                time become one track.
              </p>
              <p className="prose">
                One camera fixes the bearing to a person well and the range badly. A second camera at another angle
                closes the weak axis. Drag the person around the plan, try the presets, or switch cameras off and watch
                the ellipse change.
              </p>
            </>
          }
        >
          <FusionBench summary={summary} />
          {native && (
            <Drawer detail="Every match the tools made between two cameras, checked against where the staged people really were.">
              <Matches native={native} names={names} staged={story.corroborated.cameras} />
            </Drawer>
          )}
        </Section>
      </Chapter>

      <Chapter chapter={chapter("evidence")}>
        <Section
          id="coverage"
          eyebrow="Coverage"
          title="It says what it [cannot see]."
          when={when(story.unseen?.t ?? b.a_leaves_drive, story.unseen?.moment ?? "The person leaves the drive")}
          standing={[
            ["runs", "Nine orthogonal knowledge states, CoverageWitness intervals bound to authenticated movie presentation times, conservative screen for frozen/dark/washed-out cameras, and all 27 certified graph algorithms (including single-point-of-failure sensor cuts and temporal reachability)."],
            ["planned", "Live physical coverage maps drawn across the property twin with full occlusion geometry and FrankenNetworkX differential qualification."],
          ]}
          words={
            <>
              <p className="prose">
                A camera that saw nothing and a patch of ground that no camera covers are different facts. Absence is
                only claimed inside a coverage witness: a stretch of time in which a working camera decoded its zone
                without a gap and saw no confirmed entry.
              </p>
              <p className="prose">
                Every statement carries one of nine typed knowledge states, orthogonal to provenance. Only one of them,
                known, can authorize an action that cannot be undone.
              </p>
            </>
          }
        >
          <Figure
            className="reveal"
            eyebrow="Nine knowledge states"
            title="No blank is ever read as “nobody there”."
            titleId="states-fig"
            badge={<Badge kind="design">State registry, example lines</Badge>}
          >
            <dl className="states">
              {STATES.map(([state, example, acts]) => (
                <div key={state} className={"states__cell" + (acts ? " states__acts" : "")}>
                  <StateGlyph state={state} />
                  <dt className="data">{state}</dt>
                  <dd>
                    {example}
                    {acts && <em>The only state that can authorize an action that cannot be undone.</em>}
                  </dd>
                </div>
              ))}
            </dl>
          </Figure>
          {native && (
            <Drawer detail="The seconds of each film that one camera decoded without a gap and can vouch for.">
              <CoverageRuns native={native} names={names} />
            </Drawer>
          )}
        </Section>

        <DeliveryDropout
          replay={readDeliveryDropout(
            join(process.cwd(), "public/watch/delivery-dropout"),
            join(process.cwd(), "public/watch/intrusion/scene.json"),
          )}
        />

        <Section
          id="belief"
          eyebrow="Weighing it"
          title="A probability you can [take apart]."
          when={when(b.a_leaves_drive + 2.2, "The agent weighs what this is")}
          standing={[
            ["runs", "Exact integer milliban fusion with Wilson score intervals, split conformal prediction, sequential e-processes and automatic counterfactual recomputation without each shared failure domain."],
            ["built", "Pure-Rust frozen Model IR, offline ONNX importer and a CPU executor 16x faster than the scalar reference and bit-identical to it (0 ULP), shipping YOLOX-Nano COCO-80. Accuracy on real camera footage has not been measured."],
          ]}
          words={
            <>
              <p className="prose">
                A conclusion is a sum of evidence, counted in integer millibans so no floating-point drift reaches a
                decision. The ban is the log-odds unit Bletchley Park codebreakers used for weighing evidence.
              </p>
              <p className="prose">
                Two cameras that share a failure domain, such as the same detector fooled by the same floodlight glare,
                collapse into one cluster. The native fusion engine recomputes its answer without each source group it
                used.
              </p>
            </>
          }
        >
          <BeliefSum />
          {native && (
            <Drawer
              count={2}
              detail="The fusion engine on the same films under three declarations, and how often the shipped detector found a person who was there."
            >
              <FusionRuns native={native}>
                {native.fusionReplay && <CalibratedExcerpt replay={native.fusionReplay} summary={summary} />}
              </FusionRuns>
              <Detector native={native} names={names} />
            </Drawer>
          )}
        </Section>
      </Chapter>

      <Chapter chapter={chapter("watch")}>
        <Section
          id="agent"
          eyebrow="The briefing"
          title="A briefing with a [token budget]."
          when={when(story.corroborated.t + 1.8, "The agent asks for the situation")}
          standing={[
            ["runs", "All 14 registered fss/1 operations and 10 query targets across the fss CLI and local stdio MCP server (fss-mcp), in 8 token-budgeted views with SemanticCompressionReceipts and root-last HandoffCapsules."],
            ["planned", "Remote, authenticated MCP transport and live operator TUI."],
          ]}
          words={
            <>
              <p className="prose">
                The agent asks what is going on and gets one briefing back, pinned to a single point in the record:
                what is established, which costly possibilities are still open, what is unknown, what it may do next
                and what each option costs.
              </p>
              <p className="prose">
                Every short briefing lists what it left out, with a price on fetching each piece of deeper evidence.
                Nothing the next agent needs may live only in a chat transcript. It goes into a written handoff.
              </p>
            </>
          }
        >
          {native && <Briefing native={native} />}
          <ViewZoomBench native={native} />
          <Drawer kind="design" detail="All fourteen operations an agent can call, the same by command line and by local MCP.">
            <Figure
              eyebrow="The whole grammar"
              title="Fourteen operations, the same by command line and by MCP."
              titleId="operations-fig"
              badge={<Badge kind="design" />}
            >
              <div className="operations">
                {OPERATIONS.map(([group, rows]) => (
                  <div key={group}>
                    <h5 className="micro micro--chapter">{group}</h5>
                    <ul>
                      {rows.map(([name, text]) => (
                        <li key={name}>
                          <span className="data">{name}</span>
                          <span>{text}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </Figure>
          </Drawer>
        </Section>

        <Section
          id="effects"
          eyebrow="Effects"
          title="It can act, inside [what you allowed]."
          when={when(b.lights_on - 0.5, "The lights come on")}
          words={
            <>
              <p className="prose">
                A recommendation from a model carries no authority. An action is a written plan that names its
                preconditions and is tied by digest to the exact picture of the world it was made from. It is prepared,
                committed, dispatched once, and then checked against what the cameras show.
              </p>
              <p className="prose">
                In this scene the owner had granted two actions in advance: alerting them, and exterior lights at night
                for a corroborated person near the house. Closing the gate needed their approval. If an acknowledgement
                is lost, the outcome is recorded as indeterminate and the action is not blindly sent again.
              </p>
            </>
          }
        >
          <Figure
            className="fig--flush reveal"
            eyebrow={`${lit.name} camera`}
            title="Drag across the moment the lights were committed."
            titleId="lights-fig"
            badge={<Badge kind="staged">Staged effect, rendered films</Badge>}
          >
            <LightsWipe
              camera={lit}
              before={b.lights_on - 1.2}
              after={b.lights_on + 1.6}
              labels={[`${stamp(summary, b.lights_on - 1.2)} before`, `${stamp(summary, b.lights_on + 1.6)} after`]}
            />
          </Figure>
          <ul className="effects reveal" aria-label="Actions and where each stands">
            {EFFECTS.map(([name, kind, text]) => (
              <li key={name} className={"effects__row effects__row--" + kind}>
                <p className="effects__status">{standingLabel(kind)}</p>
                <h4>{name}</h4>
                <p>{text}</p>
              </li>
            ))}
          </ul>
          <p className="effects__never">
            <strong>Ruled out by the project.</strong> Locking or unlocking doors, anything involving a weapon, pursuit,
            autonomous drone flight, or posing as the police. Calling emergency services needs a separate policy that
            does not exist yet.
          </p>
          {native && (
            <Drawer detail="What an approved local receiver got in four cases: a first alert, the same alert again, a lost acknowledgement, and an alert the policy held.">
              <AlertRun native={native} />
            </Drawer>
          )}
        </Section>
      </Chapter>

      <Chapter chapter={chapter("machine")}>
        <Section
          id="record"
          eyebrow="Custody"
          title="Every byte has [a fingerprint]."
          when={when(summary.duration - 2.5, "The session is handed off")}
          standing={[
            ["runs", "Append-only journal with torn-tail quarantine recovery, SHA-256 source custody, child-first/root-last StagingSpool, owner privacy masks before decode/export, graph-complete local deletion closure, evidence holds and fenced local backup/restore."],
            ["planned", "Encryption at rest, RaptorQ repair symbols, off-site Backblaze B2 and Cloudflare R2 archive roots, and hash-chained/signed journals."],
          ]}
          words={
            <>
              <p className="prose">
                Each source segment, sighting, decision and action enters an append-only journal. Every large object is
                stored under the SHA-256 of its own bytes, and the root naming those objects is published last, so a
                crash mid-write leaves the previous root intact.
              </p>
              <p className="prose">
                Owner-defined masks apply before pixels reach analysis or exports, evidence holds block premature
                removal, and deletion walks every derived reference before writing a tombstone root. A correction is
                always a new revision. The old one stays where it was.
              </p>
            </>
          }
        >
          <div className="figs-2">
            <ByteCheck text={object} />
            {native && <Custody native={native} names={names} />}
          </div>
        </Section>
        {architecture}
        {status}
      </Chapter>
    </>
  );
}
