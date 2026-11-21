import { REPO } from "./TopBar";

const COLUMNS = [
  [
    "runs",
    "Runs in tests",
    [
      "Import of recorded video with SHA-256 custody of the original bytes",
      "Live capture over RTSP on TCP and over HTTP MJPEG",
      "Decoding of MJPEG, H.264 and 8-bit H.265",
      "A motion watch that needs no trained model",
      "Person detection with one small model",
      "Tracking, and corroboration between two cameras",
      "Evidence fusion with the conclusion recomputed without each source",
      "A local ledger that survives a crash mid-write",
      "One owner alert per corroborated event, through a webhook you approve",
      "All fourteen agent operations, by command line and by local MCP server",
    ],
  ],
  [
    "built",
    "Built, not yet proven",
    [
      "Matching one person across three to eight cameras",
      "Fitting a moving point in 3D from several cameras",
      "Adding a new camera to an already surveyed site",
      "Setup plans for several families of low-cost camera",
      "Checking a site description and probing its sources before use",
    ],
  ],
  [
    "planned",
    "Planned",
    [
      "Capture times as intervals, aligned across cameras",
      "Coverage drawn on the site model",
      "Lights, siren and camera pointing as actions you grant",
      "Encrypted storage and an off-site copy",
      "Measurement on real footage, then release qualification",
    ],
  ],
];

export default function Status({ measured, films }) {
  return (
    <section className="status day" id="status" aria-labelledby="status-title">
      <div className="wrap">
        <div className="status__intro">
          <h2 className="title" id="status-title">
            What runs today.
          </h2>
          <p className="prose">
            Franken Surveillance is a reference implementation: 22 Rust crates, unsafe code forbidden in all of them,
            tested on generated fixtures and lab loopback rigs. It has not been qualified for release, and nothing has
            yet been measured on footage from real cameras.
          </p>
        </div>
        <div className="status__grid">
          {COLUMNS.map(([kind, title, rows]) => (
            <div key={kind} className={"status__col status__col--" + kind}>
              <h3>{title}</h3>
              <ul>
                {rows.map((row) => (
                  <li key={row}>{row}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="status__page">
          <h3 className="subtitle">What is real on this page.</h3>
          <div className="status__halves">
            <div>
              <p className="source source--staged">Staged</p>
              <p>
                The house, which is fictional and rendered. The two people, who are 3D scans of real people moved by
                motion capture. The films, which are renders graded to look like five kinds of camera. The positions
                outlined in them. The agent's calls, the ledger rows, the lights and the gate. They show how the system
                is designed to behave.
              </p>
              {films?.held > 0 && (
                <p>
                  Where nobody is in view, a film holds one rendered picture under fresh sensor noise. That is{" "}
                  {films.held.toLocaleString("en")} of the {films.frames.toLocaleString("en")} frames. Over those
                  stretches the detector, the motion watch and the coverage watch were looking at a still.
                </p>
              )}
            </div>
            <div>
              <p className="source source--measured">Measured</p>
              {measured ?? (
                <p>
                  The project's own binaries are being run on these films. Their output will be listed here with the
                  commands that produced it.
                </p>
              )}
            </div>
          </div>
        </div>
        <div className="status__ends">
          <div>
            <h3 className="subtitle">What it will not be.</h3>
            <ul className="status__not">
              {NOT.map((row) => (
                <li key={row}>{row}</li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="subtitle">Look inside.</h3>
            <pre className="status__run data">
              <code>{RUN}</code>
            </pre>
            <p className="soft">
              <span className="data">capabilities</span> lists what this build can do.{" "}
              <span className="data">doctor</span> checks the installation and its stores. A passing build does not
              qualify any camera, codec or model.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

const NOT = [
  "A way into cameras, accounts or footage that are not yours.",
  "Covert monitoring.",
  "Face recognition across properties, or any shared identity network.",
  "A promise that nothing can be missed.",
  "Anything armed, confrontational or pursuing, including drones that fly themselves.",
  "A cloud service. It runs on a machine you own.",
];

const RUN = `git clone ${REPO}
cd franken_surveillance_system
cargo run -p fss-cli -- capabilities --json
cargo run -p fss-cli -- doctor --json`;

export function Footer({ credits }) {
  return (
    <footer className="footer day">
      <div className="wrap footer__grid">
        <div>
          <h2>Franken Surveillance</h2>
          <p className="soft">
            Local first. Video stays on a machine you own, and the software only talks to cameras and accounts that are
            yours.
          </p>
          <p className="footer__links">
            <a href={REPO}>Source on GitHub</a>
            <a href={REPO + "/blob/main/IMPLEMENTATION_STATUS.md"}>Implementation status</a>
            <a href={REPO + "/blob/main/COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md"}>The plan</a>
          </p>
        </div>
        <div className="footer__credits" id="credits">
          <h2>Scene credits</h2>
          {credits}
        </div>
      </div>
    </footer>
  );
}
