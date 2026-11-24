import { Mark, REPO } from "./TopBar";
import { Badge, Figure, Section } from "./ui";

const COLUMNS = [
  [
    "runs",
    "Runs in tests",
    [
      "File import (MP4, fMP4, MKV, MPEG-TS, MJPEG, Annex-B) with SHA-256 custody of the raw bytes",
      "Live capture over RTSP on TCP, HTTP MJPEG, and Wyze Cam v4 over pure-Rust TUTK-NEW/DTLS 1.2 on owner LAN",
      "Pure-Rust decoding of baseline JPEG/MJPEG, and of H.264 (Baseline, Main, High) and 8-bit H.265 Main bit-exact against FFmpeg on fixtures",
      "Model-free foreground watch, Kalman/Hungarian tracking, and two-camera corroboration",
      "Frozen Model IR and a CPU executor 16x faster than the scalar reference and bit-identical to it, shipping YOLOX-Nano COCO-80",
      "Integer milliban evidence fusion with Wilson intervals, split conformal prediction and common-cause ablation",
      "All 27 registered graph algorithms certified against in-tree brute-force oracles",
      "Crash-safe append journal, root-last StagingSpool, owner privacy masks, graph-complete deletion closure, evidence holds and fenced local backup",
      "One owner alert per corroborated event through an approved loopback HTTP webhook, never resent on lost ACK",
      "All 14 fss/1 agent operations and 10 query targets via CLI and local stdio MCP server (fss-mcp)",
    ],
  ],
  [
    "built",
    "Built, not yet proven",
    [
      "3-to-8 camera static matching and 4-to-16 exposure moving-point 3D fitting (fss-scene-fuse)",
      "Schur-complement bundle adjustment, Brown-Conrady/fisheye rectification and FSATLAS1 camera localization",
      "Tuya 3.4/3.5 LAN client, ONVIF Media1/Media2 onboarding, UniFi Protect bindings and atomic site probing",
      "Factory-state camera onboarding plans across friction classes A to F (fss-provision)",
      "Real-footage detection recall, AUPRC and score calibration for YOLOX-Nano",
    ],
  ],
  [
    "planned",
    "Planned",
    [
      "Live capture-time intervals aligned across cameras from shared physical events",
      "Live property coverage maps with full 3D occlusion and FrankenNetworkX differential gates",
      "Exterior lights, siren, PTZ and TLS production alert providers under explicit grants",
      "Encryption at rest, RaptorQ repair symbols and off-site Backblaze B2 / Cloudflare R2 archive roots",
      "Remote authenticated MCP, live operator TUI, USB UVC capture and local DSR release qualification",
    ],
  ],
];

const NOT = [
  "A way into cameras, accounts or footage that are not yours.",
  "Covert monitoring or evasion of owner indicators.",
  "Face recognition across properties, or any shared biometric identity network.",
  "A promise that nothing can be missed.",
  "Anything armed, confrontational or pursuing, including drones that fly themselves.",
  "A cloud-required service or a Rust wrapper around FFmpeg and Python.",
];

export default function Status({ measured, films }) {
  return (
    <Section
      id="status"
      eyebrow="Pre-release reference"
      title="What [runs today]."
      words={
        <p className="prose">
          Franken Surveillance is an unqualified reference implementation: 22 safe Rust crates and 48 binaries, unsafe code
          forbidden in all of them, tested on generated fixtures, offline oracles and lab loopback rigs (plus one owner-LAN
          Wyze Cam v4 capture proof). It has not been qualified for release, and no detection accuracy has been measured on
          real camera footage.
        </p>
      }
    >
      <div className="status__grid reveal">
        {COLUMNS.map(([kind, title, rows]) => (
          <div key={kind} className={"status__col status__col--" + kind}>
            <h4>
              {title}
              <span className="data">{rows.length}</span>
            </h4>
            <ul>
              {rows.map((row) => (
                <li key={row}>{row}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <Figure className="real" eyebrow="This page" title="What is real on this page." titleId="real-title">
        <div className="real__halves">
          <div>
            <Badge kind="staged">Staged</Badge>
            <p>
              The house, which is fictional and rendered. The two people, who are 3D scans of real people moved by motion
              capture. The films, which are renders graded to look like five kinds of camera. The positions outlined in them.
              The agent's calls, the ledger rows, the lights and the gate. They show how the system is designed to behave.
            </p>
            {films?.held > 0 && (
              <p>
                Where nobody is in view, a film holds one rendered picture under fresh sensor noise. That is{" "}
                {films.held.toLocaleString("en")} of the {films.frames.toLocaleString("en")} frames. Over those stretches the
                detector, the motion watch and the coverage watch were looking at a still.
              </p>
            )}
          </div>
          <div>
            <Badge kind="measured">Measured</Badge>
            {measured ?? (
              <p>
                The project's own binaries are being run on these films. Their output will be listed here with the commands
                that produced it.
              </p>
            )}
          </div>
        </div>
      </Figure>

      <Figure className="nots" eyebrow="Scope" title="What it will not be." titleId="not-title">
        <ul>
          {NOT.map((row) => (
            <li key={row}>{row}</li>
          ))}
        </ul>
      </Figure>
    </Section>
  );
}

export function Footer({ credits }) {
  return (
    <footer className="footer" data-outside>
      <div className="wrap footer__grid">
        <div>
          <p className="footer__mark">
            <Mark />
            <span>Franken Surveillance</span>
          </p>
          <p className="footer__line">
            Local first, pure Rust, unsafe code forbidden. Video stays on a machine you own, and the software only talks to cameras and
            accounts that are yours.
          </p>
          <ul className="footer__links">
            <li>
              <a href={REPO}>Source on GitHub</a>
            </li>
            <li>
              <a href={REPO + "/blob/main/ARCHITECTURE.md"}>Architecture</a>
            </li>
            <li>
              <a href={REPO + "/blob/main/DEPENDENCY_CONSTITUTION.md"}>Dependency constitution</a>
            </li>
            <li>
              <a href={REPO + "/blob/main/IMPLEMENTATION_STATUS.md"}>Implementation status</a>
            </li>
            <li>
              <a href={REPO + "/blob/main/COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md"}>The plan</a>
            </li>
          </ul>
        </div>
        <div className="footer__credits" id="credits">
          <h2 className="micro">Scene credits</h2>
          {credits}
        </div>
      </div>
    </footer>
  );
}
