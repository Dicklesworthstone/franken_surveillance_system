"use client";
import { useRef, useState } from "react";

const SUBSTRATE_STATS = [
  ["22", "Safe Rust crates", "unsafe_code forbidden across every crate, binary and test"],
  ["48", "Compiled binaries", "capture, decode, infer, scene-fuse, graph, MCP and doctor"],
  ["4", "Direct external crates", "asupersync, chacha20poly1305, zeroize, nix (no FFmpeg, OpenCV, Python, ONNX Runtime, Tokio or serde)"],
  ["27", "Certified graph algorithms", "canonical tie-breaks, fail-closed work bounds and complexity witnesses"],
  ["14 / 8", "Agent ops and views", "shared fss/1 contract across CLI and local stdio MCP"],
  ["0 ULP", "CPU kernel parity", "16x faster YOLOX-Nano executor bit-identical to scalar oracle (4.85 MB peak activations)"],
];

const PLANES = [
  {
    id: "packet",
    code: "PLANE 01",
    name: "Packet",
    role: "Wire bytes, container framing and source continuity",
    owns: "First-party parsing of RTP/RTCP, RTSP over TCP, HTTP MJPEG, MP4/fMP4, Matroska, MPEG-TS, ONVIF XML, UniFi extended-FLV, TUTK-NEW (0xCC51 with DTLS 1.2) and Tuya 3.4/3.5 LAN frames. Stores exact original bytes under SHA-256 before anything decodes.",
    forbids: "Cannot invent capture timestamps, claim physical continuity after a gap, decode audio by default, or mutate policy or alert state.",
    crates: ["fss-packet", "fss-container", "fss-codec-h264", "fss-codec-h265", "fss-codec-mjpeg", "fss-codec-jpeg-encode", "fss-tutk", "fss-tuya", "fss-provision"],
    binaries: ["fss-capture-rtsp", "fss-capture-tutk", "fss-capture-tuya", "fss-capture-onvif", "fss-discover", "fss-file", "fss-probe"],
    proof: "Bit-exact H.264 High (27.3 to 50.6 fps on 1080p) and H.265 Main (26.7 fps) against offline FFmpeg oracles; Wyze Cam v4 LAN lifecycle live-proven on owner hardware.",
    standing: "runs",
  },
  {
    id: "authority",
    code: "PLANE 02",
    name: "Authority",
    role: "Canonical history, custody, coverage, privacy and deletion",
    owns: "The single ordered EvidenceDeltaBatch history, crash-classifying append journal with torn-tail quarantine, child-first/root-last StagingSpool publication, CoverageWitness records, owner privacy masks, evidence holds, graph-complete deletion closure and fenced recovery backups.",
    forbids: "Never trusts model outputs as ground truth, never exposes uncommitted children through a published root, and never deletes objects locked by an active hold.",
    crates: ["fss-core", "fss-runtime", "fss-ledger", "fss-object", "fss-publication"],
    binaries: ["fss", "fss-custody", "fss-hold", "fss-backup", "fss-archive", "fss-export"],
    proof: "Torn-tail recovery, immutable sealed readers coexisting with active capture writers, graph-complete local deletion closure and irreversible restore fences tested in suite.",
    standing: "runs",
  },
  {
    id: "cognition",
    code: "PLANE 03",
    name: "Cognition",
    role: "Models, 3D geometry, calibrated fusion and certified graphs",
    owns: "Frozen Model IR (v1/v2) + offline ONNX importer, scalar and 16x bit-identical CPU executors, YOLOX-Nano COCO-80 package, HOG/Kalman/Hungarian tracking, Schur-complement bundle adjustment, Brown-Conrady/fisheye rectification, FSATLAS1 localization, integer milliban fusion with Wilson/conformal/e-process math, and all 27 registered graph algorithms.",
    forbids: "Cognition is strictly derived and rebuildable. No detector score, tracker output, graph cut or VLM summary can alter canonical custody or grant effect authority.",
    crates: ["fss-tensor", "fss-model-ir", "fss-geometry", "fss-twin", "fss-fusion", "fss-graph-algorithms"],
    binaries: ["fss-infer", "fss-event", "fss-fuse", "fss-scene-fuse", "fss-evaluate", "fss-cover", "fss-clock-align"],
    proof: "YOLOX-Nano conforms to ONNX Runtime 1.30.0 (max error 3e-5, 0 ULP scalar-vs-optimized); all 27 graph algorithms pass brute-force oracle checks; real-footage accuracy remains unmeasured.",
    standing: "built",
  },
  {
    id: "effect",
    code: "PLANE 04",
    name: "Effect",
    role: "Capability-scoped, idempotent external actions",
    owns: "Two-phase prepare, revalidate, commit, observe and reconcile lifecycle over durable EffectJournal records with idempotency keys, precondition digests, lease fences and explicit indeterminate states when a remote acknowledgement is lost.",
    forbids: "Never resends an unacknowledged dispatch blindly, never grants ambient credentials, and permanently rules out doors, weapons, pursuit or autonomous drone flight.",
    crates: ["fss-runtime", "fss-reference", "fss-cli"],
    binaries: ["fss-alert", "fss-review", "fss-export-package"],
    proof: "Loopback HTTP webhook relay proves single POST on repeat approval and zero duplicate POSTs when the receiver drops the connection without replying; TLS and physical actuators are planned.",
    standing: "runs",
  },
  {
    id: "membrane",
    code: "MEMBRANE",
    name: "Agent Operating Layer (fss/1)",
    role: "SituationCapsule, WorldEnvelope, investigations and handoffs",
    owns: "Composes lower planes into anchor-pinned SituationCapsules across 8 token-budgeted views, preserves high-loss possible worlds across compression with SemanticCompressionReceipts, tracks durable InvestigationCases, work claims and shared findings, and writes root-last HandoffCapsules so zero critical state lives only in chat.",
    forbids: "Not a fourth truth plane. Cannot strengthen a knowledge state, erase a failure domain, drop a protected warning to fit a token budget, or bypass effect authority.",
    crates: ["fss-core", "fss-reference", "fss-cli"],
    binaries: ["fss", "fss-mcp", "fss-hydration-rehearsal"],
    proof: "All 14 registered fss/1 operations and 10 query targets run identically across the CLI and local stdio MCP server; remote authenticated MCP is planned.",
    standing: "runs",
  },
];

const COMPARISON = [
  {
    dim: "Source custody",
    nvr: "Transcodes or overwrites rolling clips; mutable database",
    homelab: "Records clips via FFmpeg; no cryptographic source binding",
    vlm: "Samples transient JPEGs or video URLs with no retention proof",
    fss: "Seals raw stream bytes under SHA-256 before decode; child-first, root-last publication",
  },
  {
    dim: "Camera gaps and absence",
    nvr: "Quiet camera and failed camera both appear as no motion events",
    homelab: "Missing detections look empty unless manually monitored",
    vlm: "Prompts frequently hallucinate an all-clear across missed frames",
    fss: "Separates working silence from missing input via CoverageWitness and 9 typed knowledge states",
  },
  {
    dim: "Production runtime",
    nvr: "Proprietary C/C++ appliances or closed Windows/Linux binaries",
    homelab: "Glues Python, Node, FFmpeg, OpenCV, ONNX Runtime and MQTT",
    vlm: "Cloud API calls plus Python/JS orchestration glue",
    fss: "100% safe pure Rust (unsafe forbidden), 4 direct deps, zero foreign production runtimes",
  },
  {
    dim: "Belief and shared faults",
    nvr: "Binary motion triggers or vendor alert toggles",
    homelab: "Per-camera confidence thresholds trigger automations directly",
    vlm: "Unverified prose confidence ('high confidence intruder')",
    fss: "Integer milliban log-odds with Wilson intervals and common-cause failure-domain ablation",
  },
  {
    dim: "AI agent control",
    nvr: "No native agent control contract",
    homelab: "Ad-hoc tool wrappers over REST/MQTT endpoints",
    vlm: "Free-form prompt state lost across sessions; model calls act directly",
    fss: "14 typed fss/1 ops, token-budgeted SituationCapsules, compression receipts and root-last handoffs",
  },
  {
    dim: "Consequential effects",
    nvr: "Best-effort push/email; retries can duplicate or silently drop",
    homelab: "Fire-and-forget webhooks or automations tied to detector events",
    vlm: "Tool call executes immediately with ambient API credentials",
    fss: "Prepare, revalidate, commit by digest, observe, reconcile; lost ACK stays indeterminate, never resent",
  },
  {
    dim: "Privacy and deletion",
    nvr: "Manual clip deletion; derived thumbnails/logs often linger",
    homelab: "Optional zone masks; manual cleanup across DB and clips",
    vlm: "Raw home frames uploaded to third-party model APIs",
    fss: "Local-first; masks applied before analysis/export; graph-complete deletion closure with evidence holds",
  },
];

const STANDING_LABEL = {
  runs: "Runs in tests",
  built: "Built, not yet proven on real footage",
  planned: "Planned",
};

export default function ArchitectureDeck() {
  const [activeId, setActiveId] = useState("packet");
  const tabRefs = useRef([]);
  const plane = PLANES.find((p) => p.id === activeId) ?? PLANES[0];

  const onTabKeyDown = (event, index) => {
    let next = null;
    if (event.key === "ArrowDown" || event.key === "ArrowRight") next = (index + 1) % PLANES.length;
    else if (event.key === "ArrowUp" || event.key === "ArrowLeft") next = (index - 1 + PLANES.length) % PLANES.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = PLANES.length - 1;
    if (next == null) return;
    event.preventDefault();
    setActiveId(PLANES[next].id);
    tabRefs.current[next]?.focus();
  };

  return (
    <section className="arch night" id="architecture" aria-labelledby="arch-title">
      <div className="wrap">
        <div className="arch__intro">
          <div>
            <p className="eyebrow data">CLOSED PURE-RUST SUBSTRATE</p>
            <h2 className="title" id="arch-title">
              Built like a flight recorder, not a home-lab script.
            </h2>
          </div>
          <p className="prose soft">
            Most camera stacks bolt Python or Node glue onto FFmpeg, OpenCV, ONNX Runtime and a vendor cloud. Franken
            Surveillance owns the packet parser, video decoders, CPU model executor, 3D geometry solvers, graph kernels
            and crash-safe ledger in one safe Rust workspace, with zero unsafe code and four direct external crates.
          </p>
        </div>

        <dl className="substrate" aria-label="Verified workspace measurements">
          {SUBSTRATE_STATS.map(([value, label, note]) => (
            <div key={label} className="substrate__item">
              <dt className="substrate__val data">{value}</dt>
              <dd>
                <strong>{label}</strong>
                <span>{note}</span>
              </dd>
            </div>
          ))}
        </dl>

        <div className="planes" aria-labelledby="planes-title">
          <div className="planes__head">
            <h3 className="subtitle" id="planes-title">
              Four separated planes and one agent operating membrane.
            </h3>
            <p className="soft">
              A decoded frame is not source continuity. A model score is not physical fact. A webhook reply is not
              verified delivery. Select a layer to inspect its boundary, crates and current proof.
            </p>
          </div>

          <div className="planes__layout">
            <div className="planes__tabs" role="tablist" aria-label="Operational planes">
              {PLANES.map((item, i) => {
                const selected = item.id === plane.id;
                return (
                  <button
                    key={item.id}
                    ref={(el) => { tabRefs.current[i] = el; }}
                    type="button"
                    role="tab"
                    id={`plane-tab-${item.id}`}
                    tabIndex={selected ? 0 : -1}
                    aria-selected={selected}
                    aria-controls={`plane-panel-${item.id}`}
                    className={"planes__tab" + (selected ? " is-active" : "")}
                    onKeyDown={(e) => onTabKeyDown(e, i)}
                    onClick={() => setActiveId(item.id)}
                  >
                    <span className="planes__code data">{item.code}</span>
                    <span className="planes__name">{item.name}</span>
                    <span className="planes__role">{item.role}</span>
                  </button>
                );
              })}
            </div>

            <div
              className="planes__panel"
              role="tabpanel"
              id={`plane-panel-${plane.id}`}
              aria-labelledby={`plane-tab-${plane.id}`}
            >
              <div className="planes__panel-top">
                <div>
                  <p className="planes__code data">{plane.code}</p>
                  <h4>{plane.name}</h4>
                </div>
                <span className={"planes__standing planes__standing--" + plane.standing}>
                  {STANDING_LABEL[plane.standing]}
                </span>
              </div>

              <dl className="planes__facts">
                <div>
                  <dt>What it owns</dt>
                  <dd>{plane.owns}</dd>
                </div>
                <div className="planes__forbids">
                  <dt>Hard boundary</dt>
                  <dd>{plane.forbids}</dd>
                </div>
                <div>
                  <dt>Checked-in crates</dt>
                  <dd className="planes__chips">
                    {plane.crates.map((crateName) => (
                      <span key={crateName} className="chip data">
                        {crateName}
                      </span>
                    ))}
                  </dd>
                </div>
                <div>
                  <dt>Key binaries</dt>
                  <dd className="planes__chips">
                    {plane.binaries.map((binName) => (
                      <span key={binName} className="chip chip--bin data">
                        {binName}
                      </span>
                    ))}
                  </dd>
                </div>
                <div>
                  <dt>Current evidence</dt>
                  <dd>{plane.proof}</dd>
                </div>
              </dl>
            </div>
          </div>
        </div>

        <div className="compare" aria-labelledby="compare-title">
          <div className="compare__head">
            <h3 className="subtitle" id="compare-title">
              How it differs from ordinary setups.
            </h3>
            <p className="soft">
              Incumbent NVRs and home-lab stacks are mature, proven tools with broad camera ecosystems today. Franken
              Surveillance is an unqualified reference implementation built around a stricter architectural thesis.
            </p>
          </div>
          <p className="compare__hint data" aria-hidden="true">
            SCROLL SIDEWAYS TO COMPARE ALL FOUR APPROACHES
          </p>
          <div className="compare__scroll">
            <table className="compare__table">
              <thead>
                <tr>
                  <th scope="col">Dimension</th>
                  <th scope="col">Ordinary NVR</th>
                  <th scope="col">Home-lab glue</th>
                  <th scope="col">VLM on frames</th>
                  <th scope="col" className="is-fss">
                    Franken Surveillance
                  </th>
                </tr>
              </thead>
              <tbody>
                {COMPARISON.map((row) => (
                  <tr key={row.dim}>
                    <th scope="row">{row.dim}</th>
                    <td>{row.nvr}</td>
                    <td>{row.homelab}</td>
                    <td>{row.vlm}</td>
                    <td className="is-fss">{row.fss}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  );
}
