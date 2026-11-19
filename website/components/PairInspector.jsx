import { cameras, recording, stamp } from "../lib/scenarios";

const dispositions = {
  no_counterpart_entry: "No entry from the other camera",
  no_admissible_counterpart: "No matching entry within the gates",
  time_gate_uncertain: "Capture timing too uncertain",
};

export default function PairInspector({
  camera,
  peer,
  setPeer,
  report,
  status,
  at,
  time,
}) {
  return (
    <>
      <div className="facts">
        <div>
          <label htmlFor="comparison-camera">Second camera</label>
          <select
            id="comparison-camera"
            value={peer.id}
            onChange={(e) => setPeer(e.target.value)}
          >
            {cameras
              .filter((c) => c.id !== camera.id)
              .map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label}
                </option>
              ))}
          </select>
        </div>
        {report && (
          <>
            <div>
              <span>Ground-zone entries</span>
              <strong>{report.entries.length}</strong>
            </div>
            <div>
              <span>Paired candidates</span>
              <strong>{report.candidate_count}</strong>
            </div>
          </>
        )}
      </div>
      {report ? (
        <div className="trace native-trace">
          <div className="micro">GROUND-ZONE ENTRIES</div>
          {report.entries
            .toSorted((a, b) => a.segment - b.segment)
            .map((entry) => {
              const t = entry.segment / recording.nativeFps;
              return (
                <button
                  key={entry.observation_digest}
                  className={time >= t ? "reached" : ""}
                  onClick={() => at(t)}
                >
                  <span className="trace-dot" />
                  <span>
                    {cameras.find((c) => c.id === entry.camera).label} ·{" "}
                    {dispositions[entry.disposition] ??
                      entry.disposition.replaceAll("_", " ")}
                  </span>
                  <time>{stamp(t, true)}</time>
                </button>
              );
            })}
          {report.entries.length === 0 && (
            <p>
              Neither camera produced a measured entry in this ground zone. The
              subject may still be present.
            </p>
          )}
          {report.candidates.map((candidate) => (
            <p key={candidate.candidate_id}>
              {candidate.event_state.replaceAll("_", " ")} · policy{" "}
              {candidate.policy_action}
            </p>
          ))}
        </div>
      ) : (
        <p role="status">
          {status === "error"
            ? "Pair report unavailable."
            : "Loading pair report…"}
        </p>
      )}
      <p className="comparison-note">
        Both recordings share a simulated scene and clock. FSS compares ground
        entries within{" "}
        {report
          ? report.distance_gate + " m and " + report.time_gate_ns / 1e6 + " ms"
          : "the configured spatial and time gates"}
        . Independent confirmation requires separate evidence.
      </p>
    </>
  );
}
