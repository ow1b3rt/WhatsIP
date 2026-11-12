import { useState } from "react";
import { analyzeCapture } from "../../lib/tauri";
import type { CaptureReport, Endpoint } from "../../types/analysis";

const endpoint = (e: Endpoint) => `${e.address.includes(":") ? `[${e.address}]` : e.address}:${e.port}`;
export function AnalysisPanel() {
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<CaptureReport | null>(null);
  async function analyze() {
    setBusy(true); setError(""); setReport(null);
    try { setReport(await analyzeCapture(path.trim())); }
    catch (error) { setError(String(error)); }
    finally { setBusy(false); }
  }
  const candidates = report?.flows.flatMap(flow => flow.candidate_intervals.map(interval => ({ flow, interval }))) ?? [];
  return <section><h2>Call analysis</h2>
    <p>Analyze a saved PCAP or PCAPNG file for candidate call activity.</p>
    <form onSubmit={event => { event.preventDefault(); void analyze(); }}>
      <label htmlFor="capture-path">Capture file path</label>
      <input id="capture-path" value={path} onChange={event => setPath(event.target.value)} disabled={busy}
        placeholder="C:\Users\owl\Documents\calltest1.pcapng" required />
      <button disabled={busy || !path.trim()}>{busy ? "Analyzing…" : "Analyze capture"}</button>
    </form>
    {busy && <p role="status">Reading capture and tracking UDP flows…</p>}
    {error && <p role="alert">{error}</p>}
    {report && <>
      <p role="status">{report.total_packets} packets · {report.decoded_udp_packets} UDP decoded · {report.duration_seconds.toFixed(2)} s capture · {candidates.length} candidate interval(s)</p>
      <p className="muted">{report.skipped_packets} packets skipped · {report.truncated_packets} truncated frames</p>
      {report.warnings.map(warning => <p className="muted" key={warning}>{warning}</p>)}
      {candidates.length === 0 && <p>No candidate met the current rules. This does not rule out a call.</p>}
      {candidates.map(({ flow, interval }, index) => <article className="candidate" key={index}>
        <h3>Candidate {index + 1} · {interval.duration_seconds.toFixed(2)} s estimated activity</h3>
        <p>{endpoint(flow.endpoint_a)} ↔ {endpoint(flow.endpoint_b)}</p>
        <p>Activity: {interval.start_seconds.toFixed(2)}–{interval.end_seconds.toFixed(2)} s from capture start.
          Full flow: {(flow.last_seen_seconds - flow.first_seen_seconds).toFixed(2)} s.</p>
        <p>{interval.packets} activity packets · {flow.stun_packets} STUN packets in flow · caller/receiver unknown</p>
        <ul>{interval.evidence.map(evidence => <li key={evidence}>{evidence}</li>)}</ul>
      </article>)}
      <details><summary>All UDP flows ({report.flows.length})</summary><div className="flow-table"><table>
        <thead><tr><th>Endpoint A</th><th>Endpoint B</th><th>A → B / B → A</th><th>Frame bytes</th><th>STUN</th></tr></thead>
        <tbody>{report.flows.map((flow, index) => <tr key={index}><td>{endpoint(flow.endpoint_a)}</td><td>{endpoint(flow.endpoint_b)}</td>
          <td>{flow.packets_a_to_b} / {flow.packets_b_to_a}</td><td>{flow.frame_bytes}</td><td>{flow.stun_packets}</td></tr>)}</tbody>
      </table></div></details>
    </>}
  </section>;
}
