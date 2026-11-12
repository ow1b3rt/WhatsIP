import { useEffect, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { CapturePanel } from "./CapturePanel";
import { getLiveSnapshot, startCapture, stopCapture, resetCapture } from "../../lib/tauri";
import type { LiveSnapshot } from "../../types/live";
import { CallReport } from "../calls/CallReport";

const labels = {
  idle: "Waiting for a call", ringing: "Ringing / setting up", connected: "Call connected",
  ended: "Call ended", unanswered: "Call not connected", interrupted: "Monitoring interrupted",
};
const descriptions = {
  idle: "Start monitoring before dialing.",
  ringing: "Call setup traffic detected. Waiting for sustained two-way activity.",
  connected: "Sustained two-way call activity detected.",
  ended: "Call activity stopped. The strongest candidate is shown below.",
  unanswered: "Setup timed out without qualifying connected activity.",
  interrupted: "Monitoring stopped before the call ending could be determined.",
};
export function LivePanel() {
  const [confirmed, setConfirmed] = useState("");
  const [snapshot, setSnapshot] = useState<LiveSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [initializing, setInitializing] = useState(true);
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll() {
      try {
        if (!isTauri()) throw new Error("Open the desktop app to monitor live packets.");
        const next = await getLiveSnapshot();
        if (!disposed) { setSnapshot(next); setPollError(""); }
      } catch (error) { if (!disposed) setPollError(String(error)); }
      finally {
        if (!disposed) { setInitializing(false); timer = setTimeout(() => { void poll(); }, 500); }
      }
    }
    void poll();
    return () => { disposed = true; if (timer) clearTimeout(timer); };
  }, []);
  async function toggle(start: boolean) {
    setBusy(true); setError("");
    try {
      if (start) await startCapture(confirmed); else await stopCapture();
      setSnapshot(await getLiveSnapshot());
    } catch (error) { setError(String(error)); }
    finally { setBusy(false); }
  }
  async function reset() {
    setBusy(true); setError("");
    try {
      await resetCapture();
      setSnapshot(await getLiveSnapshot());
      setPollError("");
    } catch (error) { setError(String(error)); }
    finally { setBusy(false); }
  }
  const running = snapshot?.running ?? false;
  const status = snapshot?.call.status ?? "idle";
  const result = status === "ended" ? snapshot?.call.top_candidate : null;
  return <>
    <CapturePanel locked={initializing || busy || running} onConfirm={setConfirmed} />
    <section><h2>Live call monitor</h2>
      <div className="capture-actions">
        <button disabled={initializing || busy || running || !confirmed || !!pollError} onClick={() => { void toggle(true); }}>Start monitoring</button>
        <button disabled={initializing || busy || !running} onClick={() => { void toggle(false); }}>Stop monitoring</button>
        <button disabled={initializing || busy || !!pollError} onClick={() => { void reset(); }}
          title="Stop monitoring and clear results for a fresh start">Reset results</button>
      </div>
      <p className="muted">{busy ? "Updating capture..." : running ? "Monitoring" : "Monitoring stopped"}</p>
      {(error || pollError || snapshot?.error) && <p role="alert">{error || pollError || snapshot?.error}</p>}
      <div className={`call-status call-status-${status}`} role="status">
        <h3>{labels[status]}</h3>
        <p>{descriptions[status]}</p>
        {status === "connected" && <strong>{snapshot!.call.duration_seconds.toFixed(1)} s of estimated activity</strong>}
      </div>
      <p className="muted">Status is estimated from traffic. Ringing is not confirmed by WhatsApp; a 3-second activity gap marks the estimated end.</p>
      {result && snapshot && <CallReport key={`${snapshot.started_unix_ms}-${result.activity.start_seconds}`} snapshot={snapshot} />}
    </section>
  </>;
}
