import { LivePanel } from "../features/capture/LivePanel";
import { AnalysisPanel } from "../features/calls/AnalysisPanel";

export default function App() {
  return (
    <main>
      <header><p className="eyebrow">WHATSIP / DESKTOP</p><h1>Call traffic monitor</h1>
        <p>A workspace for packet capture, network endpoints, and call timing analysis.</p></header>
      <LivePanel />
      <details><summary>Analyze a saved capture</summary><AnalysisPanel /></details>
    </main>
  );
}
