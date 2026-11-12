import { useState } from "react";
import { listInterfaces } from "../../lib/tauri";
import type { CaptureInterface } from "../../types/capture";

export function CapturePanel({ locked = false, onConfirm }: { locked?: boolean; onConfirm?: (name: string) => void }) {
  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [status, setStatus] = useState("Refresh to find capture interfaces.");
  const [busy, setBusy] = useState(false);
  const [selectedName, setSelectedName] = useState("");
  const [confirmedName, setConfirmedName] = useState("");
  const selected = interfaces.find(device => device.name === selectedName);
  const confirmed = interfaces.find(device => device.name === confirmedName);

  async function refresh() {
    setBusy(true);
    try {
      const devices = await listInterfaces();
      setInterfaces(devices);
      setSelectedName(current => devices.some(device => device.name === current) ? current : "");
      setConfirmedName(current => devices.some(device => device.name === current) ? current : "");
      if (!devices.some(device => device.name === confirmedName)) onConfirm?.("");
      setStatus(`${devices.length} capture interface(s) found.`);
    } catch (error) {
      setInterfaces([]);
      setSelectedName("");
      setConfirmedName("");
      onConfirm?.("");
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  return <section><fieldset disabled={locked}><h2>Capture interfaces</h2><p role="status">{status}</p>
    <button onClick={refresh} disabled={busy}>{busy ? "Loading…" : "Refresh interfaces"}</button>
    <div className="interface-picker">
      <label htmlFor="capture-interface">Network interface</label>
      <select id="capture-interface" value={selectedName} disabled={busy || locked || interfaces.length === 0}
        aria-describedby="interface-details"
        onChange={event => setSelectedName(event.target.value)}>
        <option value="">{interfaces.length ? "Select an interface" : "Refresh to find interfaces"}</option>
        {interfaces.map(device => <option key={device.name} value={device.name}>
          {device.description || device.name} — {device.addresses.join(", ") || "No IP addresses reported"}
        </option>)}
      </select>
      <p id="interface-details" className="muted">
        {selected ? `${selected.name} · ${selected.addresses.join(", ") || "No IP addresses reported"}` : "Choose the interface carrying your call traffic."}
      </p>
      <button disabled={busy || locked || !selected || selectedName === confirmedName}
        onClick={() => { setConfirmedName(selectedName); onConfirm?.(selectedName); }}>
        {selected && selectedName === confirmedName ? "Interface confirmed" : "Confirm interface"}
      </button>
      <p role="status">{confirmed
        ? `Confirmed interface: ${confirmed.description || confirmed.name}.`
        : "No interface confirmed."}
        {confirmed && selectedName !== confirmedName && " Confirm your new selection to change the interface."}
      </p>
    </div>
  </fieldset></section>;
}
