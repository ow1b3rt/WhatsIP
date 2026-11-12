import { useEffect, useState } from "react";
import { lookupIp } from "../../lib/tauri";
import type { IpInfo } from "../../types/enrichment";
import type { LiveSnapshot } from "../../types/live";

const unknown = "Unknown";
const privateV4 = (ip: string) => {
  const parts = ip.split(".").map(Number);
  return parts.length === 4 && (parts[0] === 10 || (parts[0] === 192 && parts[1] === 168)
    || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31));
};
export function CallReport({ snapshot }: { snapshot: LiveSnapshot }) {
  const result = snapshot.call.top_candidate!;
  const aLocal = snapshot.local_addresses.includes(result.endpoint_a.address);
  const bLocal = snapshot.local_addresses.includes(result.endpoint_b.address);
  const local = aLocal !== bLocal ? (aLocal ? result.endpoint_a : result.endpoint_b) : null;
  const remote = local ? (aLocal ? result.endpoint_b : result.endpoint_a) : null;
  const [geo, setGeo] = useState<IpInfo | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const address = remote?.address;
  useEffect(() => {
    let disposed = false;
    setGeo(null); setError("");
    if (!address) return;
    setLoading(true);
    lookupIp(address).then(info => { if (!disposed) setGeo(info); })
      .catch(error => { if (!disposed) setError(String(error)); })
      .finally(() => { if (!disposed) setLoading(false); });
    return () => { disposed = true; };
  }, [address, attempt]);
  const start = snapshot.started_unix_ms == null ? null : new Date(snapshot.started_unix_ms + result.activity.start_seconds * 1000);
  const end = snapshot.started_unix_ms == null ? null : new Date(snapshot.started_unix_ms + result.activity.end_seconds * 1000);
  const format = (date: Date | null) => date ? new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kathmandu", dateStyle: "short", timeStyle: "medium",
  }).format(date) : unknown;
  const connection = geo?.connection;
  const fields: [string, string | number | null | undefined][] = [
    ["Date & time (Nepal)", format(start)], ["Last activity (Nepal)", format(end)],
    ["Application", "WhatsApp candidate (traffic estimate)"], ["Protocol", "UDP"],
    ["Estimated duration", `${result.activity.duration_seconds.toFixed(2)} seconds`],
    ["Source port (local)", local?.port], ["Destination port (observed remote)", remote?.port],
    ["Local address", local?.address], ["Observed remote IP", address],
    ["Remote public IPv4", address && !address.includes(":") && !privateV4(address) ? address : unknown],
    ["Remote IPv6 address", address?.includes(":") ? address : unknown],
    ["Private IP (local adapter)", snapshot.local_addresses.find(privateV4)],
    ["Remote private IP", address && privateV4(address) ? address : unknown],
    ["ISP", connection?.isp], ["Organization", connection?.org],
    ["ASN", connection?.asn == null ? null : `AS${connection.asn}`],
    ["IP city", geo?.city], ["IP region", geo?.region], ["Country", geo?.country],
    ["Domain", connection?.domain], ["Network type", unknown], ["Is VPN", unknown],
    ["Is mobile", unknown], ["Device model", unknown], ["Operating system", unknown], ["OS version", unknown],
  ];
  const lat = geo?.latitude, lon = geo?.longitude;
  const hasLocation = typeof lat === "number" && typeof lon === "number" && Number.isFinite(lat) && Number.isFinite(lon)
    && Math.abs(lat) <= 85 && Math.abs(lon) <= 180;
  const map = hasLocation ? `https://www.openstreetmap.org/export/embed.html?bbox=${encodeURIComponent([
    Math.max(-180, lon - .1), Math.max(-85, lat - .1), Math.min(180, lon + .1), Math.min(85, lat + .1),
  ].join(","))}&layer=mapnik&marker=${encodeURIComponent(`${lat},${lon}`)}` : null;
  return <article className="candidate call-report">
    <h3>Completed call · Top candidate</h3>
    <p className="muted">Observed remote endpoint may be a server/relay. Its IP location is not a verified location of your friend.</p>
    {loading && <p role="status">Looking up network and approximate location...</p>}
    {error && <p role="alert">{error} <button onClick={() => setAttempt(value => value + 1)}>Retry lookup</button></p>}
    {!remote && <p>Could not identify the local side from the selected interface addresses. Observed pair: {result.endpoint_a.address}:{result.endpoint_a.port} ↔ {result.endpoint_b.address}:{result.endpoint_b.port}</p>}
    <dl className="report-fields">{fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value == null || value === "" ? unknown : value}</dd></div>)}</dl>
    <p className="muted">Device details, VPN status, the peer's private address, and an unobserved second IP family cannot be established from this capture or the free lookup.</p>
    <h4>Approximate IP location</h4>
    {map ? <>
      <p>{[geo?.city, geo?.region, geo?.country].filter(Boolean).join(", ") || "Provider location"} · {lat!.toFixed(4)}, {lon!.toFixed(4)}</p>
      <iframe className="location-map" title="Approximate location of the observed remote IP"
        src={map} loading="lazy" referrerPolicy="no-referrer" sandbox="allow-scripts allow-same-origin" />
    </> : <p>{loading ? "Waiting for location lookup." : "No approximate map location available."}</p>}
    <p className="muted">IP data: <a href="https://ipwhois.io/documentation" target="_blank" rel="noreferrer">ipwho.is</a>.
      Map: © OpenStreetMap contributors. The observed public IP is sent to ipwho.is after the call; the map loads from OpenStreetMap.
      Location is approximate and may represent an ISP or relay facility.</p>
  </article>;
}
