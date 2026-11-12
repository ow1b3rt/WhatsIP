# WhatsIP

Desktop WhatsApp call traffic analysis project using **Rust, pcap, Tauri 2, React, and TypeScript**.

The desktop app monitors live packets on a confirmed interface and shows estimated call status: waiting, ringing/setup, connected, and ended. One top IPv4/IPv6 endpoint candidate is revealed only after a connected call is estimated to have ended. Saved PCAP/PCAPNG analysis remains available as a secondary tool. See [live monitoring](docs/live-monitoring.md) and [analysis rules and limits](docs/analysis.md). Verified WhatsApp classification, persistence, and export are not implemented yet. The UI does not generate mock calls.

Completed calls include a [structured IP report](docs/call-report.md), public ISP/ASN/geolocation enrichment, and an approximate-location map. Unsupported device and VPN fields are shown as Unknown.

## Structure

```text
WhatsIP/
├── crates/monitor-core/       # Rust library independent of Tauri
│   └── src/
│       ├── capture/          # pcap interfaces; future live/offline capture
│       ├── packet/           # future link/network/transport decoding
│       ├── analysis/         # future flows, call candidates, timing
│       ├── models/           # endpoint and candidate session models
│       └── storage/          # future persistence and exports
├── src/                      # React + TypeScript
│   ├── app/                  # app composition
│   ├── components/           # shared UI components
│   ├── features/
│   │   ├── capture/          # capture interface UI
│   │   ├── calls/            # future session views
│   │   └── settings/         # future capture preferences
│   ├── hooks/                # shared React hooks
│   ├── lib/                  # typed Tauri IPC wrappers
│   ├── styles/
│   └── types/                # frontend contracts
├── src-tauri/
│   ├── src/commands/         # thin asynchronous IPC adapters
│   ├── capabilities/        # Tauri permissions
│   └── icons/               # source SVG and generated application icons
├── public/                   # static frontend assets
├── config/                   # future example capture configuration
├── data/{captures,exports}/  # ignored local artifacts
├── docs/                     # architecture, setup, roadmap
├── scripts/                  # future development helpers
└── tests/fixtures/           # synthetic or sanitized capture fixtures
```

## Development

See [setup](docs/setup.md) for native prerequisites.

```powershell
npm.cmd install
npm.cmd run dev             # browser UI only
npm.cmd run desktop:dev     # native desktop + Vite
npm.cmd run build           # TypeScript check + frontend build
cargo check -p monitor-core # no native pcap dependency
cargo check --workspace     # requires native prerequisites
cargo fmt --all -- --check
```

Use `npm.cmd` on Windows if PowerShell execution policy blocks `npm.ps1`. Desktop bundling is disabled until installer settings are finalized. `desktop:build` builds the executable without an installer. Regenerate application icons with `npm.cmd run tauri -- icon src-tauri/icons/app-icon.svg` after editing the source SVG.

## Analysis scope

The intended output is observed IPv4/IPv6 endpoints, ports, transport, packet/byte counts, traffic timing, and candidate call sessions with evidence. Caller/receiver fields remain unknown until reliable evidence supports assignment. Both IP families can be recorded when present; a capture cannot invent an address family it never observes.

Observed traffic duration is not automatically the actual call duration. Encrypted payloads, relays, NAT, VPNs, capture location, and packet loss can prevent remote participant attribution or exact start/end detection. This scaffold does not decrypt call contents or identify phone numbers.

See [architecture](docs/architecture.md) and [roadmap](docs/roadmap.md).
